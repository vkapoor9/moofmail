"""Does an unauthenticated request actually get refused at the origin?

Two bugs guarded here.

1. Trusting the tunnel. cloudflared hands requests to 127.0.0.1 with no proof of
   who sent them. Without this middleware the server answers anything that
   reaches the port, and Cloudflare Access becomes the ONLY lock rather than the
   first of two.

2. The DNS-rebinding trap the threat model flagged. FastMCP turns rebinding
   protection on and auto-pins allowed_hosts to localhost when host is
   127.0.0.1. The tunnel forwards the REAL Host header (mcp.example.com), so
   every request would be rejected with an error mentioning nothing relevant.
   The public hostname has to be named explicitly. The documented wrong fix is
   setting httpHostHeader in cloudflared, which disables the protection instead
   of configuring it.

Real signatures, real ASGI round trips through starlette's TestClient.
"""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.applications import Starlette
from starlette.testclient import TestClient

from icloud_mcp.access import AccessConfig, JWT_HEADER
from icloud_mcp import transport

TEAM = "yourteam.cloudflareaccess.com"
AUD = "c" * 64
OWNER = "you@me.com"
CFG = AccessConfig(team_domain=TEAM, aud=AUD, allowed_emails=(OWNER,))

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
RESOLVER = lambda kid: PUB  # noqa: E731


def _token(**over):
    now = int(time.time())
    claims = {"aud": [AUD], "iss": f"https://{TEAM}", "email": OWNER,
              "iat": now, "exp": now + 3600}
    claims.update(over)
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})


def _inner():
    return Starlette(routes=[Route("/mcp", lambda r: PlainTextResponse("REACHED"))])


def _client():
    return TestClient(transport.build_app(CFG, key_resolver=RESOLVER, inner=_inner()))


def test_request_with_no_token_is_refused():
    r = _client().get("/mcp")
    assert r.status_code == 403
    assert "REACHED" not in r.text


def test_request_with_a_forged_token_is_refused():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = jwt.encode({"aud": [AUD], "iss": f"https://{TEAM}", "email": OWNER,
                         "iat": now, "exp": now + 3600},
                        other, algorithm="RS256", headers={"kid": "k1"})
    r = _client().get("/mcp", headers={JWT_HEADER: forged})
    assert r.status_code == 403
    assert "REACHED" not in r.text


def test_request_from_another_person_is_refused():
    r = _client().get("/mcp", headers={JWT_HEADER: _token(email="someone@else.com")})
    assert r.status_code == 403


def test_request_with_a_valid_token_reaches_the_server():
    r = _client().get("/mcp", headers={JWT_HEADER: _token()})
    assert r.status_code == 200
    assert r.text == "REACHED"


def test_refusal_does_not_echo_the_reason_to_the_caller():
    """Denial detail goes to the audit log, not to whoever is probing."""
    r = _client().get("/mcp")
    assert "email" not in r.text.lower()
    assert "claim" not in r.text.lower()


def test_health_endpoint_answers_without_a_token():
    """Liveness check exempt from the assertion, so the LaunchAgent can be
    verified without minting a token. NOTE: the tunnel ingress is a catch-all and
    DOES route this path; what keeps it private is that the Cloudflare Access app
    covers the whole hostname. See _health()'s docstring."""
    r = _client().get("/healthz")
    assert r.status_code == 200


def test_transport_security_names_the_public_hostname():
    """The documented trap: without this every tunnelled request is rejected."""
    srv = transport.build_mcp_server(public_hostname="mcp.example.com")
    allowed = srv.settings.transport_security.allowed_hosts
    assert "mcp.example.com" in allowed
    assert srv.settings.transport_security.enable_dns_rebinding_protection is True


def test_server_defaults_to_loopback_only():
    """C0. A 0.0.0.0 bind would serve the whole mailbox, unauthenticated, to
    everyone on whatever wifi the laptop is on."""
    srv = transport.build_mcp_server(public_hostname="mcp.example.com")
    assert srv.settings.host == "127.0.0.1"


def test_the_served_app_is_the_read_only_profile():
    """The remote process must never serve server.mcp."""
    import asyncio
    srv = transport.build_mcp_server(public_hostname="mcp.example.com")
    names = {t.name for t in asyncio.run(srv.list_tools())}
    assert "send_mail" not in names
    assert "list_inbox" in names


def test_a_valid_token_reaches_the_REAL_mcp_app_not_a_500():
    """Regression, found live 2026-09-21 and invisible to every test above.

    Mounting FastMCP's streamable_http_app inside an outer Starlette does not
    carry its lifespan across, so the StreamableHTTP session manager is never
    started and the first real request dies with "Task group is not
    initialized". The tests above all passed because they wrapped a toy inner
    app that needs no lifespan. Only a real handshake exposes it.

    base_url sets a Host: the rebinding protection accepts.
    """
    app = transport.build_app(CFG, key_resolver=RESOLVER,
                              public_hostname="mcp.example.com")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        r = client.post(
            "/mcp",
            headers={JWT_HEADER: _token(),
                     "Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "probe", "version": "1"}}},
        )
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}"
    assert "Task group is not initialized" not in r.text
