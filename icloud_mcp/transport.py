"""Streamable HTTP transport for the remote, read-only connector.

Serves `icloud_mcp.remote` (the allowlisted profile) on 127.0.0.1 behind
`cloudflared`, and refuses any request that does not carry a valid Cloudflare
Access assertion for an allowed user (control C5).

Three things here are deliberate and easy to get wrong:

**Raw ASGI middleware, not BaseHTTPMiddleware.** Streamable HTTP is a streaming
transport. Starlette's BaseHTTPMiddleware buffers, which breaks SSE-style
responses in ways that look like the connector hanging.

**allowed_hosts must name the public hostname.** FastMCP enables DNS-rebinding
protection and pins allowed_hosts to localhost when host is 127.0.0.1. The tunnel
forwards the real `Host:` header, so without this every tunnelled request is
rejected with an error that mentions nothing relevant. Do NOT "fix" that by
setting `httpHostHeader` in cloudflared: that disables the protection rather than
configuring it.

**C0: bind 127.0.0.1, never 0.0.0.0.** On a laptop a wildcard bind serves the
entire mailbox, unauthenticated, to everyone on the same wifi, going around
Cloudflare Access completely. Proven with `lsof`, not by reading this file.
"""
from __future__ import annotations

import logging
import os
import tomllib
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route

from .access import (AccessConfig, AccessDenied, jwks_resolver,
                     token_from_request, verify_token)
from .config import DEFAULT_PATH
from . import remote as _remote
from .remote import build_server
from .server import _audit

log = logging.getLogger("icloud_mcp.remote")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
EXEMPT_PATHS = ("/healthz", "/healthz/tools")


class AccessMiddleware:
    """Refuse anything without a valid Access assertion for an allowed user."""

    def __init__(self, app, cfg: AccessConfig, key_resolver,
                 exempt: tuple[str, ...] = EXEMPT_PATHS):
        self.app, self.cfg, self.resolve, self.exempt = app, cfg, key_resolver, exempt

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            # No websocket surface is intended. Refuse rather than pass through.
            _audit("remote_denied", f"non-http scope {scope['type']!r}")
            return
        if scope.get("path", "") in self.exempt:
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        jar = SimpleCookie()
        jar.load(headers.get("cookie", ""))
        cookies = {k: m.value for k, m in jar.items()}

        try:
            claims = verify_token(token_from_request(headers, cookies),
                                  self.cfg, self.resolve)
        except AccessDenied as e:
            # The reason goes to the audit log. The caller gets nothing useful.
            _audit("remote_denied", f"{scope.get('path','')} {e}")
            log.warning("remote request denied: %s", e)
            await PlainTextResponse("forbidden", status_code=403)(scope, receive, send)
            return

        _audit("remote_request", f"{claims.get('email')} {scope.get('path','')}")
        scope.setdefault("state", {})["access_email"] = claims.get("email")
        await self.app(scope, receive, send)


def build_mcp_server(public_hostname: str, host: str = DEFAULT_HOST,
                     port: int = DEFAULT_PORT, profile: str = "read") -> FastMCP:
    """The remote profile ("read" by default), configured for service behind the tunnel."""
    sec = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[public_hostname, f"{public_hostname}:443",
                       f"{host}:{port}", f"localhost:{port}"],
        allowed_origins=[f"https://{public_hostname}"],
    )
    return build_server(host=host, port=port, profile=profile, transport_security=sec)


async def _health(_request):
    """Liveness check, exempt from the Access assertion.

    What actually keeps this off the public internet is NOT the tunnel ingress:
    that is a catch-all to 127.0.0.1:8765 and does route /healthz. It is that the
    Cloudflare Access application covers the whole hostname rather than a path
    prefix, so the edge challenges every path. Verified 2026-09-22: /, /mcp,
    /healthz, /foo and /.env all return 401 unauthenticated.

    If the Access app is ever narrowed to a path, this becomes a public
    unauthenticated endpoint. It returns the literal string "ok" and nothing
    else, but re-run the unauthenticated probe after any Access change.
    """
    return PlainTextResponse("ok")


def _tools_route(profile: str, tool_names: list[str]):
    """Local-only self-test endpoint: which profile and tools this process serves.

    Exempt from the Access assertion like /healthz, so the setup self-test can
    compare what is RUNNING against what the user chose. Tool names are not
    secret, but the endpoint still refuses anything that arrived through the
    tunnel: cloudflared stamps every forwarded request with a Cf-Ray header,
    and a request from the machine itself carries none.
    """
    async def _tools(request):
        if request.headers.get("cf-ray") or request.headers.get("cf-connecting-ip"):
            return PlainTextResponse("not found", status_code=404)
        return JSONResponse({"profile": profile, "tools": sorted(tool_names)})
    return _tools


def build_app(cfg: AccessConfig, key_resolver=None, inner=None,
              public_hostname: str = "", host: str = DEFAULT_HOST,
              port: int = DEFAULT_PORT, profile: str = "read",
              tool_names: list[str] | None = None):
    """The full ASGI app: health check, MCP transport, Access enforcement."""
    cfg.validate()
    if inner is None:
        srv = build_mcp_server(public_hostname, host, port, profile)
        if tool_names is None:
            import asyncio
            tool_names = [t.name for t in asyncio.run(srv.list_tools())]
        inner = srv.streamable_http_app()

    # Mounting does NOT carry the inner app's lifespan across, and FastMCP starts
    # its StreamableHTTP session manager in exactly that lifespan. Without this the
    # first real request dies with "Task group is not initialized", which no test
    # using a toy inner app can ever surface. Found live 2026-09-21.
    inner_lifespan = getattr(getattr(inner, "router", None), "lifespan_context", None)

    lifespan = None
    if inner_lifespan is not None:
        @asynccontextmanager
        async def lifespan(_outer):  # noqa: F811
            async with inner_lifespan(inner):
                yield

    routed = Starlette(routes=[Route("/healthz", _health),
                               Route("/healthz/tools", _tools_route(profile, tool_names or [])),
                               Mount("/", app=inner)],
                       lifespan=lifespan)
    return AccessMiddleware(routed, cfg, key_resolver or jwks_resolver(cfg))


# ------------------------------------------------------------------ config
def load_remote_config(path: str | os.PathLike | None = None) -> dict:
    """Read the [remote] block from the same config.toml the rest of the server uses.

    Kept separate from config.py's parser on purpose: that file is load-bearing
    for mail routing, and this is additive.
    """
    p = Path(os.path.expanduser(str(path or DEFAULT_PATH)))
    if not p.exists():
        raise FileNotFoundError(f"no config at {p}")
    with p.open("rb") as f:
        block = tomllib.load(f).get("remote") or {}
    if not block:
        raise ValueError(f"{p} has no [remote] section; the connector is not configured")
    return block


def config_from_block(block: dict) -> tuple[AccessConfig, dict]:
    cfg = AccessConfig(
        team_domain=block.get("team_domain", ""),
        aud=block.get("aud", ""),
        allowed_emails=tuple(block.get("allowed_emails") or ()),
    ).validate()
    opts = {
        "public_hostname": block.get("public_hostname", ""),
        "host": block.get("host", DEFAULT_HOST),
        "port": int(block.get("port", DEFAULT_PORT)),
        # "read" unless the owner explicitly opts in. Anything else refuses to start.
        "profile": str(block.get("profile", "read")).strip().lower(),
    }
    if opts["profile"] not in _remote.PROFILES:
        raise ValueError(f"[remote].profile is {opts['profile']!r}; expected one of "
                         f"{_remote.PROFILES}")
    _remote.set_caps(block.get("caps"))
    if not opts["public_hostname"]:
        raise ValueError("[remote].public_hostname is not set")
    # Apply the mail-folder block list. Default blocks iCloud Notes, which Apple
    # stores as ordinary IMAP folders and which every mail tool could otherwise
    # reach through its free-text `folder` parameter.
    _remote.set_blocked_folders(block.get("blocked_folders",
                                          _remote.DEFAULT_BLOCKED_FOLDERS))

    if opts["host"] != DEFAULT_HOST:
        raise ValueError(
            f"[remote].host is {opts['host']!r}. C0 requires {DEFAULT_HOST}: a wildcard "
            "bind serves the whole mailbox unauthenticated to the local network."
        )
    return cfg, opts


def serve(path: str | os.PathLike | None = None) -> None:
    """Run the remote connector from a config file's [remote] block.

    `path` defaults to the main config.toml. The phone-access installer points it
    at its own file so it never has to edit the user's hand-written config.
    """
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    cfg, opts = config_from_block(load_remote_config(path))
    app = build_app(cfg, **opts)
    log.info("%s connector on %s:%s for %s", opts["profile"],
             opts["host"], opts["port"], ", ".join(cfg.allowed_emails))
    uvicorn.run(app, host=opts["host"], port=opts["port"], log_level="info")


def main() -> None:
    serve(os.environ.get("ICLOUD_MCP_REMOTE_CONFIG") or None)


if __name__ == "__main__":
    main()
