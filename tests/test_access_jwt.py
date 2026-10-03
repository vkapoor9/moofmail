"""Does the server independently verify the Cloudflare Access JWT? (Control C5)

The bug this guards: trusting the tunnel. cloudflared delivers requests to
127.0.0.1 with no proof of who sent them, so a server that assumes "it arrived,
therefore Access approved it" will happily serve the whole mailbox to anything
that reaches the port. Cloudflare signs an assertion precisely so the origin can
check it itself, and the threat model makes C5 a go-live gate: Managed OAuth is
not switched on until this is proven by presenting a bad token and watching the
refusal.

Real keys, real signatures, no mocked crypto. Each test builds a token that is
wrong in exactly one way, so a pass means that specific check is doing work.
"""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icloud_mcp.access import AccessConfig, AccessDenied, verify_token

TEAM = "yourteam.cloudflareaccess.com"
AUD = "a" * 64
OWNER = "you@me.com"

CFG = AccessConfig(team_domain=TEAM, aud=AUD, allowed_emails=(OWNER,))


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


GOOD_KEY = _key()
OTHER_KEY = _key()


def _pem(k):
    return k.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _resolver(key=None):
    pub = _pem(key or GOOD_KEY)
    return lambda kid: pub


def _token(key=None, **over):
    now = int(time.time())
    claims = {
        "aud": [AUD],
        "iss": f"https://{TEAM}",
        "email": OWNER,
        "iat": now,
        "exp": now + 3600,
        "sub": "user-1",
    }
    claims.update(over)
    return jwt.encode(claims, key or GOOD_KEY, algorithm="RS256",
                      headers={"kid": "test-kid"})


def test_a_correct_token_is_accepted():
    claims = verify_token(_token(), CFG, _resolver())
    assert claims["email"] == OWNER


def test_missing_token_is_denied():
    with pytest.raises(AccessDenied):
        verify_token("", CFG, _resolver())


def test_token_signed_by_another_key_is_denied():
    """Anyone can mint a JWT. Only Cloudflare can sign one Cloudflare's key verifies."""
    with pytest.raises(AccessDenied):
        verify_token(_token(key=OTHER_KEY), CFG, _resolver(GOOD_KEY))


def test_token_for_a_different_access_app_is_denied():
    """A valid token from another app on the same team must not open this one."""
    with pytest.raises(AccessDenied):
        verify_token(_token(aud=["b" * 64]), CFG, _resolver())


def test_token_from_a_different_team_is_denied():
    with pytest.raises(AccessDenied):
        verify_token(_token(iss="https://someone-else.cloudflareaccess.com"),
                     CFG, _resolver())


def test_expired_token_is_denied():
    now = int(time.time())
    with pytest.raises(AccessDenied):
        verify_token(_token(iat=now - 7200, exp=now - 60), CFG, _resolver())


def test_a_different_person_is_denied():
    """The Access policy should already stop this. C5 is the second lock:
    single-user by construction, so a policy edit cannot silently widen it."""
    with pytest.raises(AccessDenied):
        verify_token(_token(email="second@me.com"), CFG, _resolver())


def test_email_comparison_is_case_insensitive():
    claims = verify_token(_token(email="You@ME.com"), CFG, _resolver())
    assert claims["email"].lower() == OWNER


def test_token_with_no_email_claim_is_denied():
    """A service token authenticates but carries no email. It is not the owner."""
    tok = _token()
    payload = jwt.decode(tok, _pem(GOOD_KEY), algorithms=["RS256"],
                         audience=AUD, issuer=f"https://{TEAM}")
    payload.pop("email")
    with pytest.raises(AccessDenied):
        verify_token(jwt.encode(payload, GOOD_KEY, algorithm="RS256",
                                headers={"kid": "test-kid"}), CFG, _resolver())


def test_unsigned_alg_none_token_is_denied():
    """The classic JWT bypass: alg=none. Must never be accepted."""
    now = int(time.time())
    forged = jwt.encode({"aud": [AUD], "iss": f"https://{TEAM}", "email": OWNER,
                         "iat": now, "exp": now + 3600},
                        key="", algorithm="none")
    with pytest.raises(AccessDenied):
        verify_token(forged, CFG, _resolver())


def test_config_refuses_a_placeholder_aud():
    """hostcfg.py exists because a blank template value arrived as the literal
    '${user_config.x}' and read as truthy. Same trap, same refusal."""
    with pytest.raises(ValueError):
        AccessConfig(team_domain=TEAM, aud="", allowed_emails=(OWNER,)).validate()
    with pytest.raises(ValueError):
        AccessConfig(team_domain=TEAM, aud="${aud}", allowed_emails=(OWNER,)).validate()
