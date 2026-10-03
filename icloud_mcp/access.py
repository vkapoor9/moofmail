"""Control C5: independently verify the Cloudflare Access JWT.

Why the origin must check this itself. `cloudflared` delivers requests to
127.0.0.1 carrying no proof of origin, so "it arrived on the port, therefore
Access let it through" is an assumption, not a fact. Anything else that reaches
the port gets the same treatment. Cloudflare signs an assertion so the origin can
verify identity rather than infer it.

Two locks, deliberately. The Access POLICY decides who may reach the tunnel; this
decides whose token the server will honour. A policy edited in a dashboard cannot
silently widen the server, because the allowed address is also pinned here.

The threat model makes this a go-live gate, proven by presenting a bad token and
observing refusal, not by reading this file.
"""
from __future__ import annotations

from typing import Callable, NamedTuple, Sequence

import jwt

#: Cloudflare Access signs with RS256. Pinned so `alg: none` and HMAC confusion
#: attacks are refused before the key is even looked up.
ALGORITHMS = ["RS256"]

#: Header Cloudflare sets on every authenticated request.
JWT_HEADER = "Cf-Access-Jwt-Assertion"
#: Fallback for browser-style requests.
JWT_COOKIE = "CF_Authorization"


class AccessDenied(Exception):
    """The request did not carry a valid Access assertion for an allowed user."""


class AccessConfig(NamedTuple):
    team_domain: str          # e.g. yourteam.cloudflareaccess.com
    aud: str                  # the Access application's AUD tag
    allowed_emails: Sequence[str]

    @property
    def issuer(self) -> str:
        return f"https://{self.team_domain}"

    @property
    def certs_url(self) -> str:
        return f"https://{self.team_domain}/cdn-cgi/access/certs"

    def validate(self) -> "AccessConfig":
        """Refuse to run on a half-filled config.

        `hostcfg.py` exists in this project because an unfilled template value
        arrived as the literal string '${user_config.x}' and read as truthy,
        which would have inverted a safety default in silence. Same trap here:
        an empty or placeholder AUD would make the audience check meaningless.
        """
        for field in ("team_domain", "aud"):
            val = (getattr(self, field) or "").strip()
            if not val:
                raise ValueError(f"access.{field} is not set")
            if "${" in val:
                raise ValueError(f"access.{field} is still a placeholder: {val!r}")
        if not [e for e in self.allowed_emails if e and e.strip()]:
            raise ValueError("access.allowed_emails is empty; that would allow nobody")
        return self


def verify_token(token: str, cfg: AccessConfig,
                 key_resolver: Callable[[str | None], object]) -> dict:
    """Return the token's claims, or raise AccessDenied.

    `key_resolver` maps a `kid` to a public key. In production that is
    `jwks_resolver(cfg)`; tests pass a local key so the crypto path is real.
    """
    cfg.validate()

    if not token or not token.strip():
        raise AccessDenied("no Access assertion on the request")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise AccessDenied(f"malformed token: {e}") from e

    alg = header.get("alg")
    if alg not in ALGORITHMS:
        raise AccessDenied(f"unexpected signing algorithm {alg!r}")

    try:
        key = key_resolver(header.get("kid"))
    except Exception as e:  # noqa: BLE001 - a lookup failure is a denial, not a 500
        raise AccessDenied(f"no signing key for kid {header.get('kid')!r}: {e}") from e
    if not key:
        raise AccessDenied(f"no signing key for kid {header.get('kid')!r}")

    try:
        claims = jwt.decode(
            token, key, algorithms=ALGORITHMS,
            audience=cfg.aud, issuer=cfg.issuer,
            options={"require": ["exp", "iat", "aud", "iss"]},
        )
    except jwt.PyJWTError as e:
        raise AccessDenied(f"token rejected: {e}") from e

    # str() first: a non-string claim would raise AttributeError, which the
    # middleware does not catch, so the request would 500 instead of being
    # DENIED and audited. Fail closed AND logged, not just fail closed.
    email = str(claims.get("email") or "").strip().lower()
    if not email:
        raise AccessDenied("token carries no email claim (service token?)")
    allowed = {e.strip().lower() for e in cfg.allowed_emails if e and e.strip()}
    if email not in allowed:
        raise AccessDenied(f"{email} is not an allowed user of this connector")

    return claims


def jwks_resolver(cfg: AccessConfig) -> Callable[[str | None], object]:
    """Production key resolver: Cloudflare's team certs, fetched and cached."""
    client = jwt.PyJWKClient(cfg.certs_url, cache_keys=True)

    def resolve(kid: str | None):
        return client.get_signing_key(kid).key

    return resolve


def token_from_request(headers, cookies) -> str:
    """Pull the assertion from the header, falling back to the cookie."""
    tok = ""
    for k, v in (headers or {}).items():
        if k.lower() == JWT_HEADER.lower():
            tok = v or ""
            break
    return tok or (cookies or {}).get(JWT_COOKIE, "") or ""
