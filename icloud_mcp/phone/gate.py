"""The self-test gate. Setup refuses to hand out the connector URL unless it passes.

Each check is a small pure function over what was OBSERVED (HTTP status codes,
the OS's own listener table, the process list, the Access app as the API returns
it), so every one can be fed a deliberately broken setup in the tests and shown
to fail. A gate that has only ever seen good setups has not been tested.

The checks mirror the hand audit of the working connector:
  1. every path on the public hostname answers 401 without a login
  2. a forged `alg: none` token and a garbage cookie are refused at the edge
  3. a forged token sent straight to the local port gets 403 from the server
  4. the server listens on 127.0.0.1 only
  5. the running server serves exactly the chosen profile's tools
  6. the Access app covers the whole hostname and allows exactly one email
  7. the tunnel token is not visible in any process's arguments
"""
from __future__ import annotations

import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

#: (method, url, headers) -> status code, or 0 when nothing answered
Fetch = Callable[[str, str, dict], int]

def _forged_token() -> str:
    """An unsigned `alg: none` token claiming a made-up email. Built at runtime so no
    token-shaped literal sits in the source; it is worthless by construction."""
    import base64
    import json as _json
    enc = lambda d: base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none'})}.{enc({'email': 'you@example.com'})}."


FORGED = _forged_token()
EDGE_PATHS = ("/", "/mcp", "/healthz", "/.env")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    #: Could not be run (e.g. doctor without an API token). Never counts as a pass:
    #: GateResult.ok needs at least one real check, and the report says SKIP.
    skipped: bool = False


@dataclass
class GateResult:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        real = [c for c in self.checks if not c.skipped]
        return bool(real) and all(c.ok for c in real)

    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.skipped and not c.ok]

    def skipped(self) -> list[Check]:
        return [c for c in self.checks if c.skipped]

    def report(self) -> str:
        def tag(c: Check) -> str:
            return "SKIP" if c.skipped else ("PASS" if c.ok else "FAIL")
        return "\n".join(f"  [{tag(c)}] {c.name}"
                         + (f": {c.detail}" if c.detail else "") for c in self.checks)


#: Cloudflare answers Python's default "Python-urllib/x.y" agent with error 1010
#: (403) before Access ever sees the request. Found live 2026-10-03: every edge
#: check read 403 while curl got the correct 401. Always send a named agent.
USER_AGENT = "moofmail-phone/1.3"


def urllib_fetch(method: str, url: str, headers: dict) -> int:
    headers = {"User-Agent": USER_AGENT, **headers}
    req = urllib.request.Request(url, method=method, headers=headers, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


# ----------------------------------------------------------------------- checks
def check_edge_unauthenticated(hostname: str, fetch: Fetch) -> Check:
    paths = list(EDGE_PATHS) + ["/" + secrets.token_hex(6)]
    seen = {p: fetch("POST", f"https://{hostname}{p}", {}) for p in paths}
    bad = {p: s for p, s in seen.items() if s != 401}
    return Check("every path refuses an unauthenticated request (401)", not bad,
                 "" if not bad else f"unexpected status: {bad}")


def check_edge_forged(hostname: str, fetch: Fetch) -> Check:
    a = fetch("POST", f"https://{hostname}/mcp", {"Cf-Access-Jwt-Assertion": FORGED})
    b = fetch("POST", f"https://{hostname}/mcp", {"Cookie": "CF_Authorization=garbage"})
    ok = a == 401 and b == 401
    return Check("forged token and garbage cookie refused at the edge", ok,
                 "" if ok else f"forged header -> {a}, garbage cookie -> {b}")


def check_origin_forged(port: int, hostname: str, fetch: Fetch) -> Check:
    s = fetch("POST", f"http://127.0.0.1:{port}/mcp",
              {"Host": hostname, "Cf-Access-Jwt-Assertion": FORGED})
    return Check("server itself refuses a forged token (403)", s == 403,
                 "" if s == 403 else f"local server answered {s}")


_LOOPBACK = {"127.0.0.1", "::1", "[::1]", "localhost"}


def check_bind(addresses: list[str]) -> Check:
    if not addresses:
        return Check("server listens on 127.0.0.1 only", False, "nothing is listening on the port")
    bad = [a for a in addresses if a not in _LOOPBACK]
    return Check("server listens on 127.0.0.1 only", not bad,
                 "" if not bad else f"also listening on {bad}: the mailbox would be reachable "
                                    "from the local network without any login")


def check_tools(served: dict | None, expected_profile: str, expected_tools: set[str]) -> Check:
    if not served:
        return Check("running server serves exactly the chosen tools", False,
                     "could not read the local tool list")
    got = set(served.get("tools") or [])
    prof = served.get("profile")
    ok = prof == expected_profile and got == expected_tools
    detail = ""
    if not ok:
        detail = (f"profile {prof!r} (wanted {expected_profile!r}); "
                  f"extra {sorted(got - expected_tools)}; missing {sorted(expected_tools - got)}")
    return Check("running server serves exactly the chosen tools", ok, detail)


def check_access_scope(app: dict | None, hostname: str, email: str) -> Check:
    name = "Access covers the whole hostname and allows exactly one person"
    if not app:
        return Check(name, False, "Access application not found")
    problems = []
    uris = [d.get("uri", "") for d in app.get("destinations") or [] if isinstance(d, dict)]
    uris += list(app.get("self_hosted_domains") or [])
    if app.get("domain"):
        uris.append(app["domain"])
    for u in set(uris):
        if u.rstrip("/") != hostname:
            problems.append(f"covers {u!r}, not exactly {hostname!r} (a path-scoped app leaves "
                            "other paths open)")
    rules = []
    for pol in app.get("policies") or []:
        if pol.get("decision") != "allow":
            continue
        rules += pol.get("include") or []
    emails = []
    for r in rules:
        if set(r) == {"email"}:
            emails.append((r["email"] or {}).get("email", "").lower())
        else:
            problems.append(f"policy includes a non-email rule {list(r)}")
    if emails != [email.lower()]:
        problems.append(f"policy allows {emails or 'nobody'}, wanted exactly [{email.lower()}]")
    if (app.get("oauth_configuration") or {}).get("enabled") is not True:
        problems.append("Managed OAuth is off, so Claude cannot sign in")
    return Check(name, not problems, "; ".join(problems))


def check_token_hidden(process_lines: list[str], token: str | None) -> Check:
    name = "tunnel token is not visible in any process's arguments"
    if not token:
        return Check(name, False, "no tunnel token stored")
    bad = [l for l in process_lines if token in l or ("cloudflared" in l and "--token" in l)]
    return Check(name, not bad, "" if not bad else f"{len(bad)} process(es) expose it")


# ----------------------------------------------------------------------- runner
def run_gate(*, hostname: str, port: int, email: str, profile: str, expected_tools: set[str],
             token: str | None, app: dict | None, fetch: Fetch, local_tools: Callable[[], dict | None],
             listeners: Callable[[], list[str]], process_lines: Callable[[], list[str]]) -> GateResult:
    g = GateResult()
    g.checks.append(check_edge_unauthenticated(hostname, fetch))
    g.checks.append(check_edge_forged(hostname, fetch))
    g.checks.append(check_origin_forged(port, hostname, fetch))
    g.checks.append(check_bind(listeners()))
    g.checks.append(check_tools(local_tools(), profile, expected_tools))
    g.checks.append(check_access_scope(app, hostname, email))
    g.checks.append(check_token_hidden(process_lines(), token))
    return g


def expected_tools_for(profile: str) -> set[str]:
    from .. import remote
    names = set(remote.REMOTE_TOOLS)
    if profile == "write":
        names |= set(remote.REMOTE_WRITE_TOOLS)
    return names
