"""Setup, doctor and teardown for phone and voice access.

Design decisions, each one learned on a real deployment:

* **The user's config.toml is never edited.** A config.toml beats the plugin's own
  settings, and a hand-written file defaults to sending ON, so writing one would
  quietly change how the local plugin behaves. Phone access keeps its own file,
  ~/.config/moofmail/phone.toml, and the service reads only that.
* **The Cloudflare API token is used once and never stored.** It can rewrite the
  login rules in front of the mailbox. Setup asks for it, uses it, and tells the
  user to delete it. Teardown asks for a fresh one.
* **Nothing is printed as ready until the gate passes.** A half-working setup that
  hands out a URL is worse than one that stops and says what failed.
* **The team name is chosen once.** Renaming a Zero Trust team breaks Managed OAuth
  on every existing Access app, and only new apps on new hostnames recover, so
  doctor treats an issuer mismatch as "re-run setup", not as an attack.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import tomllib
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from . import gate as _gate
from . import platforms
from .cf import TAG, Cloudflare, CloudflareError, Resources

CONFIG_PATH = platforms.STATE_DIR / "phone.toml"
DEFAULT_PORT = 8770
DEFAULT_PREFIX = "com.moofmail.phone"
GRANT_DAYS = 365

#: Short permission keys a USER token template link understands, verified against
#: developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template.
#: That page documents no key for Cloudflare Tunnel, and user-token links silently
#: drop keys they do not recognise, so the tunnel permission is added by hand
#: (setup checks it and says exactly which line is missing).
TEMPLATE_KEYS = [
    {"key": "account_settings", "type": "read"},
    {"key": "access", "type": "edit"},
    {"key": "access_acct", "type": "edit"},
    {"key": "zone", "type": "read"},
    {"key": "dns", "type": "edit"},
]
MANUAL_PERMISSION = "Account > Cloudflare Tunnel > Edit"


def token_template_url() -> str:
    keys = urllib.parse.quote(json.dumps(TEMPLATE_KEYS, separators=(",", ":")), safe="")
    return ("https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys="
            f"{keys}&accountId=%2A&zoneId=all&name=moofmail-setup")


ONBOARDING_STEPS = """Zero Trust is not set up on this Cloudflare account yet. In the dashboard:
  1. Open Zero Trust (left sidebar).
  2. Choose a team name. Pick a general one: it becomes the login page for anything
     you ever protect, and renaming it later breaks existing apps.
  3. Choose the Free plan. Cloudflare asks for a card even on Free; you are not charged.
Then run setup again."""


# ======================================================================= state
@dataclass
class PhoneState:
    hostname: str = ""
    email: str = ""
    profile: str = "read"
    port: int = DEFAULT_PORT
    team_domain: str = ""
    aud: str = ""
    platform: str = ""
    store: str = ""
    label_prefix: str = DEFAULT_PREFIX
    apple_id: str = ""
    send_enabled: bool = False
    created: str = ""
    resources: Resources = field(default_factory=Resources)


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps(str(v))


def write_state(st: PhoneState, path: Path = CONFIG_PATH) -> None:
    remote = {"team_domain": st.team_domain, "aud": st.aud, "allowed_emails": [st.email],
              "public_hostname": st.hostname, "host": "127.0.0.1", "port": st.port,
              "profile": st.profile}
    phone = {k: v for k, v in asdict(st).items() if k != "resources"}
    lines = ["# Written by `moofmail-phone setup`. The [remote] block is what the",
             "# phone service reads; [phone] records what setup created, for teardown.", "",
             "[remote]"]
    lines += [f"{k} = {_toml_value(v)}" for k, v in remote.items()]
    lines += ["", "[phone]"] + [f"{k} = {_toml_value(v)}" for k, v in phone.items()]
    lines += ["", "[phone.resources]"] + [f"{k} = {_toml_value(v)}" for k, v in asdict(st.resources).items()]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


def read_state(path: Path = CONFIG_PATH) -> PhoneState | None:
    try:
        data = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return None
    ph = dict(data.get("phone") or {})
    res = Resources(**(ph.pop("resources", None) or {}))
    known = {k: v for k, v in ph.items() if k in PhoneState.__dataclass_fields__}
    return PhoneState(**known, resources=res)


# ======================================================================= helpers
class SetupError(RuntimeError):
    pass


@dataclass
class Env:
    """Everything setup touches, injectable so tests never reach a real system."""
    cf: Cloudflare
    store: platforms.SecretStore
    services: platforms.ServiceManager | None
    fetch: _gate.Fetch = _gate.urllib_fetch
    listeners: Callable[[int], list[str]] = platforms.listeners
    process_lines: Callable[[], list[str]] = platforms.process_args
    local_tools: Callable[[int], dict | None] | None = None
    say: Callable[[str], None] = print
    wait_tunnel: Callable[[Cloudflare, str, str], bool] | None = None
    #: Waits for Cloudflare to publish a new hostname before the gate judges it.
    #: None means the real wait; tests pass a no-op.
    wait_ready: Callable[["Env", "PhoneState"], None] | None = None
    #: hostname -> issuer URL from /.well-known/oauth-authorization-server, or None.
    public_issuer: Callable[[str], str | None] | None = None
    config_path: Path = CONFIG_PATH
    system: str = ""


def _public_issuer(hostname: str) -> str | None:
    import urllib.request
    try:
        req = urllib.request.Request(f"https://{hostname}/.well-known/oauth-authorization-server",
                                     headers={"User-Agent": _gate.USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("issuer")
    except Exception:
        return None


def _local_tools_http(port: int) -> dict | None:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz/tools", timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _wait_tunnel(cf: Cloudflare, account_id: str, tunnel_id: str, seconds: int = 90) -> bool:
    import time
    end = time.time() + seconds
    while time.time() < end:
        try:
            t = cf.tunnel(account_id, tunnel_id)
            if (t or {}).get("status") == "healthy":
                return True
        except CloudflareError:
            pass
        time.sleep(3)
    return False


#: Edge answers that mean "not published yet", not "wrong". 200 is NOT here: an open
#: endpoint must reach the gate immediately and fail it.
_NOT_READY = {0, 403, 404, 502, 503, 520, 521, 522, 523, 524, 530}


def _wait_ready(env: "Env", st: "PhoneState", seconds: int = 240, step: float = 5.0,
                sleep: Callable[[float], None] | None = None,
                clock: Callable[[], float] | None = None) -> None:
    """Give Cloudflare time to publish a just-created app, DNS record and tunnel.

    Found live 2026-10-03: the gate ran seconds after setup created everything and
    saw 403 on every path, which a minute later had become the correct 401. This
    only delays the gate; the gate itself still decides pass or fail.
    """
    import time
    sleep = sleep or time.sleep
    clock = clock or time.monotonic
    end = clock() + seconds
    told = False
    while clock() < end:
        edge = env.fetch("POST", f"https://{st.hostname}/mcp", {})
        local = env.listeners(st.port)
        if edge not in _NOT_READY and local:
            return
        if not told:
            env.say("Waiting for Cloudflare to publish the new hostname (this can take a few minutes)...")
            told = True
        sleep(step)


def secret_names(st: PhoneState) -> tuple[str, str]:
    return f"tunnel_token:{st.hostname}", f"app_password:{st.apple_id}"


def _pick_one(items: list, label: str, want: str | None, key: str = "name"):
    if want:
        hit = [i for i in items if i.get(key) == want or i.get("id") == want]
        if not hit:
            raise SetupError(f"{label} {want!r} not found. Available: "
                             f"{', '.join(i.get(key, '?') for i in items) or 'none'}")
        return hit[0]
    if len(items) == 1:
        return items[0]
    if not items:
        raise SetupError(f"no {label} available to this token")
    raise SetupError(f"several {label}s: pass one of {', '.join(i.get(key, '?') for i in items)}")


# ======================================================================= setup
def run_setup(env: Env, *, email: str, domain: str | None = None, hostname: str | None = None,
              profile: str = "read", port: int = DEFAULT_PORT, account: str | None = None,
              apple_id: str, app_password: str | None, send_enabled: bool = False,
              label_prefix: str = DEFAULT_PREFIX) -> PhoneState:
    say = env.say
    if profile not in ("read", "write"):
        raise SetupError("profile must be 'read' or 'write'")
    if "@" not in email:
        raise SetupError("email must be the address you will sign in with")
    say("Checking the API token...")
    tok = env.cf.verify_token()
    if (tok or {}).get("status") != "active":
        raise SetupError(f"the API token is not active ({(tok or {}).get('status')})")

    acct = _pick_one(env.cf.accounts(), "account", account)
    aid = acct["id"]

    perms = env.cf.probe(aid)
    missing = [k for k, ok in perms.items() if not ok]
    if missing:
        raise SetupError("the token is missing: " + ", ".join(missing)
                         + f". Edit the token and add them (the tunnel one is {MANUAL_PERMISSION}).")

    org = env.cf.organization(aid)
    if not org:
        raise SetupError(ONBOARDING_STEPS)
    team_domain = org["auth_domain"]

    zones = env.cf.zones(aid)
    zone = _pick_one(zones, "domain", domain)
    host = (hostname or f"mail.{zone['name']}").lower().rstrip(".")
    if not (host == zone["name"] or host.endswith("." + zone["name"])):
        raise SetupError(f"{host} is not inside {zone['name']}")
    if not env.cf.probe(aid, zone["id"]).get("DNS Edit", False):
        raise SetupError(f"the token cannot manage DNS for {zone['name']}: add Zone > DNS > Edit")
    if env.cf.dns_records(zone["id"], host):
        raise SetupError(f"{host} already has a DNS record. Pick another hostname; setup never "
                         "overwrites an existing record.")

    st = PhoneState(hostname=host, email=email.lower(), profile=profile, port=int(port),
                    team_domain=team_domain, platform=env.system, store=env.store.kind,
                    label_prefix=label_prefix, apple_id=apple_id.lower(),
                    send_enabled=bool(send_enabled and profile == "write"),
                    created=_dt.date.today().isoformat(),
                    resources=Resources(account_id=aid, zone_id=zone["id"]))
    r = st.resources
    slug = host.replace(".", "-")

    say(f"Creating the login rules and tunnel for {host}...")
    idps = env.cf.identity_providers(aid)
    otp = [i for i in idps if i.get("type") == "onetimepin"]
    if otp:
        r.idp_id = otp[0]["id"]
    else:
        r.idp_id = env.cf.create_otp_idp(aid)["id"]; r.idp_created = True
    write_state(st, env.config_path)  # record progress so teardown can clean a failed run

    r.tunnel_id = env.cf.create_tunnel(aid, f"{TAG}{slug}")["id"]; write_state(st, env.config_path)
    env.cf.put_ingress(aid, r.tunnel_id, host, st.port)
    r.dns_record_id = env.cf.create_cname(zone["id"], host, r.tunnel_id)["id"]; write_state(st, env.config_path)
    r.policy_id = env.cf.create_policy(aid, f"{TAG}{slug}-owner", st.email)["id"]; write_state(st, env.config_path)
    r.app_id = env.cf.create_app(aid, f"{TAG}{slug}", host, r.policy_id, [r.idp_id])["id"]
    st.aud = env.cf.app(aid, r.app_id)["aud"]
    write_state(st, env.config_path)

    tunnel_name, pw_name = secret_names(st)
    env.store.set(tunnel_name, env.cf.tunnel_token(aid, r.tunnel_id))
    if app_password:
        env.store.set(pw_name, app_password)
    elif not env.store.get(pw_name):
        raise SetupError("no Apple app-specific password given or stored")
    if env.store.warning:
        say("WARNING: " + env.store.warning)

    if env.services is not None:
        say("Starting the two background services...")
        env.services.install(label_prefix, env.config_path)
        (env.wait_tunnel or _wait_tunnel)(env.cf, aid, r.tunnel_id)

    return st


def gate_for(env: Env, st: PhoneState) -> _gate.GateResult:
    tunnel_name, _ = secret_names(st)
    app = None
    if env.cf is not None:
        try:
            app = env.cf.app(st.resources.account_id, st.resources.app_id)
        except CloudflareError:
            pass
    lt = env.local_tools or _local_tools_http
    (env.wait_ready or _wait_ready)(env, st)
    g = _gate.run_gate(
        hostname=st.hostname, port=st.port, email=st.email, profile=st.profile,
        expected_tools=_gate.expected_tools_for(st.profile), token=env.store.get(tunnel_name),
        app=app, fetch=env.fetch, local_tools=lambda: lt(st.port),
        listeners=lambda: env.listeners(st.port), process_lines=env.process_lines)
    if env.cf is None:
        # Doctor without a token (setup told the user to delete it). Found live
        # 2026-10-03: doctor demanded the token and crashed without one.
        for i, c in enumerate(g.checks):
            if c.name.startswith("Access covers"):
                g.checks[i] = _gate.Check(c.name, False, "needs a Cloudflare API token: run "
                                          "`doctor --with-token` to include it", skipped=True)
    return g


def finish_message(st: PhoneState) -> str:
    until = (_dt.date.fromisoformat(st.created) + _dt.timedelta(days=GRANT_DAYS)).isoformat()
    return f"""Phone access is ready and passed every check.

Connector URL:  https://{st.hostname}/mcp

In claude.ai: Customize > Connectors > Add custom connector, paste the URL, choose
"Sign in now" and "Register automatically", then sign in with {st.email}
(type the emailed code by hand; opening the link in the email uses the code up).

Now delete the Cloudflare API token you used (dash.cloudflare.com > My Profile >
API Tokens). Setup did not save it. Removing phone access later takes a fresh one:
`moofmail-phone token-url` prints the link again.

A sign-in lasts about a year (until around {until}). Consider putting two reminders
in your calendar: a week before, and on the day."""


# ======================================================================= doctor
def run_doctor(env: Env, st: PhoneState) -> tuple[_gate.GateResult, list[str]]:
    notes = []
    org = None
    if env.cf is not None:
        try:
            org = env.cf.organization(st.resources.account_id)
        except CloudflareError as e:
            notes.append(f"could not read the Zero Trust organization: {e}")
    else:
        # No token: the connector's PUBLIC OAuth metadata names the issuer, which is
        # the team domain, so a rename is still detectable.
        issuer = (env.public_issuer or _public_issuer)(st.hostname)
        if issuer:
            org = {"auth_domain": issuer.split("://", 1)[-1].strip("/")}
        else:
            notes.append("could not read the connector's public sign-in metadata")
    if org and org.get("auth_domain") and org["auth_domain"] != st.team_domain:
        notes.append(f"Team was renamed ({st.team_domain} -> {org['auth_domain']}): re-run setup. "
                     "Existing Access apps must be recreated on a NEW hostname; editing the old "
                     "ones does not recover sign-in.")
    import sys as _sys
    if st.platform in ("Darwin", "Linux") and not Path(_sys.executable).exists():
        notes.append("this Python no longer exists; run `moofmail-phone reinstall-services`")
    svc_files = []
    if st.platform == "Darwin":
        svc_files = list((Path.home() / "Library" / "LaunchAgents").glob(f"{st.label_prefix}.*.plist"))
    elif st.platform == "Linux":
        svc_files = list((Path.home() / ".config/systemd/user").glob(f"{st.label_prefix}.*.service"))
    for f in svc_files:
        text = f.read_text(errors="replace")
        if _sys.executable not in text:
            notes.append(f"{f.name} starts a different Python than this installation (a plugin "
                         "update?); run `moofmail-phone reinstall-services`")
    if st.created:
        left = (_dt.date.fromisoformat(st.created) + _dt.timedelta(days=GRANT_DAYS)
                - _dt.date.today()).days
        notes.append(f"about {left} days left on a sign-in made at setup (estimate; a later "
                     "sign-in lasts a year from then)")
    return gate_for(env, st), notes


# ======================================================================= teardown
def plan_teardown(cf: Cloudflare, st: PhoneState) -> list[tuple[str, str, str]]:
    """What teardown would delete: (kind, id, label). Only tagged resources."""
    r = st.resources
    out: list[tuple[str, str, str]] = []
    aid = r.account_id
    for a in cf.apps(aid):
        if a.get("id") == r.app_id or (a.get("name", "").startswith(TAG) and a.get("domain") == st.hostname):
            out.append(("access app", a["id"], a.get("name", "")))
    own_policy = f"{TAG}{st.hostname.replace('.', '-')}-owner"
    for p in cf.policies(aid):
        name = p.get("name", "")
        if name.startswith(TAG) and (p.get("id") == r.policy_id or name == own_policy):
            out.append(("access policy", p["id"], name))
    if r.zone_id:
        for d in cf.dns_records(r.zone_id, st.hostname):
            if "moofmail" in (d.get("comment") or "") or d.get("id") == r.dns_record_id:
                out.append(("dns record", d["id"], d.get("name", "")))
    for t in cf.tunnels(aid):
        if t.get("name", "").startswith(TAG) and (t.get("id") == r.tunnel_id
                                                  or t.get("name") == TAG + st.hostname.replace('.', '-')):
            out.append(("tunnel", t["id"], t.get("name", "")))
    if r.idp_created and r.idp_id:
        out.append(("one-time PIN login (created by setup)", r.idp_id, "One-time PIN"))
    seen, uniq = set(), []
    for item in out:
        if item[:2] not in seen:
            seen.add(item[:2]); uniq.append(item)
    return uniq


def run_teardown(env: Env, st: PhoneState, *, yes: bool = False) -> list[str]:
    plan = plan_teardown(env.cf, st)
    lines = [f"{k}: {label} ({i})" for k, i, label in plan]
    local = f"local services {st.label_prefix}.server and .tunnel, stored secrets, {env.config_path}"
    lines.append(local)
    if not yes:
        return ["DRY RUN, nothing deleted. Would remove:"] + ["  " + l for l in lines] + \
               ["Run again with --yes to delete."]
    r = st.resources
    order = {"access app": 0, "access policy": 1, "dns record": 2, "tunnel": 3}
    if env.services is not None:
        env.services.uninstall(st.label_prefix)
    for kind, rid, _ in sorted(plan, key=lambda x: order.get(x[0], 9)):
        if kind == "access app":
            env.cf.delete_app(r.account_id, rid)
        elif kind == "access policy":
            env.cf.delete_policy(r.account_id, rid)
        elif kind == "dns record":
            env.cf.delete_dns(r.zone_id, rid)
        elif kind == "tunnel":
            env.cf.delete_tunnel(r.account_id, rid)
        else:
            env.cf.delete_idp(r.account_id, rid)
    for n in secret_names(st):
        env.store.delete(n)
    try:
        Path(env.config_path).unlink()
    except OSError:
        pass
    try:
        Path(env.config_path).parent.rmdir()  # only when setup left nothing else there
    except OSError:
        pass
    return ["Deleted:"] + ["  " + l for l in lines]
