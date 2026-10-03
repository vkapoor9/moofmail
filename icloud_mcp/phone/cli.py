"""`moofmail-phone`: set up, check and remove phone and voice access.

Secrets are never read from environment variables. The Cloudflare API token and
the Apple app-specific password come from a hidden prompt, or from standard input
when you pass --token-stdin / --app-password-stdin explicitly. Neither is written
to disk by this command except into the platform secret store (and the token is
not stored at all).
"""
from __future__ import annotations

import argparse
import getpass
import os
import platform as _platform
import sys
from pathlib import Path

from . import platforms
from .cf import Cloudflare, CloudflareError
from .setup import (CONFIG_PATH, DEFAULT_PORT, DEFAULT_PREFIX, Env, SetupError, finish_message,
                    gate_for, read_state, run_doctor, run_setup, run_teardown, secret_names,
                    token_template_url, MANUAL_PERMISSION)


def _secret(prompt: str, from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().strip()
    return getpass.getpass(prompt).strip()


def _env(token: str | None, args, with_services: bool = True) -> Env:
    cfg = Path(args.config)
    if getattr(args, "platform", "auto") == "docker":
        from .gate import urllib_fetch
        probes = platforms.DockerProbes(cfg.parent)
        return Env(cf=Cloudflare(token) if token else None,
                   store=platforms.EnvFileStore(cfg.parent / "secrets.env"),
                   services=None, config_path=cfg, system="docker",
                   fetch=probes.fetch(urllib_fetch), listeners=probes.listeners,
                   process_lines=probes.process_lines, local_tools=probes.local_tools)
    system = _platform.system()
    return Env(cf=Cloudflare(token) if token else None, store=platforms.pick_store(system),
               services=platforms.pick_services(system) if with_services else None,
               config_path=cfg, system=system)


def cmd_token_url(args) -> int:
    print("Open this link while signed in to Cloudflare, check the pre-filled permissions,")
    print(f"add one more line by hand ({MANUAL_PERMISSION}), then create the token:\n")
    print(token_template_url())
    return 0


def cmd_setup(args) -> int:
    if read_state(Path(args.config)):
        print(f"{args.config} already exists. Run `teardown` first, or pass a different --config.")
        return 2
    if not args.token_stdin:
        cmd_token_url(args)
        print()
    token = _secret("Cloudflare API token (input hidden): ", args.token_stdin)
    pw = None
    if not args.keep_stored_password:
        pw = _secret(f"App-specific password for {args.apple_id} (input hidden): ",
                     args.app_password_stdin)
    if args.profile == "write":
        print("Write profile: Claude on your phone can organize and trash mail, edit events "
              "without attendees, and send to people in Contacts or already approved. Anyone "
              "new needs your confirmation. No attachments, daily caps apply.")
    env = _env(token, args)
    try:
        st = run_setup(env, email=args.email, domain=args.domain, hostname=args.hostname,
                       profile=args.profile, port=args.port, account=args.account,
                       apple_id=args.apple_id, app_password=pw, send_enabled=args.allow_send,
                       label_prefix=args.label_prefix)
    except (SetupError, CloudflareError, RuntimeError) as e:
        print(f"\nSetup stopped: {e}")
        if read_state(Path(args.config)):
            print("Some resources were already created. Remove them with: moofmail-phone teardown --yes")
        return 1
    if args.platform == "docker":
        env.store.set_plain("ICLOUD_APPLE_ID", st.apple_id)
        env.store.set_plain("ICLOUD_SEND_ENABLED", "true" if st.send_enabled else "false")
        print(f"\nDocker files are ready in {Path(args.config).parent}. Next:\n"
              "  docker compose up -d --build\n"
              f"  moofmail-phone --config {args.config} doctor --platform docker\n"
              "doctor runs the self-test gate inside the containers and prints the connector "
              "URL once it passes.")
        return 0
    print("\nRunning the self-test gate...")
    g = gate_for(env, st)
    print(g.report())
    if not g.ok:
        print("\nThe gate did not pass, so no connector URL is given. Fix the failures above, "
              "then run `moofmail-phone doctor`, or remove everything with "
              "`moofmail-phone teardown --yes`.")
        return 1
    print("\n" + finish_message(st))
    return 0


def _loaded(args, need_token: bool = True) -> tuple[Env, object] | tuple[None, None]:
    st = read_state(Path(args.config))
    if not st:
        print(f"No phone access set up ({args.config} not found).")
        return None, None
    if not need_token:
        return _env(None, args), st
    try:
        token = _secret("Cloudflare API token (input hidden): ", args.token_stdin)
    except EOFError:
        print("No Cloudflare API token was given.")
        return None, None
    return _env(token, args), st


def cmd_doctor(args) -> int:
    env, st = _loaded(args, need_token=bool(args.with_token or args.token_stdin))
    if not env:
        return 2
    g, notes = run_doctor(env, st)
    print(g.report())
    for n in notes:
        print("  note: " + n)
    if g.ok:
        skipped = f" ({len(g.skipped())} skipped, see above)" if g.skipped() else ""
        print(f"\nAll checks passed{skipped}.\n\n" + finish_message(st))
        return 0
    print("\nSome checks failed, so no connector URL is given.")
    return 1


def cmd_teardown(args) -> int:
    env, st = _loaded(args)
    if not env:
        return 2
    for line in run_teardown(env, st, yes=args.yes):
        print(line)
    if args.yes and args.platform == "docker":
        env.store.wipe()
        print("Now stop the containers: docker compose down")
    return 0


def cmd_reinstall_services(args) -> int:
    """Point the two background services at THIS installation of Moofmail.

    A plugin update installs into a new folder, and services still pointing at the
    old one stop starting. No Cloudflare token is needed: nothing remote changes.
    """
    st = read_state(Path(args.config))
    if not st:
        print(f"No phone access set up ({args.config} not found).")
        return 2
    svc = platforms.pick_services()
    svc.uninstall(st.label_prefix)
    names = svc.install(st.label_prefix, Path(args.config))
    print("Restarted: " + ", ".join(names))
    return 0


def cmd_run_server(args) -> int:
    """Started by the background service. Reads the Apple password from the store."""
    st = read_state(Path(args.config))
    if not st:
        print(f"no phone config at {args.config}", file=sys.stderr)
        return 78
    _, pw_name = secret_names(st)
    pw = platforms.pick_store().get(pw_name)
    if not pw:
        print("app-specific password missing from the secret store", file=sys.stderr)
        return 78
    os.environ["ICLOUD_APPLE_ID"] = st.apple_id
    os.environ["ICLOUD_APP_PASSWORD"] = pw
    os.environ["ICLOUD_SEND_ENABLED"] = "true" if st.send_enabled else "false"
    from .. import transport
    transport.serve(args.config)
    return 0


def cmd_run_tunnel(args) -> int:
    """Started by the background service. Token goes in the environment, never argv."""
    st = read_state(Path(args.config))
    if not st:
        print(f"no phone config at {args.config}", file=sys.stderr)
        return 78
    tunnel_name, _ = secret_names(st)
    token = platforms.pick_store().get(tunnel_name)
    if not token:
        print("tunnel token missing from the secret store", file=sys.stderr)
        return 78
    exe = args.cloudflared or _find_cloudflared()
    if not exe:
        print("cloudflared not found. Install it (brew install cloudflared, or your "
              "distribution's package) and restart the service.", file=sys.stderr)
        return 78
    env = dict(os.environ, TUNNEL_TOKEN=token)
    os.execve(exe, [exe, "tunnel", "--no-autoupdate", "run"], env)
    return 0  # not reached


def _find_cloudflared() -> str | None:
    import shutil
    for c in (shutil.which("cloudflared"), "/opt/homebrew/bin/cloudflared",
              "/usr/local/bin/cloudflared", str(Path.home() / ".local/bin/cloudflared")):
        if c and Path(c).exists():
            return c
    return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="moofmail-phone", description=__doc__.split("\n\n")[0])
    p.add_argument("--config", default=str(CONFIG_PATH), help="phone config file (default %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="{token-url,setup,doctor,teardown,reinstall-services}")

    sub.add_parser("token-url", help="print the Cloudflare token link").set_defaults(fn=cmd_token_url)

    s = sub.add_parser("setup", help="create the connector in your Cloudflare account")
    s.add_argument("--email", required=True, help="the address you will sign in with")
    s.add_argument("--apple-id", required=True, help="your Apple Account email")
    s.add_argument("--domain", help="your domain on Cloudflare (needed if you have several)")
    s.add_argument("--hostname", help="connector hostname (default mail.<domain>)")
    s.add_argument("--account", help="Cloudflare account name or id (if you have several)")
    s.add_argument("--profile", choices=("read", "write"), default="read",
                   help="read-only (default) or the opt-in write profile")
    s.add_argument("--allow-send", action="store_true",
                   help="with --profile write, let the phone send mail (Contacts and approved "
                        "people go straight out; anyone new needs confirmation)")
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--label-prefix", default=DEFAULT_PREFIX,
                   help="background service name prefix (default %(default)s)")
    s.add_argument("--token-stdin", action="store_true", help="read the API token from stdin")
    s.add_argument("--app-password-stdin", action="store_true",
                   help="read the app-specific password from stdin")
    s.add_argument("--keep-stored-password", action="store_true",
                   help="reuse an app password already in the secret store")
    s.add_argument("--platform", choices=("auto", "docker"), default="auto",
                   help="auto: this Mac or Linux machine runs the services; docker: write "
                        "files for docker compose instead")
    s.set_defaults(fn=cmd_setup)

    for name, fn, helptext in (("doctor", cmd_doctor, "re-run the self-test gate"),
                               ("teardown", cmd_teardown, "remove what setup created")):
        c = sub.add_parser(name, help=helptext)
        c.add_argument("--token-stdin", action="store_true", help="read the API token from stdin")
        if name == "doctor":
            c.add_argument("--with-token", action="store_true",
                           help="ask for an API token so the Access policy check runs too")
        c.add_argument("--platform", choices=("auto", "docker"), default="auto")
        if name == "teardown":
            c.add_argument("--yes", action="store_true", help="actually delete (default: dry run)")
        c.set_defaults(fn=fn)

    sub.add_parser("reinstall-services",
                   help="point the services at this installation (after a plugin update)"
                   ).set_defaults(fn=cmd_reinstall_services)
    r = sub.add_parser("run-server")
    r.set_defaults(fn=cmd_run_server)
    t = sub.add_parser("run-tunnel")
    t.add_argument("--cloudflared", help=argparse.SUPPRESS)
    t.set_defaults(fn=cmd_run_tunnel)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)
