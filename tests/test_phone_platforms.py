"""Platform layer and CLI: where secrets go, how services start, what the CLI reads.

Pins: secrets never on a command line, LaunchAgents not LaunchDaemons, the file
store is 0600, the services run this package with the config path, the local
tool-list endpoint refuses tunnelled requests, and the CLI never takes the API
token from an environment variable.
"""
from __future__ import annotations

import io
import os
import stat
import subprocess
import sys

import pytest

from icloud_mcp.phone import cli, platforms
from icloud_mcp import transport


class Rec:
    """Records every command; answers find-generic-password from a dict."""

    def __init__(self):
        self.calls, self.items = [], {}

    def __call__(self, args, **kw):
        self.calls.append((list(args), kw.get("input")))
        if "-i" in args and kw.get("input"):
            line = kw["input"]
            acct = line.split(" -a ")[1].split(" ")[0]
            self.items[acct] = line.split('-w "')[1].rsplit('"', 1)[0]
            return subprocess.CompletedProcess(args, 0, "", "")
        if "find-generic-password" in args:
            acct = args[args.index("-a") + 1]
            v = self.items.get(acct)
            return subprocess.CompletedProcess(args, 0 if v else 44, (v or "") + "\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")


# ---------------------------------------------------------------- macOS keychain
def test_keychain_secret_goes_through_stdin_never_argv():
    rec = Rec()
    k = platforms.MacKeychain(run=rec)
    k.set("tunnel_token:mail.example.com", "eyJsecretvalue")
    assert k.get("tunnel_token:mail.example.com") == "eyJsecretvalue"
    for args, _input in rec.calls:
        assert not any("eyJsecretvalue" in a for a in args), args
    assert any(_input and "eyJsecretvalue" in _input for _a, _input in rec.calls)


def test_keychain_refuses_values_it_cannot_quote():
    with pytest.raises(ValueError):
        platforms.MacKeychain(run=Rec()).set("x", 'has"quote')


# ---------------------------------------------------------------- file store
def test_file_store_is_0600_and_warns(tmp_path):
    fs = platforms.FileStore(tmp_path / "secrets.json")
    fs.set("a", "1")
    assert stat.S_IMODE(os.stat(tmp_path / "secrets.json").st_mode) == 0o600
    assert fs.get("a") == "1" and fs.mode_ok()
    assert "root" in fs.warning
    fs.delete("a")
    assert fs.get("a") is None


# ---------------------------------------------------------------- services
def test_launch_agents_not_daemons_and_no_secret_in_plist(tmp_path):
    rec = Rec()
    la = platforms.LaunchAgents(home=tmp_path, run=rec, uid=501)
    la.logs = tmp_path / "logs"
    labels = la.install("com.example.phone", tmp_path / "phone.toml")
    assert labels == ["com.example.phone.server", "com.example.phone.tunnel"]
    plists = sorted((tmp_path / "Library" / "LaunchAgents").glob("*.plist"))
    assert len(plists) == 2
    body = plists[1].read_text()
    assert "run-tunnel" in body and str(tmp_path / "phone.toml") in body
    assert "TUNNEL_TOKEN" not in body and "--token" not in body
    assert not (tmp_path / "Library" / "LaunchDaemons").exists()
    assert any(a[:2] == ["/bin/launchctl", "bootstrap"] and a[2] == "gui/501" for a, _ in rec.calls)
    gone = la.uninstall("com.example.phone")
    assert sorted(gone) == labels and not list((tmp_path / "Library" / "LaunchAgents").glob("*.plist"))


def test_launch_agents_uninstall_removes_only_its_own_logs(tmp_path):
    la = platforms.LaunchAgents(home=tmp_path, run=Rec(), uid=501)
    la.logs = tmp_path / "logs"
    la.install("com.example.phone", tmp_path / "phone.toml")
    for label in ("com.example.phone.server", "com.example.phone.tunnel"):
        (la.logs / f"{label}.log").write_text("x")
        (la.logs / f"{label}.err").write_text("x")
    la.uninstall("com.example.phone")
    assert not la.logs.exists()  # empty, so the folder goes too

    # Known negative: another install's logs and anything else stay put.
    la.install("com.example.phone", tmp_path / "phone.toml")
    (la.logs / "com.example.phone.server.log").write_text("x")
    (la.logs / "com.other.phone.server.log").write_text("keep")
    (la.logs / "notes.txt").write_text("keep")
    la.uninstall("com.example.phone")
    assert sorted(p.name for p in la.logs.iterdir()) == ["com.other.phone.server.log", "notes.txt"]


def test_systemd_user_units(tmp_path):
    rec = Rec()
    sd = platforms.SystemdUser(home=tmp_path, run=rec)
    names = sd.install("moofmail-phone", tmp_path / "phone.toml")
    assert names == ["moofmail-phone.server.service", "moofmail-phone.tunnel.service"]
    unit = (tmp_path / ".config/systemd/user/moofmail-phone.tunnel.service").read_text()
    assert "run-tunnel" in unit and "--token" not in unit and "Restart=always" in unit
    assert ["systemctl", "--user", "enable", "--now", "moofmail-phone.server.service"] in [a for a, _ in rec.calls]
    assert "enable-linger" in sd.describe()


def test_unsupported_os_is_refused():
    with pytest.raises(RuntimeError, match="macOS and Linux"):
        platforms.pick_services("Windows")


# ---------------------------------------------------------------- observation parsers
def test_lsof_parse():
    out = ("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
           "Python 1 u 6u IPv4 0x1 0t0 TCP 127.0.0.1:8770 (LISTEN)\n"
           "Python 1 u 7u IPv4 0x2 0t0 TCP *:8770 (LISTEN)\n")
    run = lambda args, **kw: subprocess.CompletedProcess(args, 0, out, "")
    assert platforms.listeners(8770, run=run, system="Darwin") == ["127.0.0.1", "*"]


def test_process_args_uses_the_right_ps_flags():
    seen = []
    run = lambda args, **kw: (seen.append(args), subprocess.CompletedProcess(args, 0, "a\nb\n", ""))[1]
    assert platforms.process_args(run=run, system="Linux") == ["a", "b"]
    platforms.process_args(run=run, system="Darwin")
    assert seen[0][1] == "-eww" and seen[1][1] == "-axww"


# ---------------------------------------------------------------- local tools endpoint
def _client(profile="read"):
    from starlette.testclient import TestClient
    from icloud_mcp.access import AccessConfig
    cfg = AccessConfig(team_domain="yourteam.cloudflareaccess.com", aud="x", allowed_emails=("you@example.com",))
    app = transport.build_app(cfg, key_resolver=lambda kid: None, public_hostname="mail.example.com",
                              port=8770, profile=profile)
    return TestClient(app, base_url="http://127.0.0.1:8770")


def test_tools_endpoint_reports_the_running_profile():
    with _client("write") as c:
        r = c.get("/healthz/tools")
        assert r.status_code == 200
        body = r.json()
    assert body["profile"] == "write" and "send_mail" in body["tools"]
    assert "delete_event" not in body["tools"]


def test_tools_endpoint_refuses_tunnelled_requests():
    with _client() as c:
        assert c.get("/healthz/tools", headers={"cf-ray": "abc"}).status_code == 404
        assert c.get("/healthz/tools", headers={"cf-connecting-ip": "198.51.100.7"}).status_code == 404


def test_mcp_still_needs_a_token():
    with _client() as c:
        assert c.post("/mcp", json={}).status_code == 403


# ---------------------------------------------------------------- CLI
def test_cli_never_reads_the_token_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "FROM-ENV")
    monkeypatch.setenv("CF_API_TOKEN", "FROM-ENV")
    asked = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: asked.append(prompt) or "typed-token")
    built = {}

    def fake_env(token, args, with_services=True):
        built["token"] = token
        raise SystemExit(0)
    monkeypatch.setattr(cli, "_env", fake_env)
    with pytest.raises(SystemExit):
        cli.main(["--config", str(tmp_path / "p.toml"), "setup", "--email", "you@example.com",
                  "--apple-id", "you@icloud.com"])
    assert built["token"] == "typed-token"
    assert any("Cloudflare API token" in a for a in asked)


def test_cli_token_stdin_is_explicit(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO("piped-token\napp-pw\n"))
    built = {}

    def fake_env(token, args, with_services=True):
        built["token"] = token
        raise SystemExit(0)
    monkeypatch.setattr(cli, "_env", fake_env)
    with pytest.raises(SystemExit):
        cli.main(["--config", str(tmp_path / "p.toml"), "setup", "--email", "you@example.com",
                  "--apple-id", "you@icloud.com", "--token-stdin", "--app-password-stdin"])
    assert built["token"] == "piped-token"


def test_cli_refuses_a_second_setup_over_an_existing_one(tmp_path, capsys):
    p = tmp_path / "p.toml"
    p.write_text("[remote]\n[phone]\nhostname = \"mail.example.com\"\n")
    assert cli.main(["--config", str(p), "setup", "--email", "a@example.com", "--apple-id", "a@icloud.com"]) == 2


def test_run_tunnel_passes_token_in_env_not_argv(monkeypatch, tmp_path):
    from icloud_mcp.phone import setup as S
    st = S.PhoneState(hostname="mail.example.com", apple_id="you@icloud.com", email="you@example.com")
    S.write_state(st, tmp_path / "p.toml")
    store = {"tunnel_token:mail.example.com": "eyJtoken"}
    monkeypatch.setattr(platforms, "pick_store", lambda *a: type("S", (), {"get": lambda self, n: store.get(n)})())
    seen = {}

    def fake_exec(exe, argv, env):
        seen.update(exe=exe, argv=argv, env=env)
        raise SystemExit(0)
    monkeypatch.setattr(os, "execve", fake_exec)
    with pytest.raises(SystemExit):
        cli.main(["--config", str(tmp_path / "p.toml"), "run-tunnel", "--cloudflared", "/bin/true"])
    assert seen["env"]["TUNNEL_TOKEN"] == "eyJtoken"
    assert not any("eyJtoken" in a for a in seen["argv"]) and "--token" not in seen["argv"]


# ---------------------------------------------------------------- docker
def test_env_file_store_maps_names_and_is_private(tmp_path):
    es = platforms.EnvFileStore(tmp_path / "secrets.env")
    es.set("tunnel_token:mail.example.com", "eyJtok")
    es.set("app_password:you@icloud.com", "abcd-efgh-ijkl-mnop")
    es.set_plain("ICLOUD_APPLE_ID", "you@icloud.com")
    body = (tmp_path / "secrets.env").read_text()
    assert "TUNNEL_TOKEN=eyJtok" in body and "ICLOUD_APP_PASSWORD=abcd-efgh-ijkl-mnop" in body
    assert stat.S_IMODE(os.stat(tmp_path / "secrets.env").st_mode) == 0o600
    assert es.get("tunnel_token:mail.example.com") == "eyJtok"
    es.wipe()
    assert not (tmp_path / "secrets.env").exists()


def test_docker_probes_look_inside_the_container(tmp_path):
    def run(args, **kw):
        if args[:3] == ["docker", "compose", "exec"] and "_proc_listeners" in args[-1]:
            return subprocess.CompletedProcess(args, 0, "127.0.0.1\n", "")
        if args[:3] == ["docker", "compose", "exec"] and "healthz/tools" in args[-1]:
            return subprocess.CompletedProcess(args, 0, '{"profile": "read", "tools": ["status"]}', "")
        if args[:3] == ["docker", "compose", "exec"]:
            return subprocess.CompletedProcess(args, 0, "403\n", "")
        if args[:3] == ["docker", "compose", "ps"]:
            return subprocess.CompletedProcess(args, 0, "c1\nc2\n", "")
        if args[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "cloudflared tunnel --no-autoupdate run\n", "")
        return subprocess.CompletedProcess(args, 1, "", "")
    p = platforms.DockerProbes(tmp_path, run=run)
    assert p.listeners(8770) == ["127.0.0.1"]
    assert p.local_tools(8770)["profile"] == "read"
    f = p.fetch(lambda m, u, h: 401)
    assert f("POST", "http://127.0.0.1:8770/mcp", {"Host": "mail.example.com"}) == 403
    assert f("POST", "https://mail.example.com/mcp", {}) == 401
    assert p.process_lines() == ["cloudflared tunnel --no-autoupdate run"] * 2


def test_compose_file_publishes_no_ports_and_pins_cloudflared():
    from pathlib import Path
    compose = (Path(__file__).resolve().parent.parent / "docker" / "docker-compose.yml").read_text()
    assert "ports:" not in compose
    assert 'network_mode: "service:moofmail"' in compose
    assert "cloudflare/cloudflared:2026" in compose and ":latest" not in compose
    assert "--token" not in compose
