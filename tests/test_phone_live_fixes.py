"""Two bugs the first LIVE run found (2026-10-03) that 527 offline tests did not.

1. The LaunchAgent command put `--config` AFTER the subcommand, which argparse
   rejects (exit 2), so both services crashed on every start. The fix is tested by
   feeding the exact generated argv through the REAL parser, which is the step the
   old tests skipped.
2. The gate ran seconds after Cloudflare objects were created and saw 403 on every
   path. `_wait_ready` now waits for publication, but must never wait past an OPEN
   endpoint (200): that has to reach the gate and fail it.
"""
from __future__ import annotations

from pathlib import Path

from icloud_mcp.phone import cli, platforms, setup


def _argv_after_module(argv: list[str]) -> list[str]:
    i = argv.index("icloud_mcp.phone") if "icloud_mcp.phone" in argv else None
    assert i is not None, f"unexpected launcher shape: {argv}"
    return argv[i + 1:]


def test_generated_service_commands_parse_with_the_real_parser():
    units = platforms._units("com.example.test", Path("/tmp/phone.toml"))
    expected = {"com.example.test.server": cli.cmd_run_server,
                "com.example.test.tunnel": cli.cmd_run_tunnel}
    for label, argv in units.items():
        args = cli.build_parser().parse_args(_argv_after_module(argv))
        assert args.fn is expected[label], label
        assert args.config == "/tmp/phone.toml"


class _St:
    hostname, port = "mail.example.com", 8770


class _Env:
    def __init__(self, edge_seq, local_seq):
        self.edge, self.local, self.said = list(edge_seq), list(local_seq), []

    def fetch(self, m, u, h):
        return self.edge.pop(0) if len(self.edge) > 1 else self.edge[0]

    def listeners(self, port):
        return self.local.pop(0) if len(self.local) > 1 else self.local[0]

    def say(self, s):
        self.said.append(s)


def _run(env, seconds=60):
    t = [0.0]
    sleeps = []
    def sleep(x):
        sleeps.append(x); t[0] += x
    setup._wait_ready(env, _St(), seconds=seconds, step=5, sleep=sleep, clock=lambda: t[0])
    return sleeps


def test_returns_at_once_when_ready():
    assert _run(_Env([401], [["127.0.0.1"]])) == []


def test_waits_through_403_then_returns():
    env = _Env([403, 403, 401], [["127.0.0.1"]])
    assert len(_run(env)) == 2
    assert any("Waiting for Cloudflare" in s for s in env.said)


def test_waits_until_local_server_is_listening():
    assert len(_run(_Env([401], [[], [], ["127.0.0.1"]]))) == 2


def test_never_waits_past_an_open_endpoint():
    assert _run(_Env([200], [["127.0.0.1"]])) == []


def test_gives_up_after_the_timeout_and_lets_the_gate_decide():
    sleeps = _run(_Env([403], [["127.0.0.1"]]), seconds=30)
    assert sum(sleeps) >= 30 and len(sleeps) <= 7


# 3. Doctor demanded the API token that setup told the user to delete (found live).
from icloud_mcp.phone import gate


def test_skipped_check_is_not_a_pass_and_is_labelled():
    g = gate.GateResult([gate.Check("a", True), gate.Check("b", False, "x", skipped=True)])
    assert g.ok and g.failures() == [] and len(g.skipped()) == 1
    assert "[SKIP] b" in g.report()


def test_a_gate_of_only_skipped_checks_fails():
    assert not gate.GateResult([gate.Check("b", True, skipped=True)]).ok


def test_a_real_failure_still_fails_next_to_a_skip():
    g = gate.GateResult([gate.Check("a", False), gate.Check("b", True, skipped=True)])
    assert not g.ok


def test_doctor_cli_path_builds_an_env_without_a_token(tmp_path, monkeypatch):
    """The CLI path itself, which crashed live: Cloudflare('') raised before any check ran."""
    from icloud_mcp.phone import cli as _cli
    cfg = tmp_path / "phone.toml"
    cfg.write_text('[phone]\nhostname = "mail.example.com"\nemail = "a@example.com"\n'
                   'profile = "read"\nport = 8770\nteam_domain = "t.cloudflareaccess.com"\n'
                   'platform = "Darwin"\nlabel_prefix = "com.example.test"\napple_id = "a@example.com"\n'
                   'created = "2026-10-03"\n[phone.resources]\naccount_id = "acc"\n')
    monkeypatch.setattr(_cli.platforms, "pick_store", lambda system: object())
    monkeypatch.setattr(_cli.platforms, "pick_services", lambda system: None)
    args = _cli.build_parser().parse_args(["--config", str(cfg), "doctor"])
    env, st = _cli._loaded(args, need_token=False)
    assert env is not None and env.cf is None and st is not None


# 5. Cloudflare blocks Python's default user agent with error 1010 (found live).
def test_every_outbound_request_sends_a_named_user_agent(monkeypatch):
    import urllib.request
    from icloud_mcp.phone import cf as _cf, gate as _g, setup as _s
    seen = []

    class _Resp:
        status = 401
        def read(self): return b'{"issuer": "https://t.cloudflareaccess.com"}'
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        seen.append(req.get_header("User-agent") if hasattr(req, "get_header") else None)
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    _g.urllib_fetch("POST", "https://mail.example.com/mcp", {})
    _s._public_issuer("mail.example.com")
    try:
        _cf.urllib_http("GET", "https://api.cloudflare.com/client/v4/user", {}, None)
    except Exception:
        pass
    assert seen and all(ua == _g.USER_AGENT for ua in seen), seen
    assert not any("python-urllib" in (ua or "").lower() for ua in seen)
