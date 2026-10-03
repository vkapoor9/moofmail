"""The self-test gate is calibrated: every check FAILS on a planted misconfiguration.

A gate that has only ever seen a good setup has not been tested, so each check
below is run once against a correct observation (must pass) and once against the
specific mistake it exists to catch (must fail).
"""
from __future__ import annotations

import pytest

from icloud_mcp.phone import gate

HOST, EMAIL, PORT = "mail.example.com", "you@example.com", 8770


def good_app():
    return {"domain": HOST, "self_hosted_domains": [HOST],
            "destinations": [{"type": "public", "uri": HOST}],
            "oauth_configuration": {"enabled": True},
            "policies": [{"decision": "allow", "include": [{"email": {"email": EMAIL}}]}]}


def edge_ok(method, url, headers):
    if url.startswith("http://127.0.0.1"):
        return 403
    return 401


# ---------------------------------------------------------------- edge
def test_edge_passes_when_everything_is_401():
    assert gate.check_edge_unauthenticated(HOST, edge_ok).ok


@pytest.mark.parametrize("leaky_path", ["/healthz", "/.env", "/"])
def test_edge_fails_when_one_path_is_open(leaky_path):
    def fetch(m, url, h):
        return 200 if url.endswith(leaky_path) and url.count("/") == 3 else 401
    c = gate.check_edge_unauthenticated(HOST, fetch)
    assert not c.ok and "unexpected status" in c.detail


def test_edge_fails_when_nothing_answers():
    assert not gate.check_edge_unauthenticated(HOST, lambda m, u, h: 0).ok


def test_forged_passes_and_fails():
    assert gate.check_edge_forged(HOST, edge_ok).ok
    accepted = lambda m, u, h: 200 if "Cf-Access-Jwt-Assertion" in h else 401
    assert not gate.check_edge_forged(HOST, accepted).ok


def test_origin_forged_passes_and_fails():
    assert gate.check_origin_forged(PORT, HOST, edge_ok).ok
    # a server with the second lock missing would answer 200 (or 406 from MCP)
    assert not gate.check_origin_forged(PORT, HOST, lambda m, u, h: 200).ok
    assert not gate.check_origin_forged(PORT, HOST, lambda m, u, h: 0).ok


# ---------------------------------------------------------------- bind
@pytest.mark.parametrize("addrs", [["127.0.0.1"], ["127.0.0.1", "[::1]"], ["::1"]])
def test_bind_loopback_passes(addrs):
    assert gate.check_bind(addrs).ok


@pytest.mark.parametrize("addrs", [["*"], ["0.0.0.0"], ["127.0.0.1", "192.0.2.10"], []])
def test_bind_wildcard_or_lan_fails(addrs):
    assert not gate.check_bind(addrs).ok


# ---------------------------------------------------------------- tools
def test_tools_match_passes():
    want = gate.expected_tools_for("read")
    assert gate.check_tools({"profile": "read", "tools": sorted(want)}, "read", want).ok


def test_tools_extra_write_tool_fails():
    want = gate.expected_tools_for("read")
    c = gate.check_tools({"profile": "read", "tools": sorted(want | {"send_mail"})}, "read", want)
    assert not c.ok and "send_mail" in c.detail


def test_tools_wrong_profile_fails():
    want = gate.expected_tools_for("read")
    assert not gate.check_tools({"profile": "write", "tools": sorted(want)}, "read", want).ok


def test_tools_unreadable_fails():
    assert not gate.check_tools(None, "read", gate.expected_tools_for("read")).ok


def test_write_profile_is_a_superset_of_read():
    assert gate.expected_tools_for("read") < gate.expected_tools_for("write")
    assert "send_mail" in gate.expected_tools_for("write")
    assert "delete_event" not in gate.expected_tools_for("write")


# ---------------------------------------------------------------- Access scope
def test_access_scope_passes():
    assert gate.check_access_scope(good_app(), HOST, EMAIL).ok


def test_path_scoped_app_fails():
    app = good_app()
    app["destinations"] = [{"type": "public", "uri": HOST + "/mcp"}]
    c = gate.check_access_scope(app, HOST, EMAIL)
    assert not c.ok and "path-scoped" in c.detail


def test_two_emails_in_policy_fails():
    app = good_app()
    app["policies"][0]["include"].append({"email": {"email": "stranger@example.com"}})
    assert not gate.check_access_scope(app, HOST, EMAIL).ok


def test_everyone_rule_fails():
    app = good_app()
    app["policies"][0]["include"] = [{"everyone": {}}]
    assert not gate.check_access_scope(app, HOST, EMAIL).ok


def test_domain_rule_fails():
    app = good_app()
    app["policies"][0]["include"].append({"email_domain": {"domain": "example.com"}})
    assert not gate.check_access_scope(app, HOST, EMAIL).ok


def test_oauth_off_fails():
    app = good_app()
    app["oauth_configuration"] = {"enabled": False}
    assert not gate.check_access_scope(app, HOST, EMAIL).ok


def test_missing_app_fails():
    assert not gate.check_access_scope(None, HOST, EMAIL).ok


# ---------------------------------------------------------------- token in argv
def test_token_hidden_passes():
    procs = ["/opt/homebrew/bin/cloudflared tunnel --no-autoupdate run", "python -m icloud_mcp.phone"]
    assert gate.check_token_hidden(procs, "eyJsecret").ok


def test_token_in_argv_fails():
    assert not gate.check_token_hidden(["cloudflared tunnel run --token eyJsecret"], "eyJsecret").ok


def test_token_flag_with_other_value_still_fails():
    assert not gate.check_token_hidden(["cloudflared tunnel run --token eyJother"], "eyJsecret").ok


def test_no_token_stored_fails():
    assert not gate.check_token_hidden([], None).ok


# ---------------------------------------------------------------- whole gate
def _run(**over):
    kw = dict(hostname=HOST, port=PORT, email=EMAIL, profile="read",
              expected_tools=gate.expected_tools_for("read"), token="eyJsecret", app=good_app(),
              fetch=edge_ok,
              local_tools=lambda: {"profile": "read", "tools": sorted(gate.expected_tools_for("read"))},
              listeners=lambda: ["127.0.0.1"], process_lines=lambda: ["cloudflared tunnel run"])
    kw.update(over)
    return gate.run_gate(**kw)


def test_whole_gate_passes_on_a_good_setup():
    g = _run()
    assert g.ok, g.report()
    assert len(g.checks) == 7


@pytest.mark.parametrize("over", [
    {"listeners": lambda: ["*"]},
    {"process_lines": lambda: ["cloudflared tunnel run --token eyJsecret"]},
    {"app": None},
    {"local_tools": lambda: None},
    {"fetch": lambda m, u, h: 200},
])
def test_whole_gate_fails_on_any_single_problem(over):
    g = _run(**over)
    assert not g.ok
    assert len(g.failures()) >= 1


def test_empty_gate_is_not_a_pass():
    assert not gate.GateResult().ok
