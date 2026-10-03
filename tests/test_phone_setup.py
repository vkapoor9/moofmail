"""Setup, doctor and teardown, end to end against an in-memory Cloudflare.

Pins the behaviour that matters for safety: what gets created and with which
settings, that nothing is created when the account is not ready, that the user's
own config.toml is never touched, that the API token is never stored, and that
teardown removes exactly what setup made and nothing else.
"""
from __future__ import annotations

import tomllib

import pytest

from icloud_mcp import transport
from icloud_mcp.phone import gate, setup
from icloud_mcp.phone.cf import Cloudflare, TAG
from phone_fakes import FakeCloudflare, MemoryStore, RecordingServices

EMAIL, APPLE = "you@example.com", "you@icloud.com"


@pytest.fixture
def world(tmp_path, monkeypatch):
    fake = FakeCloudflare()
    store, svc = MemoryStore(), RecordingServices()
    # the user's real config must never be read or written by phone setup
    monkeypatch.setattr("icloud_mcp.config.DEFAULT_PATH", str(tmp_path / "must-not-exist.toml"))
    env = setup.Env(cf=Cloudflare("tok", http=fake), store=store, services=svc,
                    config_path=tmp_path / "phone.toml", system="Darwin",
                    wait_tunnel=lambda *a: True, say=lambda s: None, wait_ready=lambda e, s: None,
                    fetch=lambda m, u, h: 403 if u.startswith("http://127.0.0.1") else 401,
                    listeners=lambda port: ["127.0.0.1"],
                    process_lines=lambda: ["cloudflared tunnel --no-autoupdate run"],
                    local_tools=lambda port: {"profile": "read",
                                              "tools": sorted(gate.expected_tools_for("read"))})
    return fake, store, svc, env, tmp_path


def _setup(env, **kw):
    args = dict(email=EMAIL, apple_id=APPLE, app_password="abcd-efgh-ijkl-mnop")
    args.update(kw)
    return setup.run_setup(env, **args)


# ---------------------------------------------------------------- what gets built
def test_setup_builds_everything_with_the_right_settings(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    assert st.hostname == "mail.example.com"
    app = list(fake.apps.values())[0]
    assert app["name"].startswith(TAG)
    assert app["domain"] == "mail.example.com"
    assert app["destinations"] == [{"type": "public", "uri": "mail.example.com"}]
    oauth = app["oauth_configuration"]
    assert oauth["enabled"] is True
    assert oauth["grant"] == {"session_duration": "8760h", "access_token_lifetime": "15m"}
    assert oauth["dynamic_client_registration"]["allowed_uris"] == ["https://claude.ai/*"]
    assert app["auto_redirect_to_identity"] is False
    pol = list(fake.policies.values())[0]
    assert pol["include"] == [{"email": {"email": EMAIL}}] and pol["decision"] == "allow"
    tid = st.resources.tunnel_id
    assert fake.ingress[tid] == [{"hostname": "mail.example.com", "service": "http://127.0.0.1:8770"},
                                 {"service": "http_status:404"}]
    rec = fake.dns[st.resources.zone_id][0]
    assert rec["proxied"] is True and rec["content"] == f"{tid}.cfargotunnel.com"
    assert "moofmail" in rec["comment"]
    assert svc.installed == [(setup.DEFAULT_PREFIX, str(env.config_path))]


def test_state_file_is_what_the_server_reads(world):
    fake, store, svc, env, tmp = world
    st = _setup(env, profile="write")
    block = transport.load_remote_config(env.config_path)
    cfg, opts = transport.config_from_block(block)
    assert cfg.aud == st.aud and cfg.allowed_emails == (EMAIL,)
    assert cfg.team_domain == "yourteam.cloudflareaccess.com"
    assert opts == {"public_hostname": "mail.example.com", "host": "127.0.0.1",
                    "port": 8770, "profile": "write"}


def test_state_file_is_private(world):
    import os, stat
    fake, store, svc, env, tmp = world
    _setup(env)
    assert stat.S_IMODE(os.stat(env.config_path).st_mode) == 0o600


def test_api_token_is_never_stored(world):
    fake, store, svc, env, tmp = world
    _setup(env)
    assert "tok" not in store.d.values()
    assert "tok" not in env.config_path.read_text()
    assert set(store.d) == {"tunnel_token:mail.example.com", "app_password:you@icloud.com"}


def test_users_own_config_is_never_created(world):
    fake, store, svc, env, tmp = world
    _setup(env)
    assert not (tmp / "must-not-exist.toml").exists()


def test_send_needs_write_profile(world):
    fake, store, svc, env, tmp = world
    st = _setup(env, profile="read", send_enabled=True)
    assert st.send_enabled is False


def test_existing_one_time_pin_is_reused_not_duplicated(world):
    fake, store, svc, env, tmp = world
    fake.idps.append({"id": "existing", "type": "onetimepin", "name": "One-time PIN"})
    st = _setup(env)
    assert st.resources.idp_id == "existing" and not st.resources.idp_created
    assert len(fake.idps) == 1


# ---------------------------------------------------------------- refusing early
def test_no_zero_trust_org_stops_before_creating_anything(world):
    fake, store, svc, env, tmp = world
    fake.org = None
    with pytest.raises(setup.SetupError, match="team name"):
        _setup(env)
    assert fake.tagged_count() == 0 and not svc.installed


@pytest.mark.parametrize("perm", ["Cloudflare Tunnel Edit", "Access: Apps and Policies Edit",
                                  "Zone Read", "Account Settings Read"])
def test_missing_permission_stops_before_creating_anything(world, perm):
    fake, store, svc, env, tmp = world
    fake.denied = {perm}
    with pytest.raises(Exception):
        _setup(env)
    assert fake.tagged_count() == 0


def test_missing_tunnel_permission_names_the_manual_line(world):
    fake, store, svc, env, tmp = world
    fake.denied = {"Cloudflare Tunnel Edit"}
    with pytest.raises(setup.SetupError, match="Cloudflare Tunnel > Edit"):
        _setup(env)


def test_existing_dns_record_is_never_overwritten(world):
    fake, store, svc, env, tmp = world
    zid = fake.zones[0]["id"]
    fake.dns[zid].append({"id": "r1", "name": "mail.example.com", "type": "A", "content": "192.0.2.1"})
    with pytest.raises(setup.SetupError, match="already has a DNS record"):
        _setup(env)
    assert fake.dns[zid] == [{"id": "r1", "name": "mail.example.com", "type": "A", "content": "192.0.2.1"}]


def test_hostname_outside_the_zone_is_refused(world):
    fake, store, svc, env, tmp = world
    with pytest.raises(setup.SetupError, match="not inside"):
        _setup(env, hostname="mail.other.org")


def test_inactive_token_is_refused(world):
    fake, store, svc, env, tmp = world
    fake.token_status = "expired"
    with pytest.raises(setup.SetupError, match="not active"):
        _setup(env)


def test_several_domains_require_a_choice(world):
    fake, store, svc, env, tmp = world
    fake.zones.append({"id": "z2", "name": "example.org", "account": {"id": fake.account_id}})
    fake.dns["z2"] = []
    with pytest.raises(setup.SetupError, match="several domain"):
        _setup(env)
    st = _setup(env, domain="example.org")
    assert st.hostname == "mail.example.org"


def test_failure_midway_leaves_a_state_file_for_teardown(world):
    fake, store, svc, env, tmp = world
    fake.fail_on = ("POST", r"/access/apps$")
    with pytest.raises(Exception):
        _setup(env)
    st = setup.read_state(env.config_path)
    assert st and st.resources.tunnel_id and st.resources.policy_id
    lines = setup.run_teardown(env, st, yes=True)
    assert fake.tagged_count() == 0, lines


# ---------------------------------------------------------------- gate + finish
def test_gate_passes_on_the_fresh_setup(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    g = setup.gate_for(env, st)
    assert g.ok, g.report()


def test_finish_message_names_url_and_token_deletion(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    msg = setup.finish_message(st)
    assert "https://mail.example.com/mcp" in msg
    assert "delete the Cloudflare API token" in msg
    assert "Register automatically" in msg


# ---------------------------------------------------------------- doctor
def test_doctor_detects_a_renamed_team(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    fake.org = {"auth_domain": "renamed.cloudflareaccess.com"}
    g, notes = setup.run_doctor(env, st)
    assert any("Team was renamed" in n and "NEW hostname" in n for n in notes)


def test_doctor_reports_grant_days(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    g, notes = setup.run_doctor(env, st)
    assert any("days left" in n for n in notes)
    assert g.ok


# ---------------------------------------------------------------- teardown
def test_teardown_is_a_dry_run_by_default(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    before = fake.tagged_count()
    lines = setup.run_teardown(env, st)
    assert lines[0].startswith("DRY RUN") and fake.tagged_count() == before
    assert env.config_path.exists() and not svc.removed


def test_teardown_removes_exactly_what_setup_made(world):
    fake, store, svc, env, tmp = world
    # someone else's resources in the same account: must survive
    fake.apps["theirs"] = {"id": "theirs", "name": "Their App", "domain": "app.example.com", "policies": []}
    fake.policies["theirpol"] = {"id": "theirpol", "name": "Their policy", "include": []}
    fake.tunnels["theirtun"] = {"id": "theirtun", "name": "their-tunnel"}
    zid = fake.zones[0]["id"]
    fake.dns[zid].append({"id": "theirdns", "name": "www.example.com", "type": "A"})
    st = _setup(env)
    setup.run_teardown(env, st, yes=True)
    assert fake.tagged_count() == 0
    assert "theirs" in fake.apps and "theirpol" in fake.policies and "theirtun" in fake.tunnels
    assert [r["id"] for r in fake.dns[zid]] == ["theirdns"]
    assert svc.removed == [setup.DEFAULT_PREFIX]
    assert store.d == {} and not env.config_path.exists()


def test_teardown_removes_the_config_folder_only_when_empty(world):
    fake, store, svc, env, tmp = world
    env.config_path = tmp / "moofmail" / "phone.toml"
    setup.run_teardown(env, _setup(env), yes=True)
    assert not (tmp / "moofmail").exists()

    # Known negative: anything else in the folder keeps it, untouched.
    st = _setup(env)
    (tmp / "moofmail" / "mine.txt").write_text("keep")
    setup.run_teardown(env, st, yes=True)
    assert [p.name for p in (tmp / "moofmail").iterdir()] == ["mine.txt"]


def test_teardown_keeps_a_pre_existing_one_time_pin(world):
    fake, store, svc, env, tmp = world
    fake.idps.append({"id": "existing", "type": "onetimepin"})
    st = _setup(env)
    setup.run_teardown(env, st, yes=True)
    assert [i["id"] for i in fake.idps] == ["existing"]


def test_teardown_removes_a_one_time_pin_it_created(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    setup.run_teardown(env, st, yes=True)
    assert fake.idps == []


# ---------------------------------------------------------------- token link
def test_token_template_url_uses_only_documented_keys():
    import json, urllib.parse
    url = setup.token_template_url()
    assert url.startswith("https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    keys = json.loads(q["permissionGroupKeys"][0])
    assert {k["key"] for k in keys} == {"account_settings", "access", "access_acct", "zone", "dns"}
    assert all(k["type"] in ("read", "edit") for k in keys)
    assert q["accountId"] == ["*"] and q["zoneId"] == ["all"] and q["name"] == ["moofmail-setup"]


def test_cf_client_refuses_untagged_names():
    cf = Cloudflare("tok", http=FakeCloudflare())
    with pytest.raises(ValueError):
        cf.create_tunnel("acc", "my-tunnel")
    with pytest.raises(ValueError):
        cf.create_policy("acc", "Owner", "a@example.com")


def test_doctor_flags_services_pointing_at_an_old_installation(world, monkeypatch):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    monkeypatch.setattr(setup.Path, "home", classmethod(lambda cls: tmp))
    la = tmp / "Library" / "LaunchAgents"
    la.mkdir(parents=True)
    (la / f"{st.label_prefix}.server.plist").write_text("<string>/old/plugin/1.2.2/.venv/bin/python</string>")
    g, notes = setup.run_doctor(env, st)
    assert any("reinstall-services" in n for n in notes)


# ---------------------------------------------------------------- doctor without a token
def test_doctor_without_token_skips_only_the_access_check(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    env.cf = None
    env.public_issuer = lambda host: f"https://{st.team_domain}"
    g, notes = setup.run_doctor(env, st)
    assert g.ok, g.report()
    assert [c.name for c in g.skipped()] == ["Access covers the whole hostname and allows exactly one person"]
    assert "[SKIP]" in g.report()
    assert not any("renamed" in n for n in notes)


def test_doctor_without_token_still_detects_a_rename_from_public_metadata(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    env.cf = None
    env.public_issuer = lambda host: "https://renamed.cloudflareaccess.com"
    g, notes = setup.run_doctor(env, st)
    assert any("Team was renamed" in n for n in notes)


def test_doctor_without_token_still_fails_a_real_problem(world):
    fake, store, svc, env, tmp = world
    st = _setup(env)
    env.cf = None
    env.public_issuer = lambda host: f"https://{st.team_domain}"
    env.listeners = lambda port: ["0.0.0.0"]
    g, notes = setup.run_doctor(env, st)
    assert not g.ok
