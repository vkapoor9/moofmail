"""In-memory stand-ins for Cloudflare, the secret store and the service manager.

No test in the phone suite opens a socket or runs a real command: the fake
Cloudflare answers the same paths and shapes as the API (pagination, success
envelope, 403 for a missing permission), and everything platform-specific is a
recording fake.
"""
from __future__ import annotations

import json
import re
import uuid
from urllib.parse import parse_qs, urlparse


def _id():
    return uuid.uuid4().hex


class FakeCloudflare:
    def __init__(self, *, org=True, zones=("example.com",), denied=(), token_status="active"):
        self.account_id = "acc" + _id()[:8]
        self.org = {"auth_domain": "yourteam.cloudflareaccess.com", "name": "Your Team"} if org else None
        self.zones = [{"id": "zone" + _id()[:6], "name": z, "account": {"id": self.account_id}} for z in zones]
        self.denied = set(denied)            # permission names whose probe path answers 403
        self.token_status = token_status
        self.idps, self.tunnels, self.ingress, self.dns = [], {}, {}, {}
        self.policies, self.apps = {}, {}
        self.calls = []
        self.fail_on = None                  # (method, path-regex) to raise a 500 at
        for z in self.zones:
            self.dns[z["id"]] = []

    # ------------------------------------------------------------------ helpers
    def _ok(self, result, status=200):
        return status, {"success": True, "errors": [], "result": result}

    def _err(self, status, code, msg):
        return status, {"success": False, "errors": [{"code": code, "message": msg}], "result": None}

    def __call__(self, method, url, headers, body):
        u = urlparse(url)
        path, q = u.path.replace("/client/v4", ""), parse_qs(u.query)
        data = json.loads(body) if body else None
        self.calls.append((method, path, data))
        if self.fail_on and method == self.fail_on[0] and re.search(self.fail_on[1], path):
            return self._err(500, 1000, "simulated failure")
        a = self.account_id
        deny = lambda name: self._err(403, 10000, f"Authentication error ({name})")

        if path == "/user/tokens/verify":
            return self._ok({"id": "tok", "status": self.token_status})
        if path == "/accounts":
            if "Account Settings Read" in self.denied:
                return deny("Account Settings Read")
            return self._ok([{"id": a, "name": "Your Account"}])
        if path == "/zones":
            if "Zone Read" in self.denied:
                return deny("Zone Read")
            return self._ok(list(self.zones))
        m = re.fullmatch(r"/zones/([^/]+)/dns_records(?:/([^/]+))?", path)
        if m:
            if "DNS Edit" in self.denied:
                return deny("DNS Edit")
            zid, rid = m.groups()
            recs = self.dns.setdefault(zid, [])
            if method == "GET":
                name = (q.get("name") or [None])[0]
                return self._ok([r for r in recs if not name or r["name"] == name])
            if method == "POST":
                rec = dict(data, id=_id()); recs.append(rec); return self._ok(rec)
            if method == "DELETE":
                self.dns[zid] = [r for r in recs if r["id"] != rid]; return self._ok({"id": rid})
        if not path.startswith(f"/accounts/{a}"):
            return self._err(404, 7003, "no route")
        rest = path[len(f"/accounts/{a}"):]

        if rest == "/access/organizations":
            if not self.org:
                return self._err(404, 12130, "access.api.error.not_found")
            return self._ok(self.org)
        if rest.startswith("/access/identity_providers"):
            if "Access: Organizations, Identity Providers, and Groups Edit" in self.denied:
                return deny("idp")
            if method == "GET":
                return self._ok(list(self.idps))
            if method == "POST":
                idp = dict(data, id=_id()); self.idps.append(idp); return self._ok(idp)
            if method == "DELETE":
                iid = rest.rsplit("/", 1)[1]
                self.idps = [i for i in self.idps if i["id"] != iid]; return self._ok({"id": iid})
        if rest.startswith("/cfd_tunnel"):
            if "Cloudflare Tunnel Edit" in self.denied:
                return deny("tunnel")
            parts = rest.split("/")[2:]
            if not parts or parts == [""]:
                if method == "GET":
                    return self._ok(list(self.tunnels.values()))
                t = {"id": _id(), "name": data["name"], "status": "inactive"}
                self.tunnels[t["id"]] = t; return self._ok(t)
            tid = parts[0]
            if len(parts) == 1:
                if method == "GET":
                    return self._ok(self.tunnels.get(tid))
                if method == "DELETE":
                    self.tunnels.pop(tid, None); return self._ok({"id": tid})
            if parts[1] == "configurations":
                if method == "PUT":
                    self.ingress[tid] = data["config"]["ingress"]
                return self._ok({"config": {"ingress": self.ingress.get(tid, [])}})
            if parts[1] == "token":
                return self._ok("TUNNELTOKEN-" + tid)
            if parts[1] == "connections":
                return self._ok(None)
        if rest.startswith("/access/policies"):
            if "Access: Apps and Policies Edit" in self.denied:
                return deny("policies")
            parts = rest.split("/")[3:]
            if not parts:
                if method == "GET":
                    return self._ok(list(self.policies.values()))
                p = dict(data, id=_id(), reusable=True); self.policies[p["id"]] = p; return self._ok(p)
            if method == "DELETE":
                self.policies.pop(parts[0], None); return self._ok({"id": parts[0]})
        if rest.startswith("/access/apps"):
            if "Access: Apps and Policies Edit" in self.denied:
                return deny("apps")
            parts = rest.split("/")[3:]
            if not parts:
                if method == "GET":
                    return self._ok([self._expand(x) for x in self.apps.values()])
                app = dict(data, id=_id(), aud=_id() + _id())
                self.apps[app["id"]] = app; return self._ok(self._expand(app))
            aid = parts[0]
            if method == "GET":
                app = self.apps.get(aid)
                return self._ok(self._expand(app)) if app else self._err(404, 12130, "not found")
            if method == "DELETE":
                self.apps.pop(aid, None); return self._ok({"id": aid})
        return self._err(404, 7003, f"no route {method} {path}")

    def _expand(self, app):
        """GET returns policies with their rules, as the real API does."""
        out = dict(app)
        out["policies"] = [dict(self.policies.get(p["id"], {}), precedence=p.get("precedence"))
                           for p in app.get("policies", [])]
        return out

    def tagged_count(self) -> int:
        n = sum(1 for t in self.tunnels.values() if t["name"].startswith("moofmail-"))
        n += sum(1 for p in self.policies.values() if p["name"].startswith("moofmail-"))
        n += sum(1 for x in self.apps.values() if x["name"].startswith("moofmail-"))
        n += sum(1 for recs in self.dns.values() for r in recs if "moofmail" in (r.get("comment") or ""))
        return n


class MemoryStore:
    kind = "memory"
    warning = None

    def __init__(self):
        self.d = {}

    def get(self, name):
        return self.d.get(name)

    def set(self, name, value):
        self.d[name] = value

    def delete(self, name):
        self.d.pop(name, None)


class RecordingServices:
    kind = "fake"

    def __init__(self):
        self.installed, self.removed = [], []

    def install(self, prefix, config_path):
        self.installed.append((prefix, str(config_path)))
        return [f"{prefix}.server", f"{prefix}.tunnel"]

    def uninstall(self, prefix):
        self.removed.append(prefix)
        return [f"{prefix}.server", f"{prefix}.tunnel"]

    def describe(self):
        return "fake"
