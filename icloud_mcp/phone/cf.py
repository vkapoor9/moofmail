"""A small Cloudflare API client for the phone-access installer.

Standard library only, and the HTTP layer is injectable, so every test runs
against an in-memory fake and nothing in the suite can touch a real account.

Endpoint shapes were taken from the live API while the connector was first built
(see the runbook): Access apps reject PATCH, so updates are full PUTs; an Access
app with Managed OAuth answers unauthenticated requests with 401, not a redirect.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

API = "https://api.cloudflare.com/client/v4"

#: Prefix on everything this installer creates, so teardown can find its own
#: resources and never touch anything else in the account.
TAG = "moofmail-"
DNS_COMMENT = "moofmail: phone access connector"

#: (method, url, headers, body_bytes_or_None) -> (status, parsed_json_or_text)
HTTP = Callable[[str, str, dict, bytes | None], tuple[int, object]]


class CloudflareError(RuntimeError):
    def __init__(self, status: int, errors: list, where: str):
        self.status, self.errors, self.where = status, errors, where
        msg = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors if isinstance(e, dict))
        super().__init__(f"{where}: HTTP {status} {msg or errors}")

    @property
    def forbidden(self) -> bool:
        codes = {e.get("code") for e in self.errors if isinstance(e, dict)}
        return self.status == 403 or bool(codes & {9109, 10000})


def urllib_http(method: str, url: str, headers: dict, body: bytes | None):
    from .gate import USER_AGENT
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        return status, raw.decode("utf-8", "replace")


@dataclass
class Resources:
    """Ids of what setup created. Teardown uses these first, then the tag."""
    account_id: str = ""
    zone_id: str = ""
    tunnel_id: str = ""
    dns_record_id: str = ""
    policy_id: str = ""
    app_id: str = ""
    idp_id: str = ""
    idp_created: bool = False


class Cloudflare:
    def __init__(self, token: str, http: HTTP | None = None):
        if not token or not token.strip():
            raise ValueError("an API token is required")
        self._token = token.strip()
        self._http = http or urllib_http

    # ------------------------------------------------------------ plumbing
    def _call(self, method: str, path: str, body: object = None,
              where: str = "") -> object:
        headers = {"Authorization": f"Bearer {self._token}",
                   "Content-Type": "application/json"}
        data = json.dumps(body).encode() if body is not None else None
        status, payload = self._http(method, API + path, headers, data)
        if not isinstance(payload, dict):
            raise CloudflareError(status, [{"message": str(payload)[:200]}], where or path)
        if not payload.get("success", False) or status >= 400:
            raise CloudflareError(status, payload.get("errors") or [], where or path)
        return payload.get("result")

    def _list(self, path: str, where: str = "") -> list:
        sep = "&" if "?" in path else "?"
        out, page = [], 1
        while True:
            res = self._call("GET", f"{path}{sep}page={page}&per_page=50", where=where)
            if not isinstance(res, list):
                return out + ([res] if res else [])
            out += res
            if len(res) < 50:
                return out
            page += 1

    # ------------------------------------------------------------ token + scope
    def verify_token(self) -> dict:
        return self._call("GET", "/user/tokens/verify", where="verify token")

    def accounts(self) -> list:
        return self._list("/accounts", where="list accounts")

    def zones(self, account_id: str) -> list:
        return self._list(f"/zones?account.id={account_id}", where="list zones")

    def probe(self, account_id: str, zone_id: str | None = None) -> dict:
        """Read-only check of every permission setup needs. Name -> True/False.

        Reads cannot prove a WRITE permission, so a True here means the token can
        at least see the resource; a missing write still fails at create time with
        a clear message. A False means setup would certainly fail, so it stops first.
        """
        checks = {
            "Account Settings Read": ("GET", "/accounts"),
            "Cloudflare Tunnel Edit": ("GET", f"/accounts/{account_id}/cfd_tunnel?per_page=5"),
            "Access: Apps and Policies Edit": ("GET", f"/accounts/{account_id}/access/apps"),
            "Access: Organizations, Identity Providers, and Groups Edit":
                ("GET", f"/accounts/{account_id}/access/identity_providers"),
            "Zone Read": ("GET", f"/zones?account.id={account_id}&per_page=5"),
        }
        if zone_id:
            checks["DNS Edit"] = ("GET", f"/zones/{zone_id}/dns_records?per_page=5")
        out = {}
        for name, (m, p) in checks.items():
            try:
                self._call(m, p, where=name)
                out[name] = True
            except CloudflareError as e:
                if e.forbidden:
                    out[name] = False
                else:
                    raise
        return out

    # ------------------------------------------------------------ Zero Trust org
    def organization(self, account_id: str) -> dict | None:
        """The Zero Trust org, or None when onboarding has not been done."""
        try:
            res = self._call("GET", f"/accounts/{account_id}/access/organizations",
                             where="read Zero Trust organization")
        except CloudflareError as e:
            if e.forbidden:
                raise
            return None
        return res if isinstance(res, dict) and res.get("auth_domain") else None

    def identity_providers(self, account_id: str) -> list:
        return self._list(f"/accounts/{account_id}/access/identity_providers",
                          where="list identity providers")

    def create_otp_idp(self, account_id: str) -> dict:
        return self._call("POST", f"/accounts/{account_id}/access/identity_providers",
                          {"name": "One-time PIN", "type": "onetimepin", "config": {}},
                          where="create one-time PIN login")

    def delete_idp(self, account_id: str, idp_id: str) -> None:
        self._call("DELETE", f"/accounts/{account_id}/access/identity_providers/{idp_id}",
                   where="delete identity provider")

    # ------------------------------------------------------------ tunnel
    def tunnels(self, account_id: str) -> list:
        return self._list(f"/accounts/{account_id}/cfd_tunnel?is_deleted=false",
                          where="list tunnels")

    def create_tunnel(self, account_id: str, name: str) -> dict:
        if not name.startswith(TAG):
            raise ValueError("installer resources must carry the tag prefix")
        return self._call("POST", f"/accounts/{account_id}/cfd_tunnel",
                          {"name": name, "config_src": "cloudflare"}, where="create tunnel")

    def tunnel(self, account_id: str, tunnel_id: str) -> dict:
        return self._call("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}",
                          where="read tunnel")

    def put_ingress(self, account_id: str, tunnel_id: str, hostname: str, port: int) -> dict:
        ingress = [{"hostname": hostname, "service": f"http://127.0.0.1:{int(port)}"},
                   {"service": "http_status:404"}]
        return self._call("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                          {"config": {"ingress": ingress}}, where="set tunnel route")

    def ingress(self, account_id: str, tunnel_id: str) -> list:
        res = self._call("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                         where="read tunnel route")
        return ((res or {}).get("config") or {}).get("ingress") or []

    def tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        res = self._call("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token",
                         where="read tunnel token")
        if not isinstance(res, str) or not res:
            raise CloudflareError(200, [{"message": "no tunnel token returned"}], "read tunnel token")
        return res

    def delete_tunnel(self, account_id: str, tunnel_id: str) -> None:
        # A tunnel with live connections cannot be deleted; drop them first.
        try:
            self._call("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
                       where="clean up tunnel connections")
        except CloudflareError:
            pass
        self._call("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}", where="delete tunnel")

    # ------------------------------------------------------------ DNS
    def dns_records(self, zone_id: str, name: str | None = None) -> list:
        q = f"?name={name}" if name else ""
        return self._list(f"/zones/{zone_id}/dns_records{q}", where="list DNS records")

    def create_cname(self, zone_id: str, hostname: str, tunnel_id: str) -> dict:
        return self._call("POST", f"/zones/{zone_id}/dns_records",
                          {"type": "CNAME", "name": hostname,
                           "content": f"{tunnel_id}.cfargotunnel.com", "proxied": True,
                           "ttl": 1, "comment": DNS_COMMENT}, where="create DNS record")

    def delete_dns(self, zone_id: str, record_id: str) -> None:
        self._call("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", where="delete DNS record")

    # ------------------------------------------------------------ Access
    def create_policy(self, account_id: str, name: str, email: str) -> dict:
        if not name.startswith(TAG):
            raise ValueError("installer resources must carry the tag prefix")
        return self._call("POST", f"/accounts/{account_id}/access/policies",
                          {"name": name, "decision": "allow",
                           "include": [{"email": {"email": email}}]},
                          where="create Access policy")

    def policies(self, account_id: str) -> list:
        return self._list(f"/accounts/{account_id}/access/policies", where="list Access policies")

    def delete_policy(self, account_id: str, policy_id: str) -> None:
        self._call("DELETE", f"/accounts/{account_id}/access/policies/{policy_id}",
                   where="delete Access policy")

    def create_app(self, account_id: str, name: str, hostname: str, policy_id: str,
                   idp_ids: list[str]) -> dict:
        if not name.startswith(TAG):
            raise ValueError("installer resources must carry the tag prefix")
        body = app_body(name, hostname, policy_id, idp_ids)
        return self._call("POST", f"/accounts/{account_id}/access/apps", body,
                          where="create Access application")

    def app(self, account_id: str, app_id: str) -> dict:
        return self._call("GET", f"/accounts/{account_id}/access/apps/{app_id}",
                          where="read Access application")

    def apps(self, account_id: str) -> list:
        return self._list(f"/accounts/{account_id}/access/apps", where="list Access applications")

    def delete_app(self, account_id: str, app_id: str) -> None:
        self._call("DELETE", f"/accounts/{account_id}/access/apps/{app_id}",
                   where="delete Access application")


def app_body(name: str, hostname: str, policy_id: str, idp_ids: list[str]) -> dict:
    """The Access application, exactly as the working connector has it.

    Covers the WHOLE hostname (never a path), so every path, /healthz included,
    is challenged at the edge. Managed OAuth lets Claude sign in; dynamic client
    registration is limited to claude.ai callbacks plus loopback for Claude Code.
    The grant lasts a year (unset, it is 7 days and the phone connector silently
    signs out). auto_redirect stays off: with it on and more than one login method,
    a failing provider leaves no visible way to the other.
    """
    return {
        "name": name,
        "type": "self_hosted",
        "domain": hostname,
        "self_hosted_domains": [hostname],
        "destinations": [{"type": "public", "uri": hostname}],
        "session_duration": "24h",
        "allowed_idps": list(idp_ids),
        "auto_redirect_to_identity": False,
        "app_launcher_visible": False,
        "policies": [{"id": policy_id, "precedence": 1}],
        "oauth_configuration": {
            "enabled": True,
            "grant": {"session_duration": "8760h", "access_token_lifetime": "15m"},
            "dynamic_client_registration": {
                "enabled": True,
                "allowed_uris": ["https://claude.ai/*"],
                "allow_any_on_localhost": True,
                "allow_any_on_loopback": True,
            },
        },
    }
