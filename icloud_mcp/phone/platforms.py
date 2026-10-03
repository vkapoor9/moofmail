"""Where secrets live and how the two background services run, per platform.

Two secrets: the tunnel token (lets its holder run a connector for this tunnel)
and the Apple app-specific password (the phone service runs outside Claude Code,
so it cannot borrow the plugin's copy). Neither is ever placed on a command line,
because argv is readable by every user on the machine through `ps`.

macOS: login Keychain, LaunchAgents. Never a LaunchDaemon: a system-context job
cannot unlock the login keychain, so it would start, fail to read the secret, and
look like a credential problem that does not exist.

Linux desktop: the Secret Service through `keyring`, when installed and working.
Linux headless (a VPS): a 0600 file, with a warning, because there is no keyring
to unlock. systemd --user units; `loginctl enable-linger` keeps them running
without a login session.
"""
from __future__ import annotations

import json
import os
import platform as _platform
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable

STATE_DIR = Path("~/.config/moofmail").expanduser()
SERVICE = "moofmail-phone"

Runner = Callable[..., subprocess.CompletedProcess]


def _run(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **kw)


# ======================================================================= secrets
class SecretStore:
    kind = "base"
    warning: str | None = None

    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> None: ...


class MacKeychain(SecretStore):
    """Login Keychain via `security`, with the secret passed on STDIN.

    `security add-generic-password -w <secret>` would put the secret in argv for
    as long as the command runs. `security -i` reads commands from stdin instead,
    so the value never appears in the process table.
    """
    kind = "macos-keychain"

    def __init__(self, service: str = SERVICE, run: Runner = _run):
        self.service, self._run = service, run

    def get(self, name: str) -> str | None:
        r = self._run(["/usr/bin/security", "find-generic-password", "-s", self.service,
                       "-a", name, "-w"])
        return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout.strip() else None

    def set(self, name: str, value: str) -> None:
        if any(c in value for c in '"\n\r\\'):
            raise ValueError("secret contains characters the keychain command cannot carry")
        cmd = (f'add-generic-password -U -s {shlex.quote(self.service)} '
               f'-a {shlex.quote(name)} -w "{value}"\n')
        r = self._run(["/usr/bin/security", "-i"], input=cmd)
        if r.returncode != 0 or self.get(name) != value:
            raise RuntimeError(f"could not save '{name}' to the login Keychain")

    def delete(self, name: str) -> None:
        self._run(["/usr/bin/security", "delete-generic-password", "-s", self.service, "-a", name])


class KeyringStore(SecretStore):
    kind = "keyring"

    def __init__(self, service: str = SERVICE, backend=None):
        self.service = service
        if backend is None:
            import keyring  # optional extra: pip install moofmail[phone-linux]
            backend = keyring
        self._k = backend

    def get(self, name):
        return self._k.get_password(self.service, name)

    def set(self, name, value):
        self._k.set_password(self.service, name, value)

    def delete(self, name):
        try:
            self._k.delete_password(self.service, name)
        except Exception:
            pass


class FileStore(SecretStore):
    """0600 JSON file. Only for machines with no keyring, such as a VPS."""
    kind = "file"
    warning = ("No system keyring was available, so secrets are kept in a file only "
               "your user can read ({path}). Anyone with root on this machine, "
               "including a VPS provider, can read it.")

    def __init__(self, path: Path | None = None):
        self.path = Path(path or STATE_DIR / "secrets.json")
        self.warning = self.warning.format(path=self.path)

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def get(self, name):
        return self._load().get(name)

    def set(self, name, value):
        d = self._load(); d[name] = value; self._save(d)

    def delete(self, name):
        d = self._load(); d.pop(name, None); self._save(d)

    def mode_ok(self) -> bool:
        try:
            return stat.S_IMODE(self.path.stat().st_mode) == 0o600
        except OSError:
            return True


def pick_store(system: str | None = None) -> SecretStore:
    system = system or _platform.system()
    if system == "Darwin":
        return MacKeychain()
    try:
        store = KeyringStore()
        backend = type(store._k.get_keyring()).__module__
        if "fail" in backend or "null" in backend:
            raise RuntimeError("no usable keyring backend")
        return store
    except Exception:
        return FileStore()


# ======================================================================= services
def python_cmd() -> list[str]:
    """How a service starts this package: the same interpreter that ran setup."""
    return [sys.executable, "-m", "icloud_mcp.phone"]


def package_parent() -> str:
    import icloud_mcp
    return str(Path(icloud_mcp.__file__).resolve().parent.parent)


class ServiceManager:
    kind = "base"

    def install(self, prefix: str, config_path: Path) -> list[str]: ...
    def uninstall(self, prefix: str) -> list[str]: ...
    def describe(self) -> str: ...


def _units(prefix: str, config_path: Path) -> dict[str, list[str]]:
    base = python_cmd()
    return {
        # --config is an option of the top-level parser, so it must come BEFORE the
        # subcommand. Found live 2026-10-03: in the other order argparse exits 2 and
        # both services crash on every start.
        f"{prefix}.server": base + ["--config", str(config_path), "run-server"],
        f"{prefix}.tunnel": base + ["--config", str(config_path), "run-tunnel"],
    }


class LaunchAgents(ServiceManager):
    kind = "launchd"

    def __init__(self, home: Path | None = None, run: Runner = _run, uid: int | None = None):
        self.dir = Path(home or Path.home()) / "Library" / "LaunchAgents"
        self._run = run
        self.uid = os.getuid() if uid is None else uid
        self.logs = STATE_DIR / "logs"

    def plist(self, label: str, args: list[str]) -> str:
        from xml.sax.saxutils import escape
        items = "\n".join(f"    <string>{escape(a)}</string>" for a in args)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{escape(label)}</string>
  <key>ProgramArguments</key>
  <array>
{items}
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PYTHONPATH</key><string>{escape(package_parent())}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{escape(str(self.logs / (label + '.log')))}</string>
  <key>StandardErrorPath</key><string>{escape(str(self.logs / (label + '.err')))}</string>
</dict>
</plist>
"""

    def install(self, prefix, config_path):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        done = []
        for label, args in _units(prefix, config_path).items():
            p = self.dir / f"{label}.plist"
            p.write_text(self.plist(label, args))
            self._run(["/bin/launchctl", "bootout", f"gui/{self.uid}/{label}"])
            r = self._run(["/bin/launchctl", "bootstrap", f"gui/{self.uid}", str(p)])
            if r.returncode != 0:
                raise RuntimeError(f"launchctl bootstrap {label} failed: {r.stderr.strip()}")
            done.append(label)
        return done

    def uninstall(self, prefix):
        gone = []
        for p in sorted(self.dir.glob(f"{prefix}.*.plist")):
            label = p.name[:-len(".plist")]
            self._run(["/bin/launchctl", "bootout", f"gui/{self.uid}/{label}"])
            p.unlink(missing_ok=True)
            for ext in (".log", ".err"):
                (self.logs / f"{label}{ext}").unlink(missing_ok=True)
            gone.append(label)
        try:
            self.logs.rmdir()  # only succeeds when nothing else is left in it
        except OSError:
            pass
        return gone

    def describe(self):
        return f"LaunchAgents in {self.dir}"


class SystemdUser(ServiceManager):
    kind = "systemd-user"

    def __init__(self, home: Path | None = None, run: Runner = _run):
        self.dir = Path(home or Path.home()) / ".config" / "systemd" / "user"
        self._run = run

    def unit(self, label: str, args: list[str]) -> str:
        return f"""[Unit]
Description=Moofmail phone access ({label.rsplit('.', 1)[-1]})
After=network-online.target

[Service]
ExecStart={' '.join(shlex.quote(a) for a in args)}
Environment=PYTHONPATH={package_parent()}
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=default.target
"""

    def install(self, prefix, config_path):
        self.dir.mkdir(parents=True, exist_ok=True)
        names = []
        for label, args in _units(prefix, config_path).items():
            name = f"{label}.service"
            (self.dir / name).write_text(self.unit(label, args))
            names.append(name)
        self._run(["systemctl", "--user", "daemon-reload"])
        for n in names:
            r = self._run(["systemctl", "--user", "enable", "--now", n])
            if r.returncode != 0:
                raise RuntimeError(f"systemctl enable {n} failed: {r.stderr.strip()}")
        return names

    def uninstall(self, prefix):
        gone = []
        for p in sorted(self.dir.glob(f"{prefix}.*.service")):
            self._run(["systemctl", "--user", "disable", "--now", p.name])
            p.unlink(missing_ok=True)
            gone.append(p.name)
        self._run(["systemctl", "--user", "daemon-reload"])
        return gone

    def describe(self):
        return (f"systemd user units in {self.dir}. To keep them running after you "
                "log out, run once: loginctl enable-linger $USER")


def pick_services(system: str | None = None) -> ServiceManager:
    system = system or _platform.system()
    if system == "Darwin":
        return LaunchAgents()
    if system == "Linux":
        return SystemdUser()
    raise RuntimeError(f"{system} is not supported. Moofmail phone access runs on macOS and Linux.")


# ======================================================================= observation
def listeners(port: int, run: Runner = _run, system: str | None = None) -> list[str]:
    """Local addresses with a TCP listener on `port`, from the OS itself."""
    system = system or _platform.system()
    if system == "Darwin":
        r = run(["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"])
        out = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                out.append(parts[8].rsplit(":", 1)[0])
        return out
    if shutil.which("ss"):
        r = run(["ss", "-ltnH", f"sport = :{port}"])
        return [line.split()[3].rsplit(":", 1)[0] for line in r.stdout.splitlines()
                if len(line.split()) >= 4]
    return _proc_listeners(port)


def _proc_listeners(port: int) -> list[str]:
    out = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            f = row.split()
            local, st = f[1], f[3]
            if st != "0A":
                continue
            addr, p = local.split(":")
            if int(p, 16) != port:
                continue
            if len(addr) == 8:
                octets = [str(int(addr[i:i + 2], 16)) for i in (6, 4, 2, 0)]
                out.append(".".join(octets))
            else:
                out.append("::1" if addr.endswith("01000000") and set(addr[:24]) == {"0"} else addr)
    return out


def process_args(run: Runner = _run, system: str | None = None) -> list[str]:
    system = system or _platform.system()
    args = ["ps", "-axww", "-o", "args="] if system == "Darwin" else ["ps", "-eww", "-o", "args="]
    return run(args).stdout.splitlines()


# ======================================================================= docker
class EnvFileStore(SecretStore):
    """secrets.env for Docker Compose, mode 0600, read by both containers.

    Names map onto the variables the containers expect: the tunnel token becomes
    TUNNEL_TOKEN (cloudflared reads it from the environment, never argv) and the
    Apple password becomes ICLOUD_APP_PASSWORD, paired with ICLOUD_APPLE_ID.
    """
    kind = "docker-env-file"
    warning = ("Secrets for Docker are in {path}, readable only by your user. Anyone with "
               "root on this machine, including a VPS provider, can read them.")

    def __init__(self, path: Path):
        self.path = Path(path)
        self.warning = self.warning.format(path=self.path)

    @staticmethod
    def _var(name: str) -> str:
        if name.startswith("tunnel_token:"):
            return "TUNNEL_TOKEN"
        if name.startswith("app_password:"):
            return "ICLOUD_APP_PASSWORD"
        return name

    def _load(self) -> dict:
        out = {}
        try:
            for line in self.path.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
        except OSError:
            pass
        return out

    def _save(self, d: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("# Written by moofmail-phone. Keep private (mode 600).\n")
            f.writelines(f"{k}={v}\n" for k, v in d.items())
        os.chmod(self.path, 0o600)

    def get(self, name):
        return self._load().get(self._var(name))

    def set(self, name, value):
        if "\n" in value:
            raise ValueError("secret contains a newline")
        d = self._load(); d[self._var(name)] = value; self._save(d)

    def set_plain(self, var: str, value: str) -> None:
        d = self._load(); d[var] = value; self._save(d)

    def delete(self, name):
        d = self._load(); d.pop(self._var(name), None); self._save(d)

    def wipe(self) -> None:
        self.path.unlink(missing_ok=True)


class DockerProbes:
    """Gate observations taken INSIDE the containers, where the server runs."""

    def __init__(self, compose_dir: Path, run: Runner = _run):
        self.dir, self._run = Path(compose_dir), run

    def _exec(self, service: str, code: str) -> str:
        r = self._run(["docker", "compose", "exec", "-T", service, "python", "-c", code], cwd=self.dir)
        return r.stdout if r.returncode == 0 else ""

    def listeners(self, port: int) -> list[str]:
        out = self._exec("moofmail", "from icloud_mcp.phone.platforms import _proc_listeners as f\n"
                                     f"print('\\n'.join(f({int(port)})))")
        return [l for l in out.splitlines() if l.strip()]

    def local_tools(self, port: int) -> dict | None:
        out = self._exec("moofmail", "import urllib.request,sys\n"
                                     f"sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:{int(port)}/healthz/tools',timeout=5).read().decode())")
        try:
            return json.loads(out)
        except ValueError:
            return None

    def fetch(self, fallback):
        def _fetch(method, url, headers):
            if not url.startswith("http://127.0.0.1"):
                return fallback(method, url, headers)
            code = ("import urllib.request,urllib.error,json,sys\n"
                    f"r=urllib.request.Request({url!r},method={method!r},headers=json.loads({json.dumps(json.dumps(headers))}),data=b'')\n"
                    "try:\n s=urllib.request.urlopen(r,timeout=10).status\n"
                    "except urllib.error.HTTPError as e:\n s=e.code\n"
                    "print(s)")
            out = self._exec("moofmail", code).strip()
            return int(out) if out.isdigit() else 0
        return _fetch

    def process_lines(self) -> list[str]:
        ids = self._run(["docker", "compose", "ps", "-q"], cwd=self.dir).stdout.split()
        lines = []
        for cid in ids:
            r = self._run(["docker", "inspect", "--format", "{{.Path}} {{join .Args \" \"}}", cid])
            lines += r.stdout.splitlines()
        return lines
