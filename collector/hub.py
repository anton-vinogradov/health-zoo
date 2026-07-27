#!/usr/bin/env python3
"""health-zoo hub: polls the fleet and serves the dashboard.

Runs stdlib-only (no venv on the target host is required beyond python3).
A background thread refreshes the snapshot on a timer; the HTTP layer only
ever hands out the last completed snapshot, so a slow host can never make the
page hang.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATHS = [
    Path(os.environ.get("HEALTH_ZOO_CONFIG", "")),
    Path("/etc/health-zoo.json"),
    ROOT / "collector" / "config.json",
    ROOT / "collector" / "config.example.json",
]
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def load_config() -> dict:
    for path in CONFIG_PATHS:
        if path and path.is_file():
            with path.open(encoding="utf-8") as fh:
                cfg = json.load(fh)
            cfg["_path"] = str(path)
            return cfg
    raise SystemExit("health-zoo: no config found (tried /etc/health-zoo.json)")


class Fleet:
    """Owns the current snapshot and the polling loop."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.snapshot: dict = {"generated": 0, "hosts": [], "polling": False}
        self.wake = threading.Event()

    def hosts(self) -> list[dict]:
        return self.cfg.get("hosts", [])

    def poll_once(self) -> None:
        started = time.time()
        with self.lock:
            self.snapshot["polling"] = True
        try:
            hosts = probe.probe_all(self.hosts(), self.cfg.get("ssh_key"))
            snap = {
                "generated": int(time.time()),
                "duration_ms": int((time.time() - started) * 1000),
                "subnets": self.cfg.get("subnets", []),
                "hosts": hosts,
                "poll_interval": self.cfg.get("poll_interval", 180),
                "polling": False,
            }
            with self.lock:
                self.snapshot = snap
        except Exception as exc:  # keep the loop alive whatever happens
            with self.lock:
                self.snapshot["polling"] = False
                self.snapshot["error"] = str(exc)

    def loop(self) -> None:
        while True:
            self.poll_once()
            self.wake.wait(timeout=self.cfg.get("poll_interval", 180))
            self.wake.clear()

    def get(self) -> dict:
        with self.lock:
            return self.snapshot


class Jobs:
    """Background update runs, with a live log the browser can tail."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.counter = 0
        self.active: str | None = None

    def _new_id(self) -> str:
        self.counter += 1
        return f"job{self.counter}"

    def start(self, targets: list[dict], fleet: Fleet) -> tuple[str | None, str]:
        with self.lock:
            if self.active and self.jobs[self.active]["state"] == "running":
                return None, "another update is already running"
            job_id = self._new_id()
            self.jobs[job_id] = {
                "id": job_id,
                "state": "running",
                "started": int(time.time()),
                "targets": [t["id"] for t in targets],
                "current": "",
                "log": [],
                "results": {},
            }
            self.active = job_id
        thread = threading.Thread(target=self._run, args=(job_id, targets, fleet), daemon=True)
        thread.start()
        return job_id, ""

    def _log(self, job_id: str, line: str) -> None:
        with self.lock:
            job = self.jobs[job_id]
            job["log"].append(line)
            # A full dist-upgrade log is long; keep the tail bounded.
            if len(job["log"]) > 4000:
                del job["log"][:1000]

    def _run(self, job_id: str, targets: list[dict], fleet: Fleet) -> None:
        key = self.cfg.get("ssh_key")
        for host in targets:
            with self.lock:
                self.jobs[job_id]["current"] = host["id"]
            self._log(job_id, f"=== {host['name']} ({host['addr']}) ===")
            code = self._update_host(job_id, host, key)
            with self.lock:
                self.jobs[job_id]["results"][host["id"]] = "ok" if code == 0 else f"failed ({code})"
            self._log(job_id, "")
        with self.lock:
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""
        fleet.wake.set()  # refresh the dashboard as soon as the run ends

    def _update_host(self, job_id: str, host: dict, key: str | None) -> int:
        # DEBIAN_FRONTEND + confold: never block on a config-file prompt.
        remote = (
            "export DEBIAN_FRONTEND=noninteractive; "
            "sudo -n apt-get update -qq && "
            "sudo -n apt-get -y -o Dpkg::Options::=--force-confdef "
            "-o Dpkg::Options::=--force-confold upgrade; "
            "rc=$?; "
            "[ -f /var/run/reboot-required ] && echo 'REBOOT-REQUIRED'; exit $rc"
        )
        if host.get("user") == "root":
            remote = remote.replace("sudo -n ", "")
        return self._exec(job_id, host, key, remote)

    def _exec(self, job_id: str, host: dict, key: str | None, remote: str) -> int:
        """Run a command on the host, streaming its output into the job log."""
        if host.get("local"):
            # setsid detaches the work from this service: the host running the
            # dashboard may restart python/apache mid-run and would otherwise
            # kill its own job.
            cmd = ["setsid", "sh", "-c", remote]
        else:
            cmd = list(probe.SSH_BASE)
            if key:
                cmd += ["-i", os.path.expanduser(key)]
            if host.get("port"):
                cmd += ["-p", str(host["port"])]
            target = host["addr"]
            if host.get("user"):
                target = f"{host['user']}@{target}"
            cmd += [target, remote]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
        except OSError as exc:
            self._log(job_id, f"! cannot start: {exc}")
            return 255

        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                self._log(job_id, line)
        return proc.wait()

    # Removing one of these would either cut off our own way back in or take
    # the host down. The UI hides the button for them; this is the real guard.
    PROTECTED = {
        "ssh", "sshd", "dropbear", "network", "networking", "systemd-networkd",
        "systemd-resolved", "systemd-journald", "systemd-logind", "dbus",
        "firewall", "cron", "crond", "rpcd", "log", "sysntpd", "uci",
        "health-zoo", "sudo", "polkit", "getty", "serial-getty",
    }

    @classmethod
    def protected(cls, unit: str) -> bool:
        base = re.sub(r"\.(service|timer|socket)$", "", unit)
        return base in cls.PROTECTED or base.startswith("systemd-")

    def start_removal(self, host: dict, unit: str, fleet: Fleet) -> tuple[str | None, str]:
        with self.lock:
            if self.active and self.jobs[self.active]["state"] == "running":
                return None, "another job is already running"
            job_id = self._new_id()
            self.jobs[job_id] = {
                "id": job_id,
                "kind": "remove",
                "state": "running",
                "started": int(time.time()),
                "targets": [host["id"]],
                "current": host["id"],
                "log": [],
                "results": {},
            }
            self.active = job_id
        thread = threading.Thread(target=self._run_removal,
                                  args=(job_id, host, unit, fleet), daemon=True)
        thread.start()
        return job_id, ""

    def _run_removal(self, job_id: str, host: dict, unit: str, fleet: Fleet) -> None:
        key = self.cfg.get("ssh_key")
        self._log(job_id, f"=== удаление {unit} на {host['name']} ({host['addr']}) ===")

        if host.get("agent") == "openwrt":
            # procd: disable unlinks the rc.d symlinks, then the script goes.
            remote = (
                f"set -e; /etc/init.d/{shlex.quote(unit)} stop || true; "
                f"/etc/init.d/{shlex.quote(unit)} disable || true; "
                f"rm -f /etc/init.d/{shlex.quote(unit)}; "
                f"echo 'removed /etc/init.d/{unit}'"
            )
        else:
            quoted = shlex.quote(unit)
            # Only unit files under /etc/systemd are deleted: those in
            # /usr/lib belong to a package and would come back on upgrade,
            # so there we stop and mask instead of leaving a half-removed mess.
            remote = (
                "set -e; "
                f"frag=$(systemctl show -p FragmentPath --value {quoted}); "
                f"echo \"unit file: $frag\"; "
                f"sudo -n systemctl disable --now {quoted} || true; "
                'case "$frag" in '
                '  /etc/systemd/*) sudo -n rm -f "$frag"; echo "удалён $frag";; '
                f'  *) sudo -n systemctl mask {quoted}; '
                '     echo "unit принадлежит пакету — остановлен и замаскирован, файл не тронут";; '
                "esac; "
                "sudo -n systemctl daemon-reload; sudo -n systemctl reset-failed || true"
            )
            if host.get("user") == "root":
                remote = remote.replace("sudo -n ", "")

        code = self._exec(job_id, host, key, remote)
        with self.lock:
            self.jobs[job_id]["results"][host["id"]] = "ok" if code == 0 else f"failed ({code})"
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""
        fleet.wake.set()

    def get(self, job_id: str) -> dict | None:
        with self.lock:
            job = self.jobs.get(job_id)
            return json.loads(json.dumps(job)) if job else None

    def latest(self) -> dict | None:
        with self.lock:
            if not self.active:
                return None
            return json.loads(json.dumps(self.jobs[self.active]))


def order_targets(hosts: list[dict]) -> list[dict]:
    """Updatable hosts, with the dashboard's own host deliberately last."""
    targets = [h for h in hosts if h.get("updatable")]
    return sorted(targets, key=lambda h: (bool(h.get("update_last")), h.get("id", "")))


class Handler(BaseHTTPRequestHandler):
    server_version = "health-zoo"
    fleet: Fleet
    jobs: Jobs

    def log_message(self, fmt, *args):  # quieter journal
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code: int = 200) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            file = ROOT / name
            if not file.is_file():
                self._send(404, b"not found", "text/plain")
                return
            self._send(200, file.read_bytes(), ctype)
            return

        if path == "/api/state":
            self._json(self.fleet.get())
            return

        if path == "/api/job":
            job = self.jobs.latest()
            self._json(job or {"state": "idle"})
            return

        if path.startswith("/api/job/"):
            job = self.jobs.get(path.rsplit("/", 1)[-1])
            self._json(job or {"error": "no such job"}, 200 if job else 404)
            return

        self._send(404, b"not found", "text/plain")

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path == "/api/refresh":
            self.fleet.wake.set()
            self._json({"ok": True})
            return

        if path == "/api/update":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                req = json.loads(body or "{}")
            except json.JSONDecodeError:
                self._json({"error": "bad json"}, 400)
                return

            wanted = req.get("hosts")  # None or [] means "everything"
            targets = order_targets(self.fleet.hosts())
            if wanted:
                targets = [h for h in targets if h.get("id") in wanted]
            if not targets:
                self._json({"error": "no updatable hosts matched"}, 400)
                return

            job_id, err = self.jobs.start(targets, self.fleet)
            if not job_id:
                self._json({"error": err}, 409)
                return
            self._json({"ok": True, "job": job_id,
                        "targets": [t["id"] for t in targets]})
            return

        if path == "/api/service/remove":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "bad json"}, 400)
                return

            host_id, unit = req.get("host"), (req.get("unit") or "").strip()
            host = next((h for h in self.fleet.hosts() if h.get("id") == host_id), None)
            if not host:
                self._json({"error": "unknown host"}, 404)
                return
            if not unit or not re.fullmatch(r"[A-Za-z0-9@:._-]+", unit):
                self._json({"error": "bad unit name"}, 400)
                return
            if host.get("agent") not in ("linux", "openwrt"):
                self._json({"error": "removal is only supported on linux/openwrt hosts"}, 400)
                return
            if Jobs.protected(unit):
                self._json({"error": f"{unit} is protected and cannot be removed"}, 403)
                return

            job_id, err = self.jobs.start_removal(host, unit, self.fleet)
            if not job_id:
                self._json({"error": err}, 409)
                return
            self._json({"ok": True, "job": job_id})
            return

        self._send(404, b"not found", "text/plain")


def main() -> None:
    cfg = load_config()
    fleet = Fleet(cfg)
    jobs = Jobs(cfg)
    Handler.fleet = fleet
    Handler.jobs = jobs

    threading.Thread(target=fleet.loop, daemon=True).start()

    listen = cfg.get("listen", "0.0.0.0")
    port = int(cfg.get("port", 8816))
    httpd = ThreadingHTTPServer((listen, port), Handler)
    print(f"health-zoo: config {cfg['_path']}, listening on {listen}:{port}, "
          f"{len(cfg.get('hosts', []))} hosts", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
