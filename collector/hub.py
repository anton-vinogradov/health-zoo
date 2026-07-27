#!/usr/bin/env python3
"""health-zoo hub: polls the fleet and serves the dashboard.

Runs stdlib-only (no venv on the target host is required beyond python3).
A background thread refreshes the snapshot on a timer; the HTTP layer only
ever hands out the last completed snapshot, so a slow host can never make the
page hang.
"""

from __future__ import annotations

import hmac
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
import alerts  # noqa: E402
import history  # noqa: E402
import issues  # noqa: E402
import probe  # noqa: E402
import suppressions as suppressions_mod  # noqa: E402

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
        self.alerts = alerts.Alerts(cfg)
        self.suppressions = suppressions_mod.Suppressions(
            cfg.get("suppressions_file", "/var/lib/health-zoo/suppressions.json"))
        self.history = history.History(
            cfg.get("history_db", "/var/lib/health-zoo/history.db"),
            cfg.get("history_retention_days", 180))
        # Serve the last known state immediately after a restart instead of an
        # empty page while the first poll runs.
        restored = self.history.last_snapshot()
        if restored:
            restored["restored"] = True
            self.snapshot = restored

    def hosts(self) -> list[dict]:
        return self.cfg.get("hosts", [])

    def poll_once(self) -> None:
        started = time.time()
        with self.lock:
            self.snapshot["polling"] = True
        try:
            hosts = probe.probe_all(self.hosts(), self.cfg.get("ssh_key"))
            probe.run_external_checks(self.cfg.get("external_checks", []),
                                      self.hosts(), self.cfg.get("ssh_key"), hosts)
            probe.poll_unifi_controller(self.cfg, hosts)
            probe.analyse_wifi(hosts)
            issues.annotate(hosts, self.cfg, self.suppressions)
            issues.annotate_checks(hosts, self.cfg)
            snap = {
                "suppressions": self.suppressions.listing(hosts),
                "unmanaged": probe.find_unmanaged(hosts, self.hosts()),
                "generated": int(time.time()),
                "duration_ms": int((time.time() - started) * 1000),
                "subnets": self.cfg.get("subnets", []),
                "check_categories": issues.CHECK_CATEGORIES,
                "hosts": hosts,
                "poll_interval": self.cfg.get("poll_interval", 180),
                "polling": False,
            }
            with self.lock:
                self.snapshot = snap
            try:
                self.history.record(hosts, snap)
            except Exception as exc:
                # History is a nicety and must never break polling — but it
                # should not fail silently either.
                print(f"health-zoo: history write failed: {exc}", flush=True)
            # Alerting compares whole snapshots, so it runs only on full polls;
            # a single-host refresh after an action would look like everything
            # else vanished.
            self.alerts.process(hosts)
        except Exception as exc:  # keep the loop alive whatever happens
            with self.lock:
                self.snapshot["polling"] = False
                self.snapshot["error"] = str(exc)

    def loop(self) -> None:
        while True:
            self.poll_once()
            self.wake.wait(timeout=self.cfg.get("poll_interval", 180))
            self.wake.clear()

    def refresh_hosts(self, host_ids: list[str]) -> int:
        """Re-poll just these hosts and splice them into the current snapshot.

        After removing a service or installing updates the card is stale
        immediately, and waiting out a full cycle (or even a full re-poll of
        twenty hosts) makes the UI feel like the action did not take.
        """
        wanted = [h for h in self.hosts() if h.get("id") in host_ids]
        if not wanted:
            return 0
        fresh = probe.probe_all(wanted, self.cfg.get("ssh_key"))
        issues.annotate(fresh, self.cfg, self.suppressions)
        issues.annotate_checks(fresh, self.cfg)
        by_id = {h["id"]: h for h in fresh}
        with self.lock:
            hosts = list(self.snapshot.get("hosts", []))
            for i, host in enumerate(hosts):
                if host.get("id") in by_id:
                    hosts[i] = by_id[host["id"]]
            # Camera links are cross-host, so recompute them over the merged set.
            probe.link_cameras(hosts)
            self.snapshot["hosts"] = hosts
            # Suppressions are derived from the hosts, so they have to be
            # recomputed here too: adding one and not seeing it take effect
            # until the next full cycle looks like the button did nothing.
            self.snapshot["suppressions"] = self.suppressions.listing(hosts)
            self.snapshot["generated"] = int(time.time())
        return len(fresh)

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
            # Refresh this host before moving on: its update count and
            # reboot-required flag have just changed.
            try:
                fleet.refresh_hosts([host["id"]])
            except Exception as exc:
                self._log(job_id, f"(переопрос не удался: {exc})")
            self._log(job_id, "")
        with self.lock:
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""
            self.jobs[job_id]["refreshed"] = True

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

    def start_reboot(self, host: dict, fleet: Fleet) -> tuple[str | None, str]:
        with self.lock:
            if self.active and self.jobs[self.active]["state"] == "running":
                return None, "another job is already running"
            job_id = self._new_id()
            self.jobs[job_id] = {
                "id": job_id, "kind": "reboot", "state": "running",
                "started": int(time.time()), "targets": [host["id"]],
                "current": host["id"], "log": [], "results": {},
            }
            self.active = job_id
        thread = threading.Thread(target=self._run_reboot, args=(job_id, host, fleet),
                                  daemon=True)
        thread.start()
        return job_id, ""

    def _reboot_command(self, host: dict, fleet: Fleet):
        """How to reboot this kind of device, and from where.

        Returns (command, error). The command is a remote shell string for
        `host`, or a tuple when the reboot must be issued elsewhere: from the
        hub (a Meshtastic node speaks protobuf, not shell) or from another host
        (a camera needs credentials only its recorder has).
        """
        agent = host.get("agent", "linux")

        if agent in ("linux", "openwrt"):
            # Detached: the ssh session dies with the machine, and without
            # backgrounding the command can be killed before it takes effect.
            cmd = "shutdown -r +0 health-zoo >/dev/null 2>&1 || reboot >/dev/null 2>&1 &"
            if host.get("user") != "root":
                cmd = "sudo -n " + cmd
            return cmd + " exit 0", ""

        if agent == "routeros":
            return "/system reboot", ""

        if agent == "synology":
            # DSM grants no passwordless sudo by default, and this tool
            # deliberately holds no DSM password.
            return ("sudo -n reboot 2>&1 || "
                    "{ echo 'DSM требует пароль для sudo — см. README'; exit 3; }"), ""

        if agent == "unifi":
            # Access points obey the controller; the hub asks it, not them.
            snapshot = {h.get("id"): h for h in fleet.get().get("hosts", [])}
            mac = (snapshot.get(host["id"], {}) or {}).get("unifi_mac", "")
            return ("unifi", mac, "restart"), ""

        if agent == "meshtastic":
            binary = self.cfg.get("meshtastic_python",
                                  "/opt/meshtastic-zoo/.venv/bin/python")
            if not os.path.exists(binary):
                return None, f"нет meshtastic CLI ({binary})"
            # --no-nodes matters: a full nodedb dump drowns the admin packet.
            return ("local", [binary, "-m", "meshtastic", "--host", host["addr"],
                              "--no-nodes", "--reboot"]), ""

        if host.get("role") == "camera":
            recorder_name = ""
            for entry in fleet.get().get("hosts", []):
                if entry.get("id") == host["id"]:
                    recorder_name = entry.get("recorded_by", "")
                    break
            recorder = next((h for h in fleet.hosts()
                             if recorder_name and h.get("name") == recorder_name), None)
            if not recorder or recorder.get("agent") != "linux":
                return None, ("камеру можно перезагрузить только через её рекордер "
                              "с ZoneMinder; для этой камеры он не определён")
            addr = host["addr"]
            # The credentials come out of the recorder's own ZoneMinder database
            # and are used on that machine; they never travel to the hub.
            remote = (
                "path=$(sudo -n mysql zm -N -B -e "
                "\"SELECT Path FROM Monitors WHERE Path LIKE '%" + addr + "%' LIMIT 1\"); "
                "if [ -z \"$path\" ]; then echo 'камера не найдена в ZoneMinder'; exit 4; fi; "
                "creds=$(printf '%s' \"$path\" | sed -e 's|^[a-z]*://||' -e 's|@.*||'); "
                "out=$(curl -s -m 15 --digest -u \"$creds\" -X PUT "
                "'http://" + addr + "/ISAPI/System/reboot' 2>/dev/null); "
                "case \"$out\" in *statusCode*1*) echo 'камера приняла команду';; "
                "*) echo 'камера отказала:'; printf '%.200s\\n' \"$out\"; exit 5;; esac"
            )
            return ("host", recorder, remote), ""

        return None, f"перезагрузка не поддержана для типа {agent}"

    def _run_reboot(self, job_id: str, host: dict, fleet: Fleet) -> None:
        # A planned reboot is not an outage: silence this host while it comes
        # back, or the dashboard pages about a problem we caused on purpose.
        grace = int(self.cfg.get("reboot_grace_seconds", 900))
        fleet.alerts.mute(host["id"], grace)

        self._log(job_id, f"=== перезагрузка {host['name']} ({host['addr']}) ===")
        self._log(job_id, f"алерты по этому хосту молчат {grace // 60} мин")

        command, error = self._reboot_command(host, fleet)
        if error or command is None:
            self._log(job_id, f"! {error}")
            code = 1
        elif isinstance(command, tuple) and command[0] == "unifi":
            self._log(job_id, "команда идёт через контроллер UniFi")
            ok, error = probe.unifi_command(self.cfg, command[1], command[2])
            if not ok:
                self._log(job_id, f"! {error}")
            code = 0 if ok else 1
        elif isinstance(command, tuple) and command[0] == "local":
            self._log(job_id, "команда идёт с хоста дашборда (нода не даёт shell)")
            code = self._exec(job_id, {"local": True, "id": host["id"]}, None,
                              " ".join(shlex.quote(c) for c in command[1]))
        elif isinstance(command, tuple) and command[0] == "host":
            via = command[1]
            self._log(job_id, f"через {via.get('name', via['id'])} — только у него есть доступ")
            code = self._exec(job_id, via, self.cfg.get("ssh_key"), command[2])
        else:
            code = self._exec(job_id, host, self.cfg.get("ssh_key"), command)

        if code == 0:
            self._log(job_id, "команда отправлена")
        with self.lock:
            self.jobs[job_id]["results"][host["id"]] = "ok" if code == 0 else f"failed ({code})"
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""

    def start_service_action(self, host: dict, unit: str, action: str,
                             fleet: Fleet) -> tuple[str | None, str]:
        """Restart or stop a unit. Restart is the common case — a crashed
        service usually needs starting again, not removing."""
        with self.lock:
            if self.active and self.jobs[self.active]["state"] == "running":
                return None, "another job is already running"
            job_id = self._new_id()
            self.jobs[job_id] = {
                "id": job_id, "kind": action, "state": "running",
                "started": int(time.time()), "targets": [host["id"]],
                "current": host["id"], "log": [], "results": {},
            }
            self.active = job_id
        thread = threading.Thread(target=self._run_service_action,
                                  args=(job_id, host, unit, action, fleet), daemon=True)
        thread.start()
        return job_id, ""

    def _run_service_action(self, job_id: str, host: dict, unit: str,
                            action: str, fleet: Fleet) -> None:
        quoted = shlex.quote(unit)
        verb = {"restart": "перезапуск", "stop": "остановка", "start": "запуск"}[action]
        self._log(job_id, f"=== {verb} {unit} на {host['name']} ===")

        if host.get("agent") == "openwrt":
            remote = f"/etc/init.d/{quoted} {action}"
        elif host.get("agent") == "synology":
            # DSM wraps services in packages; synopkg is the supported way in.
            remote = f"synopkg {action} {quoted} 2>&1 || sudo -n synopkg {action} {quoted}"
        else:
            remote = f"sudo -n systemctl {action} {quoted} && systemctl is-active {quoted}"
            if host.get("user") == "root":
                remote = remote.replace("sudo -n ", "")

        code = self._exec(job_id, host, self.cfg.get("ssh_key"), remote)
        try:
            fleet.refresh_hosts([host["id"]])
        except Exception as exc:
            self._log(job_id, f"(переопрос не удался: {exc})")
        with self.lock:
            self.jobs[job_id]["results"][host["id"]] = "ok" if code == 0 else f"failed ({code})"
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""

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
        # Re-poll this host right away so the card reflects what just happened.
        try:
            fleet.refresh_hosts([host["id"]])
        except Exception as exc:
            self._log(job_id, f"(переопрос не удался: {exc})")
        with self.lock:
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""
            self.jobs[job_id]["refreshed"] = True

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

    def _authorized(self) -> str:
        """Guard for anything that changes state. Returns "" when allowed.

        Two independent checks:

        * Origin/Referer must match our own Host. Browsers attach Origin to
          cross-site POSTs, including form submissions, so this blocks a page
          on another site from quietly firing `apt upgrade` or a service
          removal at a dashboard that sits on the user's LAN. Requests with no
          Origin at all (curl, scripts) are allowed — they are not the attack.
        * An optional shared token from the config, for when the dashboard is
          reachable by people who should only look at it.
        """
        host = (self.headers.get("Host") or "").strip()
        origin = self.headers.get("Origin") or ""
        if not origin:
            referer = self.headers.get("Referer") or ""
            if referer:
                origin = "//".join(referer.split("//")[:2]) if "//" in referer else referer
        if origin:
            netloc = origin.split("//", 1)[-1].split("/", 1)[0]
            if netloc != host:
                return f"cross-origin request refused (Origin {netloc} != Host {host})"

        token = self.fleet.cfg.get("action_token") or ""
        if token:
            given = self.headers.get("X-Health-Zoo-Token") or ""
            if not hmac.compare_digest(given, token):
                return "token required"
        return ""

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
            snap = dict(self.fleet.get())
            snap["needs_token"] = bool(self.fleet.cfg.get("action_token"))
            self._json(snap)
            return

        if path.startswith("/api/history/"):
            # /api/history/<host>/<metric>?days=7
            parts = path.split("/")
            if len(parts) < 5:
                self._json({"error": "usage: /api/history/<host>/<metric>"}, 400)
                return
            host_id, metric = parts[3], "/".join(parts[4:])
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            days = 7
            for chunk in query.split("&"):
                if chunk.startswith("days="):
                    try:
                        days = max(1, min(365, int(chunk[5:])))
                    except ValueError:
                        pass
            since = int(time.time()) - days * 86400
            self._json({
                "host": host_id, "metric": metric, "days": days,
                "series": self.fleet.history.series(host_id, metric, since),
                "trend": self.fleet.history.trend(host_id, metric, days),
            })
            return

        if path.startswith("/api/metrics/"):
            self._json({"metrics": self.fleet.history.metrics(path.split("/")[3])})
            return

        if path == "/api/suppressions":
            self._json({"suppressions":
                        self.fleet.suppressions.listing(self.fleet.get().get("hosts", []))})
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

        denied = self._authorized()
        if denied:
            self._json({"error": denied}, 403)
            return

        if path == "/api/refresh":
            length = int(self.headers.get("Content-Length") or 0)
            req = {}
            if length:
                try:
                    req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    req = {}
            wanted = req.get("hosts")
            if wanted:
                # Synchronous: the caller wants the fresh card, not a promise.
                count = self.fleet.refresh_hosts(wanted)
                self._json({"ok": True, "refreshed": count})
            else:
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

        if path == "/api/alerts/test":
            ok, message = self.fleet.alerts.test()
            self._json({"ok": ok, "message": message}, 200 if ok else 400)
            return

        if path in ("/api/suppress", "/api/suppress/remove"):
            length = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "bad json"}, 400)
                return

            if path.endswith("/remove"):
                suppression_id = req.get("id", "")
                removed = self.fleet.suppressions.remove(suppression_id)
                if removed:
                    # Re-poll that host straight away: waiting a full cycle to
                    # see the finding come back reads as the button failing.
                    self.fleet.refresh_hosts([suppression_id.split("/", 1)[0]])
                self._json({"ok": removed} if removed else {"error": "не найдено"},
                           200 if removed else 404)
                return

            host_id, key = req.get("host"), (req.get("key") or "").strip()
            if not any(h.get("id") == host_id for h in self.fleet.hosts()):
                self._json({"error": "unknown host"}, 404)
                return
            if not key:
                self._json({"error": "не указана проверка"}, 400)
                return
            days = req.get("days")
            ok, error = self.fleet.suppressions.add(
                host_id, key, req.get("reason", ""),
                int(days) if days else None, req.get("note", ""))
            if not ok:
                self._json({"error": error}, 400)
                return
            # Reflect it immediately: the point of suppressing is that the
            # dashboard stops shouting right now, not on the next cycle.
            self.fleet.refresh_hosts([host_id])
            self._json({"ok": True})
            return

        if path == "/api/reboot":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "bad json"}, 400)
                return
            host = next((h for h in self.fleet.hosts() if h.get("id") == req.get("host")), None)
            if not host:
                self._json({"error": "unknown host"}, 404)
                return
            job_id, err = self.jobs.start_reboot(host, self.fleet)
            if not job_id:
                self._json({"error": err}, 409)
                return
            self._json({"ok": True, "job": job_id})
            return

        if path == "/api/unifi/upgrade":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "bad json"}, 400)
                return
            snapshot = {h.get("id"): h for h in self.fleet.get().get("hosts", [])}
            host = snapshot.get(req.get("host"))
            if not host or host.get("agent") != "unifi":
                self._json({"error": "unknown access point"}, 404)
                return
            ok, error = probe.unifi_command(self.fleet.cfg, host.get("unifi_mac", ""), "upgrade")
            self._json({"ok": True} if ok else {"error": error}, 200 if ok else 400)
            return

        if path == "/api/service/action":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "bad json"}, 400)
                return
            host = next((h for h in self.fleet.hosts() if h.get("id") == req.get("host")), None)
            unit = (req.get("unit") or "").strip()
            action = req.get("action")
            if not host:
                self._json({"error": "unknown host"}, 404)
                return
            if action not in ("restart", "stop", "start"):
                self._json({"error": "action must be restart/stop/start"}, 400)
                return
            if not unit or not re.fullmatch(r"[A-Za-z0-9@:._-]+", unit):
                self._json({"error": "bad unit name"}, 400)
                return
            # Stopping sshd is as effective a way to lose a host as removing it.
            if action != "restart" and Jobs.protected(unit):
                self._json({"error": f"{unit} защищён от остановки"}, 403)
                return
            job_id, err = self.jobs.start_service_action(host, unit, action, self.fleet)
            if not job_id:
                self._json({"error": err}, 409)
                return
            self._json({"ok": True, "job": job_id})
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
