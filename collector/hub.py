#!/usr/bin/env python3
"""health-zoo hub: polls the fleet and serves the dashboard.

Runs stdlib-only (no venv on the target host is required beyond python3).
A background thread refreshes the snapshot on a timer; the HTTP layer only
ever hands out the last completed snapshot, so a slow host can never make the
page hang.
"""

from __future__ import annotations

import concurrent.futures
import hmac
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.request
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acks as acks_mod  # noqa: E402
import alerts  # noqa: E402
import history  # noqa: E402
import issues  # noqa: E402
import probe  # noqa: E402
import settings as settings_mod  # noqa: E402
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
    # The UI is split by responsibility; one file had grown past readability.
    "/ui/core.js": ("ui/core.js", "application/javascript; charset=utf-8"),
    "/ui/cards.js": ("ui/cards.js", "application/javascript; charset=utf-8"),
    "/ui/details.js": ("ui/details.js", "application/javascript; charset=utf-8"),
    "/ui/actions.js": ("ui/actions.js", "application/javascript; charset=utf-8"),
    "/ui/egress.js": ("ui/egress.js", "application/javascript; charset=utf-8"),
    "/ui/wiring.js": ("ui/wiring.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def read_version() -> dict:
    """The note deploy.sh leaves behind: which commit, when, and was it clean."""
    try:
        lines = (ROOT / "VERSION").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"commit": "unknown"}
    first = lines[0].strip() if lines else "unknown"
    return {"commit": first.split()[0],
            "dirty": "правки-вне-коммита" in first,
            "deployed": lines[1].strip() if len(lines) > 1 else ""}


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
        # Set once the Jobs registry exists; automatic reboots go through the
        # same machinery as the button, so there is one reboot path, not two.
        self.jobs_ref: "Jobs | None" = None
        self._drift: dict = {}
        self._drift_at = 0.0
        self.alerts = alerts.Alerts(cfg)
        self.acks = acks_mod.Acks(
            cfg.get("acks_file", "/var/lib/health-zoo/acks.json"))
        self.suppressions = suppressions_mod.Suppressions(
            cfg.get("suppressions_file", "/var/lib/health-zoo/suppressions.json"))
        self.settings = settings_mod.Settings(
            cfg.get("settings_file", "/var/lib/health-zoo/settings.json"))
        self.settings.apply_to(cfg)
        probe.configure(cfg)
        self.version = read_version()
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
            # Taken before the fleet is walked, not after: a targeted refresh
            # can land mid-cycle and splice a newer reading into the snapshot,
            # and comparing this cycle's older readings against that reads as
            # every refreshed host having gone backwards in time.
            previous = self.snapshot.get("hosts", [])
            previous_at = self.snapshot.get("generated")
        try:
            hosts = probe.probe_all(self.hosts(), self.cfg.get("ssh_key"))
            probe.run_external_checks(self.cfg.get("external_checks", []),
                                      self.hosts(), self.cfg.get("ssh_key"), hosts)
            probe.poll_unifi_controller(self.cfg, hosts)
            probe.poll_billing(self.cfg, hosts)
            probe.analyse_wifi(hosts)
            self.attach_channel_history(hosts)
            self.attach_link_history(hosts)
            self.attach_baselines(hosts)
            probe.check_forwards(hosts)
            # Exposure is measured, not derived: learn the address the site is
            # seen as, knock on every published port from outside, and only then
            # decide what "open to the internet" means on a card.
            probe.verify_forward_targets(hosts)
            probe.link_egress(hosts, self.cfg)
            probe.verify_exposure(hosts, self.cfg, self.cfg.get("ssh_key"))
            probe.link_exposure(hosts)
            probe.observe_outside(hosts, self.cfg, self.cfg.get("ssh_key"))
            for host in hosts:
                probe.endpoints_from_probed_ports(host)
            self.apply_camera_limits(hosts)
            probe.note_service_changes(previous, hosts, previous_at)
            self.note_reboots(hosts)
            issues.annotate(hosts, self.cfg, self.suppressions, self.acks)
            issues.annotate_checks(hosts, self.cfg)
            self.suppressions.note_firing(hosts)
            # An acknowledgement outliving its sentence would silence the next
            # occurrence too, so it is dropped the moment the wording moves.
            self.acks.forget_stale(hosts)
            snap = {
                "suppressions": self.suppressions.listing(hosts),
                "acks": self.acks.listing(hosts),
                "unmanaged": probe.find_unmanaged(hosts, self.hosts()),
                "generated": int(time.time()),
                "duration_ms": int((time.time() - started) * 1000),
                "subnets": self.cfg.get("subnets", []),
                "check_categories": issues.CHECK_CATEGORIES,
                "hosts": hosts,
                "poll_interval": self.cfg.get("poll_interval", 180),
                "polling": False,
                # What is running here and how far behind the repository it is.
                # This dashboard watches every service in the house except the
                # one it is; this is the smallest honest version of that.
                "version": dict(self.version, **self.drift()),
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
            self.maybe_auto_update(hosts)
            self.maybe_auto_reboot(hosts)
        except Exception as exc:  # keep the loop alive whatever happens
            with self.lock:
                self.snapshot["polling"] = False
                self.snapshot["error"] = str(exc)

    def loop(self) -> None:
        while True:
            self.poll_once()
            self.wake.wait(timeout=self.cfg.get("poll_interval", 180))
            self.wake.clear()

    def attach_channel_history(self, hosts: list[dict]) -> None:
        """Give each 2.4 GHz radio what it has measured on the other channels.

        Without this the only comparison available is what a radio hears about
        the far end of the band from where it sits, which is systematically
        too quiet — the receiver is filtered, not the air. Recorded history is
        the honest version: it was taken on that channel, from this antenna.
        """
        if not self.history.available:
            return
        for host in hosts:
            for radio in host.get("radios", []):
                name = radio.get("name") or radio.get("dev")
                if radio.get("band") != "2.4" or not name:
                    continue
                evidence = self.history.channel_evidence(str(host.get("id", "")), name)
                if evidence:
                    radio["channel_history"] = evidence

    # What each of these is called in history and what to call it out loud.
    # Temperature is deliberately absent: it has an absolute threshold that
    # means something physical, and "twice as hot as usual" is not a number
    # any board reaches before it stops working.
    NORMS = (("cpu_load_pct", "процессор занят"),
             ("load_pct", "очередь к процессору"))

    def drift(self) -> dict:
        """How far the deployed commit is behind the published branch.

        Asked of GitHub once an hour and forgiven entirely when it fails: a
        dashboard with no way out to the internet is still a dashboard, and this
        is a nicety rather than a health signal.
        """
        commit = self.version.get("commit") or ""
        now = time.time()
        if not commit or commit == "unknown":
            return {}
        if now - self._drift_at < 3600:
            return self._drift
        self._drift_at = now
        repo = self.cfg.get("repo", "")
        if not repo:
            return {}
        try:
            request = urllib.request.Request(
                f"https://api.github.com/repos/{repo}/compare/{commit}...main",
                headers={"Accept": "application/vnd.github+json",
                         "User-Agent": "health-zoo"})
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.load(response)
            self._drift = {"behind": int(body.get("behind_by") or 0),
                           "ahead": int(body.get("ahead_by") or 0)}
        except Exception:
            self._drift = {}
        return self._drift

    def note_reboots(self, hosts: list[dict]) -> None:
        """Separate the restarts somebody asked for from the rest, and count.

        The dashboard reboots hosts itself — on request and, inside its window,
        on its own — so counting every restart would report its own work as a
        fault. What matters is the box that keeps coming back without anybody
        asking, which is a power supply, an overheating board or a watchdog.
        """
        for host in hosts:
            host_id = str(host.get("id", ""))
            if host.get("rebooted"):
                asked = self.settings.last_reboot(host_id)
                # Provisioning, boot and the first successful poll take a few
                # minutes; a restart inside that window is the one we ordered.
                host["reboot_planned"] = bool(asked and time.time() - asked < 1800)
            if self.history.available:
                unplanned = self.history.total(host_id, "reboot_unplanned", days=7)
                if unplanned:
                    host["reboots_week"] = unplanned

    def attach_baselines(self, hosts: list[dict]) -> None:
        """Give each host its own habits to be judged against.

        A fixed threshold has to suit a router and a transcoding NAS at once, so
        it ends up suiting neither: 45% airtime is ordinary in the kitchen and
        remarkable in the hall, and 60% busy is a quiet evening for the box that
        records four cameras. What is worth saying is rarely "above 80" and
        usually "twice what this machine normally does".
        """
        if not self.history.available:
            return
        for host in hosts:
            host_id = str(host.get("id", ""))
            found = {}
            for metric, label in self.NORMS:
                norm = self.history.norm(host_id, metric)
                if norm:
                    found[label] = norm
            for radio in host.get("radios", []):
                name = radio.get("name") or radio.get("dev")
                if not name or radio.get("virtual"):
                    continue
                norm = self.history.norm(host_id, f"radio:{name}:airtime")
                if norm:
                    found[f"эфир {radio.get('band', '')} ГГц"] = norm
            if found:
                host["baselines"] = found

    def attach_link_history(self, hosts: list[dict]) -> None:
        """Tell each port the best speed it has ever negotiated.

        Whether 100 Mbit is a fault or simply what that socket is depends
        entirely on what it used to do, and only the record knows.
        """
        if not self.history.available:
            return
        for host in hosts:
            for link in host.get("links", []):
                name = link.get("name")
                if not name:
                    continue
                host_id = str(host.get("id", ""))
                best = self.history.peak(host_id, f"link:{name}:speed")
                if best:
                    link["speed_best"] = int(best)
                seen = self.history.last(host_id, f"link:{name}:flaps")
                if seen is not None:
                    link["flaps_prev"] = int(seen)

    def apply_camera_limits(self, hosts: list[dict]) -> None:
        """Attach each camera its own silence thresholds, where one was set."""
        for host in hosts:
            for cam in host.get("cameras", []):
                limits = self.settings.camera_limits(
                    str(host.get("id", "")), str(cam.get("id", "")))
                if limits:
                    cam["limits"] = limits

    def maybe_auto_update(self, hosts: list[dict]) -> None:
        """Install security updates as soon as they appear.

        Every other automatic action here waits for a window, because rebooting
        or cleaning at the wrong moment costs something. A published fix that is
        not installed costs from the moment it is published, and the machine
        that needs it most is the one nobody has looked at this week.

        Deliberately narrow, like the reboot path: only hosts the config allows
        updating, only when the packages waiting are security ones, one host at
        a time through the same job machinery as the button, and never the same
        host twice inside the interval — an update that fails would otherwise be
        retried every three minutes for ever.
        """
        conf = self.settings.auto_security()
        if not conf.get("enabled"):
            return
        excluded = set(conf.get("exclude") or [])
        gap = int(conf.get("min_interval_hours", 6)) * 3600
        now = int(time.time())
        for host in hosts:
            host_id = host.get("id")
            if not host.get("security_count") or host_id in excluded:
                continue
            source = next((h for h in self.hosts() if h.get("id") == host_id), None)
            if not source or not source.get("updatable"):
                continue
            if now - self.settings.last_update(str(host_id)) < gap:
                continue
            if not self.jobs_ref:
                return
            job_id, _ = self.jobs_ref.start([source], self)
            if not job_id:
                # Another job holds the slot; the next poll will try again
                # rather than queueing updates behind one another.
                return
            self.settings.note_update(str(host_id), now)
            self.alerts.notify(
                f"ставлю обновления на {host.get('name', host_id)}: "
                f"{host['security_count']} из {host.get('update_count', 0)} "
                "пакетов закрывают уязвимости")
            return

    def maybe_auto_reboot(self, hosts: list[dict]) -> None:
        """Reboot hosts that asked for it, if the operator turned this on.

        Deliberately narrow. Only hosts that themselves report a pending
        reboot, only inside the configured hours, one per poll, never the same
        host twice in a day, and never the host running the dashboard — it
        would kill the job reporting its own progress. Everything else waits
        for the next window, which is the whole point of having one.
        """
        conf = self.settings.auto_reboot()
        if not conf.get("enabled"):
            return
        hour = time.localtime().tm_hour
        start, end = int(conf.get("from_hour", 4)), int(conf.get("to_hour", 6))
        # A window may wrap past midnight (23 -> 5).
        inside = start <= hour < end if start <= end else (hour >= start or hour < end)
        if not inside:
            return
        excluded = set(conf.get("exclude") or [])
        min_gap = int(conf.get("min_interval_hours", 20)) * 3600
        now = int(time.time())
        for host in hosts:
            host_id = host.get("id")
            if not host.get("reboot_required") or host_id in excluded:
                continue
            source = next((h for h in self.hosts() if h.get("id") == host_id), None)
            if not source or source.get("local") or source.get("update_last"):
                continue
            if now - self.settings.last_reboot(host_id) < min_gap:
                continue
            if not self.jobs_ref:
                return
            job_id, err = self.jobs_ref.start_reboot(source, self)
            if not job_id:
                # Another job holds the slot; try again next poll rather than
                # queueing reboots up behind an update run.
                return
            self.settings.note_reboot(host_id, now)
            self.alerts.notify(
                f"перезагружаю {host.get('name', host_id)} — "
                f"{(host.get('reboot_pkgs') or '').strip() or 'система просит перезагрузку'}")
            return

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
        # An access point is described by the controller, not by an agent: since
        # UniFi Network 10 the device itself refuses ssh, so probing it alone
        # yields "нет доступа" and a card stripped of its radios. Refreshing one
        # host has to ask the same source a full cycle would.
        if any(h.get("agent") == "unifi" for h in wanted):
            probe.poll_unifi_controller(self.cfg, fresh)
            # Interference is judged against the other radios on the site, so
            # the comparison needs the hosts that were not refreshed as well.
            with self.lock:
                fresh_ids = {h.get("id") for h in fresh}
                others = [h for h in self.snapshot.get("hosts", [])
                          if h.get("id") not in fresh_ids]
            probe.analyse_wifi(fresh + others)
        self.apply_camera_limits(fresh)
        # Derived facts have to be derived again, or a targeted refresh hands
        # back a host with half its findings missing — and anything keyed on a
        # finding that vanished (an acknowledgement, for one) evaporates with
        # it. This is the same failure the access points had.
        self.note_reboots(fresh)
        self.attach_baselines(fresh)
        self.attach_link_history(fresh)
        issues.annotate(fresh, self.cfg, self.suppressions, self.acks)
        issues.annotate_checks(fresh, self.cfg)
        by_id = {h["id"]: h for h in fresh}
        with self.lock:
            hosts = list(self.snapshot.get("hosts", []))
            for i, host in enumerate(hosts):
                if host.get("id") in by_id:
                    hosts[i] = by_id[host["id"]]
            # Camera links and port forwards are cross-host, so recompute them
            # over the merged set.
            probe.link_cameras(hosts)
            probe.check_forwards(hosts)
            probe.link_exposure(hosts)
            self.snapshot["hosts"] = hosts
            # Suppressions are derived from the hosts, so they have to be
            # recomputed here too: adding one and not seeing it take effect
            # until the next full cycle looks like the button did nothing.
            self.snapshot["suppressions"] = self.suppressions.listing(hosts)
            self.snapshot["generated"] = int(time.time())
        return len(fresh)

    def reannotate(self, host_ids: list[str]) -> None:
        """Re-run the rules over the snapshot as it stands, without re-probing.

        Acknowledging a finding changes what the rules say about a host, not
        what the host is doing. Re-polling the box over ssh to answer one click
        costs seconds, collects nothing new, and makes a button that should feel
        instant feel broken. What does have to be redone is the annotation —
        skip it and the finding stays on the card until the next full cycle.
        """
        with self.lock:
            hosts = list(self.snapshot.get("hosts", []))
            wanted = [h for h in hosts if h.get("id") in host_ids]
            if not wanted:
                return
            issues.annotate(wanted, self.cfg, self.suppressions, self.acks)
            issues.annotate_checks(wanted, self.cfg)
            # Only the derived listings: "generated" says when the readings were
            # taken, and nothing was read here.
            self.snapshot["acks"] = self.acks.listing(hosts)
            self.snapshot["suppressions"] = self.suppressions.listing(hosts)

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
                "kind": "update",
                "state": "running",
                "started": int(time.time()),
                "targets": [t["id"] for t in targets],
                "current": "",
                # Per-host logs: updates run in parallel, so a single stream
                # would interleave four apt runs into something unreadable.
                "hosts": {t["id"]: {"name": t.get("name", t["id"]),
                                    "state": "pending", "log": [],
                                    "started": 0, "finished": 0}
                          for t in targets},
                "log": [],
                "results": {},
            }
            self.active = job_id
        thread = threading.Thread(target=self._run, args=(job_id, targets, fleet), daemon=True)
        thread.start()
        return job_id, ""

    def _log(self, job_id: str, line: str, host_id: str = "") -> None:
        with self.lock:
            job = self.jobs[job_id]
            stream = job["hosts"][host_id]["log"] if host_id in job.get("hosts", {}) \
                else job["log"]
            stream.append(line)
            # A full dist-upgrade log is long; keep the tail bounded.
            if len(stream) > 4000:
                del stream[:1000]

    def _run(self, job_id: str, targets: list[dict], fleet: Fleet) -> None:
        """Update everything at once, except the box we are running on.

        Hosts are independent, so waiting for one apt run before starting the
        next only makes the operator wait. The dashboard's own host is the
        exception and goes last: it restarts its own service mid-run, and
        doing that while other hosts are still reporting would lose their logs.
        """
        key = self.cfg.get("ssh_key")
        cleanup = bool(fleet.settings.auto_cleanup().get("enabled"))
        parallel = [t for t in targets if not t.get("update_last")]
        afterwards = [t for t in targets if t.get("update_last")]

        def run_one(host: dict) -> None:
            with self.lock:
                entry = self.jobs[job_id]["hosts"][host["id"]]
                entry["state"] = "running"
                entry["started"] = int(time.time())
            self._log(job_id, f"=== {host['name']} ({host['addr']}) ===", host["id"])
            code = self._update_host(job_id, host, key, cleanup)
            try:
                fleet.refresh_hosts([host["id"]])
            except Exception as exc:
                self._log(job_id, f"(переопрос не удался: {exc})", host["id"])
            with self.lock:
                entry = self.jobs[job_id]["hosts"][host["id"]]
                entry["state"] = "ok" if code == 0 else "failed"
                entry["finished"] = int(time.time())
                # A run that finished with packages still pending is not the
                # same as a clean one: reporting both as "ok" is how the fleet
                # ended up showing the same update counts after "обновить всё".
                if code == 0:
                    for i, line in enumerate(entry["log"]):
                        if line.startswith("ОСТАЛОСЬ"):
                            entry["state"] = "partial"
                            rest = entry["log"][i + 1] if i + 1 < len(entry["log"]) else ""
                            entry["reason"] = "осталось вручную: " + rest.strip()
                            break
                if code != 0:
                    # Surface why it failed without making the operator read a
                    # thousand lines of apt output. A failed mirror and a
                    # broken package need very different responses.
                    errors = [line for line in entry["log"]
                              if line.startswith("E:") or "Sub-process" in line]
                    entry["reason"] = errors[-1] if errors else f"код возврата {code}"
                self.jobs[job_id]["results"][host["id"]] = (
                    "ok" if code == 0 else f"failed ({code})")

        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(8, len(parallel))) as pool:
                list(pool.map(run_one, parallel))
        for host in afterwards:
            with self.lock:
                self.jobs[job_id]["current"] = host["id"]
            run_one(host)

        with self.lock:
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""
            self.jobs[job_id]["refreshed"] = True

    def _update_host(self, job_id: str, host: dict, key: str | None,
                     cleanup: bool = False) -> int:
        # DEBIAN_FRONTEND + confold: never block on a config-file prompt.
        #
        # --with-new-pkgs is what makes "обновить всё" mean it. Plain `upgrade`
        # silently keeps back everything that needs a new dependency — which is
        # every kernel, plus fwupd, netplan and rpi-eeprom — so a run would
        # report success while the card kept showing the same six updates. The
        # flag allows installing new packages but still never removes any;
        # anything that would need a removal stays held back and is listed
        # below rather than being quietly forced through.
        remote = (
            "export DEBIAN_FRONTEND=noninteractive; "
            "sudo -n apt-get update -qq && "
            "sudo -n apt-get -y --with-new-pkgs -o Dpkg::Options::=--force-confdef "
            "-o Dpkg::Options::=--force-confold upgrade; "
            "rc=$?; "
            # Cleanup rides along with the upgrade rather than running on its
            # own, and the second pass is the point of the ordering: a package
            # is often held back only because it conflicts with something
            # nothing needs any more. On watchcats the security update for
            # libgl1-amber-dri was stuck behind libglapi-mesa — which was
            # itself in the autoremove list. Clean first, then ask again.
            + ("echo '--- чистка ненужных пакетов ---'; "
               "sudo -n apt-get -y autoremove; "
               "echo '--- повторная попытка после чистки ---'; "
               "sudo -n apt-get -y --with-new-pkgs "
               "-o Dpkg::Options::=--force-confdef "
               "-o Dpkg::Options::=--force-confold upgrade; "
               "[ $rc -eq 0 ] && rc=$?; " if cleanup else "")
            + "left=$(apt list --upgradable 2>/dev/null | tail -n +2 | cut -d/ -f1); "
            # Third pass, by name and without recommendations. A package is
            # also held back when its new version recommends something that is
            # in no repository at all — rpi-eeprom 28.27 asks for rpieepromab,
            # which Raspberry Pi has not published. That is not a conflict and
            # not a reason to leave a machine unpatched, so ask for those
            # packages directly; anything needing a removal still refuses and
            # still gets reported below.
            "[ -n \"$left\" ] && { "
            "  echo '--- третья попытка: без необязательных рекомендаций ---'; "
            "  sudo -n apt-get -y --no-install-recommends "
            "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
            "install $left; "
            "  left=$(apt list --upgradable 2>/dev/null | tail -n +2 | cut -d/ -f1); }; "
            "[ -n \"$left\" ] && { "
            "  echo 'ОСТАЛОСЬ (нужно удаление пакетов, вручную):'; "
            "  echo \"$left\" | tr '\\n' ' '; echo; }; "
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
            self._log(job_id, f"! cannot start: {exc}", host.get("id", ""))
            return 255

        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                self._log(job_id, line, host.get("id", ""))
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
            # No controller-side confirmation here: _await_return below follows
            # the access point down and back by ping, which is firmer proof
            # than the controller's heartbeat bookkeeping and runs anyway.
            ok, error = probe.unifi_command(self.cfg, command[1], command[2],
                                            confirm_seconds=0)
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
            # Then the log went silent for as long as the machine took to come
            # back, which is exactly the stretch the operator is watching. Wait
            # for it here: first for it to actually go down (proof the command
            # took), then for it to answer again.
            code = self._await_return(job_id, host, fleet)
        with self.lock:
            self.jobs[job_id]["results"][host["id"]] = "ok" if code == 0 else f"failed ({code})"
            self.jobs[job_id]["state"] = "done"
            self.jobs[job_id]["finished"] = int(time.time())
            self.jobs[job_id]["current"] = ""

    def _await_return(self, job_id: str, host: dict, fleet: Fleet) -> int:
        """Follow the machine down and back up, reporting as it goes."""
        addr = host.get("addr")
        if not addr or host.get("local"):
            # The dashboard's own host cannot narrate its own reboot.
            return 0
        started = time.time()
        down_by = 0.0
        limit = int(self.cfg.get("reboot_wait_seconds", 600))
        step = float(self.cfg.get("reboot_poll_seconds", 5))

        while time.time() - started < limit:
            time.sleep(step)
            alive = probe.ping(addr) is not None
            waited = int(time.time() - started)
            if not down_by:
                if not alive:
                    down_by = time.time()
                    self._log(job_id, f"хост ушёл в перезагрузку через {waited} с")
                elif waited and waited % 30 < step:
                    self._log(job_id, f"ещё отвечает ({waited} с) — команда могла не пройти")
                continue
            if alive:
                back = int(time.time() - down_by)
                self._log(job_id, f"хост снова отвечает, недоступен был {back} с")
                try:
                    fleet.refresh_hosts([host["id"]])
                    self._log(job_id, "данные хоста переопрошены")
                except Exception as exc:
                    self._log(job_id, f"(переопрос не удался: {exc})")
                return 0
            if waited % 30 < step:
                self._log(job_id, f"жду возвращения… {waited} с")

        # Not a failure of the command — a failure to confirm it, which is a
        # different thing and has to read differently.
        self._log(job_id, f"! хост не ответил за {limit // 60} мин — проверьте вручную")
        return 2

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
    # Keep the connection open between requests. Every response here carries a
    # Content-Length, which is what HTTP/1.1 needs to know where one ends. The
    # dashboard is a page that talks to its server constantly, and on a link
    # where opening a socket costs seconds — this one does, from the laptop —
    # a fresh connection per request is the whole latency.
    protocol_version = "HTTP/1.1"
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

    def _request(self):
        """The POST body as JSON, or None when it is not valid JSON."""
        try:
            return json.loads(self._body.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

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

        if path == "/api/settings":
            # Defaults travel with the values so the form can show what a field
            # would fall back to, and mark the ones actually overridden.
            defaults = dict(issues.DEFAULT_THRESHOLDS)
            defaults.update(self.fleet.cfg.get("thresholds") or {})
            stored = self.fleet.settings.thresholds()
            self._json({
                "fields": settings_mod.FIELDS,
                "values": {f["key"]: stored.get(f["key"], defaults.get(f["key"]))
                           for f in settings_mod.FIELDS},
                "defaults": {f["key"]: issues.DEFAULT_THRESHOLDS.get(f["key"])
                             for f in settings_mod.FIELDS},
                "overridden": sorted(stored.keys()),
                "by_role": issues.ROLE_THRESHOLDS,
                "auto_reboot": self.fleet.settings.auto_reboot(),
                "auto_cleanup": self.fleet.settings.auto_cleanup(),
            "auto_security": self.fleet.settings.auto_security(),
                "hosts": [{"id": h.get("id"), "name": h.get("name")}
                          for h in self.fleet.hosts()],
                # Cameras come from the snapshot rather than the config: they
                # are discovered from the recorders, not declared by hand.
                "cameras": [
                    {"key": f"{host.get('id')}/{cam.get('id')}",
                     "host": host.get("name"),
                     "name": cam.get("name"),
                     "quiet_hours": cam.get("quiet_hours"),
                     "limits": self.fleet.settings.camera_limits(
                         str(host.get("id", "")), str(cam.get("id", "")))}
                    for host in self.fleet.get().get("hosts", [])
                    for cam in (host.get("cameras") or [])
                    if cam.get("enabled") == "1"
                ],
            })
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
        # Read before anything can answer. A response sent while the request
        # body is still in the socket leaves a kept-alive connection out of
        # step, and the next request on it reads the leftovers — which is what
        # every early "return" below would do: a refused origin, an unknown
        # path, a missing token.
        length = int(self.headers.get("Content-Length") or 0)
        self._body = self.rfile.read(length) if length > 0 else b""

        denied = self._authorized()
        if denied:
            self._json({"error": denied}, 403)
            return

        if path == "/api/settings":
            req = self._request()
            if req is None:
                self._json({"error": "bad json"}, 400)
                return
            if isinstance(req.get("thresholds"), dict):
                # What "default" means here is the built-in value plus whatever
                # the config file pins — the layers the UI never edits.
                defaults = dict(issues.DEFAULT_THRESHOLDS)
                defaults.update(getattr(self.fleet.settings, "_base", {}))
                self.fleet.settings.set_thresholds(req["thresholds"], defaults)
            if isinstance(req.get("auto_reboot"), dict):
                self.fleet.settings.set_auto_reboot(req["auto_reboot"])
            if isinstance(req.get("cameras"), dict):
                self.fleet.settings.set_cameras(req["cameras"])
            if isinstance(req.get("auto_cleanup"), dict):
                self.fleet.settings.set_auto_cleanup(req["auto_cleanup"])
            if isinstance(req.get("auto_security"), dict):
                self.fleet.settings.set_auto_security(req["auto_security"])
            # Applied to the live config and the current snapshot at once: a
            # threshold changed in the browser has to recolour the fleet now,
            # not at the next poll — otherwise it reads as having been ignored.
            self.fleet.settings.apply_to(self.fleet.cfg)
            hosts = self.fleet.get().get("hosts", [])
            self.fleet.apply_camera_limits(hosts)
            issues.annotate(hosts, self.fleet.cfg, self.fleet.suppressions)
            issues.annotate_checks(hosts, self.fleet.cfg)
            self._json({"ok": True,
                        "thresholds": self.fleet.settings.thresholds(),
                        "auto_reboot": self.fleet.settings.auto_reboot(),
                        "auto_cleanup": self.fleet.settings.auto_cleanup(),
                        "auto_security": self.fleet.settings.auto_security()})
            return

        if path == "/api/refresh":
            req = self._request() or {}
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
            req = self._request()
            if req is None:
                self._json({"error": "bad json"}, 400)
                return

            wanted = req.get("hosts")  # None or [] means "everything"
            targets = order_targets(self.fleet.hosts())
            if wanted:
                targets = [h for h in targets if h.get("id") in wanted]
            else:
                # "updatable" is config-level permission, not a pending count:
                # without this the "everything" button would run apt on the
                # whole fleet while the badge promised only the hosts that
                # actually have packages waiting.
                pending = {h.get("id") for h in self.fleet.get().get("hosts", [])
                           if h.get("update_count")}
                targets = [h for h in targets if h.get("id") in pending]
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

        if path in ("/api/ack", "/api/ack/remove"):
            # Reading a finding is not the same as accepting it: no reason, no
            # expiry, no entry in a list to review. It holds only while the
            # finding says what it said, and the finding decides when that ends.
            req = self._request()
            if req is None:
                self._json({"error": "bad json"}, 400)
                return

            if path.endswith("/remove"):
                removed = self.fleet.acks.remove(req.get("id", ""))
                if removed:
                    self.fleet.reannotate([req.get("id", "").split("/", 1)[0]])
                self._json({"ok": removed} if removed else {"error": "не найдено"},
                           200 if removed else 404)
                return

            host_id, key = req.get("host"), (req.get("key") or "").strip()
            host = next((h for h in self.fleet.get().get("hosts", [])
                         if h.get("id") == host_id), None)
            if not host or not key:
                self._json({"error": "не найден хост или проверка"}, 404)
                return
            # The wording is the fingerprint: "3 раза за неделю" acknowledged
            # stays quiet, "4 раза" is a different sentence and speaks again.
            finding = next((i for i in host.get("issues", [])
                             if i["key"] == key), None)
            if not finding:
                self._json({"error": "это замечание сейчас не горит"}, 404)
                return
            # Only findings about something that happened. A state that is
            # still true has no "next time" to come back at, and dismissing it
            # would hide it for good without anybody writing down why.
            if not finding.get("episodic"):
                self._json({"error": "это не разовое замечание — состояние "
                                     "никуда не денется само, ему нужно "
                                     "исключение с причиной"}, 400)
                return
            said = finding["text"]
            self.fleet.acks.add(host_id, key, said)
            self.fleet.reannotate([host_id])
            self._json({"ok": True})
            return

        if path in ("/api/suppress", "/api/suppress/remove"):
            req = self._request()
            if req is None:
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
            req = self._request()
            if req is None:
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
            req = self._request()
            if req is None:
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
            req = self._request()
            if req is None:
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
            req = self._request()
            if req is None:
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
    fleet.jobs_ref = jobs

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
