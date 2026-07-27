"""Telegram alerting for health-zoo.

The dashboard is only useful while someone is looking at it. This closes that
gap: when a problem appears — or clears — a message goes out.

Delivery reuses telegram.sh rather than talking to the Bot API directly, so
the proxy settings, retry policy and offline queue that already exist on the
host apply here too.

Alerting is edge-triggered on the issue keys from issues.py: a disk that has
been full for a week must not send a message every poll cycle.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time

import secrets

LEVEL_ICON = {"bad": "🔴", "warn": "🟡", "ok": "🟢"}


class Alerts:
    """Diffs consecutive snapshots and reports the changes."""

    def __init__(self, cfg: dict):
        self.cfg = cfg.get("telegram") or {}
        self.enabled = bool(self.cfg.get("enabled") and self.cfg.get("chats"))
        self.binary = self.cfg.get("telegram_bin", "/opt/telegram.sh-repo/telegram")
        self.spool = self.cfg.get("spool", "")
        # Only alert on real breakage by default; warnings are for the screen.
        self.min_level = self.cfg.get("min_level", "bad")
        self.startup_summary = bool(self.cfg.get("startup_summary", True))
        # Where to look when a message arrives; without it an alert tells you
        # something broke but not where to go.
        self.dashboard_url = (self.cfg.get("dashboard_url") or "").rstrip("/")
        # A problem must persist this many consecutive polls before it is
        # announced, and be gone as long before "cleared" is sent. Without it
        # a host that answers every other poll pages you all day.
        self.flap_cycles = int(self.cfg.get("flap_cycles", 2))
        # A standing problem nobody has fixed (security updates, a pending
        # reboot) is worth one reminder a day, not one every poll.
        self.digest_hour = self.cfg.get("digest_hour", 10)
        self.startup_cooldown = int(self.cfg.get("startup_cooldown_hours", 6)) * 3600
        self.state_path = self.cfg.get(
            "state_file", "/var/lib/health-zoo/alerts-state.json")

        self.lock = threading.Lock()
        self.active: dict[str, dict] = {}
        self.pending: dict[str, int] = {}   # candidate problems and their streak
        self.clearing: dict[str, int] = {}  # problems that look resolved
        self.muted: dict[str, float] = {}   # host -> ignore alerts until
        self.seeded = False
        self.last_startup = 0
        self.last_digest = 0
        self._load_state()

    # ---------- persistence ----------
    # Kept on disk so a restart neither forgets what has already been reported
    # nor re-announces it; during development that alone was the loudest
    # source of messages.

    def _load_state(self) -> None:
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            saved = {}
        self.active = saved.get("active", {})
        # Debounce counters persist too. Without this a restart resets them,
        # and a hub restarted more often than the debounce window would never
        # finish counting — so a real problem was never announced.
        self.pending = saved.get("pending", {})
        self.clearing = saved.get("clearing", {})
        self.last_startup = saved.get("last_startup", 0)
        self.last_digest = saved.get("last_digest", 0)
        self.seeded = bool(self.active) or bool(self.last_startup)

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, "w", encoding="utf-8") as fh:
                json.dump({"active": self.active,
                           "pending": self.pending,
                           "clearing": self.clearing,
                           "last_startup": self.last_startup,
                           "last_digest": self.last_digest}, fh, ensure_ascii=False)
        except OSError:
            pass

    # ---------- state diffing ----------

    @staticmethod
    def _host_url(host: dict) -> str:
        """The most useful address for this host: its own web UI if it has one."""
        for link in host.get("web", []):
            if link.get("stub"):
                continue
            port = link.get("port")
            std = ((link.get("scheme") == "http" and port == 80)
                   or (link.get("scheme") == "https" and port == 443))
            return f"{link['scheme']}://{host['addr']}" + ("" if std else f":{port}")
        return ""

    def mute(self, host_id: str, seconds: int) -> None:
        """Ignore a host for a while — used around a deliberate reboot, which
        would otherwise be reported as the host going down."""
        with self.lock:
            self.muted[host_id] = time.time() + seconds

    def _current(self, hosts: list[dict]) -> dict[str, dict]:
        wanted = ("bad",) if self.min_level == "bad" else ("bad", "warn")
        now = time.time()
        with self.lock:
            muted = {h for h, until in self.muted.items() if until > now}
            self.muted = {h: u for h, u in self.muted.items() if u > now}
        out: dict[str, dict] = {}
        for host in hosts:
            if host["id"] in muted:
                continue
            for issue in host.get("issues", []):
                if issue["level"] not in wanted:
                    continue
                out[f"{host['id']}/{issue['key']}"] = {
                    "host": host.get("name", host["id"]),
                    "addr": host.get("addr", ""),
                    "url": self._host_url(host),
                    "level": issue["level"],
                    "text": issue["text"],
                    "since": int(time.time()),
                }
        return out

    def process(self, hosts: list[dict]) -> None:
        if not self.enabled:
            return
        current = self._current(hosts)
        now = int(time.time())

        with self.lock:
            previous = dict(self.active)

            # Debounce in both directions: count how many polls in a row a
            # problem has been present (or absent) before acting on it.
            appeared, cleared = [], []
            for key, value in current.items():
                if key in previous:
                    self.clearing.pop(key, None)
                    continue
                self.pending[key] = self.pending.get(key, 0) + 1
                if self.pending[key] >= self.flap_cycles:
                    appeared.append(value)
                    self.active[key] = value
                    self.pending.pop(key, None)
            for key in list(self.pending):
                if key not in current:
                    self.pending.pop(key, None)

            for key, value in previous.items():
                if key in current:
                    continue
                self.clearing[key] = self.clearing.get(key, 0) + 1
                if self.clearing[key] >= self.flap_cycles:
                    cleared.append(value)
                    self.active.pop(key, None)
                    self.clearing.pop(key, None)

            first_run = not self.seeded
            self.seeded = True
            startup_due = first_run and (now - self.last_startup) > self.startup_cooldown
            if startup_due:
                self.last_startup = now
            digest_due = self._digest_due(now)
            if digest_due:
                self.last_digest = now
            self._save_state()

        # A restart is not an incident: the standing state is reported at most
        # once every few hours. But the diff still runs — a problem that
        # appeared while the hub was down must not be swallowed by the restart.
        if first_run and self.startup_summary and startup_due:
            self._send(self._startup_text(hosts, current))

        if appeared:
            self._send(self._change_text("Появилось", appeared, "🔴"))
        if cleared:
            self._send(self._change_text("Ушло", cleared, "🟢"))
        if digest_due:
            text = self._digest_text(hosts)
            if text:
                self._send(text)

    def _digest_due(self, now: int) -> bool:
        """Once a day, at the configured hour, and never twice."""
        if self.digest_hour is None or self.digest_hour < 0:
            return False
        if now - self.last_digest < 20 * 3600:
            return False
        return time.localtime(now).tm_hour == int(self.digest_hour)

    def _digest_text(self, hosts: list[dict]) -> str:
        """Everything still outstanding — the nag for things nobody fixed."""
        bad, warn = [], []
        for host in hosts:
            for issue in host.get("issues", []):
                name = host.get("name", host["id"])
                (bad if issue["level"] == "bad" else warn).append((name, issue["text"]))
        if not bad and not warn:
            return ""
        lines = ["🩺 health-zoo — сводка за сутки"]
        if bad:
            lines.append("")
            lines.append(f"🔴 требует внимания ({len(bad)}):")
            lines += [f"• {n}: {t}" for n, t in bad[:15]]
        if warn:
            lines.append("")
            lines.append(f"🟡 замечания ({len(warn)}):")
            lines += [f"• {n}: {t}" for n, t in warn[:15]]
        return "\n".join(lines + self._footer())

    # ---------- message shaping ----------

    def _startup_text(self, hosts: list[dict], current: dict) -> str:
        down = [h["name"] for h in hosts if not h.get("reachable")]
        lines = [f"🩺 health-zoo запущен: {len(hosts)} устройств"]
        if down:
            lines.append(f"не отвечают: {', '.join(down)}")

        if current:
            lines.append("")
            lines.append(f"Отслеживаемые проблемы ({len(current)}):")
            for value in list(current.values())[:15]:
                lines.append(f"{LEVEL_ICON.get(value['level'], '•')} {value['host']}: {value['text']}")
        else:
            lines.append("🟢 проблем нет" if self.min_level != "bad"
                         else "🟢 критических проблем нет")

        # Warnings are not alerted on by default, but staying silent about them
        # here reads as "everything is fine" when it is not.
        if self.min_level == "bad":
            warns = [(h.get("name", h["id"]), i["text"])
                     for h in hosts for i in h.get("issues", []) if i["level"] == "warn"]
            if warns:
                lines.append("")
                lines.append(f"🟡 замечания ({len(warns)}), алертов по ним не будет:")
                for name, text in warns[:10]:
                    lines.append(f"• {name}: {text}")
                if len(warns) > 10:
                    lines.append(f"…и ещё {len(warns) - 10}")
        return "\n".join(lines + self._footer())

    def _change_text(self, title: str, entries: list[dict], icon: str) -> str:
        lines = [f"{icon} health-zoo — {title.lower()} ({len(entries)}):"]
        for entry in entries[:20]:
            where = entry.get("url") or entry.get("addr") or ""
            lines.append(f"• {entry['host']}: {entry['text']}"
                         + (f"\n  {where}" if where else ""))
        if len(entries) > 20:
            lines.append(f"…и ещё {len(entries) - 20}")
        return "\n".join(lines + self._footer())

    def _footer(self) -> list[str]:
        return ["", f"дашборд: {self.dashboard_url}"] if self.dashboard_url else []

    # ---------- delivery ----------

    def _send(self, text: str) -> None:
        token = secrets.load(self.cfg, "token") or os.environ.get("HEALTH_ZOO_TG_TOKEN", "")
        chats = self.cfg.get("chats") or []
        if not token or not chats or not text:
            return
        if not os.path.exists(self.binary):
            return

        cmd = [self.binary, "-t", token, "-a", "3", "-p"]
        for chat in chats:
            cmd += ["-c", str(chat)]
        if self.spool:
            # telegram.sh's own store-and-forward queue: a message survives the
            # proxy being down, which for Telegram here is a routine event.
            cmd += ["-q", self.spool]
        # Plain text on purpose: -M would turn "SanSd_1.hbk" into an unclosed
        # Markdown entity and Telegram rejects the whole message. Host names,
        # unit names and file names are exactly the strings that break it.
        cmd += [text]

        try:
            subprocess.run(cmd, capture_output=True, timeout=120, text=True)
        except (subprocess.SubprocessError, OSError):
            pass  # a failed notification must never disturb polling

    def test(self) -> tuple[bool, str]:
        """Send a probe message; used by /api/alerts/test."""
        if not self.enabled:
            return False, "алерты выключены в конфиге"
        self._send("🩺 health-zoo: проверка связи — алерты настроены и работают"
                   + (f"\n\nдашборд: {self.dashboard_url}" if self.dashboard_url else ""))
        return True, "отправлено"
