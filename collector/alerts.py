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

import os
import subprocess
import threading
import time

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
        self.lock = threading.Lock()
        self.active: dict[str, dict] = {}
        self.seeded = False

    # ---------- state diffing ----------

    def _current(self, hosts: list[dict]) -> dict[str, dict]:
        wanted = ("bad",) if self.min_level == "bad" else ("bad", "warn")
        out: dict[str, dict] = {}
        for host in hosts:
            for issue in host.get("issues", []):
                if issue["level"] not in wanted:
                    continue
                out[f"{host['id']}/{issue['key']}"] = {
                    "host": host.get("name", host["id"]),
                    "level": issue["level"],
                    "text": issue["text"],
                    "since": int(time.time()),
                }
        return out

    def process(self, hosts: list[dict]) -> None:
        if not self.enabled:
            return
        current = self._current(hosts)
        with self.lock:
            previous = self.active
            self.active = {
                key: (previous.get(key) or value) for key, value in current.items()
            }
            first_run = not self.seeded
            self.seeded = True

        appeared = [v for k, v in current.items() if k not in previous]
        cleared = [v for k, v in previous.items() if k not in current]

        if first_run:
            # Restarting the hub is not an incident: report the standing state
            # once instead of announcing every pre-existing problem as new.
            if self.startup_summary:
                self._send(self._startup_text(hosts, current))
            return

        if appeared:
            self._send(self._change_text("Появилось", appeared, "🔴"))
        if cleared:
            self._send(self._change_text("Ушло", cleared, "🟢"))

    # ---------- message shaping ----------

    def _startup_text(self, hosts: list[dict], current: dict) -> str:
        down = [h["name"] for h in hosts if not h.get("reachable")]
        lines = [f"🩺 health-zoo запущен: {len(hosts)} устройств"]
        if down:
            lines.append(f"не отвечают: {', '.join(down)}")
        if current:
            lines.append("")
            lines.append(f"Известные проблемы ({len(current)}):")
            for value in list(current.values())[:15]:
                lines.append(f"{LEVEL_ICON.get(value['level'], '•')} {value['host']}: {value['text']}")
        else:
            lines.append("проблем нет")
        return "\n".join(lines)

    def _change_text(self, title: str, entries: list[dict], icon: str) -> str:
        lines = [f"{icon} health-zoo — {title.lower()} ({len(entries)}):"]
        for entry in entries[:20]:
            lines.append(f"• {entry['host']}: {entry['text']}")
        if len(entries) > 20:
            lines.append(f"…и ещё {len(entries) - 20}")
        return "\n".join(lines)

    # ---------- delivery ----------

    def _send(self, text: str) -> None:
        token = self.cfg.get("token") or os.environ.get("HEALTH_ZOO_TG_TOKEN", "")
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
        cmd += ["-M", text]

        try:
            subprocess.run(cmd, capture_output=True, timeout=120, text=True)
        except (subprocess.SubprocessError, OSError):
            pass  # a failed notification must never disturb polling

    def test(self) -> tuple[bool, str]:
        """Send a probe message; used by /api/alerts/test."""
        if not self.enabled:
            return False, "алерты выключены в конфиге"
        self._send("🩺 health-zoo: проверка связи — алерты настроены и работают")
        return True, "отправлено"
