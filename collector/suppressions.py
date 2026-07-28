"""Suppressions: findings deliberately accepted, with the reason recorded.

Every monitoring system eventually shows something that is known, understood
and not going to be fixed today. Without a way to say so, the operator either
stares past a permanently amber dashboard or turns the check off entirely and
forgets it existed.

A suppression here is neither: the check keeps running and its verdict stays
visible, but it no longer colours the host or sends an alert, and the reason is
displayed next to it. Reasons are mandatory — a suppression with no explanation
is indistinguishable from a check nobody understood.

They are listed fleet-wide so they can be reviewed: an expiry date, the age,
and whether the underlying problem is even still occurring.
"""

from __future__ import annotations

import json
import os
import threading
import time


class Suppressions:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.items: dict[str, dict] = {}
        self._load()

    # ---------- storage ----------

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                self.items = json.load(fh)
        except (OSError, ValueError):
            self.items = {}

    def _save(self) -> None:
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self.items, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- api ----------

    @staticmethod
    def make_id(host_id: str, key: str) -> str:
        return f"{host_id}/{key}"

    def add(self, host_id: str, key: str, reason: str,
            days: int | None = None, note: str = "") -> tuple[bool, str]:
        reason = (reason or "").strip()
        if len(reason) < 3:
            return False, "нужна причина — без неё исключение бессмысленно"
        entry = {
            "host": host_id,
            "key": key,
            "reason": reason,
            "note": note,
            "created": int(time.time()),
            "expires": int(time.time() + days * 86400) if days else 0,
        }
        with self.lock:
            self.items[self.make_id(host_id, key)] = entry
            self._save()
        return True, ""

    def remove(self, suppression_id: str) -> bool:
        with self.lock:
            existed = self.items.pop(suppression_id, None) is not None
            if existed:
                self._save()
        return existed

    def active(self) -> dict[str, dict]:
        """Non-expired entries. Expiry is what keeps this list from rotting."""
        now = time.time()
        with self.lock:
            live = {k: v for k, v in self.items.items()
                    if not v.get("expires") or v["expires"] > now}
            if len(live) != len(self.items):
                self.items = live
                self._save()
            return dict(live)

    def for_host(self, host_id: str) -> dict[str, dict]:
        prefix = f"{host_id}/"
        return {k[len(prefix):]: v for k, v in self.active().items()
                if k.startswith(prefix)}

    def listing(self, hosts: list[dict]) -> list[dict]:
        """Fleet-wide view, annotated with whether it is still doing anything.

        A suppression whose finding has stopped occurring is the interesting
        case: it can be removed, and until someone notices, it silently hides a
        check that would now pass anyway.
        """
        by_id = {h.get("id"): h for h in hosts}
        now = time.time()
        out = []
        for suppression_id, entry in self.active().items():
            host = by_id.get(entry["host"], {})
            # Same rule as when the suppression is applied: a key recorded
            # against a check covers the findings that check produces.
            firing = any(issue.get("key") == entry["key"]
                         or str(issue.get("key", "")).startswith(entry["key"] + ":")
                         for issue in host.get("issues", []))
            out.append({
                "id": suppression_id,
                "host": entry["host"],
                "host_name": host.get("name", entry["host"]),
                "key": entry["key"],
                "reason": entry["reason"],
                "note": entry.get("note", ""),
                "created": entry["created"],
                "age_days": round((now - entry["created"]) / 86400, 1),
                "expires": entry.get("expires", 0),
                "days_left": (round((entry["expires"] - now) / 86400, 1)
                              if entry.get("expires") else None),
                # False means the underlying finding is gone: the suppression
                # is no longer hiding anything and can probably be dropped.
                "still_firing": firing,
            })
        return sorted(out, key=lambda item: (not item["still_firing"], -item["created"]))
