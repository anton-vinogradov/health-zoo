"""Findings acknowledged once, until the fact behind them changes.

A suppression answers "this is fine here, and here is why" — it needs a reason,
carries an expiry and belongs in a list somebody reviews. Most of what a
dashboard says needs nothing of the sort: "перезагружался 3 раза за неделю" is
read, understood, and does not need to be read again tomorrow — but it does need
to come back the moment it becomes "4 раза".

So an acknowledgement stores what the finding said, and holds while it still
says exactly that. A new restart changes the sentence, the acknowledgement stops
matching and the finding returns as if it were new — which it is. Nothing to
write, nothing to expire, nothing to review: the fact itself decides when the
silence ends.
"""

from __future__ import annotations

import json
import os
import threading
import time


class Acks:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.items: dict[str, dict] = {}
        self._load()

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

    @staticmethod
    def make_id(host_id: str, key: str) -> str:
        return f"{host_id}/{key}"

    def add(self, host_id: str, key: str, fingerprint: str) -> None:
        """Remember this exact sentence as read."""
        with self.lock:
            self.items[self.make_id(host_id, key)] = {
                "host": host_id, "key": key,
                "said": fingerprint, "at": int(time.time())}
            self._save()

    def remove(self, ack_id: str) -> bool:
        with self.lock:
            existed = self.items.pop(ack_id, None) is not None
            if existed:
                self._save()
        return existed

    def for_host(self, host_id: str) -> dict[str, dict]:
        prefix = f"{host_id}/"
        with self.lock:
            return {k[len(prefix):]: v for k, v in self.items.items()
                    if k.startswith(prefix)}

    def forget_stale(self, hosts: list[dict]) -> None:
        """Drop acknowledgements whose finding has changed or gone.

        Kept deliberately eager: an acknowledgement that outlives its sentence
        would silence the next occurrence too, which is the one failure this
        must not have.
        """
        said = {}
        for host in hosts:
            for issue in host.get("issues", []):
                said[self.make_id(str(host.get("id")), issue["key"])] = issue["text"]
        with self.lock:
            live = {k: v for k, v in self.items.items()
                    if said.get(k) == v.get("said")}
            if len(live) != len(self.items):
                self.items = live
                self._save()

    def listing(self, hosts: list[dict]) -> list[dict]:
        by_id = {h.get("id"): h for h in hosts}
        now = time.time()
        with self.lock:
            items = dict(self.items)
        return sorted(
            ({"id": ack_id,
              "host": entry["host"],
              "host_name": by_id.get(entry["host"], {}).get("name", entry["host"]),
              "key": entry["key"],
              "said": entry["said"],
              "age_hours": round((now - entry["at"]) / 3600, 1)}
             for ack_id, entry in items.items()),
            key=lambda item: item["age_hours"])
