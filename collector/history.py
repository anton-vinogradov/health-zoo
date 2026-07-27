"""Metric history for health-zoo.

A snapshot answers "is it broken now"; history answers the questions that
actually prevent incidents — is this disk filling up, is that drive starting to
relocate sectors, has this box been getting hotter since the fan was replaced.

SQLite, one row per host per metric per poll, downsampled on read. Also doubles
as crash recovery: the hub restores its last snapshot on startup instead of
showing an empty page while the first poll runs.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts      INTEGER NOT NULL,
    host    TEXT    NOT NULL,
    metric  TEXT    NOT NULL,
    value   REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS samples_lookup ON samples (host, metric, ts);

CREATE TABLE IF NOT EXISTS snapshots (
    ts   INTEGER PRIMARY KEY,
    body TEXT NOT NULL
);
"""

# Metrics worth keeping over time. Everything else is either categorical or
# reconstructable from the snapshot.
def extract(host: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for field in ("mem_pct", "swap_pct", "update_count", "security_count",
                  "cpu_load_pct", "channel_utilization"):
        value = host.get(field)
        if isinstance(value, (int, float)):
            out[field] = float(value)

    if isinstance(host.get("load1"), (int, float)) and host.get("cpus"):
        out["load_pct"] = float(host["load1"]) * 100.0 / float(host["cpus"])

    for disk in host.get("disks", []):
        if isinstance(disk.get("pct"), (int, float)):
            out[f"disk:{disk['mount']}"] = float(disk["pct"])
            out[f"disk_used:{disk['mount']}"] = float(disk.get("used") or 0)

    temps = host.get("temps") or []
    if temps:
        out["temp_max"] = float(max(t.get("c") or 0 for t in temps))

    for disk in host.get("smarts", []):
        dev = disk.get("dev", "?")
        for field in ("realloc", "pending", "wear", "temp", "hours"):
            value = disk.get(field)
            if isinstance(value, (int, float)):
                out[f"smart:{dev}:{field}"] = float(value)

    out["up"] = 1.0 if host.get("reachable") else 0.0
    return out


class History:
    """Optional by design: if the database cannot be opened the dashboard runs
    without trends rather than refusing to start. Monitoring that dies because
    its own bookkeeping failed is worse than monitoring with no history."""

    def __init__(self, path: str, retention_days: int = 180):
        self.path = path
        self.retention = retention_days * 86400
        self.lock = threading.Lock()
        self._conn = None
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.executescript(SCHEMA)
            # WAL keeps the writer from blocking the HTTP threads that read.
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.commit()
        except (sqlite3.Error, OSError) as exc:
            print(f"health-zoo: history disabled ({path}: {exc})", flush=True)
            self._conn = None

    @property
    def available(self) -> bool:
        return self._conn is not None

    def record(self, hosts: list[dict], snapshot: dict | None = None) -> None:
        if not self._conn:
            return
        now = int(time.time())
        rows = []
        for host in hosts:
            for metric, value in extract(host).items():
                rows.append((now, host["id"], metric, value))
        with self.lock:
            self._conn.executemany(
                "INSERT INTO samples (ts, host, metric, value) VALUES (?,?,?,?)", rows)
            if snapshot is not None:
                self._conn.execute("DELETE FROM snapshots")
                self._conn.execute("INSERT INTO snapshots (ts, body) VALUES (?,?)",
                                   (now, json.dumps(snapshot, ensure_ascii=False)))
            self._conn.execute("DELETE FROM samples WHERE ts < ?", (now - self.retention,))
            self._conn.commit()

    def last_snapshot(self) -> dict | None:
        if not self._conn:
            return None
        with self.lock:
            row = self._conn.execute(
                "SELECT body FROM snapshots ORDER BY ts DESC LIMIT 1").fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def series(self, host: str, metric: str, since: int, points: int = 120) -> list[list]:
        """Downsampled [[ts, value], …] — enough for a sparkline, not a plot."""
        if not self._conn:
            return []
        with self.lock:
            rows = self._conn.execute(
                "SELECT ts, value FROM samples WHERE host=? AND metric=? AND ts>=? "
                "ORDER BY ts", (host, metric, since)).fetchall()
        if len(rows) <= points:
            return [[int(ts), value] for ts, value in rows]
        step = len(rows) / points
        out = []
        for i in range(points):
            ts, value = rows[int(i * step)]
            out.append([int(ts), value])
        return out

    def metrics(self, host: str) -> list[str]:
        if not self._conn:
            return []
        with self.lock:
            rows = self._conn.execute(
                "SELECT DISTINCT metric FROM samples WHERE host=? ORDER BY metric",
                (host,)).fetchall()
        return [r[0] for r in rows]

    def trend(self, host: str, metric: str, window_days: int = 7) -> dict | None:
        """Least-squares slope per day, plus a forecast of when it hits 100.

        This is what turns "disk at 88%" into "88% and climbing 0.4%/day —
        full in three weeks", which is the difference between a number and a
        reason to act.
        """
        if not self._conn:
            return None
        since = int(time.time()) - window_days * 86400
        with self.lock:
            rows = self._conn.execute(
                "SELECT ts, value FROM samples WHERE host=? AND metric=? AND ts>=? "
                "ORDER BY ts", (host, metric, since)).fetchall()
        if len(rows) < 8:
            return None

        t0 = rows[0][0]
        xs = [(ts - t0) / 86400.0 for ts, _ in rows]
        ys = [value for _, value in rows]
        n = len(xs)
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        denom = sum((x - mean_x) ** 2 for x in xs)
        if denom <= 0:
            return None
        slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom

        out = {"slope_per_day": round(slope, 4), "current": ys[-1],
               "samples": n, "window_days": window_days}
        # Only forecast for percentages, and only while actually growing.
        if metric.startswith("disk:") and slope > 0.01 and ys[-1] < 100:
            out["days_to_full"] = round((100.0 - ys[-1]) / slope, 1)
        return out
