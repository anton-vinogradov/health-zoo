"""Durable observations and action outcomes, independent of the latest snapshot.

Only explicit display fields are retained. The first reading of each host seeds
its baseline; unreachable or stale readings never pretend its services recovered.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import threading
import time

RETENTION_DAYS = 180
MAX_ENTRIES = 50000
MAX_JOBS = 500
MAX_LOGS = 100000


class Journal:
    def __init__(self, path, *, retention_days=RETENTION_DAYS, secrets=()):
        self.path = str(path)
        self.retention = max(1, int(retention_days)) * 86400
        self.lock = threading.RLock()
        self.error = ""
        self.started_at = 0
        self.conn = None
        self._last_prune = 0
        self._log_writes = 0
        self._secrets = sorted({str(s) for s in secrets if s}, key=len, reverse=True)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            self.conn = sqlite3.connect(self.path, timeout=3, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                    kind TEXT NOT NULL, event TEXT NOT NULL, severity TEXT NOT NULL,
                    host_id TEXT NOT NULL, host_name TEXT NOT NULL, title TEXT NOT NULL,
                    detail TEXT NOT NULL, job_id TEXT NOT NULL, dedupe TEXT UNIQUE);
                CREATE INDEX IF NOT EXISTS journal_host ON entries(host_id,id);
                CREATE INDEX IF NOT EXISTS journal_kind ON entries(kind,id);
                CREATE TABLE IF NOT EXISTS observations (
                    host_id TEXT PRIMARY KEY, ts INTEGER NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, started INTEGER NOT NULL,
                    updated INTEGER NOT NULL, state TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS job_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
                    host_id TEXT NOT NULL, line TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS journal_logs ON job_logs(job_id,id);
            """)
            now = int(time.time())
            self.conn.execute("INSERT OR IGNORE INTO meta VALUES ('started_at',?)", (str(now),))
            self.started_at = int(self.conn.execute(
                "SELECT value FROM meta WHERE key='started_at'").fetchone()[0])
            self.conn.commit()
            self._recover()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self._failed(exc)
            if self.conn:
                self.conn.close()
            self.conn = None

    def _failed(self, exc):
        self.error = "Журнал недоступен; история может быть неполной."
        # Do not expose database paths or arbitrary exception text through API.
        if self.conn:
            try:
                self.conn.rollback()
            except sqlite3.Error:
                pass

    def text(self, value, limit=2000):
        value = str(value or "")
        for secret in self._secrets:
            value = value.replace(secret, "[скрыто]")
        value = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[скрыто]@", value)
        value = re.sub(r"(?i)(/bot)[0-9]+:[A-Za-z0-9_-]+", r"\1[скрыто]", value)
        value = re.sub(r"(?i)(\b(?:password|passwd|token|secret|authorization|api[_-]?key)\b\s*[:=]\s*)(?:Bearer\s+)?[^\s,;]+", r"\1[скрыто]", value)
        value = re.sub(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[скрыто]", value)
        return value[:limit]

    def _insert(self, event, title, *, kind="events", severity="info", host_id="",
                host_name="", detail="", job_id="", ts=None, dedupe=None):
        self.conn.execute("""INSERT OR IGNORE INTO entries
            (ts,kind,event,severity,host_id,host_name,title,detail,job_id,dedupe)
            VALUES (?,?,?,?,?,?,?,?,?,?)""", (
            int(time.time()) if ts is None else int(ts), kind, event, severity,
            self.text(host_id, 160), self.text(host_name, 200), self.text(title, 300),
            self.text(detail), self.text(job_id, 160), dedupe))

    def _prune(self):
        now = int(time.time())
        if now - self._last_prune < 600:
            return
        self.conn.execute("DELETE FROM entries WHERE ts<?", (now - self.retention,))
        self.conn.execute("DELETE FROM entries WHERE id IN (SELECT id FROM entries ORDER BY id DESC LIMIT -1 OFFSET ?)", (MAX_ENTRIES,))
        self.conn.execute("DELETE FROM jobs WHERE state!='running' AND updated<?", (now - self.retention,))
        self.conn.execute("DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE state!='running' ORDER BY updated DESC LIMIT -1 OFFSET ?)", (MAX_JOBS,))
        self.conn.execute("DELETE FROM job_logs WHERE job_id NOT IN (SELECT id FROM jobs)")
        self.conn.execute("DELETE FROM job_logs WHERE id IN (SELECT id FROM job_logs ORDER BY id DESC LIMIT -1 OFFSET ?)", (MAX_LOGS,))
        self.conn.execute("DELETE FROM observations WHERE ts<?", (now - self.retention,))
        self._last_prune = now

    def action(self, event, title, *, host_id="", host_name="", detail="", severity="info"):
        if not self.conn:
            return
        with self.lock:
            try:
                self._insert(event, title, kind="actions", host_id=host_id,
                             host_name=host_name, detail=detail, severity=severity)
                self._prune()
                self.conn.commit()
                self.error = ""
            except sqlite3.Error as exc:
                self._failed(exc)

    def observe(self, hosts):
        if not self.conn:
            return
        with self.lock:
            try:
                for host in hosts:
                    if host.get("stale") or not host.get("id"):
                        continue
                    hid = str(host["id"])
                    stamp = float(host.get("polled_at") or time.time())
                    row = self.conn.execute("SELECT body FROM observations WHERE host_id=?", (hid,)).fetchone()
                    old = json.loads(row[0]) if row else None
                    if old and stamp <= old.get("stamp", 0):
                        continue
                    current = copy.deepcopy(old) if old else {}
                    current.update(stamp=stamp, reachable=bool(host.get("reachable")),
                                   name=self.text(host.get("name") or hid, 200))
                    def emit(event, title, severity="info", detail=""):
                        self._insert(event, title, severity=severity, detail=detail,
                                     host_id=hid, host_name=current["name"])
                    if old and old.get("reachable") != current["reachable"]:
                        emit("host.up" if current["reachable"] else "host.down",
                             "Устройство снова доступно" if current["reachable"] else "Устройство недоступно",
                             "ok" if current["reachable"] else "bad", host.get("error", ""))
                    # Missing metrics during an outage are not resolved problems.
                    if current["reachable"] and not host.get("error"):
                        findings = {str(i["key"]): {"level": i.get("original_level", i.get("level", "info")),
                                                   "text": self.text(i.get("text"))}
                                    for i in host.get("issues", [])
                                    if i.get("key") and i["key"] not in ("down", "rebooted")
                                    and not i["key"].startswith(("svcflap:", "svcgone:"))}
                        if old and "issues" in old:
                            for key, item in findings.items():
                                prior = old["issues"].get(key)
                                if prior is None:
                                    emit("issue.appeared", "Появилась находка", item["level"], item["text"])
                                elif prior["level"] != item["level"]:
                                    emit("issue.changed", "Изменилась серьёзность находки", item["level"], item["text"])
                            for key, item in old["issues"].items():
                                if key not in findings:
                                    emit("issue.cleared", "Находка устранена", "ok", item["text"])
                        current["issues"] = findings
                        uptime = host.get("uptime")
                        if isinstance(uptime, (int, float)):
                            earlier = old.get("uptime") if old else None
                            if earlier is not None and uptime < earlier and uptime <= stamp - old.get("uptime_at", stamp) + 600:
                                emit("host.rebooted", "Устройство перезагрузилось",
                                     "info" if host.get("reboot_planned") else "warn",
                                     "Плановая перезагрузка" if host.get("reboot_planned") else "Перезагрузка обнаружена по времени работы")
                            current.update(uptime=uptime, uptime_at=stamp)
                        if "services" in host:
                            services = {s["name"]: {"state": self.text(s.get("state"), 120),
                                                   "restarts": s.get("restarts") or 0}
                                        for s in host["services"] if s.get("name")}
                            if old and "services" in old:
                                for name, svc in services.items():
                                    prior = old["services"].get(name)
                                    if prior is None:
                                        emit("service.added", "Обнаружен сервис", detail=name)
                                    elif prior["state"] != svc["state"]:
                                        emit("service.changed", "Изменилось состояние сервиса", detail=f"{name}: {prior['state']} → {svc['state']}")
                                    elif isinstance(svc["restarts"], (int, float)) and isinstance(prior["restarts"], (int, float)) and svc["restarts"] > prior["restarts"]:
                                        emit("service.restarted", "Сервис перезапускался", "warn", f"{name}: +{svc['restarts'] - prior['restarts']} перезапусков")
                                for name in old["services"]:
                                    if name not in services:
                                        emit("service.removed", "Сервис исчез из опроса", "warn", name)
                            current["services"] = services
                    elif current["reachable"] and host.get("error"):
                        # The failed agent contributes its access error without
                        # clearing the disk/service findings it could not read.
                        known = copy.deepcopy(old.get("issues", {})) if old else {}
                        access = {i["key"]: {"level": i.get("original_level", i.get("level", "warn")),
                                            "text": self.text(i.get("text"))}
                                  for i in host.get("issues", []) if i.get("key") in ("noaccess", "hostkey")}
                        for key, item in access.items():
                            prior = known.get(key)
                            if old and prior is None:
                                emit("issue.appeared", "Появилась находка", item["level"], item["text"])
                            elif prior and prior["level"] != item["level"]:
                                emit("issue.changed", "Изменилась серьёзность находки", item["level"], item["text"])
                        known.update(access)
                        current["issues"] = known
                    self.conn.execute("INSERT OR REPLACE INTO observations VALUES (?,?,?)",
                                      (hid, int(time.time()), json.dumps(current, ensure_ascii=False)))
                self._prune()
                self.conn.commit()
                self.error = ""
            except (sqlite3.Error, ValueError, TypeError) as exc:
                self._failed(exc)

    def _job(self, job):
        # Explicit allowlist: never serialize a host config, command or request.
        clean = {k: job[k] for k in ("id", "kind", "state", "started", "finished",
                 "current", "refreshed", "outcome") if k in job}
        clean["targets"] = [self.text(h, 160) for h in job.get("targets", [])]
        clean["automatic"] = bool(job.get("automatic", False))
        if job.get("unit"):
            clean["unit"] = self.text(job["unit"], 300)
        clean["results"] = {self.text(k, 160): self.text(v) for k, v in job.get("results", {}).items()}
        # Logs have their own append-only table. Copying a whole multi-host log
        # into every snapshot would multiply storage and rewrite megabytes.
        clean["log"] = []
        clean["hosts"] = {}
        for hid, host in job.get("hosts", {}).items():
            entry = {k: host[k] for k in ("state", "started", "finished") if k in host}
            entry.update(name=self.text(host.get("name") or hid, 200),
                         log=[])
            if host.get("reason"):
                entry["reason"] = self.text(host["reason"])
            clean["hosts"][str(hid)] = entry
        return clean

    def save_job(self, job):
        if not self.conn:
            return
        clean = self._job(job)
        now = int(time.time())
        with self.lock:
            try:
                self.conn.execute("INSERT OR REPLACE INTO jobs VALUES (?,?,?,?,?)",
                                  (clean["id"], clean.get("started", now), now, clean["state"],
                                   json.dumps(clean, ensure_ascii=False)))
                finished = clean["state"] != "running"
                for hid in clean["targets"]:
                    entry = clean["hosts"].get(hid, {})
                    result = clean["results"].get(hid, "")
                    interrupted = result.startswith("interrupted") or entry.get("state") == "interrupted"
                    partial = entry.get("state") == "partial"
                    verb = {"update": "Обновление пакетов", "reboot": "Перезагрузка",
                            "restart": "Перезапуск сервиса", "stop": "Остановка сервиса",
                            "start": "Запуск сервиса", "remove": "Удаление сервиса"}.get(clean["kind"], "Действие")
                    detail = verb + (" " + clean["unit"] if clean.get("unit") else "")
                    detail += " — автоматически" if clean["automatic"] else " — вручную"
                    outcome = entry.get("reason")
                    if not outcome:
                        if interrupted or "interrupted" in result:
                            outcome = "сборщик перезапущен или действие прервано; результат неизвестен"
                        elif result == "ok":
                            outcome = "успешно"
                        elif result.startswith("failed"):
                            code = re.fullmatch(r"failed \((\d+)\)", result)
                            outcome = f"ошибка (код {code[1]})" if code else "завершилось с ошибкой"
                        else:
                            outcome = result or "результат неизвестен"
                    self._insert("job.interrupted" if interrupted else "job.finished" if finished else "job.started",
                                 "Действие прервано" if interrupted else "Действие завершено" if finished else "Действие начато",
                                 kind="actions", host_id=hid, host_name=entry.get("name", hid),
                                 severity=("warn" if interrupted or partial else "ok" if result == "ok" else "bad") if finished else "info",
                                 detail=f"{detail}: {outcome}" if finished else detail,
                                 job_id=clean["id"], dedupe=f"job:{clean['id']}:{'end' if finished else 'start'}:{hid}")
                self._prune()
                self.conn.commit()
                self.error = ""
            except (sqlite3.Error, ValueError, TypeError) as exc:
                self._failed(exc)

    def append_log(self, job_id, line, host_id=""):
        if not self.conn:
            return
        with self.lock:
            try:
                self.conn.execute("INSERT INTO job_logs(job_id,host_id,line) VALUES (?,?,?)",
                                  (job_id, host_id, self.text(line)))
                self._log_writes += 1
                if self._log_writes % 64 == 0:
                    self.conn.execute("DELETE FROM job_logs WHERE id IN (SELECT id FROM job_logs ORDER BY id DESC LIMIT -1 OFFSET ?)", (MAX_LOGS,))
                self._prune()
                self.conn.commit()
            except sqlite3.Error as exc:
                self._failed(exc)

    def get_job(self, job_id):
        if not self.conn:
            return None
        with self.lock:
            try:
                row = self.conn.execute("SELECT body FROM jobs WHERE id=?", (job_id,)).fetchone()
                if not row:
                    return None
                job = json.loads(row[0])
                # Appended lines survive a crash between job snapshot writes.
                rows = self.conn.execute("SELECT host_id,line FROM (SELECT id,host_id,line FROM job_logs WHERE job_id=? ORDER BY id DESC LIMIT ?) ORDER BY id", (job_id, 16001)).fetchall()
                if len(rows) > 16000:
                    job["log_truncated"] = True
                    rows = rows[-16000:]
                if rows:
                    streams = {}
                    for line in rows:
                        streams.setdefault(line["host_id"], []).append(line["line"])
                    for hid, lines in streams.items():
                        if hid in job.get("hosts", {}):
                            job["hosts"][hid]["log"] = lines[-4000:]
                        else:
                            job["log"] = lines[-4000:]
                return job
            except (sqlite3.Error, ValueError, TypeError) as exc:
                self._failed(exc)
                return None

    def latest_job(self):
        if not self.conn:
            return None
        with self.lock:
            try:
                row = self.conn.execute("SELECT id FROM jobs ORDER BY started DESC,rowid DESC LIMIT 1").fetchone()
                return self.get_job(row[0]) if row else None
            except sqlite3.Error as exc:
                self._failed(exc)
                return None

    def _recover(self):
        rows = self.conn.execute("SELECT id FROM jobs WHERE state='running'").fetchall()
        for row in rows:
            job = self.get_job(row[0])
            if not job:
                continue
            job.update(state="done", outcome="interrupted", current="", finished=int(time.time()))
            for hid in job["targets"]:
                entry = job["hosts"].setdefault(hid, {"name": hid, "log": []})
                if entry.get("state") in (None, "pending", "running"):
                    entry.update(state="interrupted", finished=job["finished"], reason="Сборщик перезапущен; результат операции неизвестен")
                    job["results"][hid] = "interrupted (collector restarted; result unknown)"
            self.save_job(job)

    def listing(self, *, kind="all", host="", since=0, before=None, limit=50):
        if kind not in ("all", "events", "actions"):
            raise ValueError("invalid journal kind")
        since = max(0, int(since))
        limit = max(1, min(100, int(limit)))
        before = int(before) if before not in (None, "") else None
        if since > 2**63 - 1 or before is not None and not 0 <= before <= 2**63 - 1:
            raise ValueError("journal cursor or timestamp is out of range")
        out = {"entries": [], "next_before": None, "started_at": self.started_at}
        if not self.conn:
            out["error"] = self.error
            return out
        clauses, args = ["ts>=?"], [since]
        if kind != "all":
            clauses.append("kind=?"); args.append(kind)
        if host:
            clauses.append("host_id=?"); args.append(host)
        if before is not None:
            clauses.append("id<?"); args.append(before)
        with self.lock:
            try:
                rows = self.conn.execute("SELECT id,ts,kind,event,severity,host_id,host_name,title,detail,job_id FROM entries WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?", (*args, limit + 1)).fetchall()
                out["entries"] = [dict(r) for r in rows[:limit]]
                if len(rows) > limit:
                    out["next_before"] = rows[limit - 1]["id"]
            except sqlite3.Error as exc:
                self._failed(exc)
        if self.error:
            out["error"] = self.error
        return out
