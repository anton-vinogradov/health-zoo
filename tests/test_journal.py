"""Durable journal regressions; no network, SSH or real command execution."""
import copy
import io
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
import hub
import journal
import settings
import storage


def host(stamp=1000, **kw):
    return dict(dict(id="server", name="Server", polled_at=stamp, reachable=True,
                     uptime=10000 + stamp, issues=[], services=[]), **kw)


def finding(key="disk:/", level="bad"):
    return {"key": key, "level": level, "text": "Disk full"}


def events(store):
    return [e["event"] for e in store.listing()["entries"]]


def test_first_baseline_and_restart_do_not_generate_existing_findings(tmp_path):
    path = tmp_path / "journal.db"
    store = journal.Journal(path)
    store.observe([host(issues=[finding()])])
    assert events(store) == []
    store.conn.close()
    restarted = journal.Journal(path)
    restarted.observe([host(1001, issues=[finding()])])
    assert events(restarted) == []
    restarted.observe([host(1002)])
    assert events(restarted) == ["issue.cleared"]


def test_observation_records_availability_findings_reboot_and_services(tmp_path):
    store = journal.Journal(tmp_path / "journal.db")
    store.observe([host()])
    store.observe([host(1100, issues=[finding()], services=[{"name":"demo.service", "state":"running", "restarts":0}])])
    assert set(events(store)) == {"issue.appeared", "service.added"}
    store.observe([host(1200, reachable=False, issues=[], services=[])])
    assert events(store)[0] == "host.down"
    assert "issue.cleared" not in events(store) and "service.removed" not in events(store)
    store.observe([host(1300, uptime=10, issues=[], services=[])])
    assert set(events(store)) >= {"host.up", "host.rebooted", "issue.cleared", "service.removed"}
    count = len(events(store))
    store.observe([host(1250, reachable=False)])
    store.observe([host(1400, stale=True, reachable=False)])
    assert len(events(store)) == count


def test_partial_refresh_does_not_make_other_hosts_disappear(tmp_path):
    store = journal.Journal(tmp_path / "journal.db")
    other = host(id="other")
    store.observe([host(), other])
    store.observe([host(1100, issues=[finding()])])
    store.observe([host(1200, issues=[finding()]), dict(other, polled_at=1200)])
    assert events(store) == ["issue.appeared"]


def test_service_restart_and_severity_change_are_recorded_without_metric_noise(tmp_path):
    store = journal.Journal(tmp_path / "journal.db")
    initial = host(issues=[finding(level="warn")], services=[{"name":"demo", "state":"running", "restarts":1}])
    store.observe([initial])
    changed = copy.deepcopy(initial); changed["polled_at"] = 1100
    changed["issues"][0]["text"] = "Disk 89%"
    store.observe([changed])
    assert events(store) == []
    changed["polled_at"] = 1200; changed["issues"][0]["level"] = "bad"
    changed["services"][0]["restarts"] = 2
    store.observe([changed])
    assert set(events(store)) == {"issue.changed", "service.restarted"}


def test_cursor_is_stable_with_concurrent_appends_and_filters(tmp_path):
    store = journal.Journal(tmp_path / "journal.db")
    for n in range(7):
        store.action("settings.saved", str(n), host_id="server" if n % 2 else "other")
    first = store.listing(kind="actions", host="server", limit=2)
    store.action("settings.saved", "new", host_id="server")
    second = store.listing(kind="actions", host="server", limit=2, before=first["next_before"])
    ids = [e["id"] for e in first["entries"] + second["entries"]]
    assert len(ids) == len(set(ids)) == 3
    assert second["next_before"] is None
    assert all(e["host_id"] == "server" for e in first["entries"] + second["entries"])
    assert store.listing(kind="events")["entries"] == []
    assert store.listing(since=10**12)["entries"] == []
    with pytest.raises(ValueError):
        store.listing(kind="not-a-kind")


def job(job_id="job-old"):
    return {"id":job_id, "kind":"update", "state":"running", "started":100,
            "targets":["server"], "log":[], "results":{},
            "hosts":{"server":{"name":"Server", "state":"running", "log":[], "started":100}}}


def test_running_job_recovers_as_interrupted_with_logs_and_old_api(tmp_path):
    path = tmp_path / "journal.db"
    store = journal.Journal(path)
    store.save_job(job())
    store.append_log("job-old", "last output before crash", "server")
    store.conn.close()
    restored = journal.Journal(path)
    jobs = hub.Jobs({}, restored)
    previous = jobs.get("job-old")
    assert previous["state"] == "done" and previous["outcome"] == "interrupted"
    assert previous["hosts"]["server"]["state"] == "interrupted"
    assert previous["results"]["server"].startswith("interrupted")
    assert previous["hosts"]["server"]["log"] == ["last output before crash"]
    assert jobs.latest()["id"] == "job-old"
    handler = hub.Handler.__new__(hub.Handler)
    handler.jobs = jobs; handler.path = "/api/job/job-old"
    handler._json = lambda body, code=200: setattr(handler, "response", (code, body))
    handler.do_GET()
    assert handler.response[0] == 200 and handler.response[1]["outcome"] == "interrupted"
    assert events(restored).count("job.interrupted") == 1
    restored.conn.close()
    assert events(journal.Journal(path)).count("job.interrupted") == 1


def test_finished_job_does_not_turn_into_interrupted(tmp_path):
    path = tmp_path / "journal.db"
    store = journal.Journal(path); data = job(); store.save_job(data)
    data.update(state="done", finished=200, results={"server":"ok"})
    data["hosts"]["server"]["state"] = "ok"
    store.save_job(data); store.save_job(data)
    store.conn.close()
    restored = journal.Journal(path)
    assert restored.get_job("job-old")["results"] == {"server":"ok"}
    assert events(restored).count("job.finished") == 1
    assert "job.interrupted" not in events(restored)


def test_job_persisted_before_worker_and_ids_survive_process_restart(tmp_path, monkeypatch):
    store = journal.Journal(tmp_path / "journal.db")
    jobs = hub.Jobs({}, store)
    monkeypatch.setattr(hub.threading.Thread, "start", lambda self: None)
    fleet = SimpleNamespace(settings=SimpleNamespace(note_reboot=lambda *args:None), journal=store)
    one, _ = jobs.start_reboot(host(), fleet)
    assert store.get_job(one)["state"] == "running"
    two = hub.Jobs({}, store)._new_id()
    assert one != two


def test_sensitive_data_is_redacted_and_raw_job_config_is_never_persisted(tmp_path):
    store = journal.Journal(tmp_path / "journal.db", secrets=["real-secret"])
    data = job(); data["config"] = {"password":"not-allowed"}
    store.save_job(data)
    store.append_log(data["id"], "token=abc https://u:pass@host/ real-secret", "server")
    store.action("settings.saved", "saved", detail="password=pw /bot1234:token_abc")
    serialized = json.dumps(store.get_job(data["id"])) + json.dumps(store.listing())
    assert not any(s in serialized for s in ("not-allowed", "real-secret", "u:pass", "token=abc", "password=pw", "1234:token_abc"))


def test_journal_failure_does_not_break_polling_contract(tmp_path):
    store = journal.Journal(tmp_path / "absent" / "journal.db")
    store.conn.execute("DROP TABLE observations")
    store.observe([host()])
    assert store.listing().get("error")
    store.conn.execute("CREATE TABLE observations (host_id TEXT PRIMARY KEY, ts INTEGER NOT NULL, body TEXT NOT NULL)")
    store.action("settings.saved", "still works")
    assert store.listing()["entries"]
    broken = tmp_path / "broken.db"; broken.write_text("not sqlite")
    unavailable = journal.Journal(broken)
    unavailable.observe([host()]); unavailable.save_job(job())
    assert unavailable.listing()["error"] and unavailable.get_job("missing") is None


def test_retention_and_row_cap_bound_history(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "MAX_ENTRIES", 3)
    store = journal.Journal(tmp_path / "journal.db")
    for n in range(8):
        store._last_prune = 0
        store.action("settings.saved", str(n))
    assert len(store.listing()["entries"]) == 3
    store.conn.execute("UPDATE entries SET ts=1"); store.conn.commit()
    store._last_prune = 0
    store.action("settings.saved", "now")
    assert len(store.listing()["entries"]) == 1


def test_settings_audit_only_after_success_and_never_serializes_request(tmp_path, monkeypatch):
    handler = hub.Handler.__new__(hub.Handler)
    handler.path = "/api/settings"
    request = {"auto_security":{"enabled":False}, "action_token":"DO-NOT-STORE"}
    body = json.dumps(request).encode()
    handler.headers = {"Host":"localhost", "Content-Length":str(len(body)), "X-Health-Zoo-Token":"secret"}
    handler.rfile = io.BytesIO(body)
    handler.connection = SimpleNamespace(settimeout=lambda value:None)
    store = journal.Journal(tmp_path / "journal.db")
    handler.fleet = SimpleNamespace(cfg={"action_token":"secret"}, journal=store,
        settings=settings.Settings(str(tmp_path / "settings.json")),
        alerts=SimpleNamespace(timezone=""), suppressions=None, acks=None,
        get=lambda:{"hosts":[]}, apply_camera_limits=lambda hosts:None)
    handler._json = lambda body, code=200: setattr(handler, "response", (code, body))
    with monkeypatch.context() as patch:
        patch.setattr(storage, "write_json", lambda *args: (_ for _ in ()).throw(storage.StateSaveError("failed")))
        handler.do_POST()
    assert handler.response[0] == 503 and events(store) == []
    handler.rfile = io.BytesIO(body)
    handler.do_POST()
    assert handler.response[0] == 200 and events(store) == ["settings.saved"]
    assert "DO-NOT-STORE" not in json.dumps(store.listing())
    assert store.listing()["entries"][0]["detail"] == "обновления безопасности"


def test_journal_http_bad_filters_and_limit_cap(tmp_path):
    store = journal.Journal(tmp_path / "journal.db")
    for n in range(105):
        store.action("settings.saved", str(n))
    handler = hub.Handler.__new__(hub.Handler)
    handler.fleet = SimpleNamespace(journal=store)
    handler._json = lambda body, code=200: setattr(handler, "response", (code, body))
    handler.path = "/api/journal?kind=actions&limit=900"
    handler.do_GET()
    assert len(handler.response[1]["entries"]) == 100
    handler.path = "/api/journal?before=not-a-number"
    handler.do_GET()
    assert handler.response[0] == 400
    handler.path = "/api/journal?before=9999999999999999999999999"
    handler.do_GET()
    assert handler.response[0] == 400


def test_live_job_log_is_sanitized_like_the_persisted_log(tmp_path):
    store = journal.Journal(tmp_path / "journal.db", secrets=["real-secret"])
    jobs = hub.Jobs({}, store)
    jobs.jobs["job-old"] = job()
    store.save_job(jobs.jobs["job-old"])
    jobs._log("job-old", "printed real-secret token=abc", "server")
    assert "real-secret" not in json.dumps(jobs.get("job-old"))
    assert "token=abc" not in json.dumps(jobs.get("job-old"))
    assert jobs.get("job-old")["hosts"]["server"]["log"] == store.get_job("job-old")["hosts"]["server"]["log"]


def test_agent_error_preserves_unknown_findings_but_records_lost_access(tmp_path):
    store = journal.Journal(tmp_path / "journal.db")
    store.observe([host(issues=[finding()])])
    store.observe([host(1100, error="access denied", issues=[finding("noaccess", "warn")])])
    assert events(store) == ["issue.appeared"]
    store.observe([host(1200, issues=[finding()])])
    assert events(store) == ["issue.cleared", "issue.appeared"]


@pytest.mark.parametrize("automatic", [True, False])
@pytest.mark.parametrize("kind", ["update", "reboot"])
def test_job_source_persists_and_is_explained_in_russian(tmp_path, monkeypatch, automatic, kind):
    path = tmp_path / "journal.db"
    store = journal.Journal(path)
    jobs = hub.Jobs({}, store)
    monkeypatch.setattr(hub.threading.Thread, "start", lambda self: None)
    fleet = SimpleNamespace(settings=SimpleNamespace(note_reboot=lambda *args:None,
        note_update=lambda *args:None), journal=store)
    if kind == "update":
        job_id, _ = jobs.start([host()], fleet, automatic=automatic)
    else:
        job_id, _ = jobs.start_reboot(host(), fleet, automatic=automatic)
    saved = store.get_job(job_id)
    assert saved["automatic"] is automatic
    saved.update(state="done", results={"server":"ok"})
    saved["hosts"]["server"]["state"] = "ok"
    store.save_job(saved); store.conn.close()
    restarted = journal.Journal(path)
    assert restarted.get_job(job_id)["automatic"] is automatic
    detail = restarted.listing()["entries"][0]["detail"]
    assert ("автоматически" if automatic else "вручную") in detail
    assert ("Обновление пакетов" if kind == "update" else "Перезагрузка") in detail
    assert detail.endswith(": успешно")


@pytest.mark.parametrize("local", [True, False])
def test_scheduled_reboot_passes_automatic_source(local, monkeypatch):
    node = host(local=local, reboot_required=True)
    calls = []
    fleet = SimpleNamespace(settings=SimpleNamespace(auto_reboot=lambda:{"enabled":True},
        timezone=lambda:"Europe/Moscow", last_reboot=lambda host_id:0),
        hosts=lambda:[node], alerts=SimpleNamespace(enabled=True, notify=lambda text:True),
        jobs_ref=SimpleNamespace(start_reboot=lambda *args, **kwargs: calls.append(kwargs) or ("job", "")))
    monkeypatch.setattr(hub, "inside_window", lambda *args:True)
    hub.Fleet.maybe_auto_reboot(fleet, [node])
    assert calls == [{"automatic":True}]
