"""Editing exceptions preserves their history and commits all-or-nothing."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import storage  # noqa: E402
import suppressions  # noqa: E402


ENTRY_ID = "server/disk:/recordings"
NOW = 1_800_000_000


@pytest.fixture
def existing(tmp_path, monkeypatch):
    entry = {
        "host": "server", "key": "disk:/recordings",
        "reason": "Video archive is intentionally full",
        "note": "Revisit after the retention policy changes",
        "created": NOW - 90 * 86400,
        "created_at": "legacy-metadata-kept-verbatim",
        "expires": NOW + 7 * 86400,
        "last_fired": NOW - 120,
        "observed": {"count": 5, "tags": ["recording"]},
    }
    path = tmp_path / "suppressions.json"
    path.write_text(json.dumps({ENTRY_ID: entry}), encoding="utf-8")
    monkeypatch.setattr(suppressions.time, "time", lambda: NOW)
    return suppressions.Suppressions(str(path)), path, entry


@pytest.mark.parametrize("days", [None, 0, 1, suppressions.Suppressions.MAX_DAYS])
def test_edit_preserves_history_and_sets_duration_from_now(existing, days):
    store, path, original = existing
    updated = store.update(ENTRY_ID, "  Archive retention reviewed  ", days)
    expected = dict(original, reason="Archive retention reviewed",
                    expires=NOW + days * 86400 if days else 0)
    assert updated == expected
    assert json.loads(path.read_text())[ENTRY_ID] == expected
    assert suppressions.Suppressions(str(path)).items[ENTRY_ID] == expected


@pytest.mark.parametrize("reason", [None, True, 123, [], {}, "", " \t\n ", "ab", "x" * 2001])
def test_invalid_reason_leaves_memory_and_disk_unchanged(existing, reason):
    store, path, original = existing
    before = path.read_bytes()
    with pytest.raises(ValueError):
        store.update(ENTRY_ID, reason, 7)
    assert store.items[ENTRY_ID] == original
    assert path.read_bytes() == before


@pytest.mark.parametrize("days", [-1, 3651, True, False, 1.0, 0.0, "1", "", [], {}, float("nan"), float("inf")])
def test_invalid_duration_leaves_memory_and_disk_unchanged(existing, days):
    store, path, original = existing
    before = path.read_bytes()
    with pytest.raises(ValueError):
        store.update(ENTRY_ID, "Reviewed reason", days)
    assert store.items[ENTRY_ID] == original
    assert path.read_bytes() == before


@pytest.mark.parametrize("reason", ["abc", "x" * 2000])
def test_reason_length_boundaries_are_accepted(existing, reason):
    store, _, _ = existing
    assert store.update(ENTRY_ID, reason, None)["reason"] == reason


@pytest.mark.parametrize("suppression_id", [None, False, [], {}, "", "  "])
def test_invalid_id_is_a_validation_error_without_mutation(existing, suppression_id):
    store, path, original = existing
    before = path.read_bytes()
    with pytest.raises(ValueError):
        store.update(suppression_id, "Reviewed reason", 7)
    assert store.items == {ENTRY_ID: original}
    assert path.read_bytes() == before


def test_unknown_id_does_not_create_an_exception(existing):
    store, path, original = existing
    before = path.read_bytes()
    with pytest.raises(KeyError):
        store.update("server/missing", "Reviewed reason", 7)
    assert store.items == {ENTRY_ID: original}
    assert path.read_bytes() == before


def test_failed_atomic_replace_rolls_back_and_a_retry_succeeds(existing, monkeypatch):
    store, path, original = existing
    before = path.read_bytes()
    replace = storage.os.replace

    def fail_replace(*args):
        raise OSError("disk unavailable")

    monkeypatch.setattr(storage.os, "replace", fail_replace)
    with pytest.raises(storage.StateSaveError):
        store.update(ENTRY_ID, "Reviewed reason", 30)
    assert store.items[ENTRY_ID] == original
    assert path.read_bytes() == before
    assert store.storage_error
    assert not list(path.parent.glob(".health-zoo-*"))

    monkeypatch.setattr(storage.os, "replace", replace)
    updated = store.update(ENTRY_ID, "Reviewed reason", 30)
    assert updated["created"] == original["created"]
    assert updated["expires"] == NOW + 30 * 86400
    assert not store.storage_error


def test_returned_entry_cannot_mutate_live_observation_metadata(existing):
    store, path, original = existing
    updated = store.update(ENTRY_ID, "Reviewed reason", 7)
    updated["observed"]["tags"].append("external change")
    assert store.items[ENTRY_ID]["observed"] == original["observed"]
    assert json.loads(path.read_text())[ENTRY_ID]["observed"] == original["observed"]


def test_http_edit_auth_atomic_failure_and_audit(existing, tmp_path, monkeypatch):
    import copy
    import io
    from types import SimpleNamespace
    import hub
    import journal
    store, _, original = existing
    ledger = journal.Journal(tmp_path / 'journal.db')
    changed = []
    payload = {'id': ENTRY_ID, 'reason': 'Revised explanation', 'days': 14}
    def send(token='secret'):
        handler = hub.Handler.__new__(hub.Handler)
        body = json.dumps(payload).encode()
        handler.path = '/api/suppress/update'
        handler.headers = {'Host':'localhost','Content-Length':str(len(body)),'X-Health-Zoo-Token':token}
        handler.rfile = io.BytesIO(body)
        handler.connection = SimpleNamespace(settimeout=lambda value:None)
        handler.fleet = SimpleNamespace(cfg={'action_token':'secret'}, suppressions=store,
            journal=ledger, get=lambda:{'hosts':[{'id':'server','name':'Server'}]},
            reannotate=lambda ids:changed.extend(ids))
        handler._json = lambda value,code=200:setattr(handler,'response',(code,value))
        handler.do_POST()
        return handler.response
    before = copy.deepcopy(store.items)
    assert send('wrong')[0] == 403
    assert store.items == before and not changed and not ledger.listing()['entries']
    with monkeypatch.context() as patch:
        patch.setattr(storage,'write_json',lambda *args:(_ for _ in ()).throw(storage.StateSaveError('disk unavailable')))
        assert send()[0] == 503
    assert store.items == before and not changed and not ledger.listing()['entries']
    code, response = send()
    assert code == 200 and response['ok']
    assert response['suppression']['created'] == original['created']
    assert store.items[ENTRY_ID]['reason'] == 'Revised explanation'
    assert changed == ['server']
    assert [e['event'] for e in ledger.listing()['entries']] == ['suppression.updated']
