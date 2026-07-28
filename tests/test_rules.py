"""The rules, run against a real fleet.

`test_parsers` covers turning device output into fields; this covers the far
more expensive half — deciding what those fields mean. Every rule written in a
hurry this month was wrong in the same way: it fired on a machine that was
fine. A PCIe root port idling with nothing behind it, the "powersave" governor
that boosts anyway, a second bridge that cannot have hardware offload, a
RouterOS query that reports an enabled rule as missing. None of those are
catchable by reading the rule; all of them are catchable by running it against
twenty-six hosts that are known to be healthy.

The fixture is an anonymised snapshot of the live fleet (tools/make-fixture.py)
with the findings it produced recorded alongside. A rule that starts firing on
a host nobody touched fails here, and so does one that goes quiet.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import issues  # noqa: E402
import probe  # noqa: E402

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "fleet.json")
                     .read_text(encoding="utf-8"))


def fleet() -> list[dict]:
    return copy.deepcopy(FIXTURE["hosts"])


# The thresholds the fleet was actually running with. Replaying the findings
# under the defaults would compare against a dashboard nobody has.
CFG = FIXTURE.get("cfg", {})


def host_named(hosts: list[dict], predicate) -> dict:
    for host in hosts:
        if predicate(host):
            return host
    raise AssertionError("нет подходящего хоста в корпусе")


def keys_for(host: dict) -> list[str]:
    return sorted(issue["key"] for issue in host.get("issues", []))


def test_findings_match_the_recorded_fleet():
    hosts = fleet()
    issues.annotate(hosts, CFG, None)
    for host in hosts:
        assert keys_for(host) == FIXTURE["expect"][host["id"]], host["id"]


def test_every_host_gets_a_level():
    hosts = fleet()
    issues.annotate(hosts, CFG, None)
    for host in hosts:
        assert host["level"] in ("ok", "warn", "bad", "off"), host["id"]


def test_checks_are_answerable_for_every_host():
    """Each check reports one of the statuses the UI knows how to draw."""
    hosts = fleet()
    issues.annotate(hosts, CFG, None)
    issues.annotate_checks(hosts, CFG)
    for host in hosts:
        assert host["checks"], host["id"]
        for check in host["checks"]:
            assert check["status"] in ("ok", "warn", "bad", "info", "muted", "n/a")
            assert check["name"] and check["rule"]


def fires(host: dict, key: str) -> bool:
    issues.annotate([host], CFG, None)
    return any(issue["key"] == key for issue in host["issues"])


def test_link_below_its_own_capability_is_a_finding():
    host = host_named(fleet(), lambda h: h.get("links"))
    host["links"] = [{"name": "eth0", "state": "up", "speed": 100, "capable": 1000,
                      "duplex": "full", "crc": 0, "flaps": 0}]
    assert fires(host, "link:eth0")


def test_link_at_its_capability_is_silent():
    host = host_named(fleet(), lambda h: h.get("links"))
    host["links"] = [{"name": "eth0", "state": "up", "speed": 1000, "capable": 1000,
                      "duplex": "full", "crc": 0, "flaps": 0}]
    assert not fires(host, "link:eth0")


def test_hundred_megabit_without_a_known_capability_is_silent():
    """A camera's port is 100 Mbit by design, and nothing here knows better."""
    host = host_named(fleet(), lambda h: h.get("links"))
    host["links"] = [{"name": "ether5", "state": "up", "speed": 100, "capable": 0,
                      "duplex": "full", "crc": 0, "flaps": 0}]
    assert not fires(host, "link:ether5")


def test_processor_thresholds():
    host = host_named(fleet(), lambda h: h.get("cpu_load_pct") is not None)
    for busy, expected in ((79, None), (80, "warn"), (90, "bad")):
        probe_host = copy.deepcopy(host)
        probe_host["cpu_load_pct"] = busy
        issues.annotate([probe_host], CFG, None)
        found = [i for i in probe_host["issues"] if i["key"] == "cpu"]
        assert (found[0]["level"] if found else None) == expected, busy


def test_restart_between_polls_is_a_finding():
    before = fleet()
    after = fleet()
    unit = {"name": "thing.service", "state": "active/running", "restarts": 3,
            "scope": "user"}
    host_named(before, lambda h: h.get("agent") == "linux")["services"] = [dict(unit)]
    target = host_named(after, lambda h: h.get("agent") == "linux")
    target["services"] = [dict(unit, restarts=4)]
    probe.note_service_changes(before, after)
    issues.annotate(after, CFG, None)
    assert any(i["key"] == "svcflap:thing.service" for i in target["issues"])


def test_a_unit_that_disappeared_is_a_finding():
    before = fleet()
    after = fleet()
    host_named(before, lambda h: h.get("agent") == "linux")["services"] = [
        {"name": "gone.service", "state": "active/running", "restarts": 0,
         "scope": "user"}]
    target = host_named(after, lambda h: h.get("agent") == "linux")
    target["services"] = []
    probe.note_service_changes(before, after)
    issues.annotate(after, CFG, None)
    assert any(i["key"] == "svcgone:gone.service" for i in target["issues"])


def test_first_poll_after_a_restart_says_nothing():
    """Nothing to compare against is not the same as everything being new."""
    after = fleet()
    probe.note_service_changes([], after)
    issues.annotate(after, CFG, None)
    assert not any(i["key"].startswith(("svcflap:", "svcgone:"))
                   for host in after for i in host["issues"])


def test_a_deliberate_cap_is_not_coloured():
    host = host_named(fleet(), lambda h: True)
    host["caps"] = [{"what": "маршрутизация", "detail": "так решили", "level": "info"}]
    issues.annotate([host], CFG, None)
    found = [i for i in host["issues"] if i["key"].startswith("capped:")]
    assert found and found[0]["level"] == "info"
