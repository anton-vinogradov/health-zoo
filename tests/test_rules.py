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
import re
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
            assert check["status"] in ("ok", "warn", "bad", "info", "muted",
                                       "unknown", "n/a")
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


def test_every_threshold_is_read_by_something():
    """A threshold nobody consults is a promise the dashboard does not keep.

    `cpu_warn` sat in the table from the first commit with no rule reading it,
    and a machine pinned at 100% stayed green for as long as that lasted.
    """
    root = Path(__file__).resolve().parent.parent
    code = "\n".join(
        (root / "collector" / name).read_text(encoding="utf-8")
        for name in ("issues.py", "alerts.py", "hub.py"))
    code += "\n".join(path.read_text(encoding="utf-8")
                      for path in (root / "ui").glob("*.js"))
    dynamic = set(re.findall(r"['\"]_(\w+)['\"]", code))
    forgotten = [name for name in issues.DEFAULT_THRESHOLDS
                 if code.count(f'"{name}"') + code.count(f"'{name}'") <= 1
                 and name.split("_")[-1] not in dynamic]
    assert not forgotten, f"пороги без читателя: {forgotten}"


def test_unusual_for_this_host_needs_both_guards():
    """Twice the habit, and high enough that the multiple means something."""
    host = host_named(fleet(), lambda h: True)
    cases = (({"now": 55.0, "usual": 12.0, "samples": 400}, True),   # новое поведение
             ({"now": 6.0, "usual": 2.0, "samples": 400}, False),    # арифметика, не новость
             ({"now": 40.0, "usual": 31.0, "samples": 400}, False),  # обычный вечер
             ({"now": 90.0, "usual": 0.0, "samples": 400}, False))   # делить не на что
    for norm, expected in cases:
        probe_host = copy.deepcopy(host)
        probe_host["baselines"] = {"процессор занят": norm}
        issues.annotate([probe_host], CFG, None)
        fired = any(i["key"].startswith("unusual:") for i in probe_host["issues"])
        assert fired is expected, norm


def test_a_restart_between_polls_is_noticed():
    before = fleet()
    after = fleet()
    host_named(before, lambda h: h.get("uptime"))["uptime"] = 900000
    target = host_named(after, lambda h: h.get("uptime"))
    target["uptime"] = 120
    probe.note_service_changes(before, after)
    assert target.get("rebooted")
    issues.annotate(after, CFG, None)
    assert any(i["key"] == "rebooted" for i in target["issues"])


def test_a_restart_we_asked_for_is_not_a_finding():
    hosts = fleet()
    target = host_named(hosts, lambda h: h.get("uptime"))
    target.update({"rebooted": True, "reboot_planned": True, "uptime": 120})
    issues.annotate(hosts, CFG, None)
    assert not any(i["key"] == "rebooted" for i in target["issues"])


def test_repeated_restarts_escalate():
    for count, expected in ((2, None), (3, "warn"), (5, "bad")):
        host = host_named(fleet(), lambda h: True)
        host["reboots_week"] = count
        issues.annotate([host], CFG, None)
        found = [i for i in host["issues"] if i["key"] == "reboots"]
        assert (found[0]["level"] if found else None) == expected, count


def test_an_expired_certificate_reads_as_expired():
    """"Expires in -19 days" is not a sentence anybody should have to parse."""
    host = host_named(fleet(), lambda h: True)
    host["outside"] = [{"port": 2053, "tls": True, "days": -18.6,
                        "subject": "CN = panel", "from": "сосед"}]
    issues.annotate([host], CFG, None)
    found = [i for i in host["issues"] if i["key"] == "certout:2053"]
    assert found and found[0]["level"] == "bad"
    assert "истёк 19 дн назад" in found[0]["text"]


def test_a_certificate_that_differs_from_outside_is_a_finding():
    host = host_named(fleet(), lambda h: True)
    host["web"] = [{"port": 443, "cert": {"subject": "CN = свой"}}]
    host["outside"] = [{"port": 443, "tls": True, "days": 100,
                        "subject": "CN = чужой", "from": "сосед"}]
    issues.annotate([host], CFG, None)
    assert any(i["key"] == "certdiff:443" for i in host["issues"])


def test_rent_is_counted_down():
    """A host switched off for non-payment looks exactly like a dead one."""
    import time as _time
    host = host_named(fleet(), lambda h: True)
    for offset, expected in ((30, None), (5, "warn"), (1, "bad"), (-3, "bad")):
        probe_host = copy.deepcopy(host)
        probe_host["paid_until"] = _time.strftime(
            "%Y-%m-%d", _time.localtime(_time.time() + offset * 86400))
        issues.annotate([probe_host], CFG, None)
        found = [i for i in probe_host["issues"] if i["key"] == "paid"]
        assert (found[0]["level"] if found else None) == expected, offset


def test_an_unparseable_date_says_so():
    host = host_named(fleet(), lambda h: True)
    host["paid_until"] = "первого сентября"
    issues.annotate([host], CFG, None)
    assert any(i["key"] == "paid" and "не разобрал" in i["text"]
               for i in host["issues"])


def test_provider_forecast_drives_the_balance_warning():
    """The provider computes when the money runs out; we only count the days."""
    host = host_named(fleet(), lambda h: True)
    for days, expected in ((40, None), (8, "warn"), (2, "bad"), (-1, "bad")):
        probe_host = copy.deepcopy(host)
        probe_host["billing"] = {"days_left": days, "forecast": "2026-08-10"}
        issues.annotate([probe_host], CFG, None)
        found = [i for i in probe_host["issues"] if i["key"] == "balance"]
        assert (found[0]["level"] if found else None) == expected, days


def test_an_unplanned_restart_reaches_the_operator():
    """A power cut, a watchdog, a crash and somebody at the keyboard all look
    the same by the next poll — and all four are worth a message, not a note on
    a screen nobody is watching at 03:00."""
    hosts = fleet()
    target = host_named(hosts, lambda h: h.get("uptime"))
    target.update({"rebooted": True, "reboot_planned": False, "uptime": 240})
    issues.annotate(hosts, CFG, None)

    found = [i for i in target["issues"] if i["key"] == "rebooted"]
    assert found and found[0]["level"] == "bad", "иначе алерт не уйдёт: info не алертит"
    assert "не с дашборда" in found[0]["text"]


def test_a_one_off_command_is_not_a_broken_service():
    """systemd-run leaves run-uNNNN behind; that is a finished job, not a
    service that stopped doing its job."""
    hosts = fleet()
    target = host_named(hosts, lambda h: h.get("services"))
    target["services"] = [{"name": "run-u6525.service", "state": "failed",
                           "scope": "system"}]
    issues.annotate(hosts, CFG, None)

    found = [i for i in target["issues"] if i["key"].startswith("svc:run-")]
    assert found and found[0]["level"] == "info"
    assert target["level"] != "bad"
