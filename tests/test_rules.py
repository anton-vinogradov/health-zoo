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
import time
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


def text_of(host: dict, key: str) -> str:
    issues.annotate([host], CFG, None)
    return next((i["text"] for i in host["issues"] if i["key"] == key), "")


def link_host(**fields) -> dict:
    host = host_named(fleet(), lambda h: h.get("links"))
    link = {"name": "eth0", "state": "up", "duplex": "full", "crc": 0, "flaps": 0,
            "autoneg": "on"}
    link.update(fields)
    host["links"] = [link]
    return host


def test_slow_link_blames_the_line_when_both_ends_want_more():
    """Nothing configured says 100: the drop happened on the wire."""
    host = link_host(speed=100, capable=1000, offered=1000, partner=1000)
    assert "кабель или разъём" in text_of(host, "link:eth0")


def test_slow_link_blames_configuration_when_the_port_offers_less():
    host = link_host(speed=100, capable=1000, offered=100, partner=100)
    assert "порт объявляет только" in text_of(host, "link:eth0")


def test_slow_link_blames_configuration_when_negotiation_is_off():
    host = link_host(speed=100, capable=1000, offered=1000, partner=0, autoneg="off")
    assert "автосогласование выключено" in text_of(host, "link:eth0")


def test_slow_link_at_the_neighbours_maximum_is_silent():
    """The camera on a gigabit socket is a 100 Mbit device, not a bad cable."""
    host = link_host(speed=100, capable=1000, offered=1000, partner=100)
    assert not fires(host, "link:eth0")


def test_neighbour_at_a_hundred_after_a_gigabit_is_still_the_line():
    """Ether5: the partner offers 100 now, but the port has run at a gigabit."""
    host = link_host(speed=100, capable=1000, offered=1000, partner=100,
                     speed_best=1000)
    assert "а раньше линк поднимался" in text_of(host, "link:eth0")


def test_link_without_partner_data_keeps_the_bare_finding():
    host = link_host(speed=100, capable=1000)
    assert text_of(host, "link:eth0").endswith("хотя умеет 1 Гбит/с")


def test_routeros_modes_take_the_fastest():
    assert probe._modes_mbit("10M-half,100M-full,1000M-full") == 1000
    assert probe._modes_mbit("10M-half,100M-full") == 100
    assert probe._modes_mbit("2500M-full") == 2500
    assert probe._modes_mbit("") == 0


def test_a_device_that_keeps_failing_to_authenticate_is_a_warning():
    host = host_named(fleet(), lambda h: h.get("radios"))
    host["knocking"] = [{"mac": "38:A5:C9:11:22:33", "ssid": "fclegacy", "attempts": 12}]
    assert fires(host, "authfail:38:A5:C9:11:22:33")


def test_a_couple_of_failed_attempts_are_not_a_finding():
    """A neighbour's phone brushing past is not somebody trying the door."""
    host = host_named(fleet(), lambda h: h.get("radios"))
    host["knocking"] = [{"mac": "38:A5:C9:11:22:33", "ssid": "fclegacy", "attempts": 2}]
    assert not fires(host, "authfail:38:A5:C9:11:22:33")


def camera_host(quiet_hours):
    host = host_named(fleet(), lambda h: h.get("cameras"))
    host["cameras"] = [{"id": "cam1", "name": "Outdoor", "status": "Connected",
                        "enabled": "1", "quiet_hours": quiet_hours}]
    return host


def test_a_silent_camera_can_be_read_and_dismissed():
    host = camera_host(34)
    issues.annotate([host], CFG, None)
    found = [i for i in host["issues"] if i["key"] == "camquiet:cam1"]
    assert found and found[0].get("episodic"), "замечание нельзя снять галочкой"


def test_the_silence_is_named_by_threshold_not_by_the_clock():
    """34 h and 35 h must read the same, or the dismissal evaporates hourly."""
    first = camera_host(34)
    later = camera_host(35)
    issues.annotate([first], CFG, None)
    issues.annotate([later], CFG, None)
    text = lambda host: [i["text"] for i in host["issues"] if i["key"] == "camquiet:cam1"][0]
    assert text(first) == text(later)
    assert "больше суток" in text(first)


def test_another_day_of_silence_speaks_again():
    day, two_days = camera_host(30), camera_host(54)
    issues.annotate([day], CFG, None)
    issues.annotate([two_days], CFG, None)
    text = lambda host: [i["text"] for i in host["issues"] if i["key"] == "camquiet:cam1"][0]
    assert text(day) != text(two_days)
    assert "больше 2 сут" in text(two_days)


def test_a_host_can_be_renamed_and_the_rename_undone(tmp_path):
    """The provider's name is not the operator's name, and neither is final."""
    import settings as settings_mod
    store = settings_mod.Settings(str(tmp_path / "settings.json"))
    cfg = {"hosts": [{"id": "h1", "name": "ubuntu-1cpu-1gb-fi-hel2"}]}
    store.apply_to(cfg)

    store.set_name("h1", "  amnezia  ")
    store.apply_to(cfg)
    assert cfg["hosts"][0]["name"] == "amnezia"

    store.set_name("h1", "")
    store.apply_to(cfg)
    assert cfg["hosts"][0]["name"] == "ubuntu-1cpu-1gb-fi-hel2"


def test_a_name_cannot_break_a_card():
    import settings as settings_mod
    store = settings_mod.Settings("/dev/null")
    assert store.set_name("h1", "две\nстроки\tи\tтабы") == "две строки и табы"
    assert len(store.set_name("h1", "я" * 200)) == 40


def test_a_host_without_an_interval_is_always_due():
    assert probe.due_for_poll({"id": "h"}, {"polled_at": 1000.0}, 1001.0)


def test_a_fragile_host_is_left_alone_between_its_own_polls():
    """A microcontroller with a web server is not a server: it sets its pace."""
    host = {"id": "mesh", "poll_every": 3600}
    assert not probe.due_for_poll(host, {"polled_at": 1000.0}, 1000.0 + 600)
    assert probe.due_for_poll(host, {"polled_at": 1000.0}, 1000.0 + 3600)
    # Never polled at all: ask now, whatever the interval says.
    assert probe.due_for_poll(host, None, 1000.0)


def alerting(tmp_path, script_body, monkeypatch=None):
    import os, stat
    import alerts as alerts_mod
    fake = tmp_path / "telegram"
    fake.write_text(script_body, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    os.environ["HEALTH_ZOO_TG_TOKEN"] = "test-token"
    return alerts_mod.Alerts({"telegram": {
        "enabled": True, "chats": ["1"], "telegram_bin": str(fake),
        "flap_cycles": 1, "startup_summary": False, "digest_hour": -1,
        "state_file": str(tmp_path / "state.json"), "spool": ""}})


def broken_host():
    host = host_named(fleet(), lambda h: h.get("agent") == "linux")
    host["reachable"] = False
    host["error"] = "ssh: connection timed out"
    host["issues"] = [{"level": "bad", "key": "down", "text": "не отвечает"}]
    return host


def test_a_problem_stays_unannounced_while_the_message_cannot_be_sent(tmp_path):
    """The failure that let a server die in silence: reported, then not sent."""
    post = alerting(tmp_path, "#!/bin/sh\nexit 1\n")
    post.process([broken_host()])
    assert not post.active, "проблема помечена сообщённой, хотя отправка провалилась"
    assert post.delivery["ok"] is False


def test_it_is_announced_once_the_message_gets_out(tmp_path):
    post = alerting(tmp_path, "#!/bin/sh\nexit 1\n")
    post.process([broken_host()])
    post.binary = str(tmp_path / "ok")
    ok = tmp_path / "ok"
    ok.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ok.chmod(0o755)
    post.process([broken_host()])
    assert post.active, "после успешной отправки проблема должна считаться сообщённой"
    assert post.delivery["ok"] is True


def test_the_fallback_path_counts_as_delivered(tmp_path):
    """When the usual way out is down, a message that leaves another way is out."""
    import os, stat
    import alerts as alerts_mod
    broken = tmp_path / "telegram"
    broken.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    broken.chmod(broken.stat().st_mode | stat.S_IEXEC)
    # Stands in for ssh: prints what curl would have printed on success.
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\ncat > /dev/null\nprintf 200\n", encoding="utf-8")
    fake_ssh.chmod(fake_ssh.stat().st_mode | stat.S_IEXEC)
    os.environ["HEALTH_ZOO_TG_TOKEN"] = "test-token"
    os.environ["PATH"] = str(tmp_path) + os.pathsep + os.environ["PATH"]

    post = alerts_mod.Alerts({"telegram": {
        "enabled": True, "chats": ["1"], "telegram_bin": str(broken),
        "flap_cycles": 1, "startup_summary": False, "digest_hour": -1,
        "state_file": str(tmp_path / "state.json"), "spool": "",
        "fallback_via": {"host": "somewhere"}}})
    post.process([broken_host()])
    assert post.active, "сообщение ушло запасным путём — проблема должна считаться сообщённой"
    assert post.delivery["ok"] is True


def test_a_multiline_alert_survives_the_fallback_format():
    """A newline used to end the value and take the rest of the alert with it."""
    import alerts as alerts_mod
    text = 'заголовок:\n• первый хост\n• второй хост'
    quoted = alerts_mod._curl_quote(text)
    assert "\n" not in quoted, "перевод строки обрывает значение в конфиге curl"
    assert quoted.count("\\n") == 2
    assert alerts_mod._curl_quote('он сказал "да"') == 'он сказал \\"да\\"'


def test_a_changed_host_key_is_loud():
    """Answering the network while refusing ssh is a different machine, not a hiccup."""
    host = host_named(fleet(), lambda h: h.get("agent") == "linux")
    host["reachable"] = True
    host["error"] = "Host key verification failed."
    issues.annotate([host], CFG, None)
    found = [i for i in host["issues"] if i["key"] == "hostkey"]
    assert found and found[0]["level"] == "bad"
    assert not [i for i in host["issues"] if i["key"] == "noaccess"]


def test_processor_thresholds():
    host = host_named(fleet(), lambda h: h.get("cpu_load_pct") is not None)
    for busy, expected in ((79, None), (80, "warn"), (90, "bad")):
        probe_host = copy.deepcopy(host)
        probe_host["cpu_load_pct"] = busy
        issues.annotate([probe_host], CFG, None)
        found = [i for i in probe_host["issues"] if i["key"] == "cpu"]
        assert (found[0]["level"] if found else None) == expected, busy


def test_busy_processor_names_what_is_using_it():
    """The whole point of the reading: the message says who, not just how much.

    It also has to survive a host that reports the load but no processes —
    every agent that is not Linux, and any Linux host measured before this
    existed.
    """
    host = host_named(fleet(), lambda h: h.get("cpu_load_pct") is not None)
    host["cpu_load_pct"] = 93
    host["procs"] = [
        {"pid": 2841, "pct": 61, "name": "ffmpeg", "cmd": "/usr/bin/ffmpeg -i rtsp://cam4"},
        {"pid": 914, "pct": 24, "name": "python3", "cmd": "python3 -m collector.hub"},
        {"pid": 7, "pct": 3, "name": "kworker/0:1", "cmd": "[kworker/0:1]"},
        {"pid": 12, "pct": 2, "name": "sshd", "cmd": "sshd: randoom"},
    ]
    issues.annotate([host], CFG, None)
    text = [i for i in host["issues"] if i["key"] == "cpu"][0]["text"]
    assert text.startswith("процессор занят на 93%")
    assert "ffmpeg 61%" in text and "python3 24%" in text
    # Three names is a message somebody reads; four is a wall of text.
    assert "sshd" not in text

    quiet = host_named(fleet(), lambda h: h.get("cpu_load_pct") is not None)
    quiet["cpu_load_pct"] = 93
    quiet.pop("procs", None)
    issues.annotate([quiet], CFG, None)
    assert [i for i in quiet["issues"] if i["key"] == "cpu"][0]["text"] == \
        "процессор занят на 93%"


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


def uptime_pair(was: float, now_up: float) -> tuple[list[dict], list[dict]]:
    before, after = fleet(), fleet()
    host_named(before, lambda h: h.get("agent") == "linux")["uptime"] = was
    target = host_named(after, lambda h: h.get("agent") == "linux")
    target["uptime"] = now_up
    return before, after, target


def test_a_reading_that_arrived_out_of_order_is_not_a_reboot():
    """A refresh landing mid-cycle used to make every host it touched "reboot"."""
    before, after, target = uptime_pair(523_400, 523_286)
    probe.note_service_changes(before, after, time.time() - 120)
    assert not target.get("rebooted")


def test_a_real_reboot_is_still_detected():
    before, after, target = uptime_pair(523_400, 90)
    probe.note_service_changes(before, after, time.time() - 180)
    assert target["rebooted"]


def test_a_reboot_during_a_long_outage_is_still_detected():
    """The dashboard was down for an hour; the host restarted 50 minutes ago."""
    before, after, target = uptime_pair(523_400, 3000)
    probe.note_service_changes(before, after, time.time() - 3600)
    assert target["rebooted"]


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

def test_waiting_on_a_disk_is_not_being_busy():
    """The alert that started this: 94% iowait announced as a pegged CPU."""
    host = host_named(fleet(), lambda h: h.get("cpu_load_pct") is not None)
    host.update({"cpu_load_pct": 6, "cpu_iowait_pct": 94, "cpu_steal_pct": 0})
    issues.annotate([host], CFG, None)
    keys = {i["key"]: i["level"] for i in host["issues"]}
    assert keys.get("iowait") == "bad", "ожидание диска должно быть находкой"
    assert "cpu" not in keys, "занятость 6% не должна ни о чём сообщать"


def test_stolen_time_is_reported_separately():
    host = host_named(fleet(), lambda h: h.get("cpu_load_pct") is not None)
    host.update({"cpu_load_pct": 5, "cpu_iowait_pct": 0, "cpu_steal_pct": 30})
    issues.annotate([host], CFG, None)
    assert any(i["key"] == "steal" and i["level"] == "bad" for i in host["issues"])



class FakeAcks:
    """The store as the rules see it: what was said, and for which finding."""

    def __init__(self, items):
        self.items = items

    def for_host(self, host_id):
        return self.items.get(host_id, {})


def test_an_acknowledged_finding_goes_quiet():
    hosts = fleet()
    target = host_named(hosts, lambda h: True)
    target["reboots_week"] = 3
    issues.annotate(hosts, CFG, None)
    said = next(i["text"] for i in target["issues"] if i["key"] == "reboots")

    hosts = fleet()
    target = host_named(hosts, lambda h: True)
    target["reboots_week"] = 3
    issues.annotate(hosts, CFG, None,
                    FakeAcks({target["id"]: {"reboots": {"said": said, "at": 1}}}))
    found = [i for i in target["issues"] if i["key"] == "reboots"]
    assert found and found[0]["acked"] and found[0]["level"] == "info"


def test_it_speaks_again_when_the_fact_changes():
    """Three restarts acknowledged is not four restarts acknowledged."""
    hosts = fleet()
    target = host_named(hosts, lambda h: True)
    target["reboots_week"] = 3
    issues.annotate(hosts, CFG, None)
    said = next(i["text"] for i in target["issues"] if i["key"] == "reboots")

    hosts = fleet()
    target = host_named(hosts, lambda h: True)
    target["reboots_week"] = 4
    issues.annotate(hosts, CFG, None,
                    FakeAcks({target["id"]: {"reboots": {"said": said, "at": 1}}}))
    found = [i for i in target["issues"] if i["key"] == "reboots"]
    assert found and not found[0].get("acked") and found[0]["level"] == "warn"


def test_only_findings_about_events_can_be_dismissed():
    """A state that is still true has no next time to come back at."""
    hosts = fleet()
    target = host_named(hosts, lambda h: True)
    target["reboots_week"] = 3
    target["links"] = [{"name": "eth0", "state": "up", "speed": 100,
                        "capable": 1000, "duplex": "full", "crc": 0, "flaps": 0}]
    issues.annotate(hosts, CFG, None)
    by_key = {i["key"]: i for i in target["issues"]}
    assert by_key["reboots"].get("episodic"), "перезагрузки — событие"
    assert not by_key["link:eth0"].get("episodic"), "скорость линка — состояние"


# ---------- automatic security updates ----------

class FakeSettings:
    """Only what the decision reads: the toggle and the per-host stamp."""

    def __init__(self, **conf):
        self.conf = {"enabled": True, "exclude": [], "min_interval_hours": 6}
        self.conf.update(conf)
        self.stamps = {}

    def auto_security(self):
        return self.conf

    def last_update(self, host_id):
        return self.stamps.get(host_id, 0)

    def note_update(self, host_id, when):
        self.stamps[host_id] = when


class FakeJobs:
    def __init__(self, busy=False):
        self.busy = busy
        self.started = []

    def start(self, targets, fleet):
        if self.busy:
            return None, "занято"
        self.started.append([t["id"] for t in targets])
        return "job1", ""


class FakeAlerts:
    def __init__(self):
        self.said = []

    def notify(self, text):
        self.said.append(text)


def auto_update(hosts, config, settings=None, jobs=None):
    """Run the decision with everything it touches stubbed out."""
    import hub

    class FakeFleet:
        pass

    fleet = FakeFleet()
    fleet.settings = settings or FakeSettings()
    fleet.jobs_ref = jobs or FakeJobs()
    fleet.alerts = FakeAlerts()
    fleet.hosts = lambda: config
    hub.Fleet.maybe_auto_update(fleet, hosts)
    return fleet


def test_a_security_update_starts_by_itself():
    hosts = [{"id": "srv", "name": "srv", "security_count": 2, "update_count": 7}]
    fleet = auto_update(hosts, [{"id": "srv", "updatable": True}])
    assert fleet.jobs_ref.started == [["srv"]]
    assert "закрывают уязвимости" in fleet.alerts.said[0]


def test_updates_that_are_not_security_wait_for_a_human():
    hosts = [{"id": "srv", "name": "srv", "security_count": 0, "update_count": 40}]
    fleet = auto_update(hosts, [{"id": "srv", "updatable": True}])
    assert fleet.jobs_ref.started == []


def test_a_host_the_config_does_not_allow_is_left_alone():
    hosts = [{"id": "nas", "name": "nas", "security_count": 5, "update_count": 5}]
    fleet = auto_update(hosts, [{"id": "nas", "updatable": False}])
    assert fleet.jobs_ref.started == []


def test_a_failed_update_is_not_retried_every_poll():
    hosts = [{"id": "srv", "name": "srv", "security_count": 2, "update_count": 2}]
    settings = FakeSettings()
    settings.stamps["srv"] = int(__import__("time").time()) - 600  # 10 минут назад
    fleet = auto_update(hosts, [{"id": "srv", "updatable": True}], settings)
    assert fleet.jobs_ref.started == []


def test_one_host_at_a_time():
    hosts = [{"id": "a", "name": "a", "security_count": 1, "update_count": 1},
             {"id": "b", "name": "b", "security_count": 1, "update_count": 1}]
    config = [{"id": "a", "updatable": True}, {"id": "b", "updatable": True}]
    fleet = auto_update(hosts, config)
    assert fleet.jobs_ref.started == [["a"]], "второй хост ждёт следующего опроса"


def test_switching_it_off_stops_it():
    hosts = [{"id": "srv", "name": "srv", "security_count": 9, "update_count": 9}]
    fleet = auto_update(hosts, [{"id": "srv", "updatable": True}],
                        FakeSettings(enabled=False))
    assert fleet.jobs_ref.started == []
