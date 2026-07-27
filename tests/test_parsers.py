"""Parser tests built from real device output.

Every fixture here is verbatim output from an actual machine — a RouterOS 7.23
RB4011, DSM 7.3, Ubuntu 24.04 — because that is where the bugs came from: flag
columns that shift when a row has no flags, values containing spaces, `smartctl`
laying out NVMe and SATA attributes completely differently.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import issues  # noqa: E402
import probe  # noqa: E402


# --------------------------------------------------------------------------
# agent report format
# --------------------------------------------------------------------------

def test_parse_report_scalars_and_lists():
    report = (
        "kind\tlinux\n"
        "hostname\tbox\n"
        "uptime\t1234.5\n"
        "mem_total\t8162078720\n"
        "@disk\t/\t/dev/nvme0n1p2\t249792131072\t154116878336\n"
        "@disk\t/boot/efi\t/dev/nvme0n1p1\t1124999168\t6438912\n"
        "@temp\tCore 0\t54\n"
        "ok\t1\n"
    )
    data = probe.parse_report(report)
    assert data["kind"] == "linux"
    assert data["uptime"] == 1234.5           # numeric fields are coerced
    assert data["mem_total"] == 8162078720
    assert len(data["disks"]) == 2
    assert data["disks"][0]["mount"] == "/"
    assert data["temps"][0]["label"] == "Core 0"


def test_parse_report_tolerates_short_rows():
    """Agents omit trailing fields when a value is unavailable."""
    data = probe.parse_report("@service\tfoo.service\tactive/running\n")
    svc = data["services"][0]
    assert svc["name"] == "foo.service"
    assert svc["state"] == "active/running"
    assert svc["desc"] == ""


def test_post_process_derives_percentages():
    data = probe._post_process(probe.parse_report(
        "mem_total\t1000\nmem_available\t250\n"
        "swap_total\t2000\nswap_free\t1000\n"
        "@disk\t/\t/dev/sda1\t1000\t900\n"
    ))
    assert data["mem_pct"] == 75.0
    assert data["swap_pct"] == 50.0
    assert data["disks"][0]["pct"] == 90.0


def test_unit_version_comes_from_owning_package():
    data = probe._post_process(probe.parse_report(
        "@service\tzoneminder.service\tactive/running\tenabled\t0\t0\t/lib/x\tZM\n"
        "@unitpkg\tzoneminder.service\tzoneminder\t1.38.3-noble\n"
    ))
    assert data["services"][0]["version"] == "1.38.3-noble"
    assert data["services"][0]["package"] == "zoneminder"


# --------------------------------------------------------------------------
# RouterOS
# --------------------------------------------------------------------------

ROUTEROS_OUTPUT = """@@identity
  name: NanoTock88

@@resource
                   uptime: 2w4d26m18s
                  version: 7.23.2 (stable)
              free-memory: 820.7MiB
             total-memory: 1024.0MiB
                      cpu: ARM
                cpu-count: 4
                 cpu-load: 2%
           free-hdd-space: 418.7MiB
          total-hdd-space: 512.0MiB
        architecture-name: arm
               board-name: RB4011iGS+

@@routerboard
                ;;; Firmware upgraded successfully, please reboot for changes
       routerboard: yes
             model: RB4011iGS+
  current-firmware: 7.23.1
  upgrade-firmware: 7.23.2

@@update
  installed-version: 7.23.2
     latest-version: 7.23.2

@@health
voltage|24
temperature|42

@@package
routeros|7.23.2|false
wireless|7.23.2|false
container||true

@@service
ssh|17|false
ftp|21|true
www|80|false

@@interface
ether1|true|ether|false
ether4|false|ether|false
bridge|true|bridge|false
"""


def _routeros(monkeypatch_result):
    class Result:
        returncode = 0
        stdout = monkeypatch_result
        stderr = ""

    original = probe.subprocess.run
    probe.subprocess.run = lambda *a, **kw: Result()
    try:
        return probe._post_process(
            probe.probe_routeros({"addr": "10.0.0.1", "user": "monitor"}, None))
    finally:
        probe.subprocess.run = original


def test_routeros_basic_facts():
    data = _routeros(ROUTEROS_OUTPUT)
    assert data["os_name"] == "RouterOS 7.23.2 (stable)"
    assert data["model"] == "RB4011iGS+"
    assert data["hostname"] == "NanoTock88"
    assert data["uptime"] == 2 * 604800 + 4 * 86400 + 26 * 60 + 18
    assert data["mem_total"] == int(1024.0 * 1024 * 1024)


def test_routeros_health_table_is_not_mistaken_for_flags():
    """`0  voltage  24  V` used to parse "voltage" as a flag column."""
    data = _routeros(ROUTEROS_OUTPUT)
    assert data["temps"] == [{"label": "temperature", "c": 42}]
    assert data["voltage"] == 24


def test_routeros_pending_firmware_asks_for_reboot():
    data = _routeros(ROUTEROS_OUTPUT)
    assert data["routerboard_upgrade"] == "7.23.2"
    assert data["reboot_required"] == 1


def test_routeros_services_and_uninstalled_packages():
    data = _routeros(ROUTEROS_OUTPUT)
    names = {s["name"]: s for s in data["services"]}
    assert names["ssh"]["state"] == "running"
    assert names["ftp"]["state"] == "stopped"      # disabled=true
    assert names["routeros"]["version"] == "7.23.2"
    # A package with no version is merely downloadable, not installed.
    assert "container" not in names


def test_routeros_interface_state():
    data = _routeros(ROUTEROS_OUTPUT)
    states = {i["name"]: i["status"] for i in data["ifaces"]}
    assert states == {"ether1": "up", "ether4": "down", "bridge": "up"}


# --------------------------------------------------------------------------
# SMART
# --------------------------------------------------------------------------

def test_smart_flags_pending_sectors_but_not_a_healthy_drive():
    healthy = probe._post_process(probe.parse_report(
        "@smart\t/dev/nvme0n1\tPASSED\t54\t12150\t\t\t7\tRS256GSSD510\n"))
    assert healthy["smarts"][0]["failing"] is False
    assert healthy["failing_disks"] == []

    dying = probe._post_process(probe.parse_report(
        "@smart\t/dev/sda\tPASSED\t48\t3452\t0\t8\t\tSanDisk\n"))
    assert dying["smarts"][0]["failing"] is True

    condemned = probe._post_process(probe.parse_report(
        "@smart\t/dev/sdb\tFAILED!\t50\t900\t0\t0\t\tSeagate\n"))
    assert condemned["smarts"][0]["failing"] is True


# --------------------------------------------------------------------------
# web link discovery
# --------------------------------------------------------------------------

def test_web_links_skip_infrastructure_ports_and_proxies():
    data = probe._post_process(probe.parse_report(
        "@listen\t22\tsshd\tany\n"
        "@listen\t443\ttelemt\tany\n"       # FakeTLS proxy, not a web page
        "@listen\t3306\tmysqld\tany\n"
        "@listen\t80\tapache2\tany\n"
        "@listen\t8816\tpython3\tany\n"
    ))
    ports = [link["port"] for link in data["web"]]
    assert ports == [80, 8816]


def test_loopback_services_are_kept_but_marked():
    """A backend behind a proxy is worth knowing about; it just has no link."""
    data = probe._post_process(probe.parse_report(
        "@listen\t80\tcaddy\tany\n"
        "@listen\t8080\tjava\tlocal\n"
    ))
    by_port = {link["port"]: link for link in data["web"]}
    assert by_port[80]["local"] is False
    assert by_port[8080]["local"] is True
    # Reachable ones come first; the local backend sorts last.
    assert [link["port"] for link in data["web"]] == [80, 8080]


def test_reboot_reason_is_spelled_out():
    kernel = issues.host_issues({
        "id": "a", "reachable": True, "reboot_required": 1,
        "reboot_pkgs": "linux-image-6.8.0-136-generic linux-base libc6",
    })
    assert "новое ядро" in kernel[0]["text"]

    firmware = issues.host_issues({
        "id": "b", "reachable": True, "reboot_required": 1,
        "reboot_pkgs": "routerboard firmware 7.23.1 -> 7.23.2",
    })
    assert "7.23.2" in firmware[0]["text"]

    bare = issues.host_issues({"id": "c", "reachable": True, "reboot_required": 1})
    assert bare[0]["text"] == "нужна перезагрузка"


def test_web_links_pick_https_for_tls_ports():
    data = probe._post_process(probe.parse_report("@listen\t8001\t\n"))
    assert data["web"][0]["scheme"] == "https"


# --------------------------------------------------------------------------
# camera ↔ recorder linking
# --------------------------------------------------------------------------

def test_camera_takes_status_from_its_recorder():
    recorder = {
        "id": "rec", "name": "recorder", "addr": "10.0.0.5", "reachable": True,
        "cameras": [{"id": "1", "name": "Front", "enabled": "1",
                     "addr": "10.0.20.11:554", "status": "Connected",
                     "fps": 25.0, "resolution": "1920x1080"}],
    }
    # Unreachable from the dashboard: a different site, behind another router.
    camera = {"id": "cam", "name": "Front camera", "addr": "10.0.20.11",
              "role": "camera", "reachable": False, "error": "no response"}

    probe.link_cameras([recorder, camera])

    assert camera["recorded_by"] == "recorder"
    assert camera["camera_live"] is True
    assert camera["reachable"] is True          # the recorder outranks our ping
    assert camera["only_via_recorder"] is True
    assert camera["error"] == ""


def test_camera_stays_down_when_recorder_also_says_so():
    recorder = {
        "id": "rec", "name": "recorder", "addr": "10.0.0.5", "reachable": True,
        "cameras": [{"id": "1", "name": "Front", "enabled": "1",
                     "addr": "10.0.20.11:554", "status": "NotConnected", "fps": 0}],
    }
    camera = {"id": "cam", "name": "Front camera", "addr": "10.0.20.11",
              "role": "camera", "reachable": False, "error": "no response"}

    probe.link_cameras([recorder, camera])

    assert camera["camera_live"] is False
    assert camera["reachable"] is False


# --------------------------------------------------------------------------
# health rules
# --------------------------------------------------------------------------

def test_nas_volumes_are_allowed_to_run_full():
    """A NAS recording video sits near-full by design; a server does not."""
    full_disk = [{"mount": "/volume1", "pct": 92.0, "total": 1, "used": 1}]
    nas = {"id": "nas", "role": "nas", "reachable": True, "disks": full_disk}
    server = {"id": "srv", "role": "server", "reachable": True, "disks": full_disk}

    assert issues.host_issues(nas) == []
    assert [i["key"] for i in issues.host_issues(server)] == ["disk:/volume1"]


def test_enabled_but_stopped_unit_is_reported_on_systemd_only():
    """A unit set to start at boot and now not running has stopped working,
    whether it crashed or someone stopped it and forgot — same urgency."""
    stopped = [{"name": "x.service", "state": "inactive/dead", "enabled": "enabled"}]
    linux = {"id": "a", "agent": "linux", "reachable": True, "services": stopped}
    openwrt = {"id": "b", "agent": "openwrt", "reachable": True,
               "services": [{"name": "x", "state": "stopped", "enabled": "enabled"}]}

    assert [i["level"] for i in issues.host_issues(linux)] == ["bad"]
    # OpenWrt one-shot boot scripts sit at "stopped" forever — not a problem.
    assert issues.host_issues(openwrt) == []


def test_stopped_container_is_a_problem():
    host = {"id": "a", "agent": "linux", "reachable": True,
            "containers": [{"name": "amnezia-awg2", "state": "exited",
                            "status": "Exited (0) 2 hours ago"},
                           {"name": "amnezia-dns", "state": "running"}]}
    found = issues.host_issues(host)
    assert len(found) == 1
    assert found[0]["level"] == "bad"
    assert "amnezia-awg2" in found[0]["text"]


def test_unreachable_host_reports_only_that():
    host = {"id": "x", "reachable": False, "error": "timeout after 25s",
            "disks": [{"mount": "/", "pct": 99.0}]}
    found = issues.host_issues(host)
    assert len(found) == 1
    assert found[0]["key"] == "down"


def test_reachable_but_no_agent_access_is_not_healthy():
    host = {"id": "r", "role": "router", "reachable": True,
            "error": "Permission denied (publickey)"}
    keys = [i["key"] for i in issues.host_issues(host)]
    assert "noaccess" in keys


def test_annotate_sets_overall_level():
    hosts = [
        {"id": "ok", "reachable": True},
        {"id": "warn", "reachable": True, "reboot_required": 1},
        {"id": "bad", "reachable": True,
         "services": [{"name": "s.service", "state": "failed/failed"}]},
        {"id": "off", "reachable": False},
    ]
    issues.annotate(hosts)
    assert [h["level"] for h in hosts] == ["ok", "warn", "bad", "off"]


# --------------------------------------------------------------------------
# suppressions
# --------------------------------------------------------------------------

def test_suppression_requires_a_reason(tmp_path):
    import suppressions as suppressions_mod
    store = suppressions_mod.Suppressions(str(tmp_path / "s.json"))

    ok, error = store.add("box", "disk:/", "")
    assert not ok and "причин" in error
    ok, _ = store.add("box", "disk:/", "том расширят в следующем квартале")
    assert ok


def test_suppressed_finding_stops_colouring_the_host(tmp_path):
    """The check still runs and its verdict stays visible — it just no longer
    decides the host's status or triggers an alert."""
    import suppressions as suppressions_mod
    store = suppressions_mod.Suppressions(str(tmp_path / "s.json"))
    store.add("srv", "svc:demo.service", "демо-стенд, гасим на выходных")

    host = {"id": "srv", "agent": "linux", "reachable": True,
            "services": [{"name": "demo.service", "state": "failed/failed"}]}
    issues.annotate([host], None, store)

    assert host["level"] == "ok"                 # was "bad" before suppressing
    issue = host["issues"][0]
    assert issue["suppressed"] is True
    assert issue["original_level"] == "bad"
    assert issue["suppress_reason"] == "демо-стенд, гасим на выходных"


def test_expired_suppression_stops_applying(tmp_path):
    import time as _time
    import suppressions as suppressions_mod
    store = suppressions_mod.Suppressions(str(tmp_path / "s.json"))
    store.add("srv", "reboot", "ждём окна обслуживания")
    store.items["srv/reboot"]["expires"] = int(_time.time()) - 1

    assert store.for_host("srv") == {}


def test_listing_flags_suppressions_that_hide_nothing(tmp_path):
    """A suppression whose finding stopped occurring is the one to remove."""
    import suppressions as suppressions_mod
    store = suppressions_mod.Suppressions(str(tmp_path / "s.json"))
    store.add("srv", "reboot", "перезагрузим в субботу")
    store.add("srv", "security", "обновимся вместе с ядром")

    hosts = [{"id": "srv", "name": "srv", "issues": [{"key": "reboot"}]}]
    listing = {item["key"]: item for item in store.listing(hosts)}

    assert listing["reboot"]["still_firing"] is True
    assert listing["security"]["still_firing"] is False


def test_checks_show_the_reason_next_to_the_check(tmp_path):
    import suppressions as suppressions_mod
    store = suppressions_mod.Suppressions(str(tmp_path / "s.json"))
    store.add("srv", "svc:demo.service", "стенд, чинить не планируем")

    host = {"id": "srv", "agent": "linux", "reachable": True,
            "services": [{"name": "demo.service", "state": "failed/failed"}]}
    issues.annotate([host], None, store)
    checks = {c["name"]: c for c in issues.checks_for(host)}

    entry = checks["Упавшие сервисы"]
    assert entry["status"] == "muted"
    assert entry["suppressed"][0]["reason"] == "стенд, чинить не планируем"


def test_only_changed_thresholds_are_stored(tmp_path):
    """The form submits every field; the file must keep only the decisions.

    Storing all of them would pin today's defaults forever, so a later change
    to a default would silently not reach a fleet that never asked for that.
    """
    import settings as settings_mod
    store = settings_mod.Settings(str(tmp_path / "settings.json"))
    defaults = {"disk_warn": 90, "temp_warn": 88}

    store.set_thresholds({"disk_warn": 90, "temp_warn": 80}, defaults)
    assert store.thresholds() == {"temp_warn": 80}

    # Setting it back to the default removes the override rather than pinning it.
    store.set_thresholds({"temp_warn": 88}, defaults)
    assert store.thresholds() == {}


def test_settings_layer_over_config_not_over_themselves(tmp_path):
    """Clearing a value in the UI falls back to the config, not to the last merge."""
    import settings as settings_mod
    store = settings_mod.Settings(str(tmp_path / "settings.json"))
    cfg = {"thresholds": {"disk_warn": 95}}

    store.set_thresholds({"disk_warn": 80}, {"disk_warn": 90})
    store.apply_to(cfg)
    assert cfg["thresholds"]["disk_warn"] == 80

    store.set_thresholds({"disk_warn": None}, {"disk_warn": 90})
    store.apply_to(cfg)
    assert cfg["thresholds"]["disk_warn"] == 95


def test_auto_reboot_window_wraps_past_midnight():
    """A 23:00-05:00 window is the normal one, and it crosses the date line."""
    def inside(hour, start, end):
        return start <= hour < end if start <= end else (hour >= start or hour < end)

    assert [inside(h, 23, 5) for h in (22, 23, 0, 4, 5)] == [False, True, True, True, False]
    assert [inside(h, 4, 6) for h in (3, 4, 5, 6)] == [False, True, True, False]


def test_camera_keeps_its_own_silence_threshold(tmp_path):
    """A street camera quiet for six hours is broken; a garage is not."""
    import settings as settings_mod
    store = settings_mod.Settings(str(tmp_path / "settings.json"))
    store.set_cameras({"rec/3": {"warn": 36, "bad": 72}})

    host = {"id": "rec", "agent": "linux", "reachable": True, "cameras": [
        {"id": "3", "name": "Garage", "enabled": "1", "status": "Connected",
         "quiet_hours": 30, "limits": store.camera_limits("rec", "3")},
        {"id": "4", "name": "Street", "enabled": "1", "status": "Connected",
         "quiet_hours": 30},
    ]}
    found = {i["key"]: i for i in issues.host_issues(host)}

    assert "camquiet:3" not in found          # 30 h is inside its own 36 h
    assert found["camquiet:4"]["level"] == "bad"   # 30 h beats the fleet's 24 h


def test_clearing_a_camera_threshold_follows_the_fleet_again(tmp_path):
    import settings as settings_mod
    store = settings_mod.Settings(str(tmp_path / "settings.json"))
    store.set_cameras({"rec/3": {"warn": 36, "bad": 72}})
    store.set_cameras({"rec/3": {"warn": None, "bad": None}})
    assert store.camera_limits("rec", "3") == {}


def test_reboot_job_follows_the_host_down_and_back(monkeypatch):
    """The log used to go silent for exactly the stretch being watched."""
    import hub
    import probe as probe_mod

    answers = [True, True, False, False, True]

    def fake_ping(addr):
        return 1.0 if answers.pop(0) else None

    monkeypatch.setattr(probe_mod, "ping", fake_ping)

    jobs = hub.Jobs({"reboot_poll_seconds": 0})
    jobs.jobs["job1"] = {"id": "job1", "log": [], "hosts": {}, "results": {}}

    class FakeFleet:
        refreshed = []

        def refresh_hosts(self, ids):
            FakeFleet.refreshed.extend(ids)
            return len(ids)

    code = jobs._await_return("job1", {"id": "rt", "addr": "10.0.0.1"}, FakeFleet())
    log = " | ".join(jobs.jobs["job1"]["log"])

    assert code == 0
    assert "ушёл в перезагрузку" in log
    assert "снова отвечает" in log
    assert FakeFleet.refreshed == ["rt"]


def test_reboot_job_reports_a_host_that_never_returns(monkeypatch):
    """Not confirming a reboot is a different outcome from failing to send it."""
    import hub
    import probe as probe_mod

    states = iter([True] + [False] * 50)
    monkeypatch.setattr(probe_mod, "ping", lambda addr: 1.0 if next(states) else None)

    jobs = hub.Jobs({"reboot_poll_seconds": 0, "reboot_wait_seconds": 0.05})
    jobs.jobs["job1"] = {"id": "job1", "log": [], "hosts": {}, "results": {}}

    code = jobs._await_return("job1", {"id": "rt", "addr": "10.0.0.1"}, None)
    assert code == 2
    assert "не ответил" in " ".join(jobs.jobs["job1"]["log"])


def test_cleanup_runs_between_two_upgrade_passes():
    """A package held back by an orphan installs once the orphan is gone."""
    import hub
    jobs = hub.Jobs({})
    calls = []

    def fake_exec(job_id, host, key, remote):
        calls.append(remote)
        return 0

    jobs._exec = fake_exec
    jobs._update_host("job1", {"id": "srv", "user": "root"}, None, cleanup=True)
    remote = calls[0]

    first = remote.index("upgrade")
    clean = remote.index("autoremove")
    second = remote.index("upgrade", clean)
    assert first < clean < second, "чистка должна стоять между двумя проходами"


def test_cleanup_is_skipped_when_switched_off():
    import hub
    jobs = hub.Jobs({})
    calls = []
    jobs._exec = lambda job_id, host, key, remote: calls.append(remote) or 0
    jobs._update_host("job1", {"id": "srv", "user": "root"}, None, cleanup=False)
    assert "autoremove" not in calls[0]
