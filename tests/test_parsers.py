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
