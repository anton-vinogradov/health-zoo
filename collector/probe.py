"""Host probing for health-zoo.

One agent script per OS family is streamed over `ssh host sh -s`; nothing is
installed on the targets. The agents emit a tab-separated report (PROTOCOL.md)
which `parse_report` turns into the JSON the dashboard consumes.

Hosts we cannot log into are still probed at the network level, so a router
with no SSH access shows up as reachable rather than missing.
"""

from __future__ import annotations

import concurrent.futures
import html
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent / "agents"

# Enough for a busy Celeron to answer, short enough that one dead host does not
# hold up the whole cycle.
SSH_TIMEOUT = 25
PING_TIMEOUT = 2
PORT_TIMEOUT = 2

SSH_BASE = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "LogLevel=ERROR",
]

# Report lines starting with '@' are list entries; their fields are named here.
LIST_FIELDS = {
    "disk": ["mount", "fs", "total", "used"],
    "temp": ["label", "c"],
    "update": ["pkg", "old", "new", "security", "suite"],
    "service": ["name", "state", "enabled", "since_mono", "restarts", "path", "desc"],
    "timer": ["name", "state", "next", "desc"],
    "unitpkg": ["unit", "pkg", "version"],
    "container": ["name", "image", "state", "status"],
    "repo": ["path", "branch", "commit", "describe", "committed"],
    "camera": ["id", "name", "enabled", "addr", "resolution", "status",
               "fps", "afps", "bandwidth", "last_event", "retention_days"],
    "camlink": ["addr", "proto"],
    "smart": ["dev", "health", "temp", "hours", "realloc", "pending", "wear", "model"],
    "listen": ["port", "process", "scope"],
    "udp": ["port", "process", "scope"],
    "raid": ["dev", "level", "state"],
    "backup": ["task", "name", "folders"],
    "backuprepo": ["name", "last", "size"],
    "unbacked": ["share", "volume"],
    "iface": ["name", "status", "rx", "tx", "comment"],
    "neighbor": ["id", "name", "snr", "hops", "last_heard", "battery"],
}

NUMERIC = {
    "uptime", "load1", "load5", "load15", "cpus",
    "mem_total", "mem_available", "mem_free", "swap_total", "swap_free",
    "pkg_list_mtime", "reboot_required", "zoneminder", "surveillance",
    "zm_events_count", "zm_last_event", "zm_events_bytes", "ok",
    "cpu_load_pct", "free_flash", "total_flash",
}


def _num(value: str):
    """Best-effort numeric coercion; agents emit everything as text."""
    try:
        if "." in value:
            return float(value)
        return int(value)
    except (TypeError, ValueError):
        return value


def parse_report(text: str) -> dict:
    """Turn an agent report into a nested dict."""
    out: dict = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split("\t")
        key = parts[0]
        if key.startswith("@"):
            kind = key[1:]
            fields = LIST_FIELDS.get(kind)
            values = parts[1:]
            if fields:
                entry = {}
                for i, name in enumerate(fields):
                    entry[name] = values[i].strip() if i < len(values) else ""
            else:
                entry = {"values": values}
            out.setdefault(kind + "s", []).append(entry)
        else:
            value = parts[1] if len(parts) > 1 else ""
            out[key] = _num(value) if key in NUMERIC else value
    return out


def _post_process(data: dict) -> dict:
    """Derive the numbers the UI shows, so the browser does no arithmetic."""
    mem_total = data.get("mem_total") or 0
    mem_avail = data.get("mem_available")
    if mem_avail is None:
        mem_avail = data.get("mem_free") or 0
    if mem_total:
        data["mem_used"] = mem_total - mem_avail
        data["mem_pct"] = round((mem_total - mem_avail) * 100.0 / mem_total, 1)

    swap_total = data.get("swap_total") or 0
    swap_free = data.get("swap_free") or 0
    if swap_total:
        data["swap_used"] = swap_total - swap_free
        data["swap_pct"] = round((swap_total - swap_free) * 100.0 / swap_total, 1)

    for disk in data.get("disks", []):
        total = _num(disk.get("total", 0)) or 0
        used = _num(disk.get("used", 0)) or 0
        disk["total"], disk["used"] = total, used
        disk["pct"] = round(used * 100.0 / total, 1) if total else 0.0

    for temp in data.get("temps", []):
        temp["c"] = _num(temp.get("c", 0))

    # A unit's version comes from the package that owns it.
    versions = {u["unit"]: u for u in data.get("unitpkgs", [])}
    for svc in data.get("services", []):
        hit = versions.get(svc["name"])
        if hit:
            svc["version"] = hit["version"]
            svc["package"] = hit["pkg"]
        svc["restarts"] = _num(svc.get("restarts", 0))
        # Monotonic microseconds since boot -> wall-clock start time.
        since_mono = _num(svc.get("since_mono", 0)) or 0
        uptime = data.get("uptime") or 0
        if since_mono and uptime:
            data_now = time.time()
            svc["started"] = int(data_now - uptime + since_mono / 1_000_000)
        svc.pop("since_mono", None)

    updates = data.get("updates", [])
    data["update_count"] = len(updates)
    data["security_count"] = sum(1 for u in updates if u.get("security") == "1")

    for cam in data.get("cameras", []):
        for field in ("fps", "afps", "bandwidth", "last_event", "retention_days"):
            if field in cam:
                cam[field] = _num(cam[field])

    for disk in data.get("smarts", []):
        for field in ("temp", "hours", "realloc", "pending", "wear"):
            if disk.get(field) not in (None, ""):
                disk[field] = _num(disk[field])
        # A drive is failing if SMART says so, or if it is quietly relocating
        # sectors — pending sectors in particular precede real data loss.
        bad = disk.get("health", "").upper() not in ("PASSED", "OK", "")
        bad = bad or (isinstance(disk.get("pending"), int) and disk["pending"] > 0)
        bad = bad or (isinstance(disk.get("realloc"), int) and disk["realloc"] > 0)
        disk["failing"] = bad
    data["failing_disks"] = [d for d in data.get("smarts", []) if d.get("failing")]

    for repo in data.get("backuprepos", []):
        repo["last"] = _num(repo.get("last", 0)) or 0
        repo["size"] = _num(repo.get("size", 0)) or 0
        repo["age_days"] = round((time.time() - repo["last"]) / 86400, 1) if repo["last"] else None

    data["degraded_raid"] = [r for r in data.get("raid", []) if "_" in r.get("state", "")]
    # RouterOS and Meshtastic probes already know their own UI; only derive
    # links from listening ports when nobody set them.
    if not data.get("web"):
        data["web"] = _web_links(data)
    data["endpoints"] = _endpoints(data)
    return data


# Ports whose service is worth naming even though it serves no web page.
KNOWN_SERVICES = {
    22: "SSH", 21: "FTP", 23: "telnet", 25: "SMTP", 53: "DNS", 123: "NTP",
    139: "SMB", 445: "SMB", 554: "RTSP", 1935: "RTMP", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8291: "Winbox", 8728: "MikroTik API",
    8729: "MikroTik API-SSL", 4403: "Meshtastic API", 6281: "HyperBackup",
    5000: "DSM", 5001: "DSM", 51820: "WireGuard", 1080: "SOCKS5",
    1081: "SOCKS5", 9091: "Transmission", 3261: "iSCSI", 111: "portmap",
}


def _endpoints(data: dict) -> list[dict]:
    """Everything this host publishes, web or not.

    A VPN endpoint and an MTProto proxy are as much a published service as a
    web panel — they simply cannot be opened in a browser. Listing only the
    HTTP ones would hide half of what a VPS actually does.
    """
    out: list[dict] = []
    web_ports = {link["port"] for link in data.get("web", []) if not link.get("local")}

    for entry in data.get("listens", []) + data.get("udps", []):
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        proto = "udp" if entry in data.get("udps", []) else "tcp"
        if entry.get("scope") == "local":
            continue
        if proto == "tcp" and port in web_ports:
            continue  # already offered as a link
        process = entry.get("process") or ""
        out.append({
            "port": port,
            "proto": proto,
            "process": process,
            "label": process or KNOWN_SERVICES.get(port, ""),
        })

    seen = set()
    unique = []
    for item in sorted(out, key=lambda e: (e["proto"], e["port"])):
        key = (item["proto"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


# Ports that mean "there is a web UI here". Anything in the 8000-9000 range
# counts too: self-hosted panels live there by convention.
TLS_PORTS = {443, 8443, 8001, 9443, 4443}
KNOWN_WEB = {
    80: "", 443: "", 8080: "", 8443: "", 8000: "", 8001: "DSM", 5000: "DSM",
    5001: "DSM", 631: "CUPS", 9090: "", 3000: "", 8123: "",
}
SKIP_PORTS = {22, 25, 53, 111, 139, 445, 587, 993, 995, 3306, 5432, 6379,
              11211, 27017, 9091, 4403, 554, 1935, 17, 21, 23, 123, 161,
              8291, 8728, 8729, 3261, 3262, 3263, 3264, 5357, 6281, 1900}

# Processes that hold a "web" port but serve something else entirely — a
# FakeTLS proxy on :443 is not a page anyone can open.
NON_WEB_PROCESSES = {"telemt", "sshd", "dropbear", "openvpn", "wireguard",
                     "wg-quick", "amnezia", "mysqld", "postgres", "redis-server",
                     "shadowsocks", "ss-server", "xray", "v2ray", "sing-box"}


def _web_links(data: dict) -> list[dict]:
    """Turn listening ports into candidate web UI links."""
    links: list[dict] = []
    seen: set[int] = set()
    for entry in data.get("listens", []):
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if port in seen or port in SKIP_PORTS:
            continue
        process = (entry.get("process") or "").lower()
        if process in NON_WEB_PROCESSES:
            continue
        weblike = port in KNOWN_WEB or 8000 <= port <= 9000 or port in (80, 443)
        if not weblike:
            continue
        seen.add(port)
        links.append({
            "port": port,
            "scheme": "https" if port in TLS_PORTS else "http",
            "label": entry.get("process") or KNOWN_WEB.get(port, ""),
            # Loopback-only listeners are backends behind a proxy. Still worth
            # showing — knowing the app exists is the point — but they are not
            # reachable from another machine, so the UI must not offer a link.
            "local": entry.get("scope") == "local",
        })
    links.sort(key=lambda link: (link.get("local", False),
                                 link["port"] not in (80, 443), link["port"]))
    return links


def tcp_open(addr: str, port: int, timeout: float = PORT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return True
    except OSError:
        return False


def ping(addr: str) -> float | None:
    """Round-trip in ms, or None when the host does not answer ICMP."""
    ping_bin = shutil.which("ping") or "/bin/ping"
    # -W is milliseconds on Linux, seconds on macOS; 2 works acceptably on both.
    cmd = [ping_bin, "-c", "1", "-W", "2", addr]
    try:
        started = time.time()
        res = subprocess.run(cmd, capture_output=True, timeout=PING_TIMEOUT + 2, text=True)
        if res.returncode != 0:
            return None
        match = re.search(r"time[=<]([\d.]+)\s*ms", res.stdout)
        if match:
            return float(match.group(1))
        return round((time.time() - started) * 1000, 1)
    except (subprocess.SubprocessError, OSError):
        return None


def run_agent(host: dict, key: str | None) -> tuple[bool, str]:
    """Stream the matching agent to the host and collect its report."""
    agent = host.get("agent", "linux")
    script = AGENT_DIR / f"{agent}.sh"
    if not script.exists():
        return False, f"agent {agent}.sh not found"

    body = script.read_text()
    if host.get("local"):
        cmd = ["sh", "-s"]
    else:
        cmd = list(SSH_BASE)
        if key:
            cmd += ["-i", os.path.expanduser(key)]
        target = host["addr"]
        if host.get("user"):
            target = f"{host['user']}@{target}"
        if host.get("port"):
            cmd += ["-p", str(host["port"])]
        cmd += [target, "sh -s"]

    try:
        res = subprocess.run(cmd, input=body, capture_output=True,
                             timeout=SSH_TIMEOUT, text=True)
    except subprocess.TimeoutExpired:
        return False, f"timeout after {SSH_TIMEOUT}s"
    except OSError as exc:
        return False, str(exc)

    if res.returncode != 0 or "ok\t1" not in res.stdout:
        err = (res.stderr or res.stdout or "").strip().splitlines()
        return False, (err[-1] if err else f"exit {res.returncode}")
    return True, res.stdout


# RouterOS speaks its own CLI over ssh rather than running a shell, so its
# "agent" is a command list whose output is parsed here. Markers keep the
# sections apart in one round-trip.
ROUTEROS_CMD = (
    # `print` tables cannot be parsed reliably: flags are optional and
    # space-separated, text and numeric columns align differently, and values
    # contain spaces ("679 772 199", build timestamps). Scripted :put with an
    # explicit separator sidesteps all of that.
    ':put "@@identity"; /system identity print; '
    ':put "@@resource"; /system resource print; '
    ':put "@@routerboard"; /system routerboard print; '
    ':put "@@update"; /system package update print; '
    ':put "@@health"; :foreach i in=[/system health find] do={'
    ':put ([:tostr [/system health get $i name]]."|".[:tostr [/system health get $i value]])}; '
    ':put "@@package"; :foreach i in=[/system package find] do={'
    ':put ([:tostr [/system package get $i name]]."|".[:tostr [/system package get $i version]]'
    '."|".[:tostr [/system package get $i disabled]])}; '
    ':put "@@service"; :foreach i in=[/ip service find] do={'
    ':put ([:tostr [/ip service get $i name]]."|".[:tostr [/ip service get $i port]]'
    '."|".[:tostr [/ip service get $i disabled]])}; '
    ':put "@@interface"; :foreach i in=[/interface find] do={'
    ':put ([:tostr [/interface get $i name]]."|".[:tostr [/interface get $i running]]'
    '."|".[:tostr [/interface get $i type]]."|".[:tostr [/interface get $i disabled]])}'
)


def _routeros_kv(lines: list[str]) -> dict:
    """RouterOS prints `key: value` pairs, sometimes several per line."""
    out: dict = {}
    for line in lines:
        line = line.replace(";;;", " ")  # inline notices sit above the values
        for match in re.finditer(r"([a-z0-9-]+):\s*([^\s].*?)(?=\s{2,}[a-z0-9-]+:|$)", line):
            out[match.group(1)] = match.group(2).strip()
    return out


def _routeros_rows(lines: list[str]) -> list[list[str]]:
    """Split scripted `:put a."|".b` output into fields."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line or "|" not in line:
            continue
        rows.append([cell.strip() for cell in line.split("|")])
    return rows


def _routeros_uptime(text: str) -> int:
    """`1w2d3h4m5s` -> seconds."""
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total = 0
    for value, unit in re.findall(r"(\d+)([wdhms])", text or ""):
        total += int(value) * units[unit]
    return total


def probe_routeros(host: dict, key: str | None) -> dict:
    cmd = list(SSH_BASE)
    if key:
        cmd += ["-i", os.path.expanduser(key)]
    cmd += ["-p", str(host.get("port", 17))]
    target = host["addr"]
    if host.get("user"):
        target = f"{host['user']}@{target}"
    cmd += [target, ROUTEROS_CMD]

    try:
        res = subprocess.run(cmd, capture_output=True, timeout=SSH_TIMEOUT, text=True)
    except subprocess.TimeoutExpired:
        return {"_error": f"timeout after {SSH_TIMEOUT}s"}
    except OSError as exc:
        return {"_error": str(exc)}
    if res.returncode != 0:
        err = (res.stderr or "").strip().splitlines()
        return {"_error": err[-1] if err else f"exit {res.returncode}"}

    sections: dict[str, list[str]] = {}
    current = ""
    for line in res.stdout.splitlines():
        if line.startswith("@@"):
            current = line[2:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)

    resource = _routeros_kv(sections.get("resource", []))
    health = _routeros_kv(sections.get("health", []))
    board = _routeros_kv(sections.get("routerboard", []))
    update = _routeros_kv(sections.get("update", []))
    identity = _routeros_kv(sections.get("identity", []))

    data: dict = {
        "kind": "routeros",
        "hostname": identity.get("name", ""),
        "os_name": f"RouterOS {resource.get('version', '?')}",
        "os_id": "routeros",
        "os_version": resource.get("version", ""),
        "model": board.get("model") or resource.get("board-name", ""),
        "arch": resource.get("architecture-name", ""),
        "uptime": _routeros_uptime(resource.get("uptime", "")),
        "cpu_model": resource.get("cpu", ""),
        "cpus": _num(resource.get("cpu-count", 0)),
        "cpu_load_pct": _num((resource.get("cpu-load", "0") or "0").rstrip("%")),
    }

    free = _num(resource.get("free-memory", "0").replace("MiB", "").replace("KiB", "")) or 0
    total = _num(resource.get("total-memory", "0").replace("MiB", "").replace("KiB", "")) or 0
    scale = 1024 * 1024 if "MiB" in resource.get("total-memory", "") else 1024
    if total:
        data["mem_total"] = int(total * scale)
        data["mem_available"] = int(free * scale)

    ffree = _num(resource.get("free-hdd-space", "0").replace("MiB", "").replace("KiB", "")) or 0
    ftotal = _num(resource.get("total-hdd-space", "0").replace("MiB", "").replace("KiB", "")) or 0
    fscale = 1024 * 1024 if "MiB" in resource.get("total-hdd-space", "") else 1024
    if ftotal:
        data["disks"] = [{
            "mount": "flash", "fs": "nand",
            "total": int(ftotal * fscale),
            "used": int((ftotal - ffree) * fscale),
        }]

    # health: "name|value" per line
    temps = []
    for cells in _routeros_rows(sections.get("health", [])):
        name = cells[0].lower()
        value = _num(re.sub(r"[^\d.]", "", cells[1] if len(cells) > 1 else ""))
        if not isinstance(value, (int, float)) or not value:
            continue
        if "temperature" in name:
            temps.append({"label": name, "c": value})
        elif "voltage" in name:
            data["voltage"] = value
        elif "fan" in name:
            data["fan_rpm"] = value
    if temps:
        data["temps"] = temps

    # ---------- version and pending firmware ----------
    # RouterOS reports one available channel version rather than a package list.
    installed = update.get("installed-version", "")
    latest = update.get("latest-version", "")
    if latest and installed and latest != installed:
        data["updates"] = [{"pkg": "RouterOS", "old": installed, "new": latest,
                            "security": "0", "suite": update.get("channel", "")}]
    data["firmware_installed"] = installed
    data["firmware_latest"] = latest

    # A RouterBOARD whose flashed firmware is newer than the running one needs
    # a reboot to take effect — the same signal Ubuntu gives via reboot-required.
    current_fw = board.get("current-firmware", "")
    upgrade_fw = board.get("upgrade-firmware", "")
    if current_fw:
        data["routerboard_firmware"] = current_fw
    if upgrade_fw and current_fw and upgrade_fw != current_fw:
        data["routerboard_upgrade"] = upgrade_fw
        data["reboot_required"] = 1
        data["reboot_pkgs"] = f"routerboard firmware {current_fw} -> {upgrade_fw}"

    # ---------- services ----------
    # Two different things count as a "service" on RouterOS: the management
    # services (/ip service) and the installed feature packages, which are what
    # actually decide whether the box does DHCP, wireless, routing and so on.
    services = []
    for cells in _routeros_rows(sections.get("service", [])):
        name, port = cells[0], (cells[1] if len(cells) > 1 else "")
        disabled = (cells[2] if len(cells) > 2 else "false") == "true"
        if not name:
            continue
        services.append({
            "name": name,
            "state": "stopped" if disabled else "running",
            "enabled": "disabled" if disabled else "enabled",
            "restarts": 0,
            "path": "/ip service",
            "desc": f"management service, port {port}" if port else "management service",
        })
    for cells in _routeros_rows(sections.get("package", [])):
        name, version = cells[0], (cells[1] if len(cells) > 1 else "")
        disabled = (cells[2] if len(cells) > 2 else "false") == "true"
        # /system package also lists downloadable-but-absent packages; those
        # have no version and are not installed software.
        if not name or not version:
            continue
        services.append({
            "name": name,
            "state": "stopped" if disabled else "running",
            "enabled": "disabled" if disabled else "enabled",
            "restarts": 0,
            "path": "/system package",
            "desc": "RouterOS package",
            "version": version,
        })
    if services:
        data["services"] = services
        # webfig is whichever of www / www-ssl is actually enabled.
        data["web"] = [
            {"port": int(re.sub(r"\D", "", svc["desc"]) or 0),
             "scheme": "https" if svc["name"] == "www-ssl" else "http",
             "label": "webfig"}
            for svc in services
            if svc["name"] in ("www", "www-ssl") and svc["state"] == "running"
        ]

    ifaces = []
    for cells in _routeros_rows(sections.get("interface", [])):
        name = cells[0]
        running = (cells[1] if len(cells) > 1 else "") == "true"
        kind = cells[2] if len(cells) > 2 else ""
        disabled = (cells[3] if len(cells) > 3 else "false") == "true"
        if not name:
            continue
        ifaces.append({
            "name": name,
            "status": "disabled" if disabled else ("up" if running else "down"),
            "rx": "", "tx": "", "comment": kind,
        })
    if ifaces:
        data["ifaces"] = ifaces
    return data


def probe_meshtastic(host: dict) -> dict:
    """Meshtastic firmware serves /json/report over plain HTTP — no protobuf,
    no meshtastic python package, and it works on the nodes that refuse a full
    TCP API handshake while busy."""
    import json as _json
    import urllib.error
    import urllib.request

    url = f"http://{host['addr']}/json/report"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            payload = _json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"_error": f"json/report: {exc}"}

    body = payload.get("data", {})
    air = body.get("airtime", {})
    mem = body.get("memory", {})
    power = body.get("power", {})
    radio = body.get("radio", {})
    wifi = body.get("wifi", {})

    data: dict = {
        "kind": "meshtastic",
        "os_id": "meshtastic",
        # The same HTTP server that answered /json/report serves the node UI.
        "web": [{"port": 80, "scheme": "http", "label": "node UI"}],
        "uptime": air.get("seconds_since_boot", 0),
        "channel_utilization": round(air.get("channel_utilization", 0), 1),
        "tx_utilization": round(air.get("utilization_tx", 0), 2),
        "reboot_counter": body.get("device", {}).get("reboot_counter", 0),
        "frequency": round(radio.get("frequency", 0), 3),
        "wifi_rssi": wifi.get("rssi"),
    }
    heap_total = mem.get("heap_total") or 0
    if heap_total:
        data["mem_total"] = heap_total
        data["mem_available"] = mem.get("heap_free", 0)
    fs_total = mem.get("fs_total") or 0
    if fs_total:
        data["disks"] = [{"mount": "fs", "fs": "spiffs", "total": fs_total,
                          "used": mem.get("fs_used", 0)}]
    if str(power.get("has_battery")).lower() == "true":
        data["battery_percent"] = power.get("battery_percent")
        data["battery_mv"] = power.get("battery_voltage_mv")
        data["charging"] = str(power.get("is_charging")).lower() == "true"
    else:
        data["power_source"] = "usb" if str(power.get("has_usb")).lower() == "true" else "external"
    return data


def probe_host(host: dict, key: str | None) -> dict:
    """Probe one host: network first, then the agent if we have a way in."""
    started = time.time()
    result = {
        "id": host.get("id") or host["addr"],
        "name": host.get("name") or host.get("id") or host["addr"],
        "addr": host["addr"],
        "role": host.get("role", "server"),
        "agent": host.get("agent", "linux"),
        "subnet": host.get("subnet", ""),
        "note": host.get("note", ""),
        "updatable": bool(host.get("updatable")),
        "reachable": False,
        "error": "",
    }

    # An explicit name from the config wins; otherwise fall back to PTR.
    result["web_host"] = host.get("web_host") or reverse_name(host["addr"])
    result["rtt_ms"] = ping(host["addr"])
    ports = host.get("ports") or []
    if ports:
        result["ports"] = {str(p): tcp_open(host["addr"], int(p)) for p in ports}

    agent = host.get("agent", "linux")
    if agent in ("routeros", "meshtastic"):
        data = probe_routeros(host, key) if agent == "routeros" else probe_meshtastic(host)
        if "_error" in data:
            result["error"] = data["_error"]
            result["reachable"] = result["rtt_ms"] is not None or any(
                result.get("ports", {}).values())
        else:
            result.update(_post_process(data))
            result["reachable"] = True
        result["probe_ms"] = int((time.time() - started) * 1000)
        return result

    if agent == "none":
        # Nothing to log into, but an open 80/443 is still a usable web UI
        # (cameras, appliances).
        result["web"] = [
            {"port": int(p), "scheme": "https" if int(p) in TLS_PORTS else "http", "label": ""}
            for p, is_open in (result.get("ports") or {}).items()
            if is_open and int(p) in (80, 443, 8080, 8443)
        ]
        # Network-only host (camera, or a router we cannot log into yet).
        result["reachable"] = result["rtt_ms"] is not None or any(
            result.get("ports", {}).values())
        if not result["reachable"]:
            result["error"] = "no response"
        result["probe_ms"] = int((time.time() - started) * 1000)
        return result

    ok, payload = run_agent(host, key)
    if not ok:
        result["error"] = payload
        # ICMP still tells us whether the box is alive but merely unreachable
        # over SSH — a useful distinction when a key has not been installed yet.
        result["reachable"] = result["rtt_ms"] is not None
        result["probe_ms"] = int((time.time() - started) * 1000)
        return result

    result.update(_post_process(parse_report(payload)))
    result["reachable"] = True
    result["probe_ms"] = int((time.time() - started) * 1000)
    return result


# Page titles change far less often than the fleet is polled, so they are
# cached; without this every cycle would re-fetch every panel on every host.
_TITLE_CACHE: dict[tuple[str, int], tuple[str, str, float]] = {}
_TITLE_TTL = 3600
_TITLE_LOCK = threading.Lock()

# "It works" is not an application: a distro's untouched web root answers on /
# even when the thing worth linking to lives one path down. Pi-hole's FTL even
# serves Apache's leftover index.html, so three ports on one box can all report
# the same placeholder while running three different services.
PLACEHOLDER_TITLE = re.compile(
    r"default page|it works|welcome to nginx|test page|index of /", re.I)

# Where those services actually keep their UI, by the process holding the port.
APP_PATHS = {
    "apache2": ["/zm/", "/admin/"],
    "httpd": ["/zm/", "/admin/"],
    "pihole-ftl": ["/admin/"],
    "lighttpd": ["/admin/", "/zm/"],
    "nginx": ["/zm/", "/admin/"],
}
FALLBACK_PATHS = ["/zm/", "/admin/"]


def _page_title(url: str) -> str:
    """Read a page's <title>, or "" if it will not give one up."""
    try:
        ctx = ssl.create_default_context()
        # Appliance certificates are self-signed by definition; we are reading
        # a <title>, not trusting the endpoint with anything.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "health-zoo"})
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
    except Exception:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return ""
    # DSM writes its title with &nbsp; entities; unescape before trimming.
    raw = html.unescape(match.group(1)).replace("\xa0", " ")
    return re.sub(r"\s+", " ", raw).strip()[:60]


def fetch_title(url: str, addr: str, port: int, label: str = "") -> tuple[str, str]:
    """Ask a web UI what it calls itself, so links read as names not ports.

    Returns (title, path): when the root is a distro placeholder the known
    sub-paths of whatever holds the port are tried, so the link points at the
    console instead of at "It works".
    """
    key = (addr, port)
    now = time.time()
    with _TITLE_LOCK:
        hit = _TITLE_CACHE.get(key)
        if hit and now - hit[2] < _TITLE_TTL:
            return hit[0], hit[1]

    title, path = _page_title(url), ""
    if not title or PLACEHOLDER_TITLE.search(title):
        for candidate in APP_PATHS.get(label.lower(), FALLBACK_PATHS):
            found = _page_title(url + candidate)
            if found and not PLACEHOLDER_TITLE.search(found):
                title, path = found, candidate
                break

    with _TITLE_LOCK:
        _TITLE_CACHE[key] = (title, path, now)
    return title, path


def annotate_web(results: list[dict], workers: int = 12) -> None:
    """Fill in a human-readable name for every discovered web UI."""
    jobs = []
    for host in results:
        for link in host.get("web", []):
            port = link.get("port")
            if not port or link.get("local"):
                continue  # not reachable from here; nothing to fetch a title from
            std = (link["scheme"] == "http" and port == 80) or \
                  (link["scheme"] == "https" and port == 443)
            url = f"{link['scheme']}://{host['addr']}" + ("" if std else f":{port}")
            jobs.append((link, url, host["addr"], port, link.get("label") or ""))

    if not jobs:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_title, url, addr, port, label): link
                   for link, url, addr, port, label in jobs}
        for future in concurrent.futures.as_completed(futures):
            try:
                title, path = future.result()
            except Exception:
                title, path = "", ""
            if title:
                link = futures[future]
                link["title"] = title
                if path:
                    link["path"] = path
                # A distro's out-of-the-box page is not a service worth a
                # button; keep it in the full list, but off the card. By now
                # the sub-paths have been tried, so this really is all there is.
                link["stub"] = bool(PLACEHOLDER_TITLE.search(title))


_PTR_CACHE: dict[str, tuple[str, float]] = {}
_PTR_TTL = 6 * 3600


def _is_private(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4 or not parts[0].isdigit():
        return True
    a, b = int(parts[0]), int(parts[1] or 0)
    return (a == 10 or a == 127 or (a == 192 and b == 168)
            or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254))


def reverse_name(addr: str) -> str:
    """PTR for a public address, so links use the name a TLS certificate is
    actually issued for. A VPS reached by IP answers with a certificate error
    or the wrong virtual host; by name it just works."""
    if _is_private(addr):
        return ""
    now = time.time()
    hit = _PTR_CACHE.get(addr)
    if hit and now - hit[1] < _PTR_TTL:
        return hit[0]
    name = ""
    try:
        socket.setdefaulttimeout(3)
        candidate = socket.gethostbyaddr(addr)[0].rstrip(".")
        # Trust it only if it resolves back to the same address; a stale or
        # hostile PTR should not redirect a link somewhere else.
        if candidate and addr in socket.gethostbyname_ex(candidate)[2]:
            name = candidate
    except (OSError, socket.herror, socket.gaierror):
        name = ""
    finally:
        socket.setdefaulttimeout(None)
    _PTR_CACHE[addr] = (name, now)
    return name


def link_cameras(results: list[dict]) -> None:
    """Attach each camera host to whoever records it.

    A camera cannot be asked how it is doing without credentials, but the box
    recording it already knows — ZoneMinder reports Connected/fps per monitor,
    Surveillance Station has the recording folders. Matching by IP turns a bare
    "port 554 is open" into "this camera is being recorded at 25 fps".
    """
    by_addr: dict[str, dict] = {}
    for host in results:
        for cam in host.get("cameras", []):
            addr = (cam.get("addr") or "").split(":")[0]
            if addr:
                by_addr.setdefault(addr, {"recorder": host, "cam": cam})
        # Synology cannot name its cameras unprivileged, but an established
        # RTSP session still proves who is pulling which address.
        for link in host.get("camlinks", []):
            addr = (link.get("addr") or "").split(":")[0]
            if addr:
                by_addr.setdefault(addr, {
                    "recorder": host,
                    "cam": {"status": "recording", "name": "", "addr": addr,
                            "fps": 0, "resolution": ""},
                })

    for host in results:
        if host.get("role") != "camera":
            continue
        hit = by_addr.get(host["addr"])
        if not hit:
            continue
        cam = hit["cam"]
        live = cam.get("status") in ("Connected", "recording")
        host["recorded_by"] = hit["recorder"]["name"]
        host["camera_live"] = live
        host["camera_status"] = cam.get("status", "")
        host["camera_fps"] = cam.get("fps", 0)
        host["camera_name"] = cam.get("name", "")
        host["camera_resolution"] = cam.get("resolution", "")

        # The recorder outranks our own ping. Camera segments hang off the far
        # side of a site router and are often unroutable from wherever the
        # dashboard runs. A camera actively being recorded at 25 fps is up,
        # whatever ICMP says.
        if live and not host.get("reachable"):
            host["reachable"] = True
            host["error"] = ""
            host["only_via_recorder"] = True


def probe_all(hosts: list[dict], key: str | None, workers: int = 12) -> list[dict]:
    """Probe every host in parallel; slow hosts never block the fast ones."""
    results: list[dict] = [None] * len(hosts)  # type: ignore[list-item]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_host, h, key): i for i, h in enumerate(hosts)}
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # a probe must never kill the cycle
                host = hosts[index]
                results[index] = {
                    "id": host.get("id") or host["addr"],
                    "name": host.get("name") or host["addr"],
                    "addr": host["addr"],
                    "reachable": False,
                    "error": f"probe crashed: {exc}",
                }
    link_cameras(results)
    annotate_web(results)
    return results
