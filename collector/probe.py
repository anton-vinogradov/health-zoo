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
import shlex
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import secrets

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
    # "scope" is system|user: whose service this is, the distribution's or the
    # operator's. Agents that cannot tell leave it empty and it defaults to user.
    "service": ["name", "state", "enabled", "since_mono", "restarts", "path",
                "desc", "scope"],
    "timer": ["name", "state", "next", "desc", "scope"],
    "unitpkg": ["unit", "pkg", "version"],
    "container": ["name", "image", "state", "status"],
    "repo": ["path", "branch", "commit", "describe", "committed"],
    "camera": ["id", "name", "enabled", "addr", "resolution", "status",
               "fps", "afps", "bandwidth", "last_event", "retention_days"],
    "camlink": ["addr", "proto"],
    "camevent": ["id", "name", "day_count", "last", "oldest"],
    "smart": ["dev", "health", "temp", "hours", "realloc", "pending", "wear", "model"],
    "radio": ["name", "channel", "clients", "noise", "utilization"],
    "radioiw": ["dev", "ssid", "freq", "clients"],
    "listen": ["port", "process", "scope"],
    "udp": ["port", "process", "scope"],
    "raid": ["dev", "level", "state"],
    "backup": ["task", "name", "folders", "dest", "share"],
    "backuprepo": ["name", "last", "size"],
    "unbacked": ["share", "volume"],
    "orphan": ["pkg"],
    "iface": ["name", "status", "rx", "tx", "comment"],
    "neighbor": ["id", "name", "snr", "hops", "last_heard", "battery"],
}

NUMERIC = {
    "uptime", "load1", "load5", "load15", "cpus",
    "mem_total", "mem_available", "mem_free", "swap_total", "swap_free",
    "pkg_list_mtime", "reboot_required", "zoneminder", "surveillance",
    "zm_events_count", "zm_last_event", "zm_events_bytes", "zm_oldest_event", "ok",
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
        # Agents on DSM and OpenWrt report packages and init scripts, which are
        # applications by definition there; only the systemd agent classifies.
        if not svc.get("scope"):
            svc["scope"] = "user"
    data["user_service_count"] = sum(
        1 for s in data.get("services", []) if s.get("scope") != "system")
    for timer in data.get("timers", []):
        if not timer.get("scope"):
            timer["scope"] = "user"

    data["orphan_count"] = len(data.get("orphans", []))

    updates = data.get("updates", [])
    data["update_count"] = len(updates)
    data["security_count"] = sum(1 for u in updates if u.get("security") == "1")

    for cam in data.get("cameras", []):
        for field in ("fps", "afps", "bandwidth", "last_event", "retention_days"):
            if field in cam:
                cam[field] = _num(cam[field])

    # Recording activity per camera, merged onto the camera it belongs to.
    activity = {}
    for entry in data.get("camevents", []):
        for field in ("day_count", "last", "oldest"):
            entry[field] = _num(entry.get(field, 0)) or 0
        entry["quiet_hours"] = round((time.time() - entry["last"]) / 3600, 1) if entry["last"] else None
        entry["archive_days"] = round((time.time() - entry["oldest"]) / 86400, 1) if entry["oldest"] else None
        activity[entry.get("id")] = entry
    for cam in data.get("cameras", []):
        hit = activity.get(cam.get("id"))
        if hit:
            cam.update({k: hit[k] for k in
                        ("day_count", "quiet_hours", "archive_days")})

    if data.get("zm_oldest_event"):
        data["zm_archive_days"] = round(
            (time.time() - data["zm_oldest_event"]) / 86400, 1)

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

    for radio in data.get("radios", []) + data.get("radioiws", []):
        for field in ("clients", "channel", "noise", "utilization", "freq"):
            if radio.get(field) not in (None, ""):
                radio[field] = _num(radio[field])
    data["wifi_clients"] = sum(
        r.get("clients", 0) for r in data.get("radios", []) + data.get("radioiws", [])
        if isinstance(r.get("clients"), int))

    for repo in data.get("backuprepos", []):
        repo["last"] = _num(repo.get("last", 0)) or 0
        repo["size"] = _num(repo.get("size", 0)) or 0
        repo["age_days"] = round((time.time() - repo["last"]) / 86400, 1) if repo["last"] else None

    data["degraded_raid"] = [r for r in data.get("raid", []) if "_" in r.get("state", "")]
    # RouterOS and Meshtastic probes already know their own UI; only derive
    # links from listening ports when nobody set them.
    if not data.get("web"):
        data["web"] = _web_links(data)
    # Same rule for endpoints: a probe that knows its own open ports (RouterOS
    # lists them itself) keeps them; the rest are derived from listening
    # sockets. Recomputing unconditionally quietly emptied the router cards.
    if not data.get("endpoints"):
        data["endpoints"] = _endpoints(data)
    return data


def endpoints_from_probed_ports(host: dict) -> None:
    """For devices we never log into, report the ports we actually reached.

    An access point is polled through the UniFi controller, so it has no
    listening-socket list and its card showed nothing at all — which reads as
    "nothing is running here". Something is: the TCP check already knocked on
    its ports. Show that, and let the detail view say where it came from.
    """
    if host.get("endpoints") or host.get("listens"):
        return
    found = []
    for port, open_ in (host.get("ports") or {}).items():
        if not open_ or not str(port).isdigit():
            continue
        number = int(port)
        found.append({
            "port": number,
            "process": KNOWN_SERVICES.get(number, ""),
            "label": KNOWN_SERVICES.get(number, f"порт {number}"),
            "proto": "tcp", "scope": "any", "probed": True,
        })
    if found:
        host["endpoints"] = sorted(found, key=lambda e: e["port"])
        host["endpoints_probed"] = True


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

    # Prepend the shared fragment: helpers and the collectors that are
    # genuinely identical across platforms live once, in common.sh.
    shared = AGENT_DIR / "common.sh"
    body = (shared.read_text() + "\n" if shared.exists() else "") + script.read_text()
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
    # RouterOS 7 lists every listener here, not just the management ones:
    # resolver, dhcp, ntp, ipsec, l2tp-server and the reverse proxy show up
    # alongside ssh and winbox. "address" is the access restriction, and its
    # absence is the difference between a service offered to one subnet and one
    # offered to whoever can reach the box.
    ':put "@@service"; :foreach i in=[/ip service find] do={'
    ':put ([:tostr [/ip service get $i name]]."|".[:tostr [/ip service get $i port]]'
    '."|".[:tostr [/ip service get $i disabled]]."|"'
    '.[:tostr [/ip service get $i address]])}; '
    # Tools that open a port without appearing in /ip service.
    ':put "@@extra"; '
    ':do {:put ("socks|".[:tostr [/ip socks get enabled]]."|1080")} on-error={}; '
    ':do {:put ("upnp|".[:tostr [/ip upnp get enabled]]."|1900")} on-error={}; '
    ':do {:put ("romon|".[:tostr [/tool romon get enabled]]."|")} on-error={}; '
    ':do {:put ("bandwidth-test|".[:tostr [/tool bandwidth-server get enabled]]."|2000")} on-error={}; '
    ':do {:put ("dns-resolver|".[:tostr [/ip dns get allow-remote-requests]]."|53")} on-error={}; '
    # Port forwards and tunnel policies: configuration that is supposed to
    # deliver traffic somewhere. The byte counter says whether it ever has.
    ':put "@@nat"; :foreach i in=[/ip firewall nat find] do={'
    ':put ([:tostr [/ip firewall nat get $i chain]]."|".[:tostr [/ip firewall nat get $i action]]'
    '."|".[:tostr [/ip firewall nat get $i dst-port]]."|".[:tostr [/ip firewall nat get $i to-addresses]]'
    '."|".[:tostr [/ip firewall nat get $i to-ports]]."|".[:tostr [/ip firewall nat get $i disabled]]'
    '."|".[:tostr [/ip firewall nat get $i comment]]."|".[:tostr [/ip firewall nat get $i bytes]])}; '
    ':put "@@ipsec"; :do {:foreach i in=[/ip ipsec policy find] do={'
    ':put ([:tostr [/ip ipsec policy get $i src-address]]."|".[:tostr [/ip ipsec policy get $i dst-address]]'
    '."|".[:tostr [/ip ipsec policy get $i ph2-state]]."|".[:tostr [/ip ipsec policy get $i disabled]]'
    '."|".[:tostr [/ip ipsec policy get $i active]])}} on-error={}; '
    ':put "@@interface"; :foreach i in=[/interface find] do={'
    ':put ([:tostr [/interface get $i name]]."|".[:tostr [/interface get $i running]]'
    '."|".[:tostr [/interface get $i type]]."|".[:tostr [/interface get $i disabled]])}; '
    # RouterOS 7 renamed the wireless stack: /interface wifi, not
    # /interface wireless. A router here is also the site's access point, so
    # its radios and client count matter as much as its uplink.
    # DHCP leases are the network's own inventory: addresses, names and MACs,
    # already collected by the router. More accurate than a ping sweep and
    # free — it is one more line in a command we already run.
    ':put "@@lease"; :do {:foreach l in=[/ip dhcp-server lease find] do={'
    ':put ([:tostr [/ip dhcp-server lease get $l address]]."|"'
    '.[:tostr [/ip dhcp-server lease get $l host-name]]."|"'
    '.[:tostr [/ip dhcp-server lease get $l mac-address]]."|"'
    '.[:tostr [/ip dhcp-server lease get $l status]])}} on-error={}; '
    ':put "@@wifi"; :do {:foreach i in=[/interface wifi find] do={'
    ':put ([:tostr [/interface wifi get $i name]]."|"'
    '.[:tostr [/interface wifi get $i configuration.ssid]]."|"'
    '.[:tostr [/interface wifi get $i disabled]]."|"'
    '.[:tostr [/interface wifi get $i running]]."|"'
    '.[:tostr [:len [/interface wifi registration-table find '
    'where interface=[/interface wifi get $i name]]]])}} on-error={}'
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
    # What the router actually has open. The card showed nothing here, so a
    # box with telnet and an unrestricted API looked exactly like a locked-down
    # one — while every Linux host in the fleet listed its listeners.
    endpoints: dict[tuple, dict] = {}
    for cells in _routeros_rows(sections.get("service", [])):
        name, port = cells[0], (cells[1] if len(cells) > 1 else "")
        disabled = (cells[2] if len(cells) > 2 else "false") == "true"
        restriction = cells[3] if len(cells) > 3 else ""
        if not name:
            continue
        services.append({
            "name": name,
            "state": "stopped" if disabled else "running",
            "enabled": "disabled" if disabled else "enabled",
            "restarts": 0,
            "path": "/ip service",
            "desc": (f"port {port}" if port else "служба роутера")
                    + (f", доступ с {restriction}" if restriction else ""),
            # Everything in /ip service is RouterOS itself — as is every
            # feature package. A router has no applications of its own here, so
            # the card shows its open ports instead, which is the useful view.
            "scope": "system",
        })
        if disabled or not port:
            continue
        # The same service appears once per address family; one chip is enough.
        entry = endpoints.setdefault((name, port), {
            "port": int(port) if port.isdigit() else port,
            "process": name, "label": name, "proto": "tcp",
            "scope": "lan" if restriction else "any",
            "restricted_to": restriction,
        })
        if restriction and not entry.get("restricted_to"):
            entry["restricted_to"] = restriction

    taken_ports = {e["port"] for e in endpoints.values()}
    for cells in _routeros_rows(sections.get("extra", [])):
        name = cells[0]
        on = (cells[1] if len(cells) > 1 else "false") == "true"
        port = cells[2] if len(cells) > 2 else ""
        number = int(port) if port.isdigit() else 0
        # /ip service already covers most of these under its own name (the DNS
        # resolver is "resolver" there); only report what it does not list.
        if not on or (number and number in taken_ports):
            continue
        endpoints.setdefault((name, port or name), {
            "port": number, "process": name, "label": name, "proto": "tcp",
            "scope": "any", "restricted_to": "",
        })
    data["endpoints"] = sorted(
        endpoints.values(),
        key=lambda e: (e["port"] if isinstance(e["port"], int) else 0, e.get("label", "")))

    # Port forwards. A rule pointing at a host that no longer runs the service
    # is invisible until somebody tries to use it — which is months later, from
    # outside, when it matters.
    forwards = []
    for cells in _routeros_rows(sections.get("nat", [])):
        cells += [""] * (8 - len(cells))
        chain, action, dst_port, to_addr, to_ports, disabled, comment, seen = cells[:8]
        if action not in ("dst-nat", "netmap", "redirect"):
            continue
        forwards.append({
            "chain": chain, "action": action,
            "port": dst_port, "to": to_addr, "to_port": to_ports,
            "disabled": disabled == "true",
            "comment": comment,
            "bytes": int(seen) if seen.isdigit() else 0,
        })
    if forwards:
        data["forwards"] = forwards

    policies = []
    for cells in _routeros_rows(sections.get("ipsec", [])):
        cells += [""] * (5 - len(cells))
        src, dst, phase2, disabled, active = cells[:5]
        # The IPv6 catch-all template ships with every RouterOS and is not a
        # tunnel anybody configured.
        if src.startswith("::") and dst.startswith("::"):
            continue
        policies.append({
            "src": src, "dst": dst, "state": phase2,
            "disabled": disabled == "true", "active": active == "true",
        })
    if policies:
        data["ipsec"] = policies
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
            "scope": "system",
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

    leases = []
    for cells in _routeros_rows(sections.get("lease", [])):
        if not cells[0]:
            continue
        leases.append({
            "addr": cells[0],
            "name": cells[1] if len(cells) > 1 else "",
            "mac": cells[2] if len(cells) > 2 else "",
            "state": cells[3] if len(cells) > 3 else "",
        })
    if leases:
        data["leases"] = leases

    radios = []
    for cells in _routeros_rows(sections.get("wifi", [])):
        name = cells[0]
        if not name:
            continue
        radios.append({
            "name": name,
            "ssid": cells[1] if len(cells) > 1 else "",
            "channel": 0 if (len(cells) > 3 and cells[3] != "true") else None,
            "clients": _num(cells[4]) if len(cells) > 4 else 0,
            "disabled": (cells[2] if len(cells) > 2 else "false") == "true",
        })
    if radios:
        data["radios"] = radios
    return data


def probe_sonos(host: dict) -> dict:
    """Sonos speakers over their built-in HTTP interface on port 1400.

    No credentials and no cloud: the device description gives room name, model
    and firmware, and AVTransport says whether it is playing. Useful mostly to
    know a speaker fell off the network — they are silent failures otherwise,
    since nobody notices a speaker that is merely not playing.
    """
    import urllib.error

    # Some devices are only usable from their own segment. These speakers sit
    # behind a site-to-site tunnel where the TCP handshake completes but the
    # multi-kilobyte XML response never arrives — an MTU black hole. Asking a
    # host on their own LAN to fetch it sidesteps the whole problem, the same
    # way camera status is taken from whichever host records it.
    via = host.get("probe_via")

    def fetch(path: str, timeout: int = 6) -> str:
        url = f"http://{host['addr']}:1400{path}"
        if via:
            cmd = list(SSH_BASE)
            if via.get("key"):
                cmd += ["-i", os.path.expanduser(via["key"])]
            target = via["addr"]
            if via.get("user"):
                target = f"{via['user']}@{target}"
            cmd += [target, f"curl -s -m {timeout} {shlex.quote(url)}"]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=timeout + 10, text=True)
                return res.stdout
            except (subprocess.SubprocessError, OSError):
                return ""
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError):
            return ""

    description = fetch("/xml/device_description.xml")
    if not description:
        return {"_error": "не отвечает на порту 1400"}

    def tag(name: str, body: str) -> str:
        match = re.search(rf"<{name}>([^<]*)</{name}>", body)
        return match.group(1).strip() if match else ""

    data: dict = {
        "kind": "sonos",
        "os_id": "sonos",
        "hostname": tag("roomName", description),
        "model": tag("modelName", description),
        "os_name": f"Sonos {tag('softwareVersion', description)}".strip(),
        "serial": tag("serialNum", description).split(":")[0],
        "web": [{"port": 1400, "scheme": "http", "label": "Sonos", "local": False}],
    }

    status = fetch("/status/zp")
    if status:
        data["zone"] = tag("ZoneName", status) or data["hostname"]
        data["hardware"] = tag("HardwareVersion", status)

    # Playback state is informational: a stopped speaker is not a fault.
    envelope = (
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        '<s:Body><u:GetTransportInfo '
        'xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">'
        "<InstanceID>0</InstanceID></u:GetTransportInfo></s:Body></s:Envelope>"
    )
    url = f"http://{host['addr']}:1400/MediaRenderer/AVTransport/Control"
    action = '"urn:schemas-upnp-org:service:AVTransport:1#GetTransportInfo"'
    body = ""
    try:
        if via:
            cmd = list(SSH_BASE)
            if via.get("key"):
                cmd += ["-i", os.path.expanduser(via["key"])]
            target = via["addr"]
            if via.get("user"):
                target = f"{via['user']}@{target}"
            cmd += [target, "curl -s -m 6 -X POST "
                    f"-H {shlex.quote('SOAPAction: ' + action)} "
                    "-H 'Content-Type: text/xml; charset=utf-8' "
                    f"--data {shlex.quote(envelope)} {shlex.quote(url)}"]
            result = subprocess.run(cmd, capture_output=True, timeout=20, text=True)
            body = result.stdout
        else:
            request = urllib.request.Request(
                url, data=envelope.encode(),
                headers={"SOAPAction": action,
                         "Content-Type": "text/xml; charset=utf-8"})
            with urllib.request.urlopen(request, timeout=6) as resp:
                body = resp.read().decode("utf-8", "replace")
    except Exception:
        body = ""

    state = re.search(r"<CurrentTransportState>([^<]*)</CurrentTransportState>", body)
    if state:
        data["playback"] = state.group(1)

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
        # A device can do more than one job — a router that is also an access
        # point, a NAS that also records cameras. The first role decides where
        # it is grouped and which icon it gets; the rest are shown as well.
        "role": (host.get("roles") or [host.get("role", "server")])[0],
        "roles": host.get("roles") or [host.get("role", "server")],
        "agent": host.get("agent", "linux"),
        "subnet": host.get("subnet", ""),
        "note": host.get("note", ""),
        "updatable": bool(host.get("updatable")),
        # Declared in the config: see issues.py for why it cannot be probed.
        "power_recovery": host.get("power_recovery"),
        "backup_exempt": bool(host.get("backup_exempt")),
        # Some devices are off more often than on — a 3D printer, a lab box.
        # Being down is their normal state, so it must not page anyone; a
        # problem *while running* still counts.
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
    if agent in ("routeros", "meshtastic", "sonos"):
        if agent == "routeros":
            data = probe_routeros(host, key)
        elif agent == "sonos":
            data = probe_sonos(host)
        else:
            data = probe_meshtastic(host)
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


_CERT_CACHE: dict[tuple[str, int], tuple[dict, float]] = {}
_CERT_TTL = 6 * 3600


def fetch_cert(addr: str, port: int, servername: str = "") -> dict:
    """Expiry and subject of a TLS certificate.

    Shelled out to openssl rather than parsed in Python: with verification
    disabled — which it must be, these are self-signed appliance certs —
    ssl.getpeercert() returns an empty dict, and decoding DER by hand to read
    two dates is not worth it.
    """
    key = (addr, port)
    now = time.time()
    hit = _CERT_CACHE.get(key)
    if hit and now - hit[1] < _CERT_TTL:
        return hit[0]

    info: dict = {}
    sni = servername or addr
    try:
        result = subprocess.run(
            # No -verify_return_error: appliance certificates are self-signed
            # by design, and with the flag openssl aborts before printing the
            # certificate we came for.
            ["openssl", "s_client", "-connect", f"{addr}:{port}",
             "-servername", sni],
            input="", capture_output=True, timeout=12, text=True)
        pem = result.stdout
        if "BEGIN CERTIFICATE" in pem:
            parsed = subprocess.run(
                ["openssl", "x509", "-noout", "-enddate", "-subject", "-issuer"],
                input=pem, capture_output=True, timeout=8, text=True).stdout
            for line in parsed.splitlines():
                if line.startswith("notAfter="):
                    stamp = line.split("=", 1)[1].strip()
                    expires = time.mktime(time.strptime(stamp, "%b %d %H:%M:%S %Y %Z"))
                    info["expires"] = int(expires)
                    info["days_left"] = round((expires - now) / 86400, 1)
                elif line.startswith("subject="):
                    info["subject"] = line.split("=", 1)[1].strip()[:80]
                elif line.startswith("issuer="):
                    info["issuer"] = line.split("=", 1)[1].strip()[:80]
    except (subprocess.SubprocessError, OSError, ValueError):
        info = {}

    _CERT_CACHE[key] = (info, now)
    return info


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

    # Certificates ride along on the same pass: these ports are being opened
    # anyway, and an expiring certificate is an outage with a known date.
    # Walk the hosts directly — matching link dicts by equality would pair the
    # wrong host with the wrong link whenever two hosts publish the same port.
    tls_jobs = [(link, host) for host in results
                for link in host.get("web", [])
                if link.get("scheme") == "https" and not link.get("local")]
    if tls_jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            cert_futures = {
                pool.submit(fetch_cert, host["addr"], link["port"],
                            host.get("web_host") or ""): link
                for link, host in tls_jobs}
            for future in concurrent.futures.as_completed(cert_futures):
                try:
                    info = future.result()
                except Exception:
                    info = {}
                if info:
                    cert_futures[future]["cert"] = info

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


def run_external_checks(checks: list[dict], hosts: list[dict], key: str | None,
                        results: list[dict]) -> None:
    """Test reachability from somewhere else on the internet.

    Everything else here is measured from inside the perimeter, where a service
    always looks fine. What the users of a VPN or a proxy actually experience is
    whether the port answers from outside — that is where blocking shows up, and
    it is invisible from the machine running the service.
    """
    by_id = {h.get("id"): h for h in hosts}
    per_target: dict[str, list] = {}

    def probe_one(check: dict) -> tuple[str, dict]:
        source = by_id.get(check.get("from"))
        target = by_id.get(check.get("to"))
        if not source or not target:
            return "", {}
        port = int(check.get("port", 443))
        proto = check.get("proto", "tcp")
        addr = check.get("addr") or target["addr"]
        # /dev/tcp is a bash feature and must not be nested inside sh -c,
        # which is dash on these hosts and silently fails every time.
        if proto == "udp":
            # A UDP probe cannot prove "open"; it only catches a dead route.
            remote = f"timeout 6 nc -u -z -w 3 {addr} {port} >/dev/null 2>&1 && echo 0 || echo 1"
        else:
            remote = (f"timeout 8 bash -c '</dev/tcp/{addr}/{port}' >/dev/null 2>&1 "
                      f"&& echo 0 || echo 1")

        cmd = list(SSH_BASE)
        if key:
            cmd += ["-i", os.path.expanduser(key)]
        if source.get("port"):
            cmd += ["-p", str(source["port"])]
        target_ssh = source["addr"]
        if source.get("user"):
            target_ssh = f"{source['user']}@{target_ssh}"
        cmd += [target_ssh, remote]

        try:
            res = subprocess.run(cmd, capture_output=True, timeout=25, text=True)
            ok = res.stdout.strip().endswith("0")
        except (subprocess.SubprocessError, OSError):
            ok = False
        return check["to"], {
            "from": source.get("name", check["from"]),
            "port": port, "proto": proto, "open": ok,
            "label": check.get("label", ""),
        }

    if not checks:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for target_id, outcome in pool.map(probe_one, checks):
            if target_id:
                per_target.setdefault(target_id, []).append(outcome)

    for host in results:
        found = per_target.get(host.get("id"))
        if found:
            host["external"] = found


# Vendor prefixes worth naming: seeing "Ubiquiti" next to an unknown address
# answers "what is that" far faster than the MAC does.
MAC_VENDORS = {
    "90:09:d0": "Synology", "74:83:c2": "Ubiquiti", "24:0f:9b": "Hikvision",
    "d4:e8:53": "Hikvision", "44:1b:f6": "Espressif", "48:ca:43": "Espressif",
    "e8:f6:0a": "Espressif", "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "34:7e:5c": "Sonos", "c4:ad:34": "MikroTik", "68:1d:ef": "Intel NUC",
    "b8:87:6e": "Yandex", "ac:c5:1b": "Pantum",
}


def poll_unifi_controller(cfg: dict, results: list[dict]) -> None:
    """Enrich access points from the UniFi controller's API.

    UniFi Network 10 dropped per-device SSH authentication from the standalone
    application, so the controller is the only way in — and the better one
    anyway: one login returns every AP's radios, clients, airtime and firmware
    state, without touching the access points at all.
    """
    conf = cfg.get("unifi_controller") or {}
    base = (conf.get("url") or "").rstrip("/")
    user = conf.get("username")
    password = secrets.load(conf, "password")
    if not (base and user and password):
        return

    site = conf.get("site", "default")
    context = ssl.create_default_context()
    # Controller certificates are self-signed unless someone went out of their
    # way; this reads statistics, it does not trust the endpoint with secrets
    # beyond the credentials it was given for exactly this purpose.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    import http.cookiejar
    import json as _json
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(jar))

    try:
        login = urllib.request.Request(
            f"{base}/api/login",
            data=_json.dumps({"username": user, "password": password}).encode(),
            headers={"Content-Type": "application/json"})
        opener.open(login, timeout=10).read()
        devices = _json.loads(
            opener.open(f"{base}/api/s/{site}/stat/device", timeout=15).read())
    except Exception as exc:
        for host in results:
            if host.get("agent") == "unifi" and not host.get("reachable"):
                host["error"] = f"контроллер UniFi недоступен: {exc}"
        return

    by_addr = {h.get("addr"): h for h in results}
    for device in devices.get("data", []):
        host = by_addr.get(device.get("ip"))
        if not host:
            continue
        host["reachable"] = True
        host["error"] = ""
        # The MAC is what the controller's command API addresses devices by.
        host["unifi_mac"] = device.get("mac", "")
        host["os_name"] = f"UniFi {device.get('version', '')}".strip()
        host["model"] = device.get("model", "")
        host["uptime"] = device.get("uptime", 0)
        host["wifi_clients"] = device.get("num_sta", 0)
        host["unifi_state"] = device.get("state")
        if device.get("upgradable"):
            host["updates"] = [{"pkg": "UniFi firmware",
                                "old": device.get("version", ""),
                                "new": device.get("upgrade_to_firmware", ""),
                                "security": "0", "suite": ""}]
            host["update_count"] = 1
        load = device.get("sys_stats") or {}
        if load.get("loadavg_1"):
            host["load1"] = float(load["loadavg_1"])
            host["cpus"] = 1
        if load.get("mem_total"):
            host["mem_total"] = int(load["mem_total"])
            host["mem_available"] = int(load["mem_total"]) - int(load.get("mem_used", 0))

        radios = []
        for radio in device.get("radio_table_stats", []):
            total = radio.get("cu_total")
            mine = (radio.get("cu_self_rx") or 0) + (radio.get("cu_self_tx") or 0)
            radios.append({
                "name": radio.get("radio", radio.get("name", "")),
                "band": "2.4" if radio.get("radio") == "ng" else "5",
                "ssid": "",
                "channel": radio.get("channel"),
                "clients": radio.get("user-num_sta", radio.get("num_sta", 0)),
                "utilization": total,
                # Splitting airtime into ours and everyone else's is what turns
                # "the channel is busy" into an actionable answer: our own load
                # is capacity, someone else's is a reason to change channel.
                "own_utilization": mine,
                "foreign_utilization": (total - mine) if isinstance(total, int) else None,
                "satisfaction": radio.get("satisfaction"),
                "tx_power": radio.get("tx_power"),
                "disabled": False,
            })
        if radios:
            host["radios"] = radios

        # Per-SSID quality. The radio-level number answers "is this band
        # healthy"; this answers "is the network people actually join healthy",
        # which is the question asked when someone says the wifi is bad.
        ssids = []
        for vap in device.get("vap_table", []):
            if not vap.get("essid"):
                continue
            ssids.append({
                "essid": vap.get("essid"),
                "band": "2.4" if vap.get("radio") == "ng" else "5",
                "channel": vap.get("channel"),
                "clients": vap.get("num_sta", 0),
                "satisfaction": vap.get("satisfaction"),
                "signal": vap.get("avg_client_signal"),
                "guest": bool(vap.get("is_guest")),
                "up": vap.get("state", "") != "DOWN",
            })
        if ssids:
            host["ssids"] = ssids
        _post_process(host)


def unifi_command(cfg: dict, mac: str, command: str) -> tuple[bool, str]:
    """Send a device command through the controller (restart, upgrade).

    Access points take orders from the controller, not from us — which is also
    why the controller account has to be an admin rather than view-only:
    reading statistics and rebooting a radio come through the same door.
    """
    conf = cfg.get("unifi_controller") or {}
    base = (conf.get("url") or "").rstrip("/")
    user = conf.get("username")
    password = secrets.load(conf, "password")
    if not (base and user and password):
        return False, "контроллер UniFi не настроен в конфиге"
    if not mac:
        return False, "неизвестен MAC точки (контроллер её не видит)"

    import http.cookiejar
    import json as _json
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(jar))

    site = conf.get("site", "default")
    try:
        opener.open(urllib.request.Request(
            f"{base}/api/login",
            data=_json.dumps({"username": user, "password": password}).encode(),
            headers={"Content-Type": "application/json"}), timeout=10).read()
        response = opener.open(urllib.request.Request(
            f"{base}/api/s/{site}/cmd/devmgr",
            data=_json.dumps({"cmd": command, "mac": mac.lower()}).encode(),
            headers={"Content-Type": "application/json"}), timeout=20).read()
        body = _json.loads(response)
        ok = (body.get("meta", {}).get("rc") == "ok")
        return ok, "" if ok else str(body.get("meta", {}).get("msg", "отказ контроллера"))
    except Exception as exc:
        return False, str(exc)


# In 2.4 GHz only 1, 6 and 11 do not overlap: the channels are 5 MHz apart
# while a 20 MHz carrier is four wide, so anything closer than five channels
# interferes — and adjacent-but-not-equal is worse than sharing outright,
# because carrier sense cannot see the neighbour to take turns with it.
NON_OVERLAPPING_24 = {1, 6, 11}


def analyse_wifi(results: list[dict]) -> None:
    """Look at the radios as a set, not one at a time."""
    radios_24 = []
    for host in results:
        for radio in host.get("radios", []):
            channel = radio.get("channel")
            if radio.get("band") == "2.4" and isinstance(channel, int):
                radios_24.append((host, radio))

    for host, radio in radios_24:
        channel = radio["channel"]
        clashes = [
            other_host.get("name", other_host["id"])
            for other_host, other in radios_24
            if other is not radio and abs(other["channel"] - channel) < 5
        ]
        if clashes:
            radio["overlaps_with"] = sorted(set(clashes))
        if channel not in NON_OVERLAPPING_24:
            radio["off_grid"] = True


def find_unmanaged(results: list[dict], hosts: list[dict]) -> list[dict]:
    """Devices the network knows about but the config does not.

    The routers already hold a DHCP lease table; comparing it against the
    configured hosts turns "what else is on my network" into a list — new
    hardware to add, and anything that should not be there at all.
    """
    known = set()
    for host in hosts:
        known.add(host.get("addr"))
        for alias in host.get("aliases", []) or []:
            known.add(alias)
    for host in results:
        known.add(host.get("addr"))

    seen: dict[str, dict] = {}
    for host in results:
        for lease in host.get("leases", []):
            addr = lease.get("addr")
            if not addr or addr in known or addr in seen:
                continue
            mac = (lease.get("mac") or "").lower()
            seen[addr] = {
                "addr": addr,
                "name": lease.get("name") or "",
                "mac": mac,
                "vendor": MAC_VENDORS.get(mac[:8], ""),
                "via": host.get("name", ""),
            }
    return sorted(seen.values(), key=lambda d: [int(p) for p in d["addr"].split(".")]
                  if d["addr"].count(".") == 3 and all(p.isdigit() for p in d["addr"].split("."))
                  else [0, 0, 0, 0])


def link_backups(results: list[dict]) -> None:
    """Draw the backup graph: who copies what, and to whom.

    Each side knows half the story — the source knows the destination address,
    the destination only sees repositories appear. Joining them means a NAS
    card can say "backs up to Backup" and "receives from Photo", and a NAS
    that does neither becomes visible as exactly that.
    """
    by_addr = {h.get("addr"): h for h in results}

    for host in results:
        for task in host.get("backups", []):
            dest_addr = task.get("dest")
            if not dest_addr:
                continue
            target = by_addr.get(dest_addr)
            target_name = target.get("name") if target else dest_addr
            task["dest_name"] = target_name
            host.setdefault("backs_up_to", [])
            if target_name not in host["backs_up_to"]:
                host["backs_up_to"].append(target_name)
            if target is not None:
                target.setdefault("receives_from", [])
                if host.get("name") not in target["receives_from"]:
                    target["receives_from"].append(host.get("name"))

    for host in results:
        if host.get("role") != "nas":
            continue
        # "Nothing to back up" is a real answer for a pure backup target or a
        # camera recorder, so only say it when the NAS carries data of its own
        # and neither sends it anywhere nor is itself a destination.
        has_data = any(d.get("mount", "").startswith("/volume") for d in host.get("disks", []))
        # Surveillance footage is expendable, but the configuration around it
        # is not — a NAS that neither sends nor receives a backup is
        # unprotected regardless of what it stores. Hosts that genuinely need
        # no backup can say so with "backup_exempt" in the config.
        host["backup_orphan"] = bool(
            has_data and not host.get("backs_up_to")
            and not host.get("receives_from") and not host.get("backup_exempt"))


def check_forwards(results: list[dict]) -> None:
    """Decide, for each port forward, whether anything is still behind it.

    A forward is configuration with no feedback: it keeps existing long after
    the service it points at was moved, renamed or switched off, and the first
    person to notice is whoever needed it from outside. The fleet already knows
    which host answers on which port, so the question can simply be asked.
    """
    listeners: dict[str, set] = {}
    reachable: dict[str, bool] = {}
    for host in results:
        addr = host.get("addr")
        if not addr:
            continue
        reachable[addr] = bool(host.get("reachable"))
        ports = listeners.setdefault(addr, set())
        for source in ("listens", "udps"):
            for entry in host.get(source) or []:
                port = entry.get("port")
                if str(port).isdigit():
                    ports.add(int(port))
        for entry in host.get("endpoints") or []:
            if str(entry.get("port")).isdigit():
                ports.add(int(entry["port"]))
        # A camera answers on 554 whether or not anything asked it to; the
        # recorder-side probe records that as an open port on the host itself.
        for port, open_ in (host.get("ports") or {}).items():
            if open_ and str(port).isdigit():
                ports.add(int(port))

    for host in results:
        for rule in host.get("forwards") or []:
            target = rule.get("to")
            port = rule.get("to_port") or rule.get("port")
            rule["verdict"] = "unknown"
            if rule.get("disabled"):
                rule["verdict"] = "disabled"
                continue
            if not target and rule.get("action") == "redirect":
                # A redirect with no destination sends traffic to the router
                # itself — the NTP hijack that keeps cameras on the right clock.
                target = host.get("addr")
            if not target or target not in reachable:
                # Points outside the fleet, or at something health-zoo does not
                # poll. Silence is the honest answer, not a guess.
                continue
            if not reachable[target]:
                rule["verdict"] = "host-down"
                continue
            if not str(port).isdigit():
                continue
            if int(port) in listeners.get(target, set()):
                rule["verdict"] = "ok"
            else:
                rule["verdict"] = "no-listener"


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


def resolve_probe_via(hosts: list[dict], key: str | None) -> None:
    """Turn "probe_via": "<host id>" into the connection details to use."""
    by_id = {h.get("id"): h for h in hosts}
    for host in hosts:
        via_id = host.get("probe_via")
        if isinstance(via_id, str):
            source = by_id.get(via_id)
            if source:
                host["probe_via"] = {"addr": source["addr"], "user": source.get("user"),
                                     "key": key, "name": source.get("name", via_id)}
            else:
                host.pop("probe_via", None)


def probe_all(hosts: list[dict], key: str | None, workers: int = 12) -> list[dict]:
    """Probe every host in parallel; slow hosts never block the fast ones."""
    resolve_probe_via(hosts, key)
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
    link_backups(results)
    annotate_web(results)
    return results
