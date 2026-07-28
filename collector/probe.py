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
import ipaddress
import json
import math
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
    "camfw": ["addr", "model", "firmware", "released"],
    "camevent": ["id", "name", "day_count", "last", "oldest"],
    "smart": ["dev", "health", "temp", "hours", "realloc", "pending", "wear", "model"],
    "radio": ["name", "channel", "clients", "noise", "utilization"],
    "radioiw": ["dev", "ssid", "freq", "clients"],
    "link": ["name", "speed", "duplex", "state", "errors", "crc", "flaps", "capable"],
    "listen": ["port", "process", "scope"],
    "udp": ["port", "process", "scope"],
    # Same shape the RouterOS parser builds by hand, so both kinds of router
    # arrive at the exposure walk identical.
    "forward": ["chain", "action", "port", "to", "to_port", "disabled",
                "comment", "bytes", "proto"],
    "raid": ["dev", "level", "state"],
    "backup": ["task", "name", "folders", "dest", "share"],
    "backuprepo": ["name", "last", "size"],
    "unbacked": ["share", "volume"],
    "orphan": ["pkg"],
    "vhost": ["name", "port", "scheme", "server"],
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

    for link in data.get("links", []):
        for field in ("speed", "errors", "crc", "flaps", "capable"):
            link[field] = int(_num(link.get(field, 0)) or 0)

    # An agent reports a forward's fields as text, the RouterOS path builds them
    # typed. Left as-is, the string "false" is truthy and every rule collected
    # from a shell agent reads as switched off.
    for rule in data.get("forwards", []):
        if isinstance(rule.get("disabled"), str):
            rule["disabled"] = rule["disabled"].strip().lower() in ("true", "1", "yes")
        rule["bytes"] = _num(rule.get("bytes", 0)) or 0

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
    # Whether anybody actually looked. "No updates pending" and "nothing asked"
    # look identical on a card, and only one of them is good news.
    if data.get("pkg_manager") or data.get("kind") in ("routeros", "synology"):
        data["updates_checked"] = True

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

    # Names beat addresses: a link by IP cannot be shared, does not match the
    # certificate, and for anything behind a reverse proxy it is simply wrong —
    # the backend listens on 127.0.0.1 and only the proxy knows the name. The
    # proxy's own configuration holds those names, so a vhost replaces the
    # by-address link on the port it serves.
    named = []
    for vhost in data.get("vhosts", []):
        name = vhost.get("name")
        if not name:
            continue
        try:
            port = int(vhost.get("port") or 443)
        except ValueError:
            port = 443
        named.append({
            "port": port,
            "scheme": vhost.get("scheme") or "https",
            "label": name,
            "host_name": name,
            "local": False,
            "via": vhost.get("server", ""),
        })
    if named:
        # The proxy's own by-address links are noise once its sites are named:
        # http://<ip>/ on a Caddy box is a redirect to a site already listed.
        servers = {v.get("server", "") for v in data.get("vhosts", [])}
        proxied_ports = {link["port"] for link in named}
        kept = []
        for link in data.get("web", []):
            if link.get("port") in proxied_ports:
                continue
            if (link.get("label") or "").lower() in servers:
                continue
            # A backend on 127.0.0.1 is reachable only through the proxy, so
            # say which name serves it instead of offering a dead link.
            if link.get("local") and named:
                link["served_by"] = named[0]["host_name"]
            kept.append(link)
        data["web"] = named + kept

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
    # Infrastructure ports a card used to render as "68:68/udp" — a number
    # repeated twice says less than the name of the thing holding it.
    67: "DHCP", 68: "DHCP-клиент", 500: "IPsec", 4500: "IPsec NAT-T",
    1701: "L2TP", 5678: "MikroTik discovery", 5353: "mDNS", 1900: "SSDP",
    51413: "Transmission (пиры)",
    # A camera has no web link to click (its console needs credentials), so the
    # port shows up as a chip — "порт 80:80" said nothing twice.
    80: "HTTP", 443: "HTTPS",
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
    # offered to whoever can reach the box. Most of that list is UDP, and the
    # protocol belongs to the entry rather than to the name: the resolver is
    # listed twice, once per protocol, and assuming tcp reports the wrong port
    # for half the router and hides the other half of the resolver.
    ':put "@@service"; :foreach i in=[/ip service find] do={'
    ':put ([:tostr [/ip service get $i name]]."|".[:tostr [/ip service get $i port]]'
    '."|".[:tostr [/ip service get $i disabled]]."|"'
    '.[:tostr [/ip service get $i address]]."|"'
    '.[:tostr [/ip service get $i proto]])}; '
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
    # Which of the router's own addresses faces the uplink. RouterOS has no
    # field that says "this one is the WAN", so it is derived: the address whose
    # network contains the default gateway. Everything about who can reach what
    # from outside hangs on that one address being known.
    ':put "@@address"; :foreach i in=[/ip address find] do={'
    ':put ([:tostr [/ip address get $i address]]."|".[:tostr [/ip address get $i interface]]'
    '."|".[:tostr [/ip address get $i disabled]])}; '
    ':put "@@route"; :do {:foreach i in=[/ip route find dst-address="0.0.0.0/0"] do={'
    ':put ([:tostr [/ip route get $i gateway]]."|".[:tostr [/ip route get $i active]])}} '
    'on-error={}; '
    # `monitor` reports what the port negotiated; the configuration says only
    # what it was allowed to. A gigabit port sitting at 100Mbps is the symptom
    # this exists to catch, and it is invisible in the settings.
    ':put "@@ethernet"; :do {:foreach i in=[/interface ethernet find] do={'
    ':local m [/interface ethernet monitor $i once as-value]; '
    ':put ([:tostr [/interface ethernet get $i name]]."|".[:tostr ($m->"status")]'
    '."|".[:tostr ($m->"rate")]."|".[:tostr ($m->"full-duplex")]'
    '."|".[:tostr [/interface ethernet get $i disabled]])}} on-error={}; '
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
    # monitor gives the frequency actually in use; the configuration often says
    # "auto" and a card with no channel cannot be compared with anything.
    ':put "@@wifi"; :do {:foreach i in=[/interface wifi find] do={'
    ':local mon [/interface wifi monitor $i once as-value]; '
    # A virtual access point has a master; asking a master for one is an
    # error, so it gets its own handler instead of aborting the whole loop.
    ':local master ""; :do {:set master '
    '[:tostr [/interface wifi get $i master-interface]]} on-error={}; '
    ':put ([:tostr [/interface wifi get $i name]]."|"'
    '.[:tostr [/interface wifi get $i configuration.ssid]]."|"'
    '.[:tostr [/interface wifi get $i disabled]]."|"'
    '.[:tostr [/interface wifi get $i running]]."|"'
    '.[:tostr [:len [/interface wifi registration-table find '
    'where interface=[/interface wifi get $i name]]]]."|"'
    '.[:tostr ($mon->"channel")]."|".$master)}} on-error={}'
)



def _rate_mbit(rate: str) -> int:
    """RouterOS reports "1Gbps"; everything else here counts in megabits."""
    text = (rate or "").strip().lower()
    try:
        if text.endswith("gbps"):
            return int(float(text[:-4]) * 1000)
        if text.endswith("mbps"):
            return int(float(text[:-4]))
    except ValueError:
        pass
    return 0


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
        proto = (cells[4] if len(cells) > 4 else "") or "tcp"
        if not name:
            continue
        services.append({
            "name": name,
            "state": "stopped" if disabled else "running",
            "enabled": "disabled" if disabled else "enabled",
            "restarts": 0,
            "path": "/ip service",
            "desc": (f"port {port}/{proto}" if port else "служба роутера")
                    + (f", доступ с {restriction}" if restriction else ""),
            # Everything in /ip service is RouterOS itself — as is every
            # feature package. A router has no applications of its own here, so
            # the card shows its open ports instead, which is the useful view.
            "scope": "system",
        })
        if disabled or not port:
            continue
        # A name and port can repeat — an open session is listed as an entry of
        # its own — and one chip is enough for that. The protocol is what makes
        # two entries genuinely different listeners: the resolver answers on
        # 53/tcp and 53/udp, and collapsing them loses the one that carries
        # nearly all the queries.
        entry = endpoints.setdefault((name, port, proto), {
            "port": int(port) if port.isdigit() else port,
            "process": name, "label": name, "proto": proto,
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
        endpoints.setdefault((name, port or name, "tcp"), {
            "port": number, "process": name, "label": name, "proto": "tcp",
            "scope": "any", "restricted_to": "",
        })
    data["endpoints"] = sorted(
        endpoints.values(),
        key=lambda e: (e["port"] if isinstance(e["port"], int) else 0,
                       e.get("label", ""), e.get("proto", "")))

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

    # The uplink-side address: the one whose network holds the default gateway.
    gateways = [cells[0] for cells in _routeros_rows(sections.get("route", []))
                if cells and cells[0]]
    for cells in _routeros_rows(sections.get("address", [])):
        if len(cells) > 2 and cells[2] == "true":
            continue
        try:
            local = ipaddress.ip_interface(cells[0])
        except (ValueError, IndexError):
            continue
        for gateway in gateways:
            try:
                if ipaddress.ip_address(gateway) in local.network:
                    data["wan_addr"] = str(local.ip)
                    break
            except ValueError:
                continue
        if data.get("wan_addr"):
            break

    links = []
    for cells in _routeros_rows(sections.get("ethernet", [])):
        cells += [""] * (5 - len(cells))
        name, status, rate, duplex, disabled = cells[:5]
        if not name or disabled == "true":
            continue
        links.append({
            "name": name,
            "speed": _rate_mbit(rate),
            "duplex": "full" if duplex == "true" else "half" if duplex == "false" else "-",
            "state": "up" if status == "link-ok" else "down",
            "errors": 0, "crc": 0, "flaps": 0,
        })
    if links:
        data["links"] = links

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
        # "2442/ax/Ce" — frequency, protocol, channel width layout. The layout
        # spells out one letter per 20 MHz block ("Ce" is 40 MHz wide, "Ceee"
        # is 80); a plain "2412/ax" is a single 20 MHz carrier.
        frequency = 0
        raw = cells[5] if len(cells) > 5 else ""
        parts = raw.split("/")
        head = parts[0]
        if head.isdigit():
            frequency = int(head)
        radio = {
            "name": name,
            "ssid": cells[1] if len(cells) > 1 else "",
            "clients": _num(cells[4]) if len(cells) > 4 else 0,
            "disabled": (cells[2] if len(cells) > 2 else "false") == "true",
        }
        if frequency:
            layout = parts[2] if len(parts) > 2 else ""
            radio["width"] = 20 * len(layout) if layout else 20
        master = cells[6] if len(cells) > 6 else ""
        if master:
            radio["virtual"] = True
            radio["master"] = master
        if frequency:
            radio["band"] = "2.4" if frequency < 3000 else "5"
            radio["channel"] = ((frequency - 2407) // 5 if frequency < 3000
                                else (frequency - 5000) // 5)
            radio["freq"] = frequency
        else:
            radio["channel"] = 0 if (len(cells) > 3 and cells[3] != "true") else None
        radios.append(radio)
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
        # The root answers 403 by design; /status is the page a person can read.
        "web": [{"port": 1400, "scheme": "http", "label": "Sonos",
                 "path": "/status", "local": False}],
    }

    status = fetch("/status/zp")
    if status:
        data["zone"] = tag("ZoneName", status) or data["hostname"]
        data["hardware"] = tag("HardwareVersion", status)

    def soap(path: str, service: str, action: str, args: str = "") -> str:
        """One UPnP call. The speakers answer plain SOAP over HTTP on 1400."""
        envelope = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{action} '
            f'xmlns:u="urn:schemas-upnp-org:service:{service}:1">'
            f"{args}</u:{action}></s:Body></s:Envelope>"
        )
        url = f"http://{host['addr']}:1400{path}"
        action_header = f'"urn:schemas-upnp-org:service:{service}:1#{action}"'
        try:
            if via:
                cmd = list(SSH_BASE)
                if via.get("key"):
                    cmd += ["-i", os.path.expanduser(via["key"])]
                target = via["addr"]
                if via.get("user"):
                    target = f"{via['user']}@{target}"
                cmd += [target, "curl -s -m 6 -X POST "
                        f"-H {shlex.quote('SOAPAction: ' + action_header)} "
                        "-H 'Content-Type: text/xml; charset=utf-8' "
                        f"--data {shlex.quote(envelope)} {shlex.quote(url)}"]
                result = subprocess.run(cmd, capture_output=True, timeout=20, text=True)
                return result.stdout
            request = urllib.request.Request(
                url, data=envelope.encode(),
                headers={"SOAPAction": action_header,
                         "Content-Type": "text/xml; charset=utf-8"})
            with urllib.request.urlopen(request, timeout=6) as resp:
                return resp.read().decode("utf-8", "replace")
        except Exception:
            return ""

    # Playback state is informational: a stopped speaker is not a fault.
    body = soap("/MediaRenderer/AVTransport/Control", "AVTransport",
                "GetTransportInfo", "<InstanceID>0</InstanceID>")

    state = re.search(r"<CurrentTransportState>([^<]*)</CurrentTransportState>", body)
    if state:
        data["playback"] = state.group(1)

    # Volume is the difference between "silent because nobody asked for music"
    # and "silent because someone muted it and forgot".
    volume = soap("/MediaRenderer/RenderingControl/Control", "RenderingControl",
                  "GetVolume", "<InstanceID>0</InstanceID><Channel>Master</Channel>")
    match = re.search(r"<CurrentVolume>(\d+)</CurrentVolume>", volume)
    if match:
        data["volume"] = int(match.group(1))
    muted = soap("/MediaRenderer/RenderingControl/Control", "RenderingControl",
                 "GetMute", "<InstanceID>0</InstanceID><Channel>Master</Channel>")
    if "<CurrentMute>1</CurrentMute>" in muted:
        data["muted"] = True

    if data.get("playback") == "PLAYING":
        position = soap("/MediaRenderer/AVTransport/Control", "AVTransport",
                        "GetPositionInfo", "<InstanceID>0</InstanceID>")
        meta = html.unescape(position)
        title = re.search(r"<dc:title>([^<]*)</dc:title>", meta)
        artist = re.search(r"<dc:creator>([^<]*)</dc:creator>", meta)
        if title:
            data["track"] = " — ".join(
                x.group(1) for x in (artist, title) if x and x.group(1))

    # How the speaker is attached to the network, and to which group. Sonos
    # publishes this for the whole household, so one call describes every
    # speaker — but each answers for itself, so read only its own entry.
    topology = html.unescape(soap("/ZoneGroupTopology/Control", "ZoneGroupTopology",
                                  "GetZoneGroupState"))
    mine = ""
    for member in re.findall(r"<ZoneGroupMember [^>]*>", topology):
        if f'Location="http://{host["addr"]}:1400/' in member:
            mine = member
            break
    if mine:
        def attr(name: str) -> str:
            found = re.search(rf'{name}="([^"]*)"', mine)
            return found.group(1) if found else ""

        wired = attr("EthLink") == "1"
        data["link"] = "ethernet" if wired else "wifi"
        freq = attr("ChannelFreq")
        if freq.isdigit() and not wired:
            number = int(freq)
            # 2.4 GHz starts at 2412 (channel 1), 5 GHz counts from 5000.
            data["wifi_freq"] = number
            data["wifi_channel"] = ((number - 2407) // 5 if number < 3000
                                    else (number - 5000) // 5)
            data["wifi_band"] = "2.4" if number < 3000 else "5"
        if attr("BehindWifiExtender") == "1":
            data["behind_extender"] = True

        # Who plays together with whom: a speaker alone in its group is normal,
        # but "Кухня" silently ending up grouped with another room is the kind
        # of thing that explains a complaint.
        group = re.search(r'<ZoneGroup [^>]*Coordinator="([^"]*)"[^>]*>(.*?)</ZoneGroup>',
                          topology, re.S)
        for candidate in re.finditer(r'<ZoneGroup [^>]*>(?:(?!</ZoneGroup>).)*</ZoneGroup>',
                                     topology, re.S):
            block = candidate.group(0)
            if f'Location="http://{host["addr"]}:1400/' not in block:
                continue
            names = re.findall(r'ZoneName="([^"]*)"', block)
            if len(names) > 1:
                data["group"] = names
            break

    # The speaker knows which version it would install; comparing that with the
    # one it runs is the same "updates pending" question as everywhere else.
    update = html.unescape(soap("/ZoneGroupTopology/Control", "ZoneGroupTopology",
                                "CheckForUpdate",
                                "<UpdateType>Software</UpdateType>"
                                "<CachedOnly>1</CachedOnly><Version></Version>"))
    offered = re.search(r'<UpdateItem[^>]*Version="([^"]*)"', update)
    running = data.get("os_name", "").replace("Sonos ", "").strip()
    data["updates_checked"] = bool(offered and running)
    if offered and running and offered.group(1) != running:
        data["updates"] = [{"pkg": "Sonos", "old": running,
                            "new": offered.group(1), "security": "0", "suite": ""}]
        data["update_count"] = 1

    return data


# Firmware version and the latest release, both cached: the version changes
# when somebody flashes a node, and GitHub does not need asking every 3 minutes.
_MESH_INFO_CACHE: dict[str, tuple[dict, float]] = {}
_MESH_INFO_TTL = 6 * 3600
_MESH_RELEASE_CACHE: tuple[str, float] = ("", 0.0)
_MESH_RELEASE_TTL = 12 * 3600
_MESH_LOCK = threading.Lock()
# Where the meshtastic CLI lives, told to us once at startup: probe_host has no
# config of its own, and threading a whole config through every probe to reach
# one path would be worse than a module-level setting.
MESHTASTIC_PYTHON = "/opt/meshtastic-zoo/.venv/bin/python"


def configure(cfg: dict) -> None:
    """Take the few settings the probes need from the config, once."""
    global MESHTASTIC_PYTHON
    MESHTASTIC_PYTHON = cfg.get("meshtastic_python", MESHTASTIC_PYTHON)


def _mesh_latest_release() -> str:
    """The newest published firmware tag, or "" if GitHub is not reachable.

    A dashboard that cannot reach the internet must still work; not knowing the
    latest version is a missing answer, not a failure.
    """
    global _MESH_RELEASE_CACHE
    with _MESH_LOCK:
        tag, when = _MESH_RELEASE_CACHE
        if tag and time.time() - when < _MESH_RELEASE_TTL:
            return tag
    try:
        request = urllib.request.Request(
            "https://api.github.com/repos/meshtastic/firmware/releases/latest",
            headers={"User-Agent": "health-zoo", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=8) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        tag = (payload.get("tag_name") or "").lstrip("v")
    except Exception:
        tag = ""
    if tag:
        with _MESH_LOCK:
            _MESH_RELEASE_CACHE = (tag, time.time())
    return tag


def _mesh_device_info(host: dict, cfg: dict | None = None) -> dict:
    """Firmware version and hardware model, over the protobuf API.

    /json/report does not carry them — the node reports airtime and memory but
    not what it is running. The CLI does, at the cost of a full API handshake,
    so the answer is cached for hours rather than asked every poll.
    """
    addr = host.get("addr", "")
    with _MESH_LOCK:
        hit = _MESH_INFO_CACHE.get(addr)
        if hit and time.time() - hit[1] < _MESH_INFO_TTL:
            return hit[0]

    binary = (cfg or {}).get("meshtastic_python", MESHTASTIC_PYTHON)
    info: dict = {}
    if os.path.exists(binary):
        try:
            result = subprocess.run(
                [binary, "-m", "meshtastic", "--host", addr, "--no-nodes", "--info"],
                capture_output=True, timeout=40, text=True)
            found = re.search(r'"firmwareVersion":\s*"([^"]+)"', result.stdout)
            if found:
                info["firmware"] = found.group(1)
            model = re.search(r'"hwModel":\s*"([^"]+)"', result.stdout)
            if model:
                info["model"] = model.group(1).replace("_", " ").title()
            role = re.search(r'"role":\s*"([^"]+)"', result.stdout)
            if role:
                info["role"] = role.group(1)
        except (subprocess.SubprocessError, OSError):
            info = {}
    with _MESH_LOCK:
        _MESH_INFO_CACHE[addr] = (info, time.time())
    return info


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

    info = _mesh_device_info(host)
    latest = _mesh_latest_release() if info.get("firmware") else ""
    data: dict = {
        "kind": "meshtastic",
        "os_id": "meshtastic",
        "os_name": (f"Meshtastic {info['firmware']}" if info.get("firmware") else ""),
        "model": info.get("model", ""),
        "mesh_role": info.get("role", ""),
        # The same HTTP server that answered /json/report serves the node UI.
        "web": [{"port": 80, "scheme": "http", "label": "node UI"}],
        "uptime": air.get("seconds_since_boot", 0),
        "channel_utilization": round(air.get("channel_utilization", 0), 1),
        "tx_utilization": round(air.get("utilization_tx", 0), 2),
        "reboot_counter": body.get("device", {}).get("reboot_counter", 0),
        "frequency": round(radio.get("frequency", 0), 3),
        "wifi_rssi": wifi.get("rssi"),
    }
    # Same shape as every other update in the fleet, so the card, the checks
    # and the alerts all treat it the same way.
    data["updates_checked"] = bool(latest and info.get("firmware"))
    if latest and info.get("firmware") and info["firmware"] != latest:
        data["updates"] = [{"pkg": "Meshtastic firmware", "old": info["firmware"],
                            "new": latest, "security": "0", "suite": ""}]
        data["update_count"] = 1

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
# Sonos answers 403 on / by design; its diagnostics page is one level down, so
# a link to the root is a link to an error page.
APP_PATHS = {
    "sonos": ["/status", "/xml/device_description.xml"],
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


def _channel_freq(channel: int, band: str) -> int:
    return 2407 + 5 * channel if band == "2.4" else 5000 + 5 * channel


def _channel_floor(sightings: list[dict], band: str) -> dict:
    """Per candidate channel: the least interference there can possibly be.

    A radio listens through a filter centred on its own channel, so networks at
    the far end of the band are heard faint or not at all. Every number here is
    therefore a floor, never an estimate: the channel the radio is sitting on
    is measured, the others can only be worse than they look.
    """
    floor = {}
    for option in sorted(NON_OVERLAPPING_24):
        level, landed = interference(sightings, _channel_freq(option, band), 20)
        if level is None:
            continue
        loudest = landed[0]
        floor[str(option)] = {
            "level": level,
            "networks": len(landed),
            "loudest": loudest["essid"] or "(скрытый)",
            "signal": loudest["signal"],
        }
    return floor


def _measure_neighbours(radios: list[dict], sightings: list[dict],
                        site_sightings: list[dict] | None = None,
                        ap_mac: str = "") -> None:
    """Attach measured interference — who is heard, how loud, how much overlap.

    The question is never "does anyone share our channel number" but "how much
    energy from other networks lands in our carrier". A network two channels
    away at -50 dBm hurts; one on our exact channel at -92 dBm does not.

    What the other access points on the site hear is carried alongside rather
    than merged in. They stand somewhere else, so their signal levels are not
    this radio's — but a loud network only they can hear is still a reason not
    to move onto that channel, and it is the one thing a single radio sitting
    on one channel can never learn on its own.
    """
    if not sightings:
        return
    for radio in radios:
        band = radio.get("band")
        channel = radio.get("channel")
        width = radio.get("width") or 20
        if not isinstance(channel, int) or not channel:
            continue
        near = [s for s in sightings
                if (s["freq"] < 3000) == (band == "2.4")]
        if not near:
            continue
        level, landed = interference(near, _channel_freq(channel, band), width)
        if level is None:
            continue
        radio["interference"] = level
        radio["neighbours"] = [{
            "essid": n["essid"] or "(скрытый)",
            "channel": n["channel"],
            "width": n["width"],
            "signal": n["signal"],
            "share": n["share"],
        } for n in landed[:5]]
        radio["neighbour_count"] = len(landed)
        if band != "2.4":
            continue
        radio["channel_floor"] = _channel_floor(near, band)
        elsewhere = [s for s in (site_sightings or [])
                     if s["freq"] < 3000 and s.get("heard_by") != ap_mac]
        if elsewhere:
            radio["channel_floor_site"] = _channel_floor(elsewhere, band)


def _unifi_session(conf: dict, password: str):
    """Log in to the controller and return an opener that carries the cookie."""
    import http.cookiejar
    context = ssl.create_default_context()
    # Controller certificates are self-signed unless someone went out of their
    # way; this reads statistics, it does not trust the endpoint with secrets
    # beyond the credentials it was given for exactly this purpose.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    base = (conf.get("url") or "").rstrip("/")
    opener.open(urllib.request.Request(
        f"{base}/api/login",
        data=json.dumps({"username": conf.get("username"),
                         "password": password}).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()
    return opener


def _unifi_devices(opener, base: str, site: str) -> dict:
    """MAC -> device record: the controller's own view of what it manages."""
    body = json.loads(
        opener.open(f"{base}/api/s/{site}/stat/device", timeout=15).read())
    return {(device.get("mac") or "").lower(): device
            for device in body.get("data", [])}


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
    try:
        opener = _unifi_session(conf, password)
        devices = json.loads(
            opener.open(f"{base}/api/s/{site}/stat/device", timeout=15).read())
        # What each access point currently hears. The radios collect this
        # between beacons on their own, so asking costs nothing and — unlike
        # a channel scan on the router — never takes a radio off the air.
        scan = json.loads(opener.open(urllib.request.Request(
            f"{base}/api/s/{site}/stat/rogueap",
            data=json.dumps({"within": 1}).encode(),
            headers={"Content-Type": "application/json"}), timeout=20).read())
    except Exception as exc:
        for host in results:
            if host.get("agent") == "unifi" and not host.get("reachable"):
                host["error"] = f"контроллер UniFi недоступен: {exc}"
        return

    # Sightings belong to the radio that made them, and only recent ones say
    # anything about the air as it is now.
    heard: dict = {}
    for sighting in scan.get("data", []):
        signal = sighting.get("signal")
        frequency = sighting.get("center_freq") or sighting.get("freq")
        if not isinstance(signal, (int, float)) or not frequency:
            continue
        if (sighting.get("rssi_age") or 0) > FRESH_SIGHTING_SECONDS:
            continue
        heard.setdefault(sighting.get("ap_mac"), []).append({
            "essid": sighting.get("essid") or "",
            "bssid": sighting.get("bssid") or "",
            "channel": sighting.get("channel"),
            "freq": frequency,
            "width": sighting.get("bw") or 20,
            "signal": signal,
            "heard_by": sighting.get("ap_mac"),
        })

    # One entry per network across the whole site, kept at the loudest reading
    # anyone got. A UniFi site is one location by construction, so this is the
    # band as the building experiences it — the part of it no single radio can
    # hear from where it is parked.
    site_wide: dict = {}
    for sightings in heard.values():
        for sighting in sightings:
            previous = site_wide.get(sighting["bssid"])
            if previous is None or sighting["signal"] > previous["signal"]:
                site_wide[sighting["bssid"]] = sighting

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
        # The controller answers this for every adopted device, so the check
        # ran whether or not it found anything.
        host["updates_checked"] = True
        if device.get("upgradable"):
            host["updates"] = [{"pkg": "UniFi firmware",
                                "old": device.get("version", ""),
                                "new": device.get("upgrade_to_firmware", ""),
                                "security": "0", "suite": ""}]
            host["update_count"] = 1
        # An access point on a 100 Mbit uplink throttles every client behind it
        # and says nothing about it; the controller knows what the port
        # negotiated.
        uplink = device.get("uplink") or {}
        if uplink.get("speed"):
            host["links"] = [{
                "name": uplink.get("name") or "uplink",
                "speed": int(uplink["speed"]),
                "duplex": "full" if uplink.get("full_duplex", True) else "half",
                "state": "up" if uplink.get("up", True) else "down",
                "errors": 0, "crc": 0, "flaps": 0,
            }]
        load = device.get("sys_stats") or {}
        if load.get("loadavg_1"):
            host["load1"] = float(load["loadavg_1"])
            host["cpus"] = 1
        if load.get("mem_total"):
            host["mem_total"] = int(load["mem_total"])
            host["mem_available"] = int(load["mem_total"]) - int(load.get("mem_used", 0))

        # Channel width lives in the configuration, not in the statistics —
        # and in 2.4 GHz it decides how much of the band the radio occupies.
        widths = {entry.get("radio"): entry.get("ht")
                  for entry in device.get("radio_table", [])}
        radios = []
        for radio in device.get("radio_table_stats", []):
            total = radio.get("cu_total")
            mine = (radio.get("cu_self_rx") or 0) + (radio.get("cu_self_tx") or 0)
            radios.append({
                "width": widths.get(radio.get("radio")),
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
                # Airtime says the channel is busy; retries say our own frames
                # are the ones losing. That is the difference between a band
                # that is merely occupied and one we cannot transmit on.
                "retries": radio.get("tx_retries_pct"),
                "disabled": False,
            })
        _measure_neighbours(radios, heard.get(device.get("mac"), []),
                            list(site_wide.values()), device.get("mac", ""))
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


# The controller reports a device it is happy with as state 1. Every other
# value — 0 offline, 4 upgrading, 5 provisioning, 6 heartbeat missed — means
# the device is busy or has stopped answering, which is what a command that
# actually landed looks like from the controller's side.
UNIFI_STATE_CONNECTED = 1


def _unifi_restarted(before: dict, after: dict) -> bool:
    """A rebooted access point either drops off the controller or comes back
    with less uptime than it had."""
    if after.get("state") != UNIFI_STATE_CONNECTED:
        return True
    was, now = before.get("uptime"), after.get("uptime")
    return isinstance(was, (int, float)) and isinstance(now, (int, float)) and now < was


def _unifi_upgrading(before: dict, after: dict) -> bool:
    """An upgrade shows up as the device leaving the connected state (it
    reboots into the new firmware), as the offered upgrade disappearing, or as
    the version having already changed."""
    if after.get("state") != UNIFI_STATE_CONNECTED:
        return True
    if before.get("upgradable") and not after.get("upgradable"):
        return True
    return after.get("version") != before.get("version")


# The controller answers rc=ok to any string in `cmd`. On Network 10.2.105
# {"cmd": "definitely-not-a-command"} came back ok for every MAC tried, while
# a command the controller does implement, aimed at a MAC it does not manage,
# came back rc=error with api.err.UnknownDevice — the request only gets as far
# as the device lookup when the name is real. So rc proves the JSON parsed and
# nothing more: «restrat» would report a reboot that never happened. The name
# is checked against this table before anything is sent, and each entry says
# what the device has to look like afterwards for the command to count.
UNIFI_DEVMGR_COMMANDS = {
    "restart": _unifi_restarted,
    "upgrade": _unifi_upgrading,
}

# How long to keep re-reading the device before calling the result unconfirmed.
# A reboot takes the access point off the controller within a heartbeat or two;
# past that the honest answer is "not confirmed", which is a different thing
# from "did not happen".
UNIFI_CONFIRM_SECONDS = 60
UNIFI_CONFIRM_POLL = 5


def unifi_command(cfg: dict, mac: str, command: str,
                  confirm_seconds: float | None = None) -> tuple[bool, str]:
    """Send a device command through the controller (restart, upgrade).

    Access points take orders from the controller, not from us — which is also
    why the controller account has to be an admin rather than view-only:
    reading statistics and rebooting a radio come through the same door.

    Success is read off the device afterwards, never off the reply — see
    UNIFI_DEVMGR_COMMANDS for why the reply cannot be believed. Pass
    confirm_seconds=0 when the caller has a better witness of its own: the
    reboot job pings the access point down and back, which is firmer proof
    than the controller's heartbeat bookkeeping and happens anyway.
    """
    conf = cfg.get("unifi_controller") or {}
    base = (conf.get("url") or "").rstrip("/")
    user = conf.get("username")
    password = secrets.load(conf, "password")
    if not (base and user and password):
        return False, "контроллер UniFi не настроен в конфиге"
    if not mac:
        return False, "неизвестен MAC точки (контроллер её не видит)"
    confirmed = UNIFI_DEVMGR_COMMANDS.get(command)
    if confirmed is None:
        return False, (f"контроллер не знает команду «{command}» "
                       f"и молча ответит на неё «ок»")

    site = conf.get("site", "default")
    mac = mac.lower()
    if confirm_seconds is None:
        confirm_seconds = float(conf.get("confirm_seconds", UNIFI_CONFIRM_SECONDS))

    try:
        opener = _unifi_session(conf, password)
        # Also the only place a wrong or stale MAC is caught for certain: the
        # controller's own UnknownDevice needs the command name to be real.
        before = _unifi_devices(opener, base, site).get(mac)
        if before is None:
            return False, f"контроллер не управляет точкой {mac}"

        response = opener.open(urllib.request.Request(
            f"{base}/api/s/{site}/cmd/devmgr",
            data=json.dumps({"cmd": command, "mac": mac}).encode(),
            headers={"Content-Type": "application/json"}), timeout=20).read()
        meta = json.loads(response).get("meta", {})
        if meta.get("rc") != "ok":
            return False, str(meta.get("msg", "отказ контроллера"))
        if confirm_seconds <= 0:
            return True, ""

        deadline = time.time() + confirm_seconds
        while True:
            after = _unifi_devices(opener, base, site).get(mac, {})
            if confirmed(before, after):
                return True, ""
            left = deadline - time.time()
            if left <= 0:
                break
            time.sleep(min(UNIFI_CONFIRM_POLL, left))
    except Exception as exc:
        return False, str(exc)
    return False, (f"контроллер принял «{command}», но точка не изменила "
                   f"состояние за {int(confirm_seconds)} с — проверьте вручную")


# In 2.4 GHz only 1, 6 and 11 do not overlap: the channels are 5 MHz apart
# while a 20 MHz carrier is four wide, so anything closer than five channels
# interferes — and adjacent-but-not-equal is worse than sharing outright,
# because carrier sense cannot see the neighbour to take turns with it.
NON_OVERLAPPING_24 = {1, 6, 11}

# A neighbour matters when it is heard, not when its channel number matches.
# Below roughly -85 dBm a network is a rumour: it neither defers to us nor
# raises our noise floor enough to cost a frame.
AUDIBLE_DBM = -85
# The controller keeps one row per network, updated whenever it is heard again,
# and `within` bounds that by last_seen — so the hour-long window is what makes
# the set current. `rssi_age` is asked for as well but cannot be leaned on: the
# controller has been seen returning ages of ninety days on rows it had just
# refreshed. It is a sanity check here, not the filter.
FRESH_SIGHTING_SECONDS = 900


def _span(center: float, width: int) -> tuple[float, float]:
    half = (width or 20) / 2
    return center - half, center + half


def interference(neighbours: list[dict], center: float, width: int) -> tuple:
    """Total power the neighbours actually land inside our channel.

    Powers add linearly, so the sum is done in milliwatts and reported back in
    dBm — the same unit the individual signals arrive in. Each neighbour counts
    only for the fraction of our channel it actually covers: a 40 MHz network
    straddling the edge of our 20 MHz carrier costs us half of what it would
    sitting right on top of us.
    """
    low, high = _span(center, width)
    total_mw = 0.0
    landed = []
    for neighbour in neighbours:
        signal = neighbour.get("signal")
        if not isinstance(signal, (int, float)) or signal < AUDIBLE_DBM:
            continue
        other_low, other_high = _span(neighbour.get("freq") or 0,
                                      neighbour.get("width") or 20)
        overlap = min(high, other_high) - max(low, other_low)
        if overlap <= 0:
            continue
        share = min(overlap / (width or 20), 1.0)
        total_mw += (10 ** (signal / 10)) * share
        landed.append({**neighbour, "share": round(share, 2)})
    if not total_mw:
        return None, []
    landed.sort(key=lambda n: n["signal"], reverse=True)
    return round(10 * math.log10(total_mw), 1), landed


def analyse_wifi(results: list[dict]) -> None:
    """Look at the radios as a set, not one at a time."""
    radios_24 = []
    for host in results:
        for radio in host.get("radios", []):
            channel = radio.get("channel")
            # A second SSID is not a second radio: virtual access points share
            # the transmitter of their master and cannot interfere with it.
            if radio.get("virtual"):
                continue
            if radio.get("band") == "2.4" and isinstance(channel, int):
                radios_24.append((host, radio))

    # Whether other access points actually interfere is measured, not deduced
    # from their settings: `interference` comes from what each radio hears.
    # What is left here is the one thing a configuration alone can be wrong
    # about — a channel that overlaps its neighbours by construction.
    for _host, radio in radios_24:
        if radio["channel"] not in NON_OVERLAPPING_24:
            radio["off_grid"] = True

    # Wireless clients that matter on their own: a speaker sitting on a channel
    # the access points are already fighting over explains stuttering audio,
    # and nothing else in the fleet would connect those two facts.
    for host in results:
        channel = host.get("wifi_channel")
        if host.get("link") != "wifi" or not isinstance(channel, int):
            continue
        if host.get("wifi_band") != "2.4":
            continue
        crowding = []
        for other_host, radio in radios_24:
            # Radio interference is local. Comparing a speaker on one site with
            # an access point on another produced a finding about two rooms in
            # different buildings — technically a channel overlap, physically
            # nothing at all.
            if other_host.get("subnet") != host.get("subnet"):
                continue
            if abs(radio["channel"] - channel) >= 5:
                continue
            airtime = radio.get("utilization")
            if isinstance(airtime, (int, float)) and airtime >= 40:
                crowding.append({
                    "ap": other_host.get("name", other_host.get("id", "")),
                    "channel": radio["channel"],
                    "airtime": airtime,
                })
        if crowding:
            host["wifi_crowded_by"] = crowding


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
    named: dict[str, str] = {}
    udp_seen: dict[str, bool] = {}
    for host in results:
        addr = host.get("addr")
        if not addr:
            continue
        # A forward from the uplink names the next router by its WAN-side
        # address, which is not the address the fleet knows it by. Without the
        # alias every rule between two routers reads as "points at something we
        # do not poll" — the honest answer to the wrong question.
        for alias in (addr, host.get("wan_addr")):
            if alias:
                reachable.setdefault(alias, bool(host.get("reachable")))
                named.setdefault(alias, host.get("name") or host.get("id") or alias)
                if alias != addr:
                    listeners.setdefault(alias, listeners.setdefault(addr, set()))
        # Whether this host can report UDP listeners at all. Where it cannot —
        # BusyBox without `ss` falls back to netstat, which lists TCP only — a
        # missing UDP port is our blind spot rather than a missing service, and
        # calling that "leads nowhere" is a false alarm on every VPN forward.
        udp_seen[addr] = bool(host.get("udps")) or any(
            e.get("proto") == "udp" for e in host.get("endpoints") or [])
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

    # A hop that hands the port on again is not a dead end. Two routers in a row
    # is the normal shape here — uplink to site router to host — and judging the
    # middle one by its own listeners flags a working chain as broken.
    passes_on: dict[str, set] = {}
    for host in results:
        for rule in host.get("forwards") or []:
            if rule.get("disabled"):
                continue
            port = str(rule.get("port") or "")
            if not port.isdigit():
                continue
            for alias in (host.get("addr"), host.get("wan_addr")):
                if alias:
                    passes_on.setdefault(alias, set()).add(int(port))

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
            # The card names the destination; an address alone makes the reader
            # resolve it in their head every time.
            rule["to_name"] = named.get(target, "")
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
            elif target != host.get("addr") and int(port) in passes_on.get(target, set()):
                rule["verdict"] = "transit"
            elif ((rule.get("proto") or "").lower() in ("", "udp", "tcpudp")
                  and not udp_seen.get(target, False)):
                rule["verdict"] = "unknown"   # no UDP visibility on that host
            else:
                rule["verdict"] = "no-listener"


def verify_forward_targets(results: list[dict]) -> None:
    """Knock on the far end of every forward, from inside the perimeter.

    A port in the listener list is a claim the host made about itself while the
    agent ran; it survives a process that has since wedged, and it says nothing
    about ports on devices that run no agent at all. Opening the connection is
    the difference between "was configured to listen" and "answers now".

    UDP cannot be proven this way — nothing is obliged to answer — so those
    forwards keep the evidence they have: a listening socket and the name of the
    process holding it.
    """
    by_addr = {}
    for host in results:
        for alias in (host.get("addr"), host.get("wan_addr")):
            if alias:
                by_addr.setdefault(alias, host)

    jobs = []
    for host in results:
        for rule in host.get("forwards") or []:
            if rule.get("disabled") or rule.get("verdict") in ("host-down", "transit"):
                continue
            target = rule.get("to") or (host.get("addr") if
                                        rule.get("action") == "redirect" else "")
            port = str(rule.get("to_port") or rule.get("port") or "")
            if not target or not port.isdigit():
                continue
            # A rule usually does not say which protocol it carries — uci leaves
            # it empty for "both" — so the answer comes from what the far end is
            # actually listening with. Getting this wrong turns every VPN
            # forward into an alarm, because nothing answers a TCP knock on 500.
            want = (rule.get("proto") or "").lower()
            heard = {entry.get("proto") for entry in
                     (by_addr.get(target) or {}).get("endpoints") or []
                     if str(entry.get("port")) == port}
            if want == "udp" or (want in ("", "tcpudp") and heard == {"udp"}):
                rule["live"] = None
                for entry in (by_addr.get(target) or {}).get("endpoints") or []:
                    if str(entry.get("port")) == port:
                        rule["live_by"] = entry.get("process") or entry.get("label") or ""
                continue
            jobs.append((rule, target, int(port), want == "tcp" or "tcp" in heard))

    def knock(job: tuple) -> tuple:
        _, addr, port, _ = job
        try:
            with socket.create_connection((addr, port), timeout=3):
                return job, True
        except OSError:
            return job, False

    if not jobs:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for (rule, _, _, certain), answered in pool.map(knock, jobs):
            if answered:
                rule["live"] = True
                rule["verdict"] = "ok"
            elif certain:
                # The far end is known to listen on TCP and refuses the
                # connection anyway: configuration intact, service gone — which
                # a listener list reports as healthy.
                rule["live"] = False
                if rule.get("verdict") == "ok":
                    rule["verdict"] = "no-answer"
            else:
                # Silence over TCP proves nothing when the service may be UDP.
                rule["live"] = None


def _public(addr: str) -> bool:
    """Can a stranger dial this address? Provider NAT and CGNAT cannot."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def link_egress(results: list[dict], cfg: dict) -> None:
    """Give the site's edge the address the internet sees it as.

    The address on the WAN interface answers a different question. A provider
    can hand out a private one and still map a public address onto it — which is
    exactly what happens here — so deriving "nothing is reachable" from
    `10.188.16.186` was wrong by construction. The only witness to what our
    packets look like after the provider is done with them is a host outside:
    every agent reports the address its ssh session arrives from, and on a host
    with a public address of its own that is our own way out.
    """
    egress = ""
    for host in results:
        if not _public(host.get("addr") or ""):
            continue
        peer = host.get("ssh_peer") or ""
        if _public(peer):
            egress = peer
            break
    if not egress:
        return

    # The observation belongs to the site the collector polls from, and its edge
    # is the last router before the internet in the configured tree.
    local = next((h for h in cfg.get("hosts", []) if h.get("local")), None)
    if not local:
        return
    subnets = {s.get("cidr"): s for s in cfg.get("subnets", [])}
    node = subnets.get(local.get("subnet"))
    edge_addr = ""
    while node:
        if node.get("router"):
            edge_addr = node["router"]
        parent = node.get("parent")
        if not parent or parent == "0.0.0.0/0":
            break
        node = subnets.get(parent)
    for host in results:
        if host.get("addr") == edge_addr:
            host["egress_addr"] = egress


def verify_exposure(results: list[dict], cfg: dict, key: str | None) -> None:
    """Knock on every published port from the outside and record who answers.

    A forwarding rule is an intention; this is the only step that turns it into
    a fact. It runs from a host on the internet, because from inside the
    perimeter every one of these ports answers whether or not the world can
    reach it.
    """
    # The login details live in the configuration, not in a probe result — the
    # snapshot deliberately carries no credentials.
    up = {h.get("addr") for h in results if h.get("reachable")}
    prober = next((h for h in cfg.get("hosts", [])
                   if h.get("addr") in up and _public(h.get("addr") or "")
                   and h.get("user")), None)
    if not prober:
        return

    jobs = []
    for host in results:
        entrance = host.get("egress_addr") or host.get("wan_addr") or ""
        if not _public(entrance) or entrance == prober.get("addr"):
            continue
        for rule in host.get("forwards") or []:
            port = str(rule.get("port") or "")
            if rule.get("disabled") or not port.isdigit():
                continue
            if (rule.get("proto") or "").lower() == "udp":
                # Nothing answers a UDP probe by contract; silence would be
                # reported as "closed" and that is worse than saying nothing.
                rule["verified"] = None
                continue
            jobs.append((rule, entrance, int(port)))

    def knock(job: tuple) -> tuple:
        _, addr, port = job
        remote = (f"timeout 8 bash -c '</dev/tcp/{addr}/{port}' >/dev/null 2>&1 "
                  f"&& echo 0 || echo 1")
        cmd = list(SSH_BASE)
        if key:
            cmd += ["-i", os.path.expanduser(key)]
        if prober.get("port"):
            cmd += ["-p", str(prober["port"])]
        target = prober["addr"]
        if prober.get("user"):
            target = f"{prober['user']}@{target}"
        try:
            res = subprocess.run(cmd + [target, remote],
                                 capture_output=True, timeout=25, text=True)
            return job, res.stdout.strip().endswith("0")
        except (subprocess.SubprocessError, OSError):
            return job, False

    if not jobs:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for (rule, _, _), answered in pool.map(knock, jobs):
            rule["verified"] = answered
            rule["verified_from"] = prober.get("name", "")


def link_exposure(results: list[dict]) -> None:
    """Mark the listeners the internet can actually reach.

    Being open is not a property of a listener, and not of a forwarding rule
    either: a rule on the site router publishes nothing while the uplink itself
    sits behind the provider's NAT. So the walk starts where the answer can only
    come from — an address the outside world can dial — and follows the forwards
    inward, hop by hop, until it lands on a port something is listening on.
    """
    by_addr: dict[str, dict] = {}
    for host in results:
        for addr in (host.get("addr"), host.get("wan_addr")):
            if addr:
                by_addr.setdefault(addr, host)

    def arrive(host: dict, port: int, public: str, wan_port: int,
               path: list, seen: set, checked) -> None:
        """Traffic reached `host:port`. Note it, then keep following."""
        for entry in host.get("endpoints") or []:
            if str(entry.get("port")) == str(port):
                entry["exposed"] = {"wan_port": wan_port, "addr": public,
                                    "via": " → ".join(path), "verified": checked}
        # The hop may itself be a router that forwards this port further in.
        forward(host, public, path, seen, only_port=port, wan_port=wan_port,
                checked=checked)

    def forward(host: dict, public: str, path: list, seen: set,
                only_port: int | None = None, wan_port: int | None = None,
                checked=None) -> None:
        key = (host.get("id"), only_port)
        if key in seen or len(path) > 4:
            return
        seen.add(key)
        for rule in host.get("forwards") or []:
            if rule.get("disabled"):
                continue
            # A shell agent reports the zone the rule listens in; a redirect
            # scoped to the LAN is not an entrance from the internet, however
            # public the router's other side is. RouterOS names its chains
            # instead and its rules are not zone-scoped.
            zone = (rule.get("chain") or "").lower()
            if zone and zone not in ("wan", "dstnat", "srcnat"):
                continue
            outside = str(rule.get("port") or "")
            if not outside.isdigit():
                continue  # ranges and protocol-only rules say nothing precise
            if only_port is not None and int(outside) != only_port:
                continue
            target = by_addr.get(rule.get("to") or "")
            inside = str(rule.get("to_port") or outside)
            # The rule itself is worth marking: a card can then say which of a
            # router's forwards the internet can use and which are internal
            # plumbing that happens to look identical in the config.
            rule["public_addr"] = public
            rule["wan_port"] = wan_port if wan_port is not None else int(outside)
            # Only the edge is knocked on; a hop behind it carries the same
            # packet, so it carries the same verdict rather than "unknown".
            rule.setdefault("verified", checked)
            if not target or not inside.isdigit():
                continue
            # Only the rule at the edge is knocked on from outside; the hops
            # behind it inherit that verdict, because they are the same packet.
            arrive(target, int(inside), public,
                   wan_port if wan_port is not None else int(outside),
                   path + [host.get("name") or host.get("id") or ""], seen,
                   rule.get("verified") if checked is None else checked)

    for host in results:
        # A host on a public address is its own edge: everything it listens on
        # is offered to the internet, no forwarding involved.
        own = host.get("addr") or ""
        if _public(own):
            for entry in host.get("endpoints") or []:
                entry.setdefault("exposed", {"wan_port": entry.get("port"),
                                             "addr": own, "via": "",
                                             "verified": None})
        # What the world dials, which is not always what sits on the interface:
        # a provider can NAT a public address onto a private WAN.
        edge = host.get("egress_addr") or host.get("wan_addr") or ""
        if not _public(edge):
            continue
        # An input policy of ACCEPT means the edge answers on its own ports too.
        if str(host.get("wan_input", "")).upper() == "ACCEPT":
            for entry in host.get("endpoints") or []:
                entry.setdefault("exposed", {"wan_port": entry.get("port"),
                                             "addr": edge, "via": ""})
        # The path starts empty: each hop adds itself as it forwards, so the
        # chip reads "hEX → MikroTik" and not the edge's name twice.
        forward(host, edge, [], set())

    for host in results:
        host["exposed_count"] = sum(
            1 for entry in host.get("endpoints") or [] if entry.get("exposed"))


def link_camera_firmware(results: list[dict]) -> None:
    """Give each camera the firmware its recorder was able to read.

    The version is only available to an authenticated request, and only the
    recorder holds those credentials — so it asks, and passes on the answer.
    The dashboard never sees the login.
    """
    by_addr = {host.get("addr"): host for host in results if host.get("addr")}
    for host in results:
        for entry in host.get("camfws", []):
            camera = by_addr.get(entry.get("addr"))
            if not camera:
                continue
            camera["model"] = entry.get("model") or camera.get("model", "")
            firmware = entry.get("firmware", "")
            if firmware:
                camera["os_name"] = firmware
                camera["firmware_source"] = host.get("name", host.get("id", ""))
            released = entry.get("released", "")
            camera["firmware_date_raw"] = released
            # "build 230427" — yymmdd, which is the only date the camera gives.
            digits = re.sub(r"\D", "", released)
            if len(digits) == 6:
                try:
                    built = time.mktime((2000 + int(digits[:2]), int(digits[2:4]),
                                         int(digits[4:6]), 12, 0, 0, 0, 0, -1))
                    camera["firmware_date"] = int(built)
                    camera["firmware_age_days"] = round((time.time() - built) / 86400)
                except (ValueError, OverflowError):
                    pass


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
    link_camera_firmware(results)
    link_backups(results)
    link_exposure(results)
    annotate_web(results)
    return results
