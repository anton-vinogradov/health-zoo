"""Health rules for health-zoo.

Deliberately server-side and shared: the dashboard banner, the card colours and
the Telegram alerts all read the same list. When this lived in the browser the
alerting layer would have had to re-implement every threshold, and the two
copies would drift the first time one of them was tuned.

Each issue carries a stable `key`, which is what alerting deduplicates on —
"the disk is still full" must not page you every poll.
"""

from __future__ import annotations

# Defaults; every value can be overridden per role or per host from the config.
DEFAULT_THRESHOLDS = {
    "disk_warn": 90, "disk_bad": 96,
    "mem_warn": 90, "mem_bad": 97,
    "swap_warn": 60, "swap_bad": 90,
    # Low-power x86 boxes idle in the 70s and transcode in the 80s; Tjmax is
    # 105. Warning earlier would mean a permanently amber dashboard.
    "temp_warn": 88, "temp_bad": 96,
    "load_warn": 150, "load_bad": 300,
    "cpu_warn": 85, "cpu_bad": 96,
}

# A NAS recording video is *supposed* to sit near-full: the archive grows until
# rotation overwrites the oldest footage.
ROLE_THRESHOLDS = {
    "nas": {"disk_warn": 96, "disk_bad": 99},
    "router": {"disk_warn": 90, "disk_bad": 96},
}


def thresholds_for(host: dict, cfg: dict | None = None) -> dict:
    limits = dict(DEFAULT_THRESHOLDS)
    limits.update(ROLE_THRESHOLDS.get(host.get("role", ""), {}))
    cfg = cfg or {}
    limits.update(cfg.get("thresholds", {}))
    limits.update(cfg.get("thresholds_by_role", {}).get(host.get("role", ""), {}))
    limits.update(cfg.get("thresholds_by_host", {}).get(host.get("id", ""), {}))
    return limits


def _level(value, warn, bad) -> str:
    if not isinstance(value, (int, float)):
        return ""
    if value >= bad:
        return "bad"
    if value >= warn:
        return "warn"
    return ""


def host_issues(host: dict, cfg: dict | None = None) -> list[dict]:
    """Everything wrong with one host, worst first."""
    limits = thresholds_for(host, cfg)
    out: list[dict] = []

    def add(level: str, key: str, text: str) -> None:
        out.append({"level": level, "key": key, "text": text})

    if not host.get("reachable"):
        add("bad", "down", host.get("error") or "не отвечает")
        return out

    # Reachable over the network but the agent could not run: half-known is not
    # healthy — otherwise a router with no key installed looks perfectly fine.
    if host.get("error"):
        add("warn", "noaccess", f"нет доступа: {host['error']}")

    for disk in host.get("disks", []):
        level = _level(disk.get("pct"), limits["disk_warn"], limits["disk_bad"])
        if level:
            add(level, f"disk:{disk.get('mount')}",
                f"диск {disk.get('mount')} {disk.get('pct')}%")

    level = _level(host.get("mem_pct"), limits["mem_warn"], limits["mem_bad"])
    if level:
        add(level, "mem", f"память {host['mem_pct']}%")
    level = _level(host.get("swap_pct"), limits["swap_warn"], limits["swap_bad"])
    if level:
        add(level, "swap", f"swap {host['swap_pct']}%")

    # Only the hottest sensor: a quad-core reports one reading per core plus a
    # package total, and six identical "82°" entries say nothing extra.
    temps = host.get("temps") or []
    if temps:
        hot = max(temps, key=lambda t: t.get("c") or 0)
        level = _level(hot.get("c"), limits["temp_warn"], limits["temp_bad"])
        if level:
            add(level, "temp", f"нагрев {hot['c']}° ({hot.get('label', '')})")

    for svc in host.get("services", []):
        state = svc.get("state", "")
        name = svc.get("name", "").removesuffix(".service")
        if "failed" in state:
            add("bad", f"svc:{svc.get('name')}", f"{name} упал")
        elif (host.get("agent") == "linux"
              and str(svc.get("enabled", "")).startswith("enabled")
              and "running" not in state and "exited" not in state):
            # systemd only: OpenWrt reports a coarse running/stopped where
            # one-shot boot scripts legitimately sit at "stopped" forever.
            add("warn", f"svc:{svc.get('name')}", f"{name} включён, но не запущен")

    for raid in host.get("degraded_raid", []):
        add("bad", f"raid:{raid.get('dev')}",
            f"RAID {raid.get('dev')} {raid.get('state')}")

    for disk in host.get("failing_disks", []):
        health = (disk.get("health") or "").upper()
        if health and health not in ("PASSED", "OK"):
            why = f"SMART {disk['health']}"
        elif disk.get("pending"):
            why = f"{disk['pending']} pending-секторов"
        else:
            why = f"{disk.get('realloc')} переназначенных секторов"
        add("bad", f"smart:{disk.get('dev')}", f"диск {disk.get('dev')}: {why}")

    for cam in host.get("cameras", []):
        status = cam.get("status") or ""
        if cam.get("enabled") == "1" and status and status not in ("Connected", "recording"):
            add("bad", f"cam:{cam.get('id')}", f"камера {cam.get('name')}: {status}")

    if host.get("reboot_required"):
        # "Needs a reboot" on its own is not actionable; say what is waiting —
        # a flashed RouterBOARD firmware, a new kernel, a libc upgrade.
        why = (host.get("reboot_pkgs") or "").strip()
        packages = why.split()
        if "->" in why:
            # Not a package list: RouterOS phrases it as
            # "routerboard firmware 7.23.1 -> 7.23.2".
            detail = why
        elif any(p.startswith(("linux-image", "linux-base")) for p in packages):
            detail = "новое ядро"
            rest = [p for p in packages if not p.startswith("linux-")]
            if rest:
                detail += f" и ещё {len(rest)}"
        elif len(packages) > 3:
            detail = ", ".join(packages[:3]) + f" и ещё {len(packages) - 3}"
        else:
            detail = why
        add("warn", "reboot", f"нужна перезагрузка: {detail}" if detail else "нужна перезагрузка")

    security = host.get("security_count") or 0
    if security:
        add("warn", "security", f"{security} security-обновлений")

    order = {"bad": 0, "warn": 1}
    out.sort(key=lambda issue: order.get(issue["level"], 2))
    return out


def annotate(hosts: list[dict], cfg: dict | None = None) -> None:
    """Attach issues and an overall level to every host in place."""
    for host in hosts:
        issues = host_issues(host, cfg)
        host["issues"] = issues
        if not host.get("reachable"):
            host["level"] = "off"
        elif any(i["level"] == "bad" for i in issues):
            host["level"] = "bad"
        elif any(i["level"] == "warn" for i in issues):
            host["level"] = "warn"
        else:
            host["level"] = "ok"
        host["thresholds"] = thresholds_for(host, cfg)
