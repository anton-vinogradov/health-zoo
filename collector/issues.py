"""Health rules for health-zoo.

Deliberately server-side and shared: the dashboard banner, the card colours and
the Telegram alerts all read the same list. When this lived in the browser the
alerting layer would have had to re-implement every threshold, and the two
copies would drift the first time one of them was tuned.

Each issue carries a stable `key`, which is what alerting deduplicates on —
"the disk is still full" must not page you every poll.
"""

from __future__ import annotations

import time

# Defaults; every value can be overridden per role or per host from the config.
DEFAULT_THRESHOLDS = {
    "disk_warn": 90, "disk_bad": 96,
    "mem_warn": 90, "mem_bad": 97,
    "swap_warn": 60, "swap_bad": 90,
    # Low-power x86 boxes idle in the 70s and transcode in the 80s; Tjmax is
    # 105. Warning earlier would mean a permanently amber dashboard.
    "temp_warn": 88, "temp_bad": 96,
    "load_warn": 150, "load_bad": 300,
    "cpu_warn": 80, "cpu_bad": 90,
    # Waiting on a disk is normal in bursts and a fault when sustained; a
    # quarter of the time gone to the hypervisor means the neighbours are
    # louder than the tenant.
    "iowait_warn": 50, "iowait_bad": 80,
    "steal_warn": 10, "steal_bad": 25,
    # HyperBackup here runs nightly; two days without a run means it stopped.
    "backup_stale_days": 2,
    # Motion detection that has produced nothing all night is suspicious;
    # a full day of silence on a street camera is broken, not quiet.
    "camera_quiet_warn_hours": 12,
    "camera_quiet_bad_hours": 24,
    # 2.4 GHz has three usable channels and long airtime per frame: it is
    # congested at levels where 5 GHz is still comfortable.
    "airtime_warn_24": 40, "airtime_bad_24": 70,
    "airtime_warn_5": 60, "airtime_bad_5": 85,
    # Retries are normal — rate adaptation lives on them — but a third of
    # frames repeated means the channel is being lost, not shared.
    "retries_warn_24": 35, "retries_warn_5": 45,
    "wifi_satisfaction_warn": 80,
    # Moving channel costs every client a reconnect, so it has to buy back
    # more than measurement noise: eight points of foreign airtime, backed by
    # enough polls that a single busy evening cannot be the whole sample.
    "channel_gain_pct": 8,
    "channel_evidence_samples": 10,
    # A candidate heard this much louder than the channel we are on is worse
    # even before correcting for the receiver being deaf to it.
    "channel_gain_db": 6,
    # Let's Encrypt renews at 30 days; a warning at 21 means renewal has
    # already failed twice, and 7 means it is now urgent.
    # "Unusual for this host" needs two guards: a floor, below which a multiple
    # is arithmetic rather than news, and how many times over the habit counts
    # as a departure from it.
    # Ten days is enough to notice a bill and pay it without hurrying; three is
    # enough to hurry.
    "balance_warn_days": 10, "balance_bad_days": 3,
    # A week is enough to notice and pay; two days is enough to panic.
    "paid_warn_days": 7, "paid_bad_days": 2,
    # Hardware that comes back on its own: once is an event, three times in a
    # week is a power supply, a board or a watchdog.
    "reboots_week_warn": 3, "reboots_week_bad": 5,
    # Attempts to authenticate from a device that never gets in. One or two are
    # a neighbour's phone brushing past; a device retrying every twenty seconds
    # is either yours with an outdated password or somebody guessing.
    "authfail_warn": 5,
    "baseline_floor": 25,
    "baseline_factor": 2.0,
    "cert_warn_days": 21,
    "cert_bad_days": 7,
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


def _channels_ruled_out(radio: dict, limits: dict) -> dict:
    """Candidates already known to be worse than where the radio is now.

    Off-channel readings understate — the receiver is filtered — so a candidate
    that already sounds louder than the channel we are measuring properly is
    genuinely louder. That is the one direction in which this data can be
    trusted, and it is enough to strike a channel off the list without ever
    moving the radio onto it.
    """
    # Both sides of the comparison have to be measured over the same width.
    # `interference` spans the carrier the radio actually runs, which on a
    # 40 MHz radio collects roughly twice the neighbourhood — comparing that
    # against 20 MHz candidates would quietly clear every one of them.
    floor = radio.get("channel_floor") or {}
    same_width = (floor.get(str(radio.get("channel"))) or {}).get("level")
    here = same_width if isinstance(same_width, (int, float)) else radio.get("interference")
    if not isinstance(here, (int, float)):
        return {}
    margin = limits.get("channel_gain_db", 6)
    out = {}
    for key, entry in floor.items():
        level = (entry or {}).get("level")
        if not str(key).isdigit() or not isinstance(level, (int, float)):
            continue
        if int(key) != radio.get("channel") and level - here >= margin:
            out[int(key)] = entry
    return out


def _ago(hours: float) -> str:
    if hours < 1:
        return "только что"
    if hours < 48:
        return f"{round(hours)} ч назад"
    return f"{round(hours / 24)} дн назад"


def _channel_advice(radio: dict, limits: dict) -> tuple:
    """Where this 2.4 GHz radio should sit — or nothing, if nobody can tell.

    Returns (text, level); "info" means there is nothing to be done about it.

    Silence is a valid answer here and used to be the missing one: the check
    this replaced compared the channel it was on against what it thought the
    others sounded like, and recommended moves onto channels it had simply
    failed to hear.
    """
    if radio.get("band") != "2.4":
        return "", ""
    channel = radio.get("channel")
    if not isinstance(channel, int) or not channel:
        return "", ""

    measured = {}
    for key, entry in (radio.get("channel_history") or {}).items():
        if str(key).isdigit() and isinstance(entry, dict):
            measured[int(key)] = entry
    enough = limits.get("channel_evidence_samples", 10)
    gain = limits.get("channel_gain_pct", 8)
    ruled_out = _channels_ruled_out(radio, limits)
    here = measured.get(channel)

    if here and here.get("samples", 0) >= enough:
        better = sorted(
            (c for c, entry in measured.items()
             if c != channel and c not in ruled_out
             and entry.get("samples", 0) >= enough
             and here["median"] - entry["median"] >= gain),
            key=lambda c: measured[c]["median"])
        if better:
            best = measured[better[0]]
            return (f"канал {channel}: чужой эфир {here['median']}% по "
                    f"{here['samples']} замерам. На канале {better[0]} было "
                    f"{best['median']}% ({best['samples']} замеров, последний "
                    f"{_ago(best['age_hours'])}) — стоит перейти туда", "warn")

    # Nothing is provable, so speak only if something is actually hurting —
    # and busy air is not the only way it can. A channel can read as half
    # empty while a third of our frames go out twice, which is the case that
    # a threshold on airtime alone sits quietly through.
    util = radio.get("utilization")
    retries = radio.get("retries")
    busy = (isinstance(util, (int, float))
            and util >= limits.get("airtime_warn_24", 40))
    losing = (isinstance(retries, (int, float))
              and retries >= limits.get("retries_warn_24", 35))
    if not (busy or losing):
        return "", ""
    symptom = f"эфир {util}%" if busy else f"{retries}% передач повторно"

    known = set(measured) | set(ruled_out) | {channel}
    for key in (radio.get("channel_floor") or {}):
        if str(key).isdigit():
            known.add(int(key))
    untried = sorted(c for c in known
                     if c != channel and c not in ruled_out
                     and measured.get(c, {}).get("samples", 0) < enough)
    struck = ", ".join(
        f"{c} занят ({entry['loudest']} {entry['signal']} дБм)"
        for c, entry in sorted(ruled_out.items()))
    # A wide neighbour lands on several candidates at once, so it is named once
    # with the channels it covers rather than repeated under each of them.
    from_others: dict = {}
    for key, entry in (radio.get("channel_floor_site") or {}).items():
        if str(key).isdigit() and int(key) in untried:
            from_others.setdefault(
                (entry["loudest"], entry["signal"]), []).append(int(key))
    elsewhere = ", ".join(
        f"{essid} {signal} дБм на {'/'.join(str(c) for c in sorted(channels))}"
        for (essid, signal), channels in from_others.items())

    if not untried:
        # Neither of the answers below asks for anything: the channel is busy
        # and every alternative was measured and is no better. Amber on a card
        # is a request to act, and there is no action — so this is a fact, not
        # a finding, and it says so by its level.
        # "Worse" and "better, but not by enough to be worth every client
        # reconnecting" are different answers, and the check above has already
        # refused the move for the second reason. Reporting it as the first
        # sends the reader hunting for an error in numbers that are correct.
        rivals = sorted((entry["median"], c) for c, entry in measured.items()
                        if c != channel and c not in ruled_out
                        and entry.get("samples", 0) >= enough)
        if here and rivals and rivals[0][0] < here["median"]:
            level, best_channel = rivals[0]
            return (f"канал {channel}: {symptom}, чужого {here['median']}% по "
                    f"{here['samples']} замерам. Тише всех канал {best_channel} "
                    f"({level}%), но выигрыш "
                    f"{round(here['median'] - level, 1)} п.п. меньше порога "
                    f"в {gain} — переезд не окупает переподключение клиентов",
                    "info")
        return (f"канал {channel}: {symptom}, но остальные каналы хуже"
                + (f" — {struck}" if struck else ""), "info")
    parts = [f"канал {channel}: {symptom}, а на "
             f"{', '.join(str(c) for c in untried)} это радио не стояло — "
             "сравнить не с чем, нужен перебор с замерами"]
    if struck:
        parts.append(struck)
    if elsewhere:
        parts.append(f"с другой точки там слышно {elsewhere}")
    return ". ".join(parts), "warn"


def _speed(mbit: int) -> str:
    if mbit < 1000:
        return f"{mbit} Мбит/с"
    gigabits = mbit / 1000
    # 2.5GbE exists and rounding it to "2 Гбит/с" would misstate the hardware.
    return f"{gigabits:g} Гбит/с"


def _level(value, warn, bad) -> str:
    if not isinstance(value, (int, float)):
        return ""
    if value >= bad:
        return "bad"
    if value >= warn:
        return "warn"
    return ""


def _link_verdict(link: dict) -> tuple[str, str]:
    """Is a slow port configured that way, or is the line failing?

    Both ends of an ethernet link say out loud what they are willing to run at,
    and the port itself says what it is able to run at. A gigabit port that
    offers only 100 was told to; a port that offers a gigabit to a neighbour
    offering a gigabit and still settles for 100 is losing the signal somewhere
    between them. Returns the verdict and the evidence behind it, or a pair of
    empty strings when the port did not report enough to tell.
    """
    speed = link.get("speed") or 0
    capable = link.get("capable") or 0
    offered = link.get("offered") or 0
    partner = link.get("partner") or 0
    best = link.get("speed_best") or 0

    if link.get("autoneg") == "off":
        return "настройка", ("настройка: автосогласование выключено, "
                             "скорость закреплена вручную")
    if capable and offered and offered < capable:
        return "настройка", (f"настройка: порт объявляет только {_speed(offered)}, "
                             f"хотя умеет {_speed(capable)}")
    if not partner:
        return "", ""
    if partner > speed:
        # Both sides asked for more than they got: whatever refused is between
        # them, and that is the cable, the connectors or the sockets.
        return "линия", (f"кабель или разъём: обе стороны объявляют "
                         f"{_speed(partner)}, а договорились на {_speed(speed)}")
    if best > speed:
        # The neighbour asks for no more than it has, but this port has run
        # faster before, so the neighbour is not a 100 Mbit device: it dropped
        # to 100 and stayed there. That is the classic downshift.
        return "линия", (f"кабель или разъём: сосед объявляет {_speed(partner)}, "
                         f"а раньше линк поднимался на {_speed(best)}")
    return "сосед", f"предел соседа: он объявляет только {_speed(partner)}"


def host_issues(host: dict, cfg: dict | None = None) -> list[dict]:
    """Everything wrong with one host, worst first."""
    limits = thresholds_for(host, cfg)
    out: list[dict] = []

    def add(level: str, key: str, text: str, episodic: bool = False) -> None:
        """`episodic` marks a finding about something that happened.

        A restart counted over a week, a unit that came back three times, half
        an hour spent above this machine's habits: those are events. They can be
        read once and dismissed, because the next occurrence writes a different
        sentence and speaks again.

        Everything else describes a state that is still true — a port that
        negotiated 100 Mbit, an expired certificate, a full disk. Dismissing
        those "until next time" would be a lie: there is no next time, only now,
        and accepting them takes a reason in writing.
        """
        entry = {"level": level, "key": key, "text": text}
        if episodic:
            entry["episodic"] = True
        out.append(entry)

    if not host.get("reachable"):
        # An unreachable host is a problem, full stop. "This one is usually
        # off" used to be a config flag that quietly demoted the finding, which
        # meant the fleet had two different ways to accept a known state — and
        # only one of them demanded a reason or came up for review. Now there
        # is one: suppress the finding, in writing.
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

    # Busy time, not load average: a load of 4 on four cores is a box doing its
    # job, while 90% busy is one with nothing left to give whatever the queue
    # length says. The two answer different questions and only this one is
    # asked here.
    level = _level(host.get("cpu_load_pct"), limits["cpu_warn"], limits["cpu_bad"])
    if level:
        add(level, "cpu", f"процессор занят на {host['cpu_load_pct']}%")

    # Waiting on storage is the opposite of busy, and saying "processor at 100%"
    # about it sends everybody looking in the wrong place. This host spent
    # twenty minutes at 94% iowait while its disk answered four operations a
    # second: nothing to optimise, something to complain to the provider about.
    level = _level(host.get("cpu_iowait_pct"),
                   limits["iowait_warn"], limits["iowait_bad"])
    if level:
        add(level, "iowait",
            f"процессор ждёт диск {host['cpu_iowait_pct']}% времени")

    # Stolen time is not ours at all: the hypervisor gave the core to somebody
    # else. Nothing inside the guest can fix it and nothing inside the guest
    # shows it except this counter.
    level = _level(host.get("cpu_steal_pct"),
                   limits["steal_warn"], limits["steal_bad"])
    if level:
        add(level, "steal",
            f"гипервизор забирает {host['cpu_steal_pct']}% процессорного времени")

    # Load average answers the other half of the question: how many processes
    # want the machine, including the ones stuck on a disk. A box can be 40%
    # busy with a queue six deep — that is I/O, not idleness, and busy time
    # alone reports it as healthy.
    if isinstance(host.get("load1"), (int, float)) and host.get("cpus"):
        queued = round(host["load1"] * 100.0 / host["cpus"])
        level = _level(queued, limits["load_warn"], limits["load_bad"])
        if level:
            add(level, "load",
                f"очередь к процессору: {host['load1']} на {host['cpus']} "
                f"ядра — {queued}% от их числа")

    level = _level(host.get("mem_pct"), limits["mem_warn"], limits["mem_bad"])
    if level:
        add(level, "mem", f"память {host['mem_pct']}%")
    level = _level(host.get("swap_pct"), limits["swap_warn"], limits["swap_bad"])
    if level:
        add(level, "swap", f"swap {host['swap_pct']}%")

    # A port that used to run at a gigabit and now negotiates 100 Mbit is a
    # cable, a connector or a socket on its way out. Nothing on the host
    # notices: the link is up, traffic flows, and everything is merely eight
    # times slower than it was. The comparison is against what this port itself
    # has done before, because 100 Mbit is a fault on one socket and the normal
    # state of the next.
    for link in host.get("links", []):
        if link.get("state") != "up":
            continue
        speed, best = link.get("speed") or 0, link.get("speed_best") or 0
        capable = link.get("capable") or 0
        verdict, evidence = _link_verdict(link)
        # A port running at its neighbour's maximum is not a fault. Saying so
        # is what the advertised modes are for: without them every camera on a
        # gigabit socket read as a broken cable.
        slow = (speed and best and speed < best) or (speed and capable and speed < capable)
        if slow and verdict == "сосед":
            continue
        tail = f" — {evidence}" if evidence else ""
        if speed and best and speed < best:
            add("warn" if speed >= 100 else "bad", f"link:{link['name']}",
                f"порт {link['name']}: {_speed(speed)} вместо {_speed(best)}{tail}")
        elif link.get("duplex") == "half":
            add("warn", f"link:{link['name']}",
                f"порт {link['name']}: полудуплекс — договорились не с той стороной")
        elif link.get("flaps") and link.get("flaps_prev") is not None \
                and link["flaps"] > link["flaps_prev"]:
            # The counter only goes up, so any growth happened since the last
            # poll: the link is dropping and coming back right now.
            add("warn", f"link:{link['name']}",
                f"порт {link['name']}: линк оборвался "
                f"{link['flaps'] - link['flaps_prev']} раз с прошлого опроса")
        elif link.get("crc"):
            # CRC errors are the cable telling you before the speed drops.
            add("warn", f"link:{link['name']}",
                f"порт {link['name']}: {link['crc']} битых кадров — кабель или разъём")
        elif speed and capable and speed < capable:
            # The port itself says what it can do, so this needs no history and
            # no guessing: a socket that supports a gigabit and agreed on 100
            # has a cable, a connector or a switch port going bad.
            add("warn" if speed >= 100 else "bad", f"link:{link['name']}",
                f"порт {link['name']}: {_speed(speed)}, хотя умеет {_speed(capable)}{tail}")

    # Unusual for this machine, whatever the fixed thresholds say. The whole
    # point is the range below them: a box that normally idles at 12% and has
    # been sitting at 55% for half an hour is doing something new, and 55 is
    # nowhere near any threshold that would suit the fleet.
    for label, norm in (host.get("baselines") or {}).items():
        now, usual = norm.get("now"), norm.get("usual")
        if not isinstance(now, (int, float)) or not isinstance(usual, (int, float)):
            continue
        # A floor keeps arithmetic out of it: three times two per cent is six
        # per cent, and nobody needs to hear about it.
        if now < limits.get("baseline_floor", 25):
            continue
        if usual <= 0 or now / usual < limits.get("baseline_factor", 2.0):
            continue
        add("warn", f"unusual:{label}",
            f"{label}: {now}% последние полчаса против обычных {usual}% "
            f"({norm.get('samples')} замеров)", episodic=True)

    # What a stranger is served. The local view reads the certificate from the
    # host that offers it; this one reads what actually comes back over the
    # internet, which is a different claim and occasionally a different
    # certificate.
    local_subjects = {link.get("port"): (link.get("cert") or {}).get("subject")
                      for link in host.get("web") or [] if link.get("cert")}
    for seen in host.get("outside") or []:
        if not seen.get("tls"):
            continue
        days = seen.get("days")
        if isinstance(days, (int, float)):
            level = ("bad" if days < limits["cert_bad_days"]
                     else "warn" if days < limits["cert_warn_days"] else "")
            if level:
                # An expiry in the past is not an expiry "in -19 days".
                when = (f"истёк {abs(round(days))} дн назад" if days < 0
                        else f"истекает через {round(days)} дн")
                add("bad" if days < 0 else level, f"certout:{seen['port']}",
                    f"сертификат на порту {seen['port']} {when} — "
                    f"так его видно снаружи (смотрел {seen.get('from')})")
        here = local_subjects.get(seen["port"])
        if here and seen.get("subject") and here != seen["subject"]:
            add("warn", f"certdiff:{seen['port']}",
                f"порт {seen['port']}: снаружи отдаётся «{seen['subject']}», "
                f"а сам хост показывает «{here}»")

    # Hardware that could do more than it is doing. Stated as a finding rather
    # than a fault: none of these stops anything working, they just cost the
    # difference quietly, every day, until somebody looks.
    for cap in host.get("caps", []):
        # A cap somebody chose on purpose is worth seeing and not worth
        # colouring: the agent that knows it was deliberate says so.
        add(cap.get("level") or "warn", f"capped:{cap.get('what')}",
            f"{cap.get('what')}: {cap.get('detail')}")

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
        # The operator's services are the point of the host; the distribution's
        # are its plumbing. A broken one of ours is a problem, a broken one of
        # theirs is worth seeing but does not turn the host red — some units
        # (e2scrub_reap, remount-fs) sit at "failed" on a healthy machine and
        # would otherwise drown out everything that matters.
        own = svc.get("scope") != "system"
        # A transient unit is a one-off command somebody ran (systemd-run
        # names them run-uNNNN), not a service that stopped doing its job. It
        # stays visible — a failed job is still worth seeing — but as a note:
        # "run-u6525 упал" as a fleet problem sends the reader hunting for a
        # service that never existed.
        if svc.get("name", "").startswith("run-"):
            if "failed" in state:
                add("info", f"svc:{svc.get('name')}",
                    f"разовая задача {name} завершилась с ошибкой "
                    "(запущена вручную через systemd-run, не сервис)")
            continue
        if "failed" in state:
            add("bad" if own else "warn", f"svc:{svc.get('name')}",
                f"{name} упал" + ("" if own else " (системный)"))
        elif (host.get("agent") == "linux" and own
              and str(svc.get("enabled", "")).startswith("enabled")
              and "running" not in state and "exited" not in state):
            # systemd only: OpenWrt reports a coarse running/stopped where
            # one-shot boot scripts legitimately sit at "stopped" forever.
            # Treated as breakage, not a note: a service set to start at boot
            # and now not running has stopped doing its job, whether it
            # crashed or was stopped and forgotten.
            add("bad", f"svc:{svc.get('name')}", f"{name} не работает (включён в автозапуск)")

    # What the money is doing. A prepaid server that stops is indistinguishable
    # from a dead one, and the difference costs an hour to work out at the worst
    # possible time.
    money = host.get("billing") or {}
    days = money.get("days_left")
    if isinstance(days, (int, float)):
        note = f"по расчёту провайдера средств хватает до {money.get('forecast')}"
        if days < 0:
            add("bad", "balance", f"средства кончились {abs(round(days))} дн назад — {note}")
        elif days <= limits.get("balance_bad_days", 3):
            add("bad", "balance", f"денег на {round(days)} дн — {note}")
        elif days <= limits.get("balance_warn_days", 10):
            add("warn", "balance", f"денег на {round(days)} дн — {note}")

    # Rent, counted down. A server that vanishes because nobody topped up the
    # balance looks exactly like a server that died, and costs a great deal
    # more to work out at two in the morning.
    paid = str(host.get("paid_until") or "").strip()
    if paid:
        try:
            until = time.mktime(time.strptime(paid, "%Y-%m-%d"))
            days = round((until - time.time()) / 86400)
            if days < 0:
                add("bad", "paid", f"оплачен по {paid} — срок прошёл "
                                   f"{abs(days)} дн назад")
            elif days <= limits.get("paid_bad_days", 2):
                add("bad", "paid", f"оплачен по {paid} — остался"
                                   f"{'' if days == 1 else 'ось'} {days} дн")
            elif days <= limits.get("paid_warn_days", 7):
                add("warn", "paid", f"оплачен по {paid} — осталось {days} дн")
        except ValueError:
            add("warn", "paid", f"не разобрал дату оплаты «{paid}», "
                                "ожидается ГГГГ-ММ-ДД")

    # A restart nobody asked for is invisible by the next poll: the host is up,
    # healthy and identical to one that never went anywhere. It also needs to
    # reach the operator rather than just the screen — a power cut, a watchdog,
    # a crash and somebody at the keyboard all look like this, and the last two
    # are worth hearing about the same minute. Our own reboots stay a note.
    if host.get("rebooted") and not host.get("reboot_planned"):
        minutes = max(1, round((host.get("uptime") or 0) / 60))
        add("bad", "rebooted",
            f"перезагрузился {minutes} мин назад, и не с дашборда — "
            "питание, сбой или перезагрузка вручную", episodic=True)
    weekly = host.get("reboots_week") or 0
    if weekly >= limits.get("reboots_week_bad", 5):
        add("bad", "reboots",
            f"перезагружался {weekly} раз за неделю сам по себе", episodic=True)
    elif weekly >= limits.get("reboots_week_warn", 3):
        add("warn", "reboots",
            f"перезагружался {weekly} раза за неделю сам по себе", episodic=True)

    # Somebody trying the door. A device that authenticates and fails leaves
    # nothing behind — no lease, no ARP entry, no name — so until this rule it
    # was invisible: the only trace is the radio log, and nobody reads that
    # until they already suspect something. Whose door it is matters: this is
    # usually the owner's own gadget still holding last year's password, and
    # occasionally it is not.
    for guest in host.get("knocking") or []:
        if (guest.get("attempts") or 0) < limits.get("authfail_warn", 5):
            continue
        where = f" «{guest['ssid']}»" if guest.get("ssid") else ""
        # No number in the sentence, deliberately. The count is read from a
        # rolling window and changes at every poll, so a finding that named it
        # could never be dismissed: the acknowledgement is keyed on the wording
        # and would evaporate a minute later. The exact figure lives on the
        # card, where it can move without undoing anybody's decision.
        add("warn", f"authfail:{guest['mac']}",
            f"{guest['mac']} стучится в сеть{where} и не проходит авторизацию — "
            "устройства нет ни в арендах, ни в ARP", episodic=True)

    # A unit that dies and is brought back looks healthy at every poll; the
    # restart counter is the only place it shows, and only as a difference.
    for svc in host.get("services", []):
        if svc.get("restarts_delta"):
            name = svc.get("name", "").removesuffix(".service")
            add("warn" if svc.get("scope") != "system" else "info",
                f"svcflap:{svc.get('name')}",
                f"{name} перезапускался {svc['restarts_delta']} раз с прошлого опроса", episodic=True)

    for name in host.get("services_gone") or []:
        # Removing a service is a normal thing to do — and doing it by accident
        # looks exactly the same, which is why it gets said out loud once.
        add("warn", f"svcgone:{name}",
            f"{name.removesuffix('.service')} исчез: юнит работал в прошлый опрос, "
            "сейчас его нет в системе", episodic=True)

    for container in host.get("containers", []):
        if container.get("state") != "running":
            add("bad", f"container:{container.get('name')}",
                f"контейнер {container.get('name')} не работает: {container.get('status', '')}")

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

    # An unmeasured disk is not a healthy disk. Say it once, quietly, so a NAS
    # card cannot look green purely because nobody could look inside it.
    if host.get("smart_blocked") and not host.get("smarts"):
        add("warn", "smart_blocked", f"здоровье дисков не видно: {host['smart_blocked']}")

    for cam in host.get("cameras", []):
        status = cam.get("status") or ""
        name = cam.get("name")
        if cam.get("enabled") != "1":
            continue
        if status and status not in ("Connected", "recording"):
            add("bad", f"cam:{cam.get('id')}", f"камера {name}: {status}")
            continue
        # Connected but recording nothing: a broken zone or a stuck analysis
        # thread looks identical to a quiet night, except it never ends. This
        # is the failure the whole fleet exists to avoid.
        quiet = cam.get("quiet_hours")
        # A camera may carry its own pair: what counts as silence differs
        # between a street and a garage, and one fleet-wide number makes one of
        # them wrong by construction.
        own = (cam.get("limits") or {})
        quiet_bad = own.get("bad", limits.get("camera_quiet_bad_hours", 24))
        quiet_warn = own.get("warn", limits.get("camera_quiet_warn_hours", 12))
        # The sentence names the threshold that was crossed, not the running
        # count. "34 ч" becomes "35 ч" an hour later, and a finding whose
        # wording moves every poll can never be read and dismissed — the
        # acknowledgement is keyed on what it said. Naming the bucket instead
        # holds still while nothing changes and speaks again when the silence
        # gets a day longer, which is the point at which somebody should hear
        # about it twice. The exact figure is on the card, in "молчит".
        def _silence(hours: float, floor: float) -> str:
            days = int(hours // 24)
            if days >= 2:
                return f"больше {days} сут"
            if days == 1:
                return "больше суток"
            return f"больше {int(floor)} ч"

        if quiet is not None and quiet >= quiet_bad:
            add("bad", f"camquiet:{cam.get('id')}",
                f"камера {name}: нет событий {_silence(quiet, quiet_bad)} — "
                "детекция молчит", episodic=True)
        elif quiet is not None and quiet >= quiet_warn:
            add("warn", f"camquiet:{cam.get('id')}",
                f"камера {name}: нет событий {_silence(quiet, quiet_warn)}",
                episodic=True)

    # A backup that has not run is the failure mode nobody sees until restore
    # day; a share outside the task is the same failure, arranged in advance.
    stale_after = limits.get("backup_stale_days", 2)
    for repo in host.get("backuprepos", []):
        age = repo.get("age_days")
        if age is None:
            continue
        if age > stale_after * 3:
            add("bad", f"backup:{repo['name']}",
                f"бэкап {repo['name']} не обновлялся {int(age)} сут")
        elif age > stale_after:
            add("warn", f"backup:{repo['name']}",
                f"бэкап {repo['name']} старше {int(age)} сут")

    if host.get("backup_orphan"):
        add("bad", "no_backup", "не бэкапится никуда и не принимает бэкапы")

    unbacked = [u.get("share") for u in host.get("unbackeds", []) if u.get("share")]
    if unbacked:
        add("warn", "unbacked",
            "не входит в бэкап: " + ", ".join(sorted(unbacked)[:6]))

    # Auto power-on cannot be read from the OS: on x86 it is a BIOS setting
    # with no SMBIOS field, and DSM keeps its state behind root. So it is an
    # operator-declared fact — recorded once in the config, then watched here
    # instead of being forgotten until the next outage.
    if host.get("power_recovery") is False:
        add("warn", "power_recovery",
            "не включится сам после пропадания электричества")

    # An access point with a dead radio still pings, still answers ssh, and
    # serves nobody — the one failure a network-level check cannot see.
    radios = host.get("radios", []) + host.get("radioiws", [])
    for radio in radios:
        name = radio.get("name") or radio.get("dev") or "?"
        band = radio.get("band")
        label = f"{band} ГГц" if band else name
        if radio.get("disabled"):
            continue  # deliberately off is not broken
        if radio.get("channel") == 0 or radio.get("freq") == 0:
            ssid = radio.get("ssid")
            add("bad", f"radio:{name}",
                f"радио {name}{' (' + ssid + ')' if ssid else ''} не вещает")

        # 2.4 GHz is a narrow, crowded band and degrades much earlier than 5.
        util = radio.get("utilization")
        warn_at = limits.get("airtime_warn_24" if band == "2.4" else "airtime_warn_5", 60)
        bad_at = limits.get("airtime_bad_24" if band == "2.4" else "airtime_bad_5", 80)
        if isinstance(util, (int, float)) and util >= warn_at:
            foreign = radio.get("foreign_utilization")
            source = ""
            if isinstance(foreign, (int, float)):
                source = (f", из них {foreign}% чужие сети"
                          if foreign * 2 >= util else f", в основном свой трафик ({util - foreign}%)")
            add("bad" if util >= bad_at else "warn", f"radioair:{name}",
                f"эфир {label} занят на {util}%{source}")

        # Airtime says the band is busy; retries say our own frames are the
        # ones not getting through. A quiet-looking channel with a third of
        # transmissions repeated is the case airtime alone would have missed.
        retries = radio.get("retries")
        retry_at = limits.get("retries_warn_24" if band == "2.4" else "retries_warn_5", 40)
        if isinstance(retries, (int, float)) and retries >= retry_at:
            add("warn", f"radioretry:{name}",
                f"{label}: {retries}% передач уходят повторно")

        # Which channel to sit on is decided on measurements taken from that
        # channel — and a radio only ever measures the one it is on. What it
        # hears about the rest of the band comes through its own filter and is
        # always too quiet, so it can prove a channel bad and never prove one
        # good. Recommendations therefore come from recorded history; what the
        # radio hears right now is only allowed to rule candidates out.
        verdict, urgency = _channel_advice(radio, limits)
        if verdict:
            add(urgency, f"radioneighbours:{name}", verdict)
        elif radio.get("off_grid"):
            add("warn", f"radiogrid:{name}",
                f"канал {radio.get('channel')} в 2.4 ГГц перекрывается с соседними; "
                "непересекающиеся — 1, 6, 11")

        # 40 MHz in 2.4 GHz doubles the occupied spectrum in a band with room
        # for three carriers: half the neighbours counted as "foreign airtime"
        # are only heard because the channel is twice as wide as it needs.
        width = radio.get("width")
        if band == "2.4" and isinstance(width, (int, float)) and width > 20:
            add("warn", f"radiowidth:{name}",
                f"ширина канала {int(width)} МГц в 2.4 ГГц — вдвое шире нужного; "
                "непересекающихся каналов при такой ширине не остаётся")

        satisfaction = radio.get("satisfaction")
        if isinstance(satisfaction, (int, float)) and 0 < satisfaction < limits.get(
                "wifi_satisfaction_warn", 80):
            add("warn", f"radiosat:{name}",
                f"качество связи {label}: {satisfaction}%")
    # Per-SSID quality, which is the level a complaint arrives at: nobody says
    # "the ng radio is unhappy", they say "ferretclub is bad in the kitchen".
    for net in host.get("ssids") or []:
        satisfaction = net.get("satisfaction")
        if not net.get("up") or not net.get("clients"):
            continue
        if isinstance(satisfaction, (int, float)) and 0 < satisfaction < limits.get(
                "wifi_satisfaction_warn", 80):
            add("warn", f"ssidsat:{net['essid']}/{net['band']}",
                f"сеть {net['essid']} ({net['band']} ГГц): качество "
                f"{satisfaction}% у {net['clients']} клиентов")

    # A router publishes by definition, so listing open ports as findings would
    # be noise. These are the ones that are a decision rather than a default:
    # clear-text management, an unauthenticated tool port, or a service that
    # turns the box into someone else's infrastructure.
    RISKY = {
        "telnet": "management в открытом виде",
        "ftp": "передача паролей в открытом виде",
        "api": "API без TLS",
        "bandwidth-test": "сервер нагрузочного теста",
        "socks": "SOCKS-прокси",
        "upnp": "UPnP: клиенты сами открывают порты наружу",
    }
    for endpoint in host.get("endpoints") or []:
        why = RISKY.get(str(endpoint.get("label", "")).lower())
        if not why or endpoint.get("restricted_to"):
            continue
        add("warn", f"open:{endpoint.get('label')}",
            f"{endpoint.get('label')}:{endpoint.get('port')} доступен без "
            f"ограничения по адресу — {why}")

    # Firmware with no vendor feed to check. Age alone is not a fault: a
    # four-year-old build on a camera the manufacturer never updated again is
    # simply the newest there is, and saying otherwise sends somebody hunting
    # for a download that does not exist. So this fires only when a newer
    # published build is known by name.
    known = host.get("firmware_known") or {}
    if host.get("firmware_outdated") and known:
        newer = known.get("version") or ""
        built = known.get("built") or ""
        when = (f", сборка {built[4:6]}.{built[2:4]}.20{built[0:2]}"
                if len(built) == 6 else "")
        add("warn", "firmware_age",
            f"есть прошивка новее: {newer}{when} — у вас "
            f"{host.get('os_name', '')}"
            + (f" ({int(host['firmware_age_days'])} сут)"
               if host.get("firmware_age_days") else ""))

    # Forwards and tunnels: configuration that silently stops working. Nothing
    # complains when the service behind a forward moves away, and an IPsec
    # policy that never came up looks identical to one nobody is using today.
    for rule in host.get("forwards") or []:
        where = f"{rule.get('port') or '?'} → {rule.get('to')}:{rule.get('to_port') or ''}"
        label = rule.get("comment") or where
        if rule.get("verdict") == "no-listener":
            add("warn", f"fwd:{rule.get('port')}",
                f"проброс «{label}» ведёт в никуда: на {rule.get('to')} "
                f"порт {rule.get('to_port')} никто не слушает")
        elif rule.get("verdict") == "no-answer":
            # The port is bound and the connection is refused or times out —
            # a wedged service, which a listener list reports as healthy.
            add("warn", f"fwd:{rule.get('port')}",
                f"проброс «{label}»: {rule.get('to')}:{rule.get('to_port')} "
                f"слушает, но соединение не принимает")
        elif rule.get("verdict") == "host-down":
            add("warn", f"fwd:{rule.get('port')}",
                f"проброс «{label}»: хост {rule.get('to')} не отвечает")

    for policy in host.get("ipsec") or []:
        if policy.get("disabled"):
            continue
        if policy.get("state") != "established":
            add("warn", f"ipsec:{policy.get('dst')}",
                f"IPsec {policy.get('src')} → {policy.get('dst')} не поднят"
                + (f" ({policy['state']})" if policy.get("state") else ""))

    # A wireless client on a channel the access points are already saturating.
    # The speaker itself reports nothing wrong — it just sounds bad.
    crowded = host.get("wifi_crowded_by") or []
    if crowded:
        worst = max(crowded, key=lambda c: c.get("airtime") or 0)
        add("warn", "wifi_crowded",
            f"на Wi-Fi канале {host.get('wifi_channel')} (2.4 ГГц) тесно: "
            f"{worst['ap']} на канале {worst['channel']} занимает "
            f"{worst['airtime']}% эфира")

    # UniFi device states: 1 is connected and managed — the normal one. 0 is
    # disconnected, 2 pending adoption, 4 upgrading, 5 provisioning. Only
    # disconnected and pending are worth reporting; the rest are transient.
    unifi_state = host.get("unifi_state")
    if radios and unifi_state in (0, 2):
        add("warn", "unifi_state",
            "точка не управляется контроллером"
            + (" (ожидает adoption)" if unifi_state == 2 else " (отключена)"))

    # A certificate is a scheduled outage with a known date; the only question
    # is whether anyone notices before the date arrives.
    for link in host.get("web", []):
        cert = link.get("cert") or {}
        days = cert.get("days_left")
        if days is None:
            continue
        where = f"{link['scheme']}://{host['addr']}:{link['port']}"
        if days < 0:
            add("bad", f"cert:{link['port']}", f"сертификат {where} истёк {int(-days)} сут назад")
        elif days < limits.get("cert_bad_days", 7):
            add("bad", f"cert:{link['port']}", f"сертификат {where} истекает через {int(days)} сут")
        elif days < limits.get("cert_warn_days", 21):
            add("warn", f"cert:{link['port']}", f"сертификат {where} истекает через {int(days)} сут")

    # Measured from another machine on the internet: this is the only check
    # that reflects what a user outside the perimeter actually gets.
    for check in host.get("external", []):
        if check.get("open") is None:
            # Nobody could look. Green would be a lie and red would blame the
            # wrong machine, so this stays a note.
            add("info", f"external:{check['port']}",
                f"{check.get('label') or 'порт ' + str(check['port'])}: "
                f"{check.get('why') or 'снаружи не проверено'}")
        elif not check.get("open"):
            label = check.get("label") or f"порт {check['port']}"
            add("bad", f"external:{check['port']}",
                f"{label} недоступен снаружи (проверено с {check['from']})")

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

    orphans = host.get("orphan_count") or 0
    if orphans:
        # Not a fault — rot. Libraries and old kernels that keep being scanned,
        # backed up and offered for upgrade long after whatever needed them was
        # removed, and on a 16 GB router-adjacent box that adds up.
        names = ", ".join(o.get("pkg", "") for o in (host.get("orphans") or [])[:4])
        add("warn", "orphans",
            f"{orphans} пакетов больше не нужны никому: {names}"
            + (" и др." if orphans > 4 else ""))

    security = host.get("security_count") or 0
    if security:
        # A security update is a known, published hole in a machine that is
        # running right now. That is a problem, not a note to get to later.
        word = "обновление" if security % 10 == 1 and security % 100 != 11 else (
            "обновления" if 2 <= security % 10 <= 4 and not 12 <= security % 100 <= 14
            else "обновлений")
        add("bad", "security", f"{security} security-{word}")

    order = {"bad": 0, "warn": 1, "info": 2}
    out.sort(key=lambda issue: order.get(issue["level"], 2))
    return out


def annotate(hosts: list[dict], cfg: dict | None = None,
             suppressions=None, acks=None) -> None:
    """Attach issues and an overall level to every host in place.

    A suppressed finding keeps its place in the list — the check still ran and
    its verdict is still true — but it stops colouring the host and stops
    alerting, and carries the reason it was accepted.
    """
    for host in hosts:
        issues = host_issues(host, cfg)
        muted = suppressions.for_host(host["id"]) if suppressions else {}
        # Read once, and only while it still says the same thing. Unlike a
        # suppression this carries no reason and no expiry: the finding itself
        # decides when the silence ends, by changing.
        read = acks.for_host(host["id"]) if acks else {}
        for issue in issues:
            seen = read.get(issue["key"])
            if seen and seen.get("said") == issue["text"]:
                issue["acked"] = True
                issue["acked_at"] = seen.get("at", 0)
                issue["original_level"] = issue["level"]
                issue["level"] = "info"
        for issue in issues:
            # A suppression recorded against the check ("radioretry") covers the
            # findings it produces ("radioretry:ng"). Without that, accepting a
            # check would only silence the one radio that happened to be firing
            # when the button was pressed.
            entry = muted.get(issue["key"]) or next(
                (value for key, value in muted.items()
                 if issue["key"].startswith(key + ":")), None)
            if not entry:
                continue
            issue["suppressed"] = True
            issue["suppress_reason"] = entry.get("reason", "")
            issue["suppress_since"] = entry.get("created", 0)
            issue["suppress_expires"] = entry.get("expires", 0)
            issue["original_level"] = issue["level"]
            issue["level"] = "info"
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


# --------------------------------------------------------------------------
# Self-description: what is actually being watched on a given host
# --------------------------------------------------------------------------
#
# A dashboard that shows only findings leaves the operator guessing about
# everything it does *not* show: is the disk fine, or simply not checked? This
# turns the rule set into an inventory — every check, whether it applies to
# this host, and what it currently says.

CHECK_CATEGORIES = [
    ("availability", "Доступность"),
    ("resources", "Ресурсы"),
    ("disks", "Диски"),
    ("services", "Сервисы"),
    ("updates", "Обновления"),
    ("backup", "Бэкапы"),
    ("cameras", "Камеры"),
    ("network", "Сеть"),
]


def checks_for(host: dict, cfg: dict | None = None) -> list[dict]:
    """Every check this host is subject to, with its current verdict."""
    limits = thresholds_for(host, cfg)
    found = {issue["key"]: issue for issue in host.get("issues", [])}
    agent = host.get("agent", "linux")
    out: list[dict] = []

    def add(category: str, name: str, rule: str, *,
            applies: bool = True, keys: tuple = (), skipped: str = "",
            blind: str = "") -> None:
        hits = [found[k] for k in found if any(
            k == key or k.startswith(key + ":") for key in keys)]
        if not applies:
            status, detail = "n/a", skipped
        elif blind and not hits:
            # The check ran and could not answer: no data, or data that proves
            # nothing. Green here would be a lie of exactly the kind this
            # dashboard exists to avoid — "fine" and "nobody could look" are
            # opposite answers and used to render identically.
            status, detail = "unknown", blind
        elif hits:
            suppressed = [h for h in hits if h.get("suppressed")]
            live = [h for h in hits if not h.get("suppressed")]
            if live:
                status = "bad" if any(h["level"] == "bad" for h in live) else "warn"
                detail = "; ".join(h["text"] for h in live[:3])
            else:
                # Fires, but accepted on purpose — shown with the reason so the
                # decision is visible where the check is, not buried elsewhere.
                status = "muted"
                detail = "; ".join(h["text"] for h in suppressed[:2])
        else:
            status, detail = "ok", ""
        entry = {"category": category, "name": name, "rule": rule,
                 "status": status, "detail": detail,
                 # The keys let the dashboard accept a check that is not firing
                 # at this second — which is the only way to accept one that
                 # comes and goes.
                 "keys": list(keys)}
        muted_hits = [h for h in hits if h.get("suppressed")]
        if muted_hits:
            entry["suppressed"] = [{
                "key": h["key"], "reason": h.get("suppress_reason", ""),
                "since": h.get("suppress_since", 0),
                "expires": h.get("suppress_expires", 0),
                "text": h["text"],
            } for h in muted_hits]
        out.append(entry)

    reachable = host.get("reachable")

    # ---------- availability ----------
    add("availability", "Хост отвечает",
        "ICMP и, где есть доступ, успешный опрос агентом каждые "
        f"{(cfg or {}).get('poll_interval', 180) // 60} мин",
        keys=("down",))
    add("availability", "Баланс у провайдера",
        f"Остаток на счету, делённый на суточную стоимость серверов: "
        f"предупреждение за {limits.get('balance_warn_days', 10)} дней, критично "
        f"за {limits.get('balance_bad_days', 3)}. Спрашивается у провайдера по API",
        applies=bool(host.get("billing")),
        skipped="биллинг для этого хоста не настроен",
        blind=((host.get("billing") or {}).get("error") or ""),
        keys=("balance",))
    add("availability", "Оплата",
        f"Дата, до которой хост оплачен, записана в конфиге: предупреждение за "
        f"{limits.get('paid_warn_days', 7)} дней, критично за "
        f"{limits.get('paid_bad_days', 2)}. Провайдер про это не спрашивается — "
        "выключенный за неуплату сервер выглядит как умерший, и разбираться с "
        "этим ночью дороже, чем раз в год поправить дату",
        applies=bool(host.get("paid_until")),
        skipped="срок оплаты не указан в конфиге", keys=("paid",))
    add("availability", "Перезагрузки",
        f"Аптайм, который стал меньше, чем был в прошлый опрос. "
        f"Предупреждение с {limits.get('reboots_week_warn', 3)} внеплановых "
        f"перезагрузок за неделю, критично с {limits.get('reboots_week_bad', 5)}. "
        "Перезагрузки, заказанные с дашборда, не считаются",
        keys=("rebooted", "reboots"))
    add("availability", "Полнота опроса",
        "Агент отработал и вернул данные; иначе видно только сетевой уровень",
        keys=("noaccess",))
    add("availability", "Автостарт после сбоя питания",
        "Значение из конфига (power_recovery): из ОС эта настройка BIOS не читается",
        applies=host.get("power_recovery") is not None,
        skipped="не задано в конфиге", keys=("power_recovery",))

    # ---------- resources ----------
    add("resources", "Заполнение дисков",
        f"Предупреждение с {limits['disk_warn']}%, проблема с {limits['disk_bad']}% "
        "по каждому смонтированному разделу",
        applies=bool(host.get("disks")), skipped="разделы не отдаются", keys=("disk",))
    add("resources", "Память",
        f"Предупреждение с {limits['mem_warn']}%, проблема с {limits['mem_bad']}%",
        applies=host.get("mem_pct") is not None, skipped="нет данных", keys=("mem",))
    add("resources", "Swap",
        f"Предупреждение с {limits['swap_warn']}%: активный swap на слабых машинах "
        "означает нехватку памяти",
        applies=bool(host.get("swap_total")), skipped="swap не настроен", keys=("swap",))
    add("resources", "Работает не на полную",
        "Железо, которое умеет больше, чем делает: потолок частоты процессора, "
        "PCIe или SATA, договорившиеся ниже своих возможностей, выключенная "
        "разгрузка маршрутизации. Ничего из этого не ломается — оно просто "
        "молча стоит дешевле, чем куплено",
        keys=("capped",))
    add("services", "Перезапуски юнитов",
        "Счётчик рестартов systemd сравнивается с прошлым опросом: юнит, который "
        "падает и поднимается заново, в каждый отдельный момент выглядит "
        "работающим",
        applies=host.get("agent") == "linux",
        skipped="только для systemd", keys=("svcflap",))
    add("services", "Юнит исчез",
        "Юнит работал в прошлый опрос, а сейчас его нет в системе — файл юнита "
        "удалён или переименован. Снимок сам по себе такого не замечает: "
        "пропавшее не с чем сравнить",
        applies=host.get("agent") == "linux",
        skipped="только для systemd", keys=("svcgone",))
    add("network", "Взгляд снаружи",
        "Сертификаты и TLS на портах, до которых достаёт интернет, прочитанные "
        "не с самого хоста, а с другой машины в сети. Локальный вид отвечает "
        "«что хост отдаёт», этот — «что получает чужой»",
        applies=bool(host.get("outside")),
        skipped="снаружи до этого хоста ничего не открыто",
        keys=("certout", "certdiff"))
    add("network", "Скорость линка",
        "Скорость, на которой договорился порт, против лучшей, что он выдавал "
        "за последний месяц, и против того, что объявляют обе стороны. По "
        "трафику падение гигабита до сотни незаметно — линк поднят, всё "
        "работает — поэтому проверка сразу пишет вердикт: настройка (порт "
        "объявляет меньше, чем умеет, или согласование выключено), линия "
        "(объявляют оба, а договорились ниже) или предел соседа, и последнее "
        "не считается поломкой",
        applies=bool(host.get("links")), skipped="хост не отдаёт состояние портов",
        blind=("" if any((l.get("capable") or l.get("speed_best"))
                         for l in host.get("links") or [])
               else "порты не сообщают своих возможностей, а истории замеров "
                    "ещё нет — сравнить текущую скорость не с чем"),
        keys=("link",))
    add("network", "Стучатся в сеть",
        "Устройства, которые раз за разом пытаются авторизоваться и не "
        "проходят. Такого устройства нет ни в арендах DHCP, ни в ARP — оно "
        "существует только в журнале радио, поэтому заметить его иначе можно "
        "было лишь вручную. Обычно это своя железка со старым паролем, но "
        f"не всегда. Предупреждение с {limits.get('authfail_warn', 5)} попыток",
        applies=bool(host.get("radios")),
        skipped="у хоста нет радио",
        blind=("" if host.get("agent") == "routeros"
               else "точками управляет контроллер UniFi, а он неудачные "
                    "авторизации наружу не отдаёт — здесь проверка слепа"),
        keys=("authfail",))
    add("resources", "Ожидание диска",
        f"Доля времени, которую процессор простоял в ожидании диска: "
        f"предупреждение с {limits.get('iowait_warn', 50)}%, критично с "
        f"{limits.get('iowait_bad', 80)}%. Это не занятость — считать одним "
        "числом с ней значит искать проблему не там",
        applies=host.get("cpu_iowait_pct") is not None,
        skipped="хост не отдаёт разбивку процессорного времени", keys=("iowait",))
    add("resources", "Украденное время",
        f"Сколько процессорного времени забрал гипервизор: предупреждение с "
        f"{limits.get('steal_warn', 10)}%, критично с {limits.get('steal_bad', 25)}%. "
        "Изнутри гостя ни исправить, ни увидеть иначе",
        applies=host.get("cpu_steal_pct") is not None,
        skipped="не виртуальная машина или счётчик недоступен", keys=("steal",))
    add("resources", "Отклонение от своей нормы",
        f"Медиана последнего получаса против медианы месяца: тревога, когда "
        f"стало вдвое больше обычного и при этом выше {limits.get('baseline_floor', 25)}%. "
        "Ловит то, что ниже общих порогов: хост, который обычно скучает на 12%, "
        "а сейчас держит 40%, ничем другим не отличается от здорового",
        applies=bool(host.get("baselines")),
        skipped="истории по этому хосту ещё нет", keys=("unusual",))
    add("resources", "Очередь к процессору",
        f"Load average против числа ядер: предупреждение с {limits['load_warn']}%, "
        f"критично с {limits['load_bad']}%. Отвечает не на «сколько занято», а на "
        "«сколько ждёт» — в очередь попадают и процессы, застрявшие на диске",
        applies=host.get("load1") is not None and bool(host.get("cpus")),
        skipped="хост не отдаёт load average", keys=("load",))
    add("resources", "Загрузка процессора",
        f"Доля занятого процессорного времени: предупреждение с {limits['cpu_warn']}%, "
        f"критично с {limits['cpu_bad']}%. Считается по занятости, а не по load "
        "average — очередь может быть длинной на незагруженной машине и наоборот",
        applies=host.get("cpu_load_pct") is not None,
        skipped="хост не отдаёт занятость процессора", keys=("cpu",))
    add("resources", "Температура",
        f"По самому горячему датчику: предупреждение с {limits['temp_warn']}°, "
        f"проблема с {limits['temp_bad']}°",
        applies=bool(host.get("temps")), skipped="датчиков нет", keys=("temp",))

    # ---------- disks ----------
    add("disks", "SMART-здоровье",
        "Оценка самого накопителя, переназначенные и pending-секторы, износ SSD",
        applies=bool(host.get("smarts")),
        skipped=host.get("smart_blocked") or "накопители не опрашиваются",
        keys=("smart",))
    add("disks", "RAID-массивы",
        "Состояние каждого массива: [U_] вместо [UU] — деградация",
        applies=bool(host.get("raid")), skipped="массивов нет", keys=("raid",))

    # ---------- services ----------
    add("services", "Упавшие сервисы",
        "Юнит в состоянии failed — срочная проблема",
        applies=bool(host.get("services")), skipped="сервисы не перечисляются",
        keys=("svc",))
    add("services", "Остановленные, но включённые",
        "Юнит в автозапуске и не работает: считается поломкой наравне с падением",
        applies=agent == "linux" and bool(host.get("services")),
        skipped="только для systemd", keys=("svc",))
    add("services", "Контейнеры",
        "Каждый контейнер должен быть running",
        applies=bool(host.get("containers")), skipped="контейнеров нет",
        keys=("container",))
    add("network", "Радио вещает",
        "Каждое включённое радио должно быть в эфире; точка должна управляться "
        "контроллером",
        applies=bool(host.get("radios") or host.get("radioiws")),
        skipped="радио нет", keys=("radio", "unifi_state"))
    add("network", "Загрузка эфира",
        f"2.4 ГГц: предупреждение с {limits.get('airtime_warn_24', 40)}%, проблема с "
        f"{limits.get('airtime_bad_24', 70)}%; 5 ГГц — с "
        f"{limits.get('airtime_warn_5', 60)}% и {limits.get('airtime_bad_5', 85)}%. "
        "Отдельно считается доля чужих сетей: это разница между «мы сами грузим» "
        "и «канал занят соседями»",
        applies=any(r.get("utilization") is not None
                    for r in (host.get("radios") or []) + (host.get("radioiws") or [])),
        skipped="загрузка эфира не отдаётся", keys=("radioair",))
    add("network", "Выбор канала",
        "В 2.4 ГГц не перекрываются только 1, 6 и 11; соседние точки на близких "
        "каналах глушат друг друга сильнее, чем стоя на одном. Сравниваются "
        "только точки одной площадки. Переход на другой канал советуется, "
        f"только если радио там уже стояло и намеряло минимум на "
        f"{limits.get('channel_gain_pct', 8)}% меньше чужого эфира "
        f"(не меньше {limits.get('channel_evidence_samples', 10)} замеров): "
        "то, что радио слышит про чужие каналы со своего, всегда тише правды "
        "и годится только чтобы канал вычеркнуть",
        applies=any(r.get("band") == "2.4" for r in host.get("radios", [])),
        skipped="радио 2.4 ГГц нет",
        blind=("радио не стояло на других каналах достаточно долго — "
               "сравнивать не с чем, а слышимость с текущего канала врёт в "
               "одну сторону"
               if not any((r.get("channel_history") or {})
                          for r in host.get("radios") or []) else ""),
        keys=("radiooverlap", "radiogrid", "radioneighbours"))
    add("network", "Повторные передачи",
        f"Доля кадров, ушедших повторно: с {limits.get('retries_warn_24', 35)}% "
        f"в 2.4 ГГц и {limits.get('retries_warn_5', 45)}% в 5 ГГц. Показывает "
        "то, чего не видно по загрузке эфира: канал может быть свободен, а наши "
        "кадры всё равно не доходить",
        applies=any(r.get("retries") is not None for r in host.get("radios", [])),
        skipped="точка не отдаёт долю повторов", keys=("radioretry",))
    add("network", "Ширина канала 2.4 ГГц",
        "В 2.4 ГГц помещаются три канала по 20 МГц; 40 МГц занимают половину "
        "диапазона и приносят чужой трафик, которого можно было не слышать",
        applies=any(r.get("band") == "2.4" and r.get("width")
                    for r in host.get("radios", [])),
        skipped="ширина канала не отдаётся", keys=("radiowidth",))
    add("network", "Качество связи по сети (SSID)",
        "Оценка контроллера для каждой Wi-Fi сети на точке: если клиенты этой "
        "сети работают плохо, видно, какой именно сети это касается.",
        applies=bool(host.get("ssids")),
        skipped="точка не отдаёт статистику по сетям", keys=("ssidsat",))

    add("network", "Качество связи клиентов",
        f"Оценка контроллера (satisfaction) ниже "
        f"{limits.get('wifi_satisfaction_warn', 80)}%",
        applies=any(r.get("satisfaction") is not None for r in host.get("radios", [])),
        skipped="оценка недоступна", keys=("radiosat",))

    # ---------- updates ----------
    add("updates", "Обновления пакетов",
        "Список из кэша пакетного менеджера; security-обновления считаются отдельно",
        applies=bool(host.get("pkg_manager") or host.get("update_count")),
        skipped="пакеты не отслеживаются", keys=("security",))
    add("updates", "Ненужные пакеты",
        "Пакеты, которые ставились как зависимости и никому больше не нужны "
        "(apt autoremove). Их можно вычищать автоматически — переключатель в "
        "настройках.",
        applies=agent == "linux", skipped="только для apt", keys=("orphans",))

    add("updates", "Требуется перезагрузка",
        "reboot-required у Debian, непринятая прошивка RouterBOARD — с причиной",
        keys=("reboot",))
    add("updates", "Сертификаты TLS",
        f"Предупреждение за {limits.get('cert_warn_days', 21)} сут до истечения, "
        f"проблема за {limits.get('cert_bad_days', 7)}",
        applies=any(link.get("cert") for link in host.get("web", [])),
        skipped="https-сервисов не найдено", keys=("cert",))

    # ---------- backup ----------
    add("backup", "Свежесть бэкапа",
        f"Репозиторий старше {limits.get('backup_stale_days', 2)} сут — предупреждение, "
        "втрое дольше — проблема",
        applies=bool(host.get("backuprepos")), skipped="репозиториев на хосте нет",
        keys=("backup",))
    add("backup", "Покрытие бэкапом",
        "Общие папки, не входящие ни в одну задачу",
        applies=bool(host.get("backups") or host.get("unbackeds")),
        skipped="задач резервного копирования нет", keys=("unbacked",))
    add("backup", "Хост вообще бэкапится",
        "NAS с данными должен либо отправлять бэкап, либо принимать его",
        applies=host.get("role") == "nas" and not host.get("backup_exempt"),
        skipped="не применимо или отключено через backup_exempt", keys=("no_backup",))

    # ---------- cameras ----------
    add("cameras", "Состояние потока",
        "Статус монитора у того хоста, который камеру пишет",
        applies=bool(host.get("cameras")), skipped="камер не записывает",
        keys=("cam",))
    add("cameras", "Детекция не молчит",
        f"Нет событий {limits.get('camera_quiet_warn_hours', 12)} ч — предупреждение, "
        f"{limits.get('camera_quiet_bad_hours', 24)} ч — проблема",
        applies=any(c.get("quiet_hours") is not None for c in host.get("cameras", [])),
        skipped="событийная статистика недоступна", keys=("camquiet",))

    # ---------- network ----------
    add("network", "Открытые службы роутера",
        "Службы, включённые без ограничения по адресу: telnet, ftp, API без "
        "TLS, нагрузочный тест, SOCKS, UPnP. Остальное роутер публикует по "
        "своей природе и замечанием не считается.",
        applies=bool(host.get("endpoints")) and host.get("agent") == "routeros",
        skipped="не роутер RouterOS", keys=("open",))

    add("network", "Пробросы портов",
        "Каждое правило dst-nat сверяется с парком: слушает ли кто-нибудь "
        "порт, на который оно ведёт, и отвечает ли вообще этот хост. Правило, "
        "указывающее в никуда, не жалуется само — о нём узнают снаружи и не "
        "вовремя.",
        applies=bool(host.get("forwards")), skipped="пробросов нет",
        blind=("правило ведёт туда, куда дашборд не заглядывает: цель вне флота "
               "или её UDP-слушателей не видно"
               if any(r.get("verdict") == "unknown"
                      for r in host.get("forwards") or []) else ""),
        keys=("fwd",))

    add("network", "Туннели IPsec",
        "Включённые политики должны быть в состоянии established; политика, "
        "которая никогда не поднималась, выглядит так же, как та, что просто "
        "не нужна сегодня.",
        applies=bool(host.get("ipsec")), skipped="IPsec не настроен",
        keys=("ipsec",))

    add("network", "Канал беспроводного клиента",
        "Для устройств, подключённых по Wi-Fi: не стоит ли клиент на канале, "
        "который точки доступа уже загрузили. Само устройство об этом не "
        "сообщает — оно просто хуже работает.",
        applies=host.get("link") == "wifi",
        skipped="подключено кабелем или не по Wi-Fi", keys=("wifi_crowded",))

    add("updates", "Прошивка устройства",
        "Точка доступа спрашивает контроллер, колонка — сервис обновлений "
        "Sonos, мешнода — последний релиз meshtastic/firmware на GitHub; все "
        "сравнивают предложенную версию с текущей.",
        applies=agent in ("unifi", "sonos", "meshtastic"),
        skipped="не устройство с собственной прошивкой", keys=("updates",))

    # Said out loud rather than left blank: a camera card with no firmware line
    # otherwise reads as "firmware is fine", when the truth is nobody looked.
    add("updates", "Прошивка камеры",
        "Версию читает рекордер, у которого есть учётные данные камеры. "
        "Автоматически сверить её не с чем: сайт производителя закрыт для "
        "роботов, а его каталог файлов не сопоставляется с моделью без "
        "догадок. Поэтому свежая версия вносится в настройках вручную — и "
        "замечание появляется только тогда, когда есть конкретная более новая "
        "сборка, которую можно скачать.",
        applies=bool(host.get("os_name")) and host.get("role") == "camera",
        skipped=("версию камеры прочитать не удалось — нужен доступ, который "
                 "есть только у рекордера" if host.get("role") == "camera"
                 else "не камера"),
        keys=("firmware_age",))

    add("network", "Доступность снаружи",
        "Порт проверяется с другого хоста в интернете — то, что видит клиент",
        applies=bool(host.get("external")), skipped="внешние проверки не заданы",
        keys=("external",))

    return out


def annotate_checks(hosts: list[dict], cfg: dict | None = None) -> None:
    for host in hosts:
        host["checks"] = checks_for(host, cfg)
