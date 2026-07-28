"""Measure 2.4 GHz channels by sitting on them, because nothing else works.

An access point measures the channel it is tuned to and guesses at the rest
through its own receive filter, which makes every other channel sound quieter
than it is. The only honest comparison is to park the radio on each candidate
in turn and read the airtime it reports from there.

Two things make that harder than it sounds, and both are handled here:

*The access points cannot be tested one at a time.* Radios in the same flat
hear each other, so a measurement of one depends on where the other is sitting.
The schedule is a Latin square: every round moves every radio, each radio
visits every channel, and no two radios ever share one. A second block runs the
cycle the other way round, so each radio sees each channel under both possible
placements of its neighbour and the neighbour's effect cancels out.

*One reading is noise.* Airtime on a single poll has been seen swinging from
27% to 49% and back inside three minutes. Each round is therefore sampled
repeatedly and reported as a median, and the samples are written into the
dashboard's own history so the finding outlives this run.

    sudo -n systemd-creds decrypt --name=unifi-password \
        /etc/health-zoo.d/unifi-password.cred - | \
        python3 tools/channel-trial.py --config /etc/health-zoo.json

Channels are restored on the way out, including on Ctrl-C and on error. The
originals are also written to a file first, so a trial killed with SIGKILL can
still be undone by hand.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import signal
import sqlite3
import ssl
import statistics
import sys
import time
import urllib.request

CHANNELS = (1, 6, 11)
# The radio re-provisions after a channel change and reports nonsense while it
# does. Nothing is sampled until it has been on the new channel this long.
SETTLE_SECONDS = 90


class Controller:
    def __init__(self, base: str, site: str, user: str, password: str):
        self.base = base.rstrip("/")
        self.site = site
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.jar))
        self.call("/api/login", {"username": user, "password": password})

    def call(self, path: str, data=None, method=None):
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Content-Type": "application/json"},
            method=method)
        for cookie in self.jar:
            if cookie.name == "csrf_token":
                request.add_header("X-Csrf-Token", cookie.value)
        return json.loads(self.opener.open(request, timeout=30).read() or b"{}")

    def devices(self) -> list[dict]:
        return self.call(f"/api/s/{self.site}/stat/device").get("data", [])

    def set_channel(self, device: dict, channel: int) -> None:
        table = json.loads(json.dumps(device["radio_table"]))
        for radio in table:
            if radio.get("radio") == "ng":
                radio["channel"] = channel
                radio["ht"] = 20
        self.call(f"/api/s/{self.site}/rest/device/{device['_id']}",
                  {"radio_table": table}, "PUT")

    def optimizer_enabled(self) -> bool:
        for setting in self.call(f"/api/s/{self.site}/rest/setting").get("data", []):
            if setting.get("key") == "radio_ai":
                return bool(setting.get("enabled") or setting.get("auto_enabled"))
        return False


def schedule(count: int, blocks: int, cochannel: bool = False) -> list[list[int]]:
    """Round r puts access point i on CHANNELS[(r + i * (block + 1)) % 3].

    Within a block that is a Latin square — every radio visits every channel
    exactly once and no two share one. Successive blocks step the offset, which
    is what pairs each radio's visit to a channel with a different neighbour
    placement the second time around.

    Keeping the radios apart is what makes the blocks balanced, and it is also
    the one arrangement a Latin square can never test. Two access points we own,
    on one channel, at minimum power, take turns through carrier sense; the same
    two a few channels apart cannot hear each other well enough to take turns at
    all. Where that trade lands is a measurement, so `cochannel` adds the rounds
    that make it.
    """
    rounds = []
    for block in range(blocks):
        for r in range(len(CHANNELS)):
            rounds.append([CHANNELS[(r + i * (block + 1)) % len(CHANNELS)]
                           for i in range(count)])
    if cochannel:
        rounds.extend([channel] * count for channel in CHANNELS)
    return rounds


def radio_stats(device: dict, radio_name: str) -> dict | None:
    for radio in device.get("radio_table_stats", []):
        if radio.get("radio") != radio_name:
            continue
        total = radio.get("cu_total")
        mine = (radio.get("cu_self_rx") or 0) + (radio.get("cu_self_tx") or 0)
        return {
            "channel": radio.get("channel"),
            "state": radio.get("state"),
            "total": total,
            "foreign": (total - mine) if isinstance(total, int) else None,
            "retries": radio.get("tx_retries_pct"),
            "satisfaction": radio.get("satisfaction"),
            "clients": radio.get("user-num_sta"),
        }
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/health-zoo.json")
    parser.add_argument("--minutes", type=float, default=10.0,
                        help="время на раунд, без учёта прогрева")
    parser.add_argument("--blocks", type=int, default=2, choices=(1, 2),
                        help="1 — быстрый прогон, 2 — с балансировкой соседа")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="период опроса внутри раунда, с")
    parser.add_argument("--cochannel", action="store_true",
                        help="добавить раунды, где обе точки на одном канале")
    parser.add_argument("--history", default="/var/lib/health-zoo/history.db",
                        help='"" — не писать замеры в историю дашборда')
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    config = json.load(open(args.config, encoding="utf-8"))
    conf = config.get("unifi_controller") or {}
    password = "" if args.dry_run else sys.stdin.read().strip()
    if not password and not args.dry_run:
        print("пароль контроллера ожидается на stdin", file=sys.stderr)
        return 2

    # The dashboard's own host ids, so samples land on the same cards.
    host_ids = {host.get("addr"): host.get("id") for host in config.get("hosts", [])
                if host.get("agent") == "unifi"}

    if args.dry_run:
        names = list(host_ids.values()) or ["ap-1", "ap-2"]
        rounds = schedule(len(names), args.blocks, args.cochannel)
        per_round = args.minutes + SETTLE_SECONDS / 60.0
        print(f"{len(rounds)} раундов × {per_round:.1f} мин = "
              f"{len(rounds) * per_round:.0f} мин")
        for number, assignment in enumerate(rounds, 1):
            shared = " (общий канал)" if len(set(assignment)) == 1 else ""
            print(f"  раунд {number}: " + ", ".join(
                f"{name} → {channel}" for name, channel in zip(names, assignment))
                + shared)
        return 0

    controller = Controller(conf["url"], conf.get("site", "default"),
                            conf["username"], password)
    if controller.optimizer_enabled():
        print("RF-оптимизатор контроллера включён — он переставит каналы "
              "под ногами. Выключите radio_ai и повторите.", file=sys.stderr)
        return 3

    devices = [d for d in controller.devices()
               if any(r.get("radio") == "ng" for r in d.get("radio_table", []))]
    devices.sort(key=lambda d: d.get("ip") or "")
    if not devices:
        print("на площадке нет радио 2.4 ГГц", file=sys.stderr)
        return 4

    original = {}
    for device in devices:
        for radio in device.get("radio_table", []):
            if radio.get("radio") == "ng":
                original[device["mac"]] = radio.get("channel")
    restore_path = "/tmp/channel-trial-restore.json"
    with open(restore_path, "w", encoding="utf-8") as handle:
        json.dump({"channels": original,
                   "ids": {d["mac"]: d["_id"] for d in devices}}, handle, indent=1)

    names = {d["mac"]: d.get("name") or d.get("ip") for d in devices}
    print("исходные каналы: " + ", ".join(
        f"{names[mac]} {channel}" for mac, channel in original.items()))
    print(f"на случай аварии сохранено в {restore_path}\n")

    restored = False

    def restore(*_):
        nonlocal restored
        if restored:
            return
        restored = True
        print("\nвозвращаю исходные каналы…")
        for device in controller.devices():
            if device.get("mac") in original:
                controller.set_channel(device, original[device["mac"]])
        print("готово")

    signal.signal(signal.SIGINT, lambda *a: (restore(), sys.exit(130)))
    signal.signal(signal.SIGTERM, lambda *a: (restore(), sys.exit(143)))

    samples: dict = {}
    try:
        rounds = schedule(len(devices), args.blocks, args.cochannel)
        for number, assignment in enumerate(rounds, 1):
            # Sharing a channel and standing apart are different experiments,
            # so their readings are kept apart too — averaging them would
            # describe an arrangement that was never actually tried.
            shared = len(set(assignment)) == 1
            plan = ", ".join(f"{names[d['mac']]} → {c}"
                             for d, c in zip(devices, assignment))
            print(f"раунд {number}/{len(rounds)}: {plan}"
                  + (" (общий канал)" if shared else ""))
            fresh = {d["mac"]: d for d in controller.devices()}
            for device, channel in zip(devices, assignment):
                controller.set_channel(fresh[device["mac"]], channel)

            # Clients on 5 GHz are the ones that matter; counting them across
            # the switch turns "this costs a reconnect" into a measured number.
            before = {d.get("mac"): (radio_stats(d, "na") or {}).get("clients")
                      for d in fresh.values()}
            time.sleep(SETTLE_SECONDS)

            until = time.time() + args.minutes * 60
            taken = 0
            while time.time() < until:
                for device in controller.devices():
                    mac = device.get("mac")
                    if mac not in names:
                        continue
                    stats = radio_stats(device, "ng")
                    if not stats or stats.get("state") != "RUN":
                        continue
                    wanted = assignment[[d["mac"] for d in devices].index(mac)]
                    if stats.get("channel") != wanted:
                        continue
                    samples.setdefault((mac, wanted, shared), []).append(
                        (int(time.time()), stats))
                    taken += 1
                time.sleep(args.interval)

            after = {d.get("mac"): (radio_stats(d, "na") or {}).get("clients")
                     for d in controller.devices() if d.get("mac") in names}
            lost = [names[mac] for mac in before
                    if mac in after and (before[mac] or 0) > (after[mac] or 0)]
            print(f"  {taken} замеров"
                  + (f"; клиентов 5 ГГц стало меньше у: {', '.join(lost)}" if lost
                     else "; на 5 ГГц клиенты не потерялись"))
    finally:
        restore()

    def report(shared: bool) -> dict:
        print("  " + "точка".ljust(18) + "".join(f"ch {c:<15}" for c in CHANNELS))
        best_per_ap = {}
        for device in devices:
            mac = device["mac"]
            row = "  " + str(names[mac]).ljust(18)
            best = None
            for channel in CHANNELS:
                taken = samples.get((mac, channel, shared), [])
                foreign = [s["foreign"] for _, s in taken
                           if isinstance(s.get("foreign"), (int, float))]
                retries = [s["retries"] for _, s in taken
                           if isinstance(s.get("retries"), (int, float))]
                if not foreign:
                    row += "—".ljust(18)
                    continue
                median = statistics.median(foreign)
                row += (f"{median:.0f}% повт {statistics.median(retries or [0]):.0f}%"
                        f" n={len(foreign)}").ljust(18)
                if best is None or median < best[1]:
                    best = (channel, median)
            print(row)
            if best:
                best_per_ap[names[mac]] = best
        return best_per_ap

    print("\nчужой эфир, медиана по замерам (меньше — лучше), точки на разных каналах:")
    verdict = report(False)
    if any(key[2] for key in samples):
        print("\nто же самое, когда обе точки стоят на одном канале:")
        report(True)
    print()
    for name, (channel, median) in verdict.items():
        print(f"  {name}: канал {channel} ({median:.0f}% чужого эфира)")

    if args.history:
        written = write_history(args.history, samples, devices, host_ids)
        print(f"\n{written} замеров записано в {args.history} — "
              "дашборд теперь может на них ссылаться")
    return 0


def write_history(path: str, samples: dict, devices: list[dict],
                  host_ids: dict) -> int:
    """Put the trial's readings where the dashboard's own check looks.

    Same table and same metric names the hub writes every poll, so a trial is
    simply a burst of unusually well-distributed samples rather than a separate
    kind of evidence that something would have to learn to read.

    Only the balanced rounds go in. The dashboard's history has no room for
    "and the other access point was sitting on top of us at the time", so
    filing those readings under the same channel would quietly average two
    different arrangements into one number.
    """
    by_mac = {d["mac"]: host_ids.get(d.get("ip")) for d in devices}
    rows = []
    for (mac, channel, shared), taken in samples.items():
        host = by_mac.get(mac)
        if not host or shared:
            continue
        for stamp, stats in taken:
            foreign = stats.get("foreign")
            if isinstance(foreign, (int, float)):
                rows.append((stamp, host, f"radio:ng:ch{channel}:foreign",
                             float(foreign)))
    if not rows:
        return 0
    connection = sqlite3.connect(path)
    try:
        connection.executemany(
            "INSERT INTO samples (ts, host, metric, value) VALUES (?,?,?,?)", rows)
        connection.commit()
    finally:
        connection.close()
    return len(rows)


if __name__ == "__main__":
    sys.exit(main())
