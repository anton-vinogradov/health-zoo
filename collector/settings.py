"""Settings the operator changes from the dashboard, kept apart from the config.

/etc/health-zoo.json describes the fleet: which hosts exist, how to reach them,
where the secrets live. It is hand-written and belongs to whoever installed the
service. Thresholds are a different kind of decision — "88° is fine on this
hardware", "a NAS at 96% is normal" — and they get revised while looking at the
dashboard, not while editing a file over ssh.

So they live here, in a file the service owns and can rewrite, and they are
layered on top of the config rather than replacing it: a value never set in the
UI keeps whatever the config (or the built-in default) says.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time

# What the UI is allowed to change, with enough description to render a form
# nobody has to guess at. Anything not listed here is not editable from the
# browser — the fleet definition is deliberately not a web form.
FIELDS = [
    {"key": "disk_warn", "group": "Диски", "label": "Диск: предупреждение",
     "unit": "%", "min": 50, "max": 99,
     "hint": "Обычные хосты. У NAS порог свой — архив растёт до ротации."},
    {"key": "disk_bad", "group": "Диски", "label": "Диск: проблема",
     "unit": "%", "min": 60, "max": 100},
    {"key": "temp_warn", "group": "Железо", "label": "Нагрев: предупреждение",
     "unit": "°C", "min": 40, "max": 110,
     "hint": "Малые x86-коробки простаивают в районе 70° и греются до 80° "
             "при транскоде; Tjmax обычно 105°."},
    {"key": "temp_bad", "group": "Железо", "label": "Нагрев: проблема",
     "unit": "°C", "min": 50, "max": 120},
    {"key": "mem_warn", "group": "Железо", "label": "Память: предупреждение",
     "unit": "%", "min": 50, "max": 99},
    {"key": "mem_bad", "group": "Железо", "label": "Память: проблема",
     "unit": "%", "min": 60, "max": 100},
    {"key": "swap_warn", "group": "Железо", "label": "Swap: предупреждение",
     "unit": "%", "min": 10, "max": 99},
    {"key": "airtime_warn_24", "group": "Wi-Fi", "label": "Эфир 2.4 ГГц: предупреждение",
     "unit": "%", "min": 10, "max": 95,
     "hint": "В 2.4 ГГц всего три непересекающихся канала и длинный эфир на "
             "кадр — там тесно при значениях, где 5 ГГц ещё свободен."},
    {"key": "airtime_bad_24", "group": "Wi-Fi", "label": "Эфир 2.4 ГГц: проблема",
     "unit": "%", "min": 20, "max": 100},
    {"key": "airtime_warn_5", "group": "Wi-Fi", "label": "Эфир 5 ГГц: предупреждение",
     "unit": "%", "min": 10, "max": 95},
    {"key": "airtime_bad_5", "group": "Wi-Fi", "label": "Эфир 5 ГГц: проблема",
     "unit": "%", "min": 20, "max": 100},
    {"key": "retries_warn_24", "group": "Wi-Fi", "label": "Повторы 2.4 ГГц: предупреждение",
     "unit": "%", "min": 10, "max": 90,
     "hint": "Доля кадров, ушедших повторно. Ловит то, чего не видно по "
             "загрузке эфира: канал свободен, а наши кадры не доходят."},
    {"key": "retries_warn_5", "group": "Wi-Fi", "label": "Повторы 5 ГГц: предупреждение",
     "unit": "%", "min": 10, "max": 90},
    {"key": "channel_gain_pct", "group": "Wi-Fi", "label": "Смена канала оправдана с",
     "unit": "%", "min": 2, "max": 50,
     "hint": "Насколько меньше чужого эфира радио должно было намерять на "
             "другом канале, стоя на нём. Смена канала стоит всем клиентам "
             "переподключения, поэтому меньший выигрыш того не стоит."},
    {"key": "channel_evidence_samples", "group": "Wi-Fi", "label": "Замеров на канал",
     "unit": "шт", "min": 3, "max": 200,
     "hint": "Загрузка эфира гуляет вдвое за минуты, поэтому один замер — шум. "
             "Совет о смене канала опирается на медиану по такому числу опросов."},
    {"key": "wifi_satisfaction_warn", "group": "Wi-Fi",
     "label": "Качество связи ниже", "unit": "%", "min": 10, "max": 100,
     "hint": "Оценка контроллера по радио и по каждой сети (SSID)."},
    {"key": "backup_stale_days", "group": "Бэкапы", "label": "Бэкап устарел через",
     "unit": "сут", "min": 1, "max": 60},
    {"key": "camera_quiet_warn_hours", "group": "Камеры",
     "label": "Тишина детекции: предупреждение", "unit": "ч", "min": 1, "max": 168},
    {"key": "camera_quiet_bad_hours", "group": "Камеры",
     "label": "Тишина детекции: проблема", "unit": "ч", "min": 2, "max": 336},
    {"key": "cert_warn_days", "group": "Сертификаты", "label": "Истекает через",
     "unit": "сут", "min": 1, "max": 90},
    {"key": "cert_bad_days", "group": "Сертификаты", "label": "Срочно: истекает через",
     "unit": "сут", "min": 1, "max": 60},
]

EDITABLE = {f["key"] for f in FIELDS}

# Rebooting is not a threshold, so it gets its own shape. Off by default: a
# dashboard that reboots hosts without being asked is a surprise, and the first
# time it surprises somebody is during a recording or a backup.
AUTO_REBOOT_DEFAULT = {
    "enabled": False,
    # Local hours. A window rather than "as soon as needed": kernel updates land
    # during the day and nobody wants the cameras to blink at 15:00. Morning
    # rather than the small hours on purpose — a host that does not come back
    # is found in minutes instead of at breakfast.
    "from_hour": 8,
    "to_hour": 9,
    # Hosts that must never be rebooted automatically, by id.
    "exclude": [],
    # Never reboot the same host twice within this many hours, whatever the
    # flag says: a host that comes back up still asking for a reboot is broken,
    # and a loop of reboots would hide that rather than surface it.
    "min_interval_hours": 20,
}


# Removing packages nothing depends on is safe in a way rebooting is not — apt
# keeps the running kernel and anything still needed — so this one may default
# to on. It runs as part of an update, never on its own schedule: cleanup is a
# consequence of upgrading, not an event.
AUTO_CLEANUP_DEFAULT = {"enabled": True}

# Security updates install themselves unless somebody says otherwise. A machine
# left unpatched because nobody looked at the dashboard that week is the exact
# failure a dashboard is supposed to prevent, and "there is a fix, and it is
# not applied" is the one finding where waiting has a cost and acting does not.
AUTO_SECURITY_DEFAULT = {"enabled": True, "exclude": [], "min_interval_hours": 6}


class Settings:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            self.data = {}

    def _save(self) -> None:
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            # A dashboard that cannot persist a threshold still has to keep
            # showing the fleet; the value stays in memory until restart.
            pass

    # ---------- thresholds ----------

    def thresholds(self) -> dict:
        return dict(self.data.get("thresholds") or {})

    def set_thresholds(self, values: dict, defaults: dict | None = None) -> dict:
        """Store only what differs from the default; forget the rest.

        The form submits every field, changed or not. Writing all of them back
        would freeze today's defaults into the file forever, and a later change
        to a default would then silently not apply to a fleet that never asked
        to pin it.
        """
        defaults = defaults or {}
        with self.lock:
            current = dict(self.data.get("thresholds") or {})
            for key, value in values.items():
                if key not in EDITABLE:
                    continue
                if value is None or value == "":
                    current.pop(key, None)
                    continue
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    continue
                if key in defaults and number == defaults[key]:
                    current.pop(key, None)
                else:
                    current[key] = number
            self.data["thresholds"] = current
            self._save()
            return current

    # ---------- per-camera silence thresholds ----------
    #
    # One number for the whole fleet cannot be right: a street camera that sees
    # nothing for six hours is broken, a garage camera that sees nothing for
    # two days is a garage nobody entered. So each camera may carry its own
    # pair, keyed "<host>/<camera id>".

    def cameras(self) -> dict:
        return dict(self.data.get("cameras") or {})

    def camera_limits(self, host_id: str, cam_id: str) -> dict:
        return dict(self.cameras().get(f"{host_id}/{cam_id}") or {})

    def set_cameras(self, values: dict) -> dict:
        with self.lock:
            current = dict(self.data.get("cameras") or {})
            for key, limits in (values or {}).items():
                entry = {}
                for field in ("warn", "bad"):
                    value = (limits or {}).get(field)
                    if value in (None, ""):
                        continue
                    try:
                        entry[field] = max(1, int(value))
                    except (TypeError, ValueError):
                        continue
                # An empty pair means "follow the fleet-wide value"; storing it
                # would pin whatever that value happens to be today.
                if entry:
                    current[key] = entry
                else:
                    current.pop(key, None)
            self.data["cameras"] = current
            self._save()
            return current

    # ---------- known firmware releases ----------
    #
    # Cameras have no feed to check: the vendor's site refuses bots (403) and
    # its file catalogue cannot be matched to a model without guessing — and a
    # guess here means either a false "update available" or a false "up to
    # date". So the newest published build is written down by hand, keyed by a
    # substring of the model, and the dashboard complains only when there is a
    # concrete newer build to point at.

    def firmware(self) -> dict:
        return dict(self.data.get("firmware") or {})

    def firmware_for(self, model: str) -> dict:
        """The newest published build known for this model, if any."""
        model = (model or "").upper()
        if not model:
            return {}
        for key, entry in self.firmware().items():
            if key.upper() in model:
                return dict(entry)
        return {}

    def set_firmware(self, values: dict) -> dict:
        with self.lock:
            current = dict(self.data.get("firmware") or {})
            for key, entry in (values or {}).items():
                key = str(key).strip()
                if not key:
                    continue
                version = str((entry or {}).get("version", "")).strip()
                built = re.sub(r"\D", "", str((entry or {}).get("built", "")))[:6]
                url = str((entry or {}).get("url", "")).strip()
                if not version and not built:
                    current.pop(key, None)
                    continue
                current[key] = {"version": version, "built": built, "url": url}
            self.data["firmware"] = current
            self._save()
            return current

    # ---------- automatic cleanup ----------

    def auto_cleanup(self) -> dict:
        out = dict(AUTO_CLEANUP_DEFAULT)
        out.update(self.data.get("auto_cleanup") or {})
        return out

    def set_auto_cleanup(self, values: dict) -> dict:
        with self.lock:
            current = self.auto_cleanup()
            if "enabled" in values:
                current["enabled"] = bool(values["enabled"])
            self.data["auto_cleanup"] = current
            self._save()
            return current

    # ---------- automatic security updates ----------

    def auto_security(self) -> dict:
        out = dict(AUTO_SECURITY_DEFAULT)
        out.update(self.data.get("auto_security") or {})
        return out

    def set_auto_security(self, values: dict) -> dict:
        with self.lock:
            current = self.auto_security()
            if "enabled" in values:
                current["enabled"] = bool(values["enabled"])
            if "min_interval_hours" in values:
                try:
                    current["min_interval_hours"] = max(1, int(values["min_interval_hours"]))
                except (TypeError, ValueError):
                    pass
            if isinstance(values.get("exclude"), list):
                current["exclude"] = [str(x) for x in values["exclude"]]
            self.data["auto_security"] = current
            self._save()
            return current

    def last_update(self, host_id: str) -> int:
        return int((self.data.get("last_update") or {}).get(host_id, 0))

    def note_update(self, host_id: str, when: int) -> None:
        with self.lock:
            stamps = dict(self.data.get("last_update") or {})
            stamps[host_id] = int(when)
            self.data["last_update"] = stamps
            self._save()

    # ---------- automatic reboots ----------

    def auto_reboot(self) -> dict:
        out = dict(AUTO_REBOOT_DEFAULT)
        out.update(self.data.get("auto_reboot") or {})
        return out

    def set_auto_reboot(self, values: dict) -> dict:
        with self.lock:
            current = self.auto_reboot()
            for key in ("enabled",):
                if key in values:
                    current[key] = bool(values[key])
            for key in ("from_hour", "to_hour", "min_interval_hours"):
                if key in values:
                    try:
                        current[key] = max(0, int(values[key]))
                    except (TypeError, ValueError):
                        pass
            if isinstance(values.get("exclude"), list):
                current["exclude"] = [str(x) for x in values["exclude"]]
            self.data["auto_reboot"] = current
            self._save()
            return current

    def note_reboot(self, host_id: str, when: int) -> None:
        with self.lock:
            history = dict(self.data.get("auto_reboot_history") or {})
            history[host_id] = when
            self.data["auto_reboot_history"] = history
            self._save()

    def last_reboot(self, host_id: str) -> int:
        return int((self.data.get("auto_reboot_history") or {}).get(host_id, 0))

    # ---------- applying ----------

    # ---------- names ----------

    def names(self) -> dict:
        return dict(self.data.get("names") or {})

    def set_name(self, host_id: str, name: str) -> str:
        """Rename a host, or clear the rename and fall back to the config.

        A name is the one thing about a host that is purely for the person
        reading it, and the one most likely to be wrong on the day the host is
        added — a provider's "ubuntu-1cpu-1gb-fi-hel2" says nothing about what
        the machine is for. Editing the fleet file over ssh to fix that is out
        of proportion to the change, so it lives here with the thresholds.
        """
        host_id = str(host_id).strip()
        if not host_id:
            raise ValueError("не сказано, какой хост переименовать")
        # One line, no control characters, and short enough to fit a card.
        name = " ".join(str(name).split())[:40]
        with self.lock:
            names = dict(self.data.get("names") or {})
            if name:
                names[host_id] = name
            else:
                names.pop(host_id, None)
            self.data["names"] = names
            self._save()
        return name

    def paid_until(self) -> dict:
        return dict(self.data.get("paid_until") or {})

    def set_paid_until(self, host_id: str, date: str) -> str:
        """Record that the rent on a machine has been paid to a date.

        Renewing a VPS takes a minute on the provider's site and used to take
        longer here: the date lives in the fleet file, so writing it down meant
        an ssh session and an editor, which is exactly the kind of chore that
        does not get done — and then the dashboard warns about an expiry that
        was paid weeks ago, until nobody reads that warning any more.

        Empty clears the override and falls back to whatever the file says.
        """
        host_id = str(host_id).strip()
        if not host_id:
            raise ValueError("не сказано, для какого хоста")
        date = str(date).strip()
        if date:
            try:
                stamp = time.strptime(date, "%Y-%m-%d")
            except ValueError:
                raise ValueError("дата нужна в виде ГГГГ-ММ-ДД") from None
            # A date in the past is how a typo announces itself: it would put
            # the host straight into "не оплачен" instead of clearing it.
            if time.mktime(stamp) < time.time() - 86400:
                raise ValueError("эта дата уже прошла — проверьте год")
        with self.lock:
            dates = dict(self.data.get("paid_until") or {})
            if date:
                dates[host_id] = date
            else:
                dates.pop(host_id, None)
            self.data["paid_until"] = dates
            self._save()
        return date

    def apply_to(self, cfg: dict) -> None:
        """Layer the stored thresholds and names over the config, in place.

        The config layer is remembered on the first call, so clearing a value
        in the UI falls back to the file rather than to whatever this function
        merged in last time.
        """
        if not hasattr(self, "_base"):
            self._base = dict(cfg.get("thresholds") or {})
        merged = dict(self._base)
        merged.update(self.thresholds())
        cfg["thresholds"] = merged

        if not hasattr(self, "_base_names"):
            self._base_names = {str(h.get("id")): h.get("name")
                                for h in cfg.get("hosts") or []}
        if not hasattr(self, "_base_paid"):
            self._base_paid = {str(h.get("id")): h.get("paid_until")
                               for h in cfg.get("hosts") or []}
        chosen = self.names()
        paid = self.paid_until()
        for host in cfg.get("hosts") or []:
            host_id = str(host.get("id"))
            renamed = chosen.get(host_id)
            host["name"] = renamed or self._base_names.get(host_id) or host.get("name")
            host["paid_until"] = (paid.get(host_id)
                                  or self._base_paid.get(host_id)
                                  or host.get("paid_until") or "")
