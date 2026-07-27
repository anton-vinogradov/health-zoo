#!/bin/sh
# health-zoo agent: Synology DSM (BusyBox userland, no sudo).
#
# DSM gives an unprivileged shell account very little, so this deliberately
# sticks to world-readable files. Anything that needs root (smartctl, the
# Surveillance Station database, firewall state) is simply not reported —
# better an honest gap than a half-truth.

echo "kind	synology"
echo "hostname	$(hostname 2>/dev/null)"

# ---------- DSM version ----------
if [ -r /etc/VERSION ]; then
  # shellcheck disable=SC1091  # target-side file, not available to the linter
  . /etc/VERSION 2>/dev/null
  emit os_name "DSM ${majorversion:-?}.${minorversion:-?}.${micro:-0}-${buildnumber:-?}"
  emit os_version "${majorversion:-}.${minorversion:-}.${micro:-}"
  emit dsm_build "${buildnumber:-}"
  emit dsm_smallfix "${smallfixnumber:-0}"
fi
emit os_id synology
emit kernel "$(uname -r 2>/dev/null)"
emit arch "$(uname -m 2>/dev/null)"
[ -r /proc/sys/kernel/syno_hw_version ] && \
  emit model "$(cat /proc/sys/kernel/syno_hw_version 2>/dev/null)"

# ---------- uptime / load / cpu ----------
common_uptime_load
emit cpus "$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
emit cpu_model "$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"

# ---------- memory ----------
# The 512 MB units swap constantly; swap pressure is the headline metric here.
common_memory

# ---------- volumes ----------
df -P -k 2>/dev/null | awk '
  NR>1 && ($1 ~ /^\/dev\// || $6 ~ /^\/volume/) && $1 !~ /loop/ && $6 !~ /^\/tmp\// {
    print "@disk\t" $6 "\t" $1 "\t" $2*1024 "\t" $3*1024
  }'

# ---------- RAID / array health ----------
# "[UU]" means every member is up; "[U_]" is a degraded array and the single
# most important thing this agent can report.
if [ -r /proc/mdstat ]; then
  awk '
    /^md[0-9]+ :/ { dev=$1; level=$4; next }
    /blocks/ && dev != "" {
      state="unknown"
      if (match($0, /\[[U_]+\]/)) state=substr($0, RSTART+1, RLENGTH-2)
      print "@raid\t" dev "\t" level "\t" state
      dev=""
    }
  ' /proc/mdstat
fi

# ---------- temperature ----------
# Only the x86 units (DS224+) expose sensors; the aarch64 DS120j/DS220j do not.
# Per-core readings collapse to one hottest value per sensor chip: a NAS card
# showing "coretemp 41" five times is noise, the peak is the signal.
for hw in /sys/class/hwmon/hwmon*; do
  name=$(cat "$hw/name" 2>/dev/null)
  max=0
  for f in "$hw"/temp*_input; do
    [ -r "$f" ] || continue
    t=$(cat "$f" 2>/dev/null)
    [ -n "$t" ] && [ "$t" -gt "$max" ] 2>/dev/null && max=$t
  done
  [ "$max" -gt 1000 ] 2>/dev/null && row "@temp	${name:-hwmon}	$((max / 1000))"
done
# DSM keeps its own disk temperature file on some models.
if [ -r /sys/block/sata1/device/syno_disk_temperature ]; then
  for d in /sys/block/sata*/device/syno_disk_temperature; do
    [ -r "$d" ] || continue
    t=$(cat "$d" 2>/dev/null)
    disk=$(echo "$d" | sed -e 's|/sys/block/||' -e 's|/device.*||')
    [ -n "$t" ] && row "@temp	$disk	$t"
  done
fi

# ---------- physical disk health ----------
# DSM keeps SMART behind root. Where the operator has allowed smartctl through
# sudoers this fills in the single biggest blind spot on a NAS: the units here
# run single disks with no RAID, so a dying drive is data loss, not redundancy
# wearing thin. Without the permission the section is simply absent.
# Probe the exact command, not sudo in general: a careful sudoers grants
# smartctl alone, and `sudo -n true` would fail on such a host.
if command -v smartctl >/dev/null 2>&1 && sudo -n smartctl --version >/dev/null 2>&1; then
  for dev in /dev/sata? /dev/sd? /dev/nvme?n?; do
    [ -b "$dev" ] || continue
    # DSM presents SATA drives through a SCSI layer, where plain smartctl
    # reports "device lacks SMART capability". -d sat translates the ATA
    # commands through it and returns the real attribute table; fall back to
    # autodetection for anything genuinely SCSI or NVMe.
    out=$(sudo -n smartctl -d sat -H -A -i "$dev" 2>/dev/null)
    case "$out" in
      *"lacks SMART"*|"") out=$(sudo -n smartctl -H -A -i "$dev" 2>/dev/null) ;;
    esac
    [ -n "$out" ] || continue

    model=$(printf '%s' "$out" | awk -F': *' '/Device Model|Model Number/{print $2; exit}')
    health=$(printf '%s' "$out" | awk -F': *' '
      /overall-health self-assessment test result/ {print $2; exit}
      /SMART Health Status/ {print $2; exit}')
    [ -n "$health" ] || health=unknown
    temp=$(printf '%s' "$out" | awk '
      /^194 |Temperature_Celsius/ {print $10; exit}
      /^Temperature:/ {print $2; exit}
      /Current Drive Temperature:/ {print $4; exit}')
    hours=$(printf '%s' "$out" | awk '
      /^  9 |Power_On_Hours/ {print $10; exit}
      /^Power On Hours:/ {gsub(/,/, "", $4); print $4; exit}
      /Accumulated power on time/ {split($0, a, ":"); split(a[2], b, "."); gsub(/ /, "", b[1]); print b[1]; exit}')
    realloc=$(printf '%s' "$out" | awk '/^  5 |Reallocated_Sector_Ct/ {print $10; exit}')
    pending=$(printf '%s' "$out" | awk '/Current_Pending_Sector/ {print $10; exit}')
    wear=$(printf '%s' "$out" | awk -F': *' '/Percentage Used/ {gsub(/%/, "", $2); print $2; exit}')

    row "@smart	$dev	$health	${temp:-}	${hours:-}	${realloc:-}	${pending:-}	${wear:-}	${model:-}"
  done
else
  # Say so explicitly: a NAS card with no disk health is not a healthy NAS,
  # it is an unmeasured one.
  emit smart_blocked "нет прав на smartctl (нужен sudo)"
fi

# ---------- installed packages and their versions ----------
# /var/packages/<name>/INFO is world-readable, unlike `synopkg` which is not
# usable unprivileged.
for p in /var/packages/*/; do
  [ -d "$p" ] || continue
  name=$(basename "$p")
  info="${p}INFO"
  [ -r "$info" ] || continue
  ver=$(awk -F'"' '/^version=/{print $2; exit}' "$info" 2>/dev/null)
  # enabled/ and target/ presence marks a running package on DSM 7.
  if [ -f "$p/enabled" ]; then state=running; else state=stopped; fi
  [ -e "$p/target" ] || state=notinstalled
  # DSM says so itself: install_type=system (or system_hidden) marks the parts
  # of the OS that arrive with it — FileStation, OAuthService, StorageManager.
  # Anything without it was installed on purpose: Surveillance Station,
  # HyperBackup, a codec pack.
  itype=$(awk -F'"' '/^install_type=/{print $2; exit}' "$info" 2>/dev/null)
  case "$itype" in system|system_hidden) scope=system ;; *) scope=user ;; esac
  row "@service	$name	$state	installed	0	0	$info	Synology package	$scope"
  [ -n "$ver" ] && row "@unitpkg	$name	$name	$ver"
done

# ---------- pending DSM updates ----------
# The updater writes its findings here; readable without root on 7.x.
for f in /usr/syno/etc/dsm_update_status /var/lib/dsm-update/status; do
  [ -r "$f" ] || continue
  avail=$(awk -F'=' '/available/{gsub(/"/,"",$2); print $2; exit}' "$f" 2>/dev/null)
  [ -n "$avail" ] && emit dsm_update "$avail"
  break
done
emit pkg_manager synology

# ---------- listening ports ----------
# DSM listens on non-standard ports far more often than not (8000/8001 here),
# so the web link has to be discovered rather than assumed.
common_listeners

# ---------- Surveillance Station: cameras this NAS records ----------
# Recording folders are the only camera fact visible without the SS database.
SSCONF=/var/packages/SurveillanceStation/etc/settings.conf
if [ -r "$SSCONF" ]; then
  emit surveillance 1
  for d in /volume*/surveillance/*/; do
    [ -d "$d" ] || continue
    cam=$(basename "$d")
    case "$cam" in @*|.*) continue ;; esac
    # Recordings live in YYYYMMDD{AM,PM} folders; the newest one tells whether
    # recording is actually alive, and the count gives the archive depth.
    newest=""
    days=0
    for half in "$d"[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][AP]M; do
      [ -d "$half" ] || continue
      days=$((days + 1))
      newest="$half"
    done
    [ -n "$newest" ] || continue
    lastts=$(find "$newest" -maxdepth 1 -type f -newermt '-2 days' -printf '%T@\n' 2>/dev/null \
             | sort -rn | head -1)
    lastts=${lastts%%.*}
    row "@camera	$cam	$cam	1		 	recording	0	0	0	${lastts:-0}	$((days / 2))"
  done

  # Which cameras this NAS is actually pulling right now. The recording folder
  # is named by the operator and says nothing about the camera's address, and
  # Surveillance Station keeps its camera table in a PostgreSQL database that
  # is root-only. An established RTSP session is the one piece of evidence
  # available unprivileged — and it doubles as proof the stream is alive.
  netstat -tn 2>/dev/null | awk '
    $NF == "ESTABLISHED" && $5 ~ /:554$/ {
      split($5, a, ":"); print a[1]
    }' | sort -u | while read -r ip; do
      [ -n "$ip" ] && row "@camlink	$ip	rtsp"
    done
fi

# ---------- HyperBackup: what is protected, and what is not ----------
# Two different questions, answered on two different machines. On the source
# NAS: which shares the task actually covers — an untouched share is the kind
# of gap nobody notices until it matters. On the destination: how fresh the
# repository is, since the task's own last-run time is not readable here.
HBCONF=/var/packages/HyperBackup/etc/synobackup.conf
if [ -r "$HBCONF" ]; then
  # Credentials live in this same file; only structural fields are read.
  folders=$(awk -F'=' '/^backup_folders=/{print $2; exit}' "$HBCONF" 2>/dev/null)
  taskname=$(awk -F'"' '/^name=/{if ($2 != "") {print $2; exit}}' "$HBCONF" 2>/dev/null)
  # Where the data goes. remote_user sits two lines away in the same file and
  # is deliberately not read: the destination is the useful fact, not the login.
  dest=$(awk -F'"' '/^remote_addr=/{print $2; exit}' "$HBCONF" 2>/dev/null)
  share=$(awk -F'"' '/^remote_share=/{print $2; exit}' "$HBCONF" 2>/dev/null)
  [ -n "$folders" ] && row "@backup	task	${taskname:-HyperBackup}	$folders	${dest:-}	${share:-}"

  for vol in /volume1 /volume2; do
    [ -d "$vol" ] || continue
    for share in "$vol"/*/; do
      [ -d "$share" ] || continue
      name=$(basename "$share")
      case "$name" in @*|.*|"#recycle"|surveillance|"docker") continue ;; esac
      # A share is covered when the task lists it, exactly or as a parent.
      case "$folders" in
        *"\"/$name\""*) continue ;;
      esac
      row "@unbacked	$name	$vol"
    done
  done
fi

# Repositories stored on this NAS: their mtime is when the last backup landed.
for repo in /volume*/*/*.hbk; do
  [ -d "$repo" ] || continue
  last=$(date -r "$repo" +%s 2>/dev/null)
  size=$(awk -F'=' '/^size=/{print $2; exit}' "$repo/last_status.conf" 2>/dev/null)
  printf '@backuprepo\t%s\t%s\t%s\n' "$(basename "$repo")" "${last:-0}" "${size:-0}"
done | sort -u

echo "ok	1"
