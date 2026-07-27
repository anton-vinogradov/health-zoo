#!/bin/sh
# health-zoo agent: Synology DSM (BusyBox userland, no sudo).
#
# DSM gives an unprivileged shell account very little, so this deliberately
# sticks to world-readable files. Anything that needs root (smartctl, the
# Surveillance Station database, firewall state) is simply not reported —
# better an honest gap than a half-truth.

set -u
LC_ALL=C
export LC_ALL

emit() { printf '%s\t%s\n' "$1" "$2"; }
row() { printf '%s\n' "$*"; }

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
[ -r /proc/uptime ] && emit uptime "$(cut -d' ' -f1 /proc/uptime)"
if [ -r /proc/loadavg ]; then
  # shellcheck disable=SC2046  # word splitting is the point: three fields
  set -- $(cat /proc/loadavg)
  emit load1 "$1"; emit load5 "$2"; emit load15 "$3"
fi
emit cpus "$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
emit cpu_model "$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"

# ---------- memory ----------
# The 512 MB units swap constantly; swap pressure is the headline metric here.
if [ -r /proc/meminfo ]; then
  awk '
    /^MemTotal:/     {print "mem_total\t"     $2*1024}
    /^MemAvailable:/ {print "mem_available\t" $2*1024}
    /^MemFree:/      {print "mem_free\t"      $2*1024}
    /^SwapTotal:/    {print "swap_total\t"    $2*1024}
    /^SwapFree:/     {print "swap_free\t"     $2*1024}
  ' /proc/meminfo
fi

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
  row "@service	$name	$state	installed	0	0	$info	Synology package"
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

# ---------- listening TCP ports ----------
# DSM listens on non-standard ports far more often than not (8000/8001 here),
# so the web link has to be discovered rather than assumed.
netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {
  addr = $4
  port = addr; sub(/.*:/, "", port)
  host = addr; sub(/:[0-9]+$/, "", host)
  if (port !~ /^[0-9]+$/) next
  # A loopback-only listener is a backend behind a proxy, not a page to open.
  local = (host ~ /^(::ffff:)?127\./ || host == "::1") ? "local" : "any"
  print "@listen\t" port "\t\t" local
}' | sort -u

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

# ---------- HyperBackup task freshness ----------
HBCONF=/var/packages/HyperBackup/etc/synobackup.conf
if [ -r "$HBCONF" ]; then
  # Only the task name and its last-run marker; never the credentials next to them.
  awk -F'=' '
    /^\[.*\]/ { task=$0; gsub(/[][]/, "", task) }
    /^name=/  { gsub(/"/,"",$2); n=$2 }
    /^last_bkp_time=/ { gsub(/"/,"",$2); print "@backup\t" task "\t" n "\t" $2 }
  ' "$HBCONF" 2>/dev/null
fi

echo "ok	1"
