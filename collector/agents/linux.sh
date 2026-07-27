#!/bin/sh
# health-zoo agent: Debian/Ubuntu family.
#
# Runs over `ssh host sh -s` — nothing is installed on the target host.
# Emits a flat, tab-separated report (see PROTOCOL.md); the collector turns it
# into JSON. Never prints credentials: connection strings are stripped down to
# host:port before they leave the machine.
#
# Must stay POSIX sh: no bashisms, no jq, no python on the target. Weak CPUs
# (Celeron N5105) run this every cycle, so batch the systemctl/dpkg calls
# instead of forking per unit.

set -u
LC_ALL=C
export LC_ALL

emit() { printf '%s\t%s\n' "$1" "$2"; }
row() { printf '%s\n' "$*"; }

echo "kind	linux"
echo "hostname	$(hostname 2>/dev/null)"

# ---------- OS / kernel ----------
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091  # target-side file, not available to the linter
  . /etc/os-release 2>/dev/null
  emit os_name "${PRETTY_NAME:-${NAME:-Linux}}"
  emit os_id "${ID:-linux}"
  emit os_version "${VERSION_ID:-}"
fi
emit kernel "$(uname -r 2>/dev/null)"
emit arch "$(uname -m 2>/dev/null)"

# ---------- uptime / load / cpu ----------
[ -r /proc/uptime ] && emit uptime "$(cut -d' ' -f1 /proc/uptime)"
if [ -r /proc/loadavg ]; then
  # shellcheck disable=SC2046  # word splitting is the point: three fields
  set -- $(cat /proc/loadavg)
  emit load1 "$1"; emit load5 "$2"; emit load15 "$3"
fi
emit cpus "$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
emit cpu_model "$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"

# ---------- memory ----------
if [ -r /proc/meminfo ]; then
  awk '
    /^MemTotal:/     {print "mem_total\t"     $2*1024}
    /^MemAvailable:/ {print "mem_available\t" $2*1024}
    /^MemFree:/      {print "mem_free\t"      $2*1024}
    /^SwapTotal:/    {print "swap_total\t"    $2*1024}
    /^SwapFree:/     {print "swap_free\t"     $2*1024}
  ' /proc/meminfo
fi

# ---------- disks ----------
# Real filesystems only; overlay/tmpfs/loop noise is dropped.
df -P -k 2>/dev/null | awk 'NR>1 && $1 ~ /^\/dev\// && $1 !~ /loop/ {
  print "@disk\t" $6 "\t" $1 "\t" $2*1024 "\t" $3*1024
}'

# ---------- temperatures ----------
# hwmon and thermal_zone expose the same sensors under different names; keep
# one reading per (label, value) pair so the card is not flooded with dupes.
{
  for hw in /sys/class/hwmon/hwmon*; do
    name=$(cat "$hw/name" 2>/dev/null)
    for f in "$hw"/temp*_input; do
      [ -r "$f" ] || continue
      t=$(cat "$f" 2>/dev/null)
      lbl=$(cat "$(echo "$f" | sed 's/_input$/_label/')" 2>/dev/null)
      [ -n "$t" ] && [ "$t" -gt 1000 ] 2>/dev/null && \
        printf '%s\t%s\n' "${lbl:-${name:-hwmon}}" "$((t / 1000))"
    done
  done
  for z in /sys/class/thermal/thermal_zone*; do
    [ -r "$z/temp" ] || continue
    t=$(cat "$z/temp" 2>/dev/null)
    lbl=$(cat "$z/type" 2>/dev/null)
    [ -n "$t" ] && [ "$t" -gt 1000 ] 2>/dev/null && \
      printf '%s\t%s\n' "${lbl:-thermal}" "$((t / 1000))"
  done
} | sort -u -t'	' -k1,1 | awk -F'\t' '{print "@temp\t" $1 "\t" $2}'

# ---------- pending package updates ----------
# Reads the apt cache as-is: refreshing it needs root, and the host's own
# apt-daily timer already does that. pkg_list_mtime tells the UI how stale it is.
if command -v apt-get >/dev/null 2>&1; then
  emit pkg_manager apt
  for s in /var/lib/apt/periodic/update-success-stamp /var/lib/apt/lists; do
    [ -e "$s" ] && { emit pkg_list_mtime "$(stat -c %Y "$s" 2>/dev/null)"; break; }
  done
  # zoneminder/noble-updates 1.38.3 amd64 [upgradable from: 1.38.2]
  apt list --upgradable 2>/dev/null | awk -F'[/ ]' '
    /upgradable from:/ {
      pkg=$1; suite=$2; new=$3
      old=$0; sub(/.*upgradable from: */, "", old); sub(/].*$/, "", old)
      sec = (suite ~ /security/) ? 1 : 0
      print "@update\t" pkg "\t" old "\t" new "\t" sec "\t" suite
    }'
fi
[ -f /var/run/reboot-required ] && emit reboot_required 1
[ -f /var/run/reboot-required.pkgs ] && \
  emit reboot_pkgs "$(tr '\n' ' ' < /var/run/reboot-required.pkgs)"

# ---------- services (auto-discovered) ----------
# Shown when the unit is enabled, hand-installed under /etc/systemd/system, or
# failed — minus base-OS noise. No per-host whitelist anywhere in this project,
# so a newly installed unit appears on the dashboard by itself.
skip_unit() {
  case "$1" in
    systemd-*|dbus*|user@*|user-runtime-dir@*|getty@*|serial-getty@*|console-setup*|\
    apparmor*|polkit*|udisks2*|modprobe@*|blk-availability*|cryptsetup*|\
    e2scrub*|keyboard-setup*|kmod*|lvm2*|multipathd*|networkd-dispatcher*|\
    plymouth*|rsyslog*|setvtrgb*|snapd.*|ssh.service|sshd.service|\
    cron.service|dmesg*|finalrd*|ifupdown*|irqbalance*|open-vm-tools*|\
    packagekit*|rescue*|emergency*|sys-*|swap*|thermald*|unattended-upgrades*|\
    upower*|wpa_supplicant*|ureadahead*|uuidd*|whoopsie*|kerneloops*|apport*|\
    binfmt*|hwclock*|logrotate.*|man-db*|apt-daily*|dpkg-db-backup*|fwupd*|\
    fstrim*|motd-news*|update-notifier*|anacron*|plocate*|sysstat*|ua-*|\
    cloud-init*|cloud-config*|cloud-final*|chrony*|ntp*|rpcbind*|nfs-*|\
    auditd*|rc-local*|secureboot*|grub-*|kdump*|lm-sensors*) return 0 ;;
  esac
  return 1
}

if command -v systemctl >/dev/null 2>&1; then
  # One `systemctl show` for all units beats one call per unit on slow boxes.
  units=$(systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null \
          | awk '$3 ~ /^(active|failed|activating)$/ {print $1}')
  keep=""
  for u in $units; do skip_unit "$u" || keep="$keep $u"; done
  if [ -n "$keep" ]; then
    # shellcheck disable=SC2086
    systemctl show -p Id -p ActiveState -p SubState -p UnitFileState \
      -p ActiveEnterTimestampMonotonic -p NRestarts -p FragmentPath -p Description \
      $keep 2>/dev/null \
    | awk -v RS='' -F'\n' '
      {
        delete f
        for (i = 1; i <= NF; i++) { split($i, kv, "="); k = kv[1]
          v = substr($i, index($i, "=") + 1); f[k] = v }
        # Base-OS units that are neither enabled nor hand-installed are noise.
        keepit = (f["UnitFileState"] ~ /^enabled/) ||
                 (f["FragmentPath"] ~ /^\/etc\/systemd\//) ||
                 (f["ActiveState"] == "failed")
        if (!keepit) next
        printf "@service\t%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\n",
          f["Id"], f["ActiveState"], f["SubState"],
          (f["UnitFileState"] == "" ? "unknown" : f["UnitFileState"]),
          (f["ActiveEnterTimestampMonotonic"] == "" ? 0 : f["ActiveEnterTimestampMonotonic"]),
          (f["NRestarts"] == "" ? 0 : f["NRestarts"]),
          f["FragmentPath"], f["Description"]
      }'
  fi

  # Timers matter here: zm-telegram-drain is a timer, not a long-lived service.
  timers=$(systemctl list-timers --all --no-legend --no-pager 2>/dev/null \
           | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) { print $i; break } }')
  keept=""
  for t in $timers; do skip_unit "$t" || keept="$keept $t"; done
  if [ -n "$keept" ]; then
    # shellcheck disable=SC2086
    systemctl show -p Id -p ActiveState -p NextElapseUSecRealtime -p Description \
      $keept 2>/dev/null \
    | awk -v RS='' -F'\n' '
      {
        delete f
        for (i = 1; i <= NF; i++) { split($i, kv, "="); k = kv[1]
          v = substr($i, index($i, "=") + 1); f[k] = v }
        printf "@timer\t%s\t%s\t%s\t%s\n", f["Id"], f["ActiveState"],
          (f["NextElapseUSecRealtime"] == "" ? 0 : f["NextElapseUSecRealtime"]),
          f["Description"]
      }'
  fi

  # ---------- version behind each unit ----------
  # unit -> owning .deb -> version answers "which ZoneMinder is this" without
  # the collector knowing anything about ZoneMinder.
  if command -v dpkg >/dev/null 2>&1 && [ -n "$keep" ]; then
    tmpd=${TMPDIR:-/tmp}/.hz.$$
    mkdir -p "$tmpd" 2>/dev/null || tmpd=/tmp
    # shellcheck disable=SC2086
    systemctl show -p Id -p FragmentPath $keep 2>/dev/null \
    | awk -v RS='' -F'\n' '{
        delete f
        for (i = 1; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = substr($i, index($i, "=") + 1) }
        if (f["FragmentPath"] != "") print f["Id"] "\t" f["FragmentPath"]
      }' > "$tmpd/units"
    if [ -s "$tmpd/units" ]; then
      paths=$(cut -f2 "$tmpd/units" | tr '\n' ' ')
      # dpkg -S prints "pkg: /path" (or "p1, p2: /path" for diverted files).
      # shellcheck disable=SC2086
      dpkg -S $paths 2>/dev/null | sed 's/: /\t/' | awk -F'\t' '{
        split($1, ps, ", "); print $2 "\t" ps[1]
      }' > "$tmpd/owners"
      if [ -s "$tmpd/owners" ]; then
        pkgs=$(cut -f2 "$tmpd/owners" | sort -u | tr '\n' ' ')
        # shellcheck disable=SC2086
        dpkg-query -W -f='${Package}\t${Version}\n' $pkgs 2>/dev/null > "$tmpd/vers"
        awk -F'\t' -v vers="$tmpd/vers" -v owners="$tmpd/owners" '
          BEGIN {
            while ((getline line < vers) > 0)   { split(line, a, "\t"); ver[a[1]]   = a[2] }
            while ((getline line < owners) > 0) { split(line, a, "\t"); owner[a[1]] = a[2] }
          }
          { p = owner[$2]; if (p != "" && ver[p] != "") print "@unitpkg\t" $1 "\t" p "\t" ver[p] }
        ' "$tmpd/units"
      fi
    fi
    rm -rf "$tmpd"
  fi
fi

# ---------- physical disk health (SMART) ----------
# Disk usage says nothing about a drive that is about to die. Needs smartctl
# and root; where either is missing the section is simply absent rather than
# guessed at.
# Probe the exact command, not sudo in general: a careful sudoers grants
# smartctl alone, and `sudo -n true` would fail on such a host.
if command -v smartctl >/dev/null 2>&1 && sudo -n smartctl --version >/dev/null 2>&1; then
  for dev in /dev/sd? /dev/nvme?n? /dev/hd?; do
    [ -b "$dev" ] || continue
    out=$(sudo -n smartctl -H -A -i "$dev" 2>/dev/null) || continue
    [ -n "$out" ] || continue

    model=$(printf '%s' "$out" | awk -F': *' '/Device Model|Model Number/{print $2; exit}')
    health=$(printf '%s' "$out" | awk -F': *' '
      /overall-health self-assessment test result/ {print $2; exit}
      /SMART Health Status/ {print $2; exit}')
    [ -n "$health" ] || health=unknown

    # SATA attributes are a numbered table; NVMe prints "Key: value" lines.
    temp=$(printf '%s' "$out" | awk '
      /^194 |Temperature_Celsius/ {print $10; exit}
      /^Temperature:/ {print $2; exit}')
    hours=$(printf '%s' "$out" | awk '
      /^  9 |Power_On_Hours/ {print $10; exit}
      /^Power On Hours:/ {gsub(/,/, "", $4); print $4; exit}')
    realloc=$(printf '%s' "$out" | awk '/^  5 |Reallocated_Sector_Ct/ {print $10; exit}')
    pending=$(printf '%s' "$out" | awk '/Current_Pending_Sector/ {print $10; exit}')
    # SSD/NVMe wear: how much of the rated endurance is gone.
    wear=$(printf '%s' "$out" | awk -F': *' '
      /Percentage Used/ {gsub(/%/, "", $2); print $2; exit}')
    [ -n "$wear" ] || wear=$(printf '%s' "$out" | awk '/Wear_Leveling_Count/ {print 100 - $4; exit}')

    row "@smart	$dev	$health	${temp:-}	${hours:-}	${realloc:-}	${pending:-}	${wear:-}	${model:-}"
  done
fi

# ---------- listening TCP ports ----------
# Feeds the "open web UI" links: whatever answers on a web-ish port here shows
# up as a button, so a newly installed panel is reachable without editing config.
# The bind address matters: a backend on 127.0.0.1 is reachable only through
# whatever proxies it, so offering a link to it would send you nowhere.
# UDP is collected too: a VPN endpoint (WireGuard, AmneziaWG) is one of the
# more important things a box publishes, and it never shows up over TCP.
if command -v ss >/dev/null 2>&1; then
  ss -ulnH 2>/dev/null | awk '{
    addr = $4
    port = addr; sub(/.*:/, "", port)
    host = addr; sub(/:[0-9]+$/, "", host)
    if (port !~ /^[0-9]+$/ || port == 0) next
    local = (host ~ /^\[?(::ffff:)?127\./ || host == "[::1]" || host == "::1") ? "local" : "any"
    print port "\t" local
  }' | sort -u | while IFS='	' read -r p scope; do
      [ "$scope" = "local" ] && continue
      proc=$(ss -ulnpH "sport = :$p" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -1)
      row "@udp	$p	${proc:-}	$scope"
    done
fi
if command -v ss >/dev/null 2>&1; then
  ss -tlnH 2>/dev/null | awk '{
    addr = $4
    port = addr; sub(/.*:/, "", port)
    host = addr; sub(/:[0-9]+$/, "", host)
    if (port !~ /^[0-9]+$/) next
    local = (host ~ /^\[?(::ffff:)?127\./ || host == "[::1]" || host == "::1") ? "local" : "any"
    print port "\t" local
  }' | sort -u | while IFS='	' read -r p scope; do
      proc=$(ss -tlnpH "sport = :$p" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -1)
      row "@listen	$p	${proc:-}	$scope"
    done
elif command -v netstat >/dev/null 2>&1; then
  netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {
    addr = $4
    port = addr; sub(/.*:/, "", port)
    host = addr; sub(/:[0-9]+$/, "", host)
    if (port !~ /^[0-9]+$/) next
    local = (host ~ /^(::ffff:)?127\./ || host == "::1") ? "local" : "any"
    print "@listen\t" port "\t\t" local
  }' | sort -u
fi

# ---------- containers ----------
# Membership in the docker group is not a given; fall back to passwordless sudo.
if command -v docker >/dev/null 2>&1; then
  DOCKER=""
  if docker ps >/dev/null 2>&1; then DOCKER="docker"
  elif sudo -n docker ps >/dev/null 2>&1; then DOCKER="sudo -n docker"
  fi
  if [ -n "$DOCKER" ]; then
    $DOCKER ps -a --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}' 2>/dev/null \
    | while IFS='	' read -r n i st stat; do
        row "@container	$n	$i	$st	$stat"
      done
  fi
fi

# ---------- git checkouts (our own projects) ----------
# safe.directory: these live under /opt owned by root, and git otherwise
# refuses to read them as "dubious ownership".
if command -v git >/dev/null 2>&1; then
  for d in /opt/*/.git /srv/*/.git /usr/local/*/.git; do
    [ -d "$d" ] || continue
    repo=$(dirname "$d")
    g="git -c safe.directory=$repo -C $repo"
    commit=$($g rev-parse --short HEAD 2>/dev/null) || continue
    [ -n "$commit" ] || continue
    branch=$($g rev-parse --abbrev-ref HEAD 2>/dev/null)
    desc=$($g describe --tags --always 2>/dev/null)
    when=$($g log -1 --format=%ct 2>/dev/null)
    row "@repo	$repo	$branch	$commit	$desc	${when:-0}"
  done
fi

# ---------- ZoneMinder monitors, i.e. cameras this host records ----------
# Camera addresses are extracted without their credentials.
if [ -d /etc/zm ] && command -v mysql >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  emit zoneminder 1
  sudo -n mysql zm -N -B -e \
    'SELECT m.Id, m.Name, m.Enabled, m.Path, m.Width, m.Height,
            COALESCE(s.Status,""), COALESCE(s.CaptureFPS,0), COALESCE(s.AnalysisFPS,0),
            COALESCE(s.CaptureBandwidth,0)
     FROM Monitors m LEFT JOIN Monitor_Status s ON s.MonitorId = m.Id;' 2>/dev/null \
  | while IFS='	' read -r id name en path w h st cfps afps bw; do
      # rtsp://user:pass@10.0.0.5:554/path -> 10.0.0.5:554
      addr=$(printf '%s' "$path" | sed -e 's|^[a-zA-Z]*://||' -e 's|^[^@/]*@||' -e 's|/.*$||')
      row "@camera	$id	$name	$en	$addr	${w}x${h}	$st	$cfps	$afps	$bw"
    done
  # Archive stats come from the database, not the filesystem: `du` over a
  # multi-gigabyte events tree took ~40s on the N5105 and stalled every cycle.
  sudo -n mysql zm -N -B -e \
    'SELECT COUNT(*), COALESCE(MAX(UNIX_TIMESTAMP(StartDateTime)),0),
            COALESCE(ROUND(SUM(DiskSpace)),0),
            COALESCE(MIN(UNIX_TIMESTAMP(StartDateTime)),0) FROM Events;' 2>/dev/null \
  | while IFS='	' read -r cnt last used oldest; do
      emit zm_events_count "$cnt"
      emit zm_last_event "$last"
      emit zm_events_bytes "$used"
      emit zm_oldest_event "$oldest"
    done

  # Per-monitor recording activity. A camera can be Connected and still record
  # nothing — a broken zone, a stuck analysis thread — and that silence is
  # invisible unless the events are counted per camera.
  sudo -n mysql zm -N -B -e \
    'SELECT m.Id, m.Name,
            COALESCE(SUM(e.StartDateTime > NOW() - INTERVAL 24 HOUR), 0),
            COALESCE(MAX(UNIX_TIMESTAMP(e.StartDateTime)), 0),
            COALESCE(MIN(UNIX_TIMESTAMP(e.StartDateTime)), 0)
     FROM Monitors m LEFT JOIN Events e ON e.MonitorId = m.Id
     WHERE m.Enabled = 1 GROUP BY m.Id, m.Name;' 2>/dev/null \
  | while IFS='	' read -r id name day last oldest; do
      row "@camevent	$id	$name	$day	$last	$oldest"
    done
fi

echo "ok	1"
