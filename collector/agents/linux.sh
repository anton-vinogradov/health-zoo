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
common_uptime_load
emit cpus "$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
emit cpu_model "$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"

# ---------- memory ----------
common_memory

# ---------- disks ----------
common_disks

# ---------- temperatures ----------
common_temps

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
# Packages nothing depends on any more. They are not a fault, but they are
# rot: old kernels and libraries that keep being downloaded, scanned and
# backed up long after the thing that needed them was removed.
if command -v apt-get >/dev/null 2>&1; then
  LC_ALL=C apt-get -s autoremove 2>/dev/null \
    | awk '/^Remv /{print "@orphan\t" $2}' | head -100
fi

[ -f /var/run/reboot-required ] && emit reboot_required 1
[ -f /var/run/reboot-required.pkgs ] && \
  emit reboot_pkgs "$(tr '\n' ' ' < /var/run/reboot-required.pkgs)"

# ---------- services (auto-discovered) ----------
# Every unit that is running or broken is reported; what differs is whose it is.
# The card shows the operator's services, the detail view shows both.
#
# No single fact answers "whose is this", and each candidate was tried:
#   - package priority: modern Ubuntu marks nearly everything "optional", so
#     ufw and rsyslog came out looking like applications;
#   - apt-mark showmanual: true on watchcats, useless on the VPS images and on
#     Raspberry Pi OS, where the base system is flagged manual as well;
#   - unit path alone: says nothing about anything shipped in /lib.
# So three signals are combined, and a short list names the base-OS families
# that no metadata separates. The list only *classifies* — nothing is hidden
# because of it, which is what made the previous skip list wrong in both
# directions.
sys_family='^(systemd-|user@|user-runtime-dir@|getty@|serial-getty@|console-setup|
keyboard-setup|setvtrgb|apparmor|polkit|udisks2|upower|snapd|dbus|cron|anacron|
rsyslog|syslog-ng|apport|whoopsie|kerneloops|ModemManager|wpa_supplicant|
NetworkManager|networkd-dispatcher|ifupdown|networking|systemd|blk-availability|
lvm2|multipathd|cryptsetup|e2scrub|kmod|modprobe@|plymouth|finalrd|thermald|
fwupd|unattended-upgrades|apt-daily|dpkg-db-backup|man-db|logrotate|fstrim|
motd-news|update-notifier|plocate|sysstat|ua-|ubuntu-fan|cloud-init|cloud-config|
cloud-final|chrony|ntp|systemd-timesyncd|rpcbind|nfs-|auditd|rc-local|secureboot|
grub-|kdump|lm-sensors|irqbalance|open-vm-tools|packagekit|rescue|emergency|sys-|
rpc-|qemu-guest-agent|serial-getty|rc-local|
swap|uuidd|ureadahead|binfmt|hwclock|dmesg|avahi-daemon|bluetooth|triggerhappy|
raspi-config|rpi-|dphys-swapfile|fake-hwclock|hciuart|nftables|containerd)'
sys_family=$(printf '%s' "$sys_family" | tr -d '\n')

unit_scopes=""
if command -v dpkg >/dev/null 2>&1; then
  unit_scopes=$( { apt-mark showmanual 2>/dev/null | sed 's/^/MAN\t/'
                   dpkg-query -W -f='PRIO\t${Package}\t${Priority}\n' 2>/dev/null
                   dpkg -S /lib/systemd/system/*.service /usr/lib/systemd/system/*.service \
                          /lib/systemd/system/*.timer /usr/lib/systemd/system/*.timer \
                     2>/dev/null | sed 's/^/OWN\t/'; } \
    | awk -F'\t' '
        $1 == "MAN"  { manual[$2] = 1; next }
        $1 == "PRIO" { prio[$2] = $3; next }
        $1 == "OWN" {
          i = index($2, ": ")
          if (i == 0) next
          split(substr($2, 1, i - 1), owners, ", ")
          pkg = owners[1]
          base = 0; app = 0
          for (j in owners) {
            if (prio[owners[j]] ~ /^(required|important|standard)$/) base = 1
            # Deliberately installed, or from a repository dpkg has no priority
            # for at all (docker, zoneminder): the operator put it there.
            if (manual[owners[j]] || prio[owners[j]] == "") app = 1
          }
          print substr($2, i + 2) "\t" (base ? "system" : (app ? "user" : "system"))
        }')
fi

if command -v systemctl >/dev/null 2>&1; then
  # One `systemctl show` for all units beats one call per unit on slow boxes.
  units=$(systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null \
          | awk '$3 ~ /^(active|failed|activating)$/ {print $1}')
  if [ -n "$units" ]; then
    # shellcheck disable=SC2086
    systemctl show -p Id -p ActiveState -p SubState -p UnitFileState \
      -p ActiveEnterTimestampMonotonic -p NRestarts -p FragmentPath -p Description \
      $units 2>/dev/null \
    | awk -v RS='' -F'\n' -v scopemap="$unit_scopes" -v family="$sys_family" '
      BEGIN {
        n = split(scopemap, lines, "\n")
        for (i = 1; i <= n; i++) {
          split(lines[i], kv, "\t")
          if (kv[1] != "") uscope[kv[1]] = kv[2]
        }
      }
      {
        delete f
        for (i = 1; i <= NF; i++) { split($i, kv, "="); k = kv[1]
          v = substr($i, index($i, "=") + 1); f[k] = v }
        path = f["FragmentPath"]
        # Base-OS families first: a VPS image ships serial-getty@ttyS0 as a
        # hand-written unit under /etc, and it is still part of the base
        # system. Only then does the location argument apply.
        if (f["Id"] ~ family) scope = "system"
        else if (path ~ /^\/(etc|opt|usr\/local|srv|home)\//) scope = "user"
        else {
          scope = uscope[path]
          # No owning package and not a known base-OS unit: installed outside
          # dpkg, which on these hosts means somebody put it there on purpose.
          if (scope == "") scope = "user"
        }
        printf "@service\t%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
          f["Id"], f["ActiveState"], f["SubState"],
          (f["UnitFileState"] == "" ? "unknown" : f["UnitFileState"]),
          (f["ActiveEnterTimestampMonotonic"] == "" ? 0 : f["ActiveEnterTimestampMonotonic"]),
          (f["NRestarts"] == "" ? 0 : f["NRestarts"]),
          path, f["Description"], scope
      }'
  fi

  # Timers matter here: zm-telegram-drain is a timer, not a long-lived service.
  timers=$(systemctl list-timers --all --no-legend --no-pager 2>/dev/null \
           | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) { print $i; break } }')
  if [ -n "$timers" ]; then
    # shellcheck disable=SC2086
    systemctl show -p Id -p ActiveState -p NextElapseUSecRealtime -p Description \
      -p FragmentPath $timers 2>/dev/null \
    | awk -v RS='' -F'\n' -v scopemap="$unit_scopes" -v family="$sys_family" '
      BEGIN {
        n = split(scopemap, lines, "\n")
        for (i = 1; i <= n; i++) {
          split(lines[i], kv, "\t")
          if (kv[1] != "") uscope[kv[1]] = kv[2]
        }
      }
      {
        delete f
        for (i = 1; i <= NF; i++) { split($i, kv, "="); k = kv[1]
          v = substr($i, index($i, "=") + 1); f[k] = v }
        if (f["Id"] ~ family) scope = "system"
        else if (f["FragmentPath"] ~ /^\/(etc|opt|usr\/local|srv|home)\//) scope = "user"
        else {
          scope = uscope[f["FragmentPath"]]
          if (scope == "") scope = "user"
        }
        printf "@timer\t%s\t%s\t%s\t%s\t%s\n", f["Id"], f["ActiveState"],
          (f["NextElapseUSecRealtime"] == "" ? 0 : f["NextElapseUSecRealtime"]),
          f["Description"], scope
      }'
  fi

  # ---------- version behind each unit ----------
  # unit -> owning .deb -> version answers "which ZoneMinder is this" without
  # the collector knowing anything about ZoneMinder.
  if command -v dpkg >/dev/null 2>&1 && [ -n "$units" ]; then
    tmpd=${TMPDIR:-/tmp}/.hz.$$
    mkdir -p "$tmpd" 2>/dev/null || tmpd=/tmp
    # shellcheck disable=SC2086
    systemctl show -p Id -p FragmentPath $units 2>/dev/null \
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

# ---------- names the web servers answer to ----------
# A link by IP is a link nobody can share and a certificate nobody matches, and
# for a service behind a reverse proxy it is simply wrong: the backend listens
# on 127.0.0.1 and only the proxy knows the name. The names live in plain text
# in the proxy's own configuration, so read them from there.
emit_vhosts() {
  # Caddy: "example.com, www.example.com {" at the start of a block. Caddy
  # serves https by default and redirects http, so the scheme is https unless
  # the site block says otherwise.
  for f in /etc/caddy/Caddyfile /etc/caddy/conf.d/*.caddy /etc/caddy/sites/*; do
    [ -r "$f" ] || continue
    awk '/^[a-zA-Z0-9*][^ \t]*(,[^ \t]*)* *\{/ {
      line = $0
      sub(/ *\{.*/, "", line)
      n = split(line, names, /, */)
      for (i = 1; i <= n; i++) {
        name = names[i]
        gsub(/^[ \t]+|[ \t]+$/, "", name)
        if (name ~ /^https?:\/\//) { sub(/^https?:\/\//, "", name) }
        if (name == "" || name ~ /^:/ || name ~ /^#/) continue
        scheme = (name ~ /^http:/) ? "http" : "https"
        print "@vhost\t" name "\t443\thttps\tcaddy"
      }
    }' "$f" 2>/dev/null
  done

  # nginx: server_name inside a server block, with the listen port of that
  # block. A wildcard or "_" is a catch-all, not a name anybody can type.
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [ -r "$f" ] || continue
    awk '
      /listen[ \t]/ {
        p = $2; gsub(/[;#].*/, "", p); sub(/.*:/, "", p)
        if (p ~ /^[0-9]+$/) port = p
        if ($0 ~ /ssl/) tls = 1
      }
      /server_name[ \t]/ {
        line = $0; sub(/.*server_name[ \t]+/, "", line); gsub(/[;#].*/, "", line)
        n = split(line, names, /[ \t]+/)
        for (i = 1; i <= n; i++) {
          if (names[i] == "" || names[i] == "_" || names[i] ~ /\*/) continue
          scheme = (tls || port == 443) ? "https" : "http"
          print "@vhost\t" names[i] "\t" (port ? port : 80) "\t" scheme "\tnginx"
        }
      }' "$f" 2>/dev/null
  done

  # Apache: ServerName / ServerAlias, port from the VirtualHost header.
  for f in /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf; do
    [ -r "$f" ] || continue
    awk '
      /<VirtualHost/ { p = $2; sub(/.*:/, "", p); sub(/>.*/, "", p)
                       if (p ~ /^[0-9]+$/) port = p }
      /^[ \t]*Server(Name|Alias)[ \t]/ {
        for (i = 2; i <= NF; i++) {
          if ($i ~ /^#/) break
          scheme = (port == 443) ? "https" : "http"
          print "@vhost\t" $i "\t" (port ? port : 80) "\t" scheme "\tapache"
        }
      }' "$f" 2>/dev/null
  done
}
emit_vhosts | sort -u | head -40

# ---------- listening ports ----------
common_cpu
common_peer
common_listeners
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

  # Camera firmware. The version is only given to an authenticated request, and
  # the recorder already holds the credentials — they are in the stream path it
  # uses every second. Asking from here means the password never leaves this
  # host: the dashboard receives a version string, not a login.
  sudo -n mysql zm -N -B -e \
    'SELECT Path FROM Monitors WHERE Enabled = 1;' 2>/dev/null \
  | while IFS= read -r path; do
      case "$path" in *@*) ;; *) continue ;; esac
      creds=$(printf '%s' "$path" | sed -E 's|^[a-zA-Z]+://([^@]+)@.*|\1|')
      camaddr=$(printf '%s' "$path" | sed -E 's|^[a-zA-Z]+://[^@]+@([^:/]+).*|\1|')
      [ -n "$camaddr" ] || continue
      info=$(curl -s --digest -u "$creds" --max-time 5 \
             "http://$camaddr/ISAPI/System/deviceInfo" 2>/dev/null)
      case "$info" in *"<firmwareVersion>"*) ;; *) continue ;; esac
      one() { printf '%s' "$info" | sed -n "s|.*<$1>\\([^<]*\\)</$1>.*|\\1|p" | head -1; }
      row "@camfw	$camaddr	$(one model)	$(one firmwareVersion)	$(one firmwareReleasedDate)"
    done
fi

echo "ok	1"
