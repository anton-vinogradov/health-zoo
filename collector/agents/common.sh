# health-zoo: fragment shared by every POSIX-sh agent.
#
# Prepended to the OS-specific agent before it is streamed to the host, so the
# parts that are genuinely identical — helpers, disks, temperatures, listening
# ports — exist once. Anything a platform does differently stays in its own
# agent rather than growing conditionals here.
#
# Must stay POSIX sh: this runs on dash, BusyBox and ash.

set -u
LC_ALL=C
export LC_ALL

emit() { printf '%s\t%s\n' "$1" "$2"; }
row() { printf '%s\n' "$*"; }

# ---------- uptime / load ----------
common_uptime_load() {
  [ -r /proc/uptime ] && emit uptime "$(cut -d' ' -f1 /proc/uptime)"
  if [ -r /proc/loadavg ]; then
    # shellcheck disable=SC2046  # word splitting is the point: three fields
    set -- $(cat /proc/loadavg)
    emit load1 "$1"; emit load5 "$2"; emit load15 "$3"
  fi
}

# ---------- memory ----------
common_memory() {
  [ -r /proc/meminfo ] || return 0
  awk '
    /^MemTotal:/     {print "mem_total\t"     $2*1024}
    /^MemAvailable:/ {print "mem_available\t" $2*1024}
    /^MemFree:/      {print "mem_free\t"      $2*1024}
    /^SwapTotal:/    {print "swap_total\t"    $2*1024}
    /^SwapFree:/     {print "swap_free\t"     $2*1024}
  ' /proc/meminfo
}

# ---------- disks ----------
# Real filesystems only; overlay/tmpfs/loop noise is dropped. Callers pass an
# extra mount-point pattern when a platform needs one (DSM volumes, OpenWrt
# overlay).
common_disks() {
  extra="${1:-}"
  df -P -k 2>/dev/null | awk -v extra="$extra" '
    NR > 1 && $1 !~ /loop/ {
      keep = ($1 ~ /^\/dev\//)
      if (!keep && extra != "" && $6 ~ extra) keep = 1
      if (keep && $6 !~ /^\/tmp\//) print "@disk\t" $6 "\t" $1 "\t" $2*1024 "\t" $3*1024
    }'
}

# ---------- temperatures ----------
# hwmon and thermal_zone expose the same sensors under different names; one
# reading per label keeps a card from filling with duplicates.
common_temps() {
  {
    for hw in /sys/class/hwmon/hwmon*; do
      [ -d "$hw" ] || continue
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
}

# ---------- hardware running below what it can do ----------
# One row shape for every such finding — a subject and a phrase — so a new
# source is a few lines here and no new rule anywhere else. Only genuine caps
# are reported: a PCIe root port idling at 2.5 GT/s with nothing behind it is
# not one, and neither is the "powersave" governor, which on intel_pstate is
# the normal setting and still boosts to the top frequency.
common_capped() {
  freq=/sys/devices/system/cpu/cpu0/cpufreq
  if [ -r "$freq/scaling_max_freq" ] && [ -r "$freq/cpuinfo_max_freq" ]; then
    now=$(cat "$freq/scaling_max_freq"); top=$(cat "$freq/cpuinfo_max_freq")
    [ "$now" -lt "$top" ] 2>/dev/null && \
      row "@cap	процессор	потолок частоты $((now / 1000)) МГц из $((top / 1000))"
  fi
  # Storage and network devices only: those are the ones where a downtrained
  # link costs throughput somebody notices.
  for dev in /sys/bus/pci/devices/*; do
    class=$(cat "$dev/class" 2>/dev/null)
    case "$class" in 0x01*|0x02*) ;; *) continue ;; esac
    name=$(basename "$dev")
    cur=$(cut -d' ' -f1 "$dev/current_link_speed" 2>/dev/null)
    max=$(cut -d' ' -f1 "$dev/max_link_speed" 2>/dev/null)
    curw=$(cat "$dev/current_link_width" 2>/dev/null)
    maxw=$(cat "$dev/max_link_width" 2>/dev/null)
    [ -n "$cur" ] && [ -n "$max" ] && [ "${cur%%.*}" -lt "${max%%.*}" ] 2>/dev/null && \
      row "@cap	PCIe $name	$cur ГТ/с из $max"
    [ -n "$curw" ] && [ -n "$maxw" ] && [ "$curw" -lt "$maxw" ] 2>/dev/null && \
      row "@cap	PCIe $name	x$curw линий из x$maxw"
  done
  # SATA negotiates like ethernet does, and fails the same way: a drive that
  # supports 6 Gb/s and came up at 3 has a cable or a backplane problem.
  if command -v smartctl >/dev/null 2>&1; then
    sm="smartctl"
    if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      sm="sudo -n smartctl"
    fi
    for disk in /dev/sd?; do
      [ -b "$disk" ] || continue
      $sm -i "$disk" 2>/dev/null | awk -v d="$(basename "$disk")" '
        /SATA Version is:/ {
          top = ""; now = ""
          for (i = 1; i <= NF; i++) {
            if ($i ~ /Gb\/s/ && top == "") top = $(i-1)
            if ($i ~ /current:/) now = $(i+1)
          }
          if (top != "" && now != "" && now + 0 < top + 0)
            printf "@capped\tдиск %s\tSATA %s Гбит/с из %s\n", d, now, top
        }'
    done
  fi
}

# ---------- physical links ----------
# A gigabit port that negotiated 100 Mbit is almost always a cable, a connector
# or a socket that has started to fail — and nothing on the host complains,
# because the link is up and traffic flows. What the port *can* do is asked for
# separately: 100 Mbit is a fault on a gigabit socket and the normal state of a
# camera's. Only real hardware is reported; bridges and veth pairs have a
# "speed" too and it means nothing.
common_links() {
  eth_cmd=""
  if command -v ethtool >/dev/null 2>&1; then
    eth_cmd="ethtool"
    if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      eth_cmd="sudo -n ethtool"
    fi
  fi
  for path in /sys/class/net/*; do
    [ -e "$path/device" ] || continue
    name=$(basename "$path")
    carrier=$(cat "$path/carrier" 2>/dev/null || echo 0)
    if [ "$carrier" != "1" ]; then
      row "@link	$name	0	-	down	0	0	0	0	0	0	on"
      continue
    fi
    speed=$(cat "$path/speed" 2>/dev/null || echo 0)
    # Virtio and some USB adapters report -1 for "cannot say".
    [ "$speed" -gt 0 ] 2>/dev/null || speed=0
    capable=0; offered=0; partner=0; autoneg=on
    if [ -n "$eth_cmd" ]; then
      # Three lists, not one. What the port can do decides whether a slow link
      # is a fault at all; what it offers decides whether the limit was
      # configured here; what the other end offers decides whether to go looking
      # for a cable or for a setting on the far device.
      report=$($eth_cmd "$name" 2>/dev/null)
      autoneg=$(printf '%s\n' "$report" | awk -F': ' '/Auto-negotiation:/ {print $2; exit}')
      for section in "Supported link modes:|capable" \
                     "Advertised link modes:|offered" \
                     "Link partner advertised link modes:|partner"; do
        heading=${section%|*}
        value=$(printf '%s\n' "$report" | awk -v want="$heading" '
          index($0, want) {grab = 1; sub(/.*:/, "")}
          grab && /^[[:space:]]*[A-Z]/ && !index($0, want) {grab = 0}
          grab {
            n = split($0, parts, /[ \t]+/)
            for (i = 1; i <= n; i++)
              if (parts[i] ~ /^[0-9]+base/) {
                mode = parts[i]; sub(/base.*/, "", mode)
                if (mode + 0 > max) max = mode + 0
              }
          }
          END {print max + 0}')
        case ${section#*|} in
          capable) capable=$value ;;
          offered) offered=$value ;;
          partner) partner=$value ;;
        esac
      done
    fi
    row "@link	$name	$speed	$(cat "$path/duplex" 2>/dev/null || echo -)	up	$(cat "$path/statistics/rx_errors" 2>/dev/null || echo 0)	$(cat "$path/statistics/rx_crc_errors" 2>/dev/null || echo 0)	$(cat "$path/carrier_changes" 2>/dev/null || echo 0)	${capable:-0}	${offered:-0}	${partner:-0}	${autoneg:-on}"
  done
}

# ---------- processor: busy, waiting, stolen ----------
# Load average answers "how many want the CPU", which on a four-core box reads
# alarming at 4 and fine at 3.9. Busy time answers "how much is left", which is
# the question a threshold can be set on.
#
# Three numbers, not one, because they mean different things and the first
# version of this reported all of them as "busy": a VPS whose storage stalled
# for twenty minutes was announced as a processor pegged at 100%, when the
# processor was doing nothing at all — it was waiting on a disk that answered
# four operations a second. iowait is not work, and stolen time is not even
# ours: the hypervisor took it.
common_cpu() {
  [ -r /proc/stat ] || return 0
  # shellcheck disable=SC2046  # word splitting is the point: busy and idle
  # /proc/stat: user nice system idle iowait irq softirq steal
  # busy is the first three plus both interrupt columns; the rest are not work.
  set -- $(awk '/^cpu /{print $2+$3+$4+$7+$8, $5, $6, $9; exit}' /proc/stat)
  busy1=$1; idle1=$2; wait1=$3; steal1=$4
  # A third of a second is enough to divide two counters and costs every host
  # in the fleet two thirds of a second less per poll. BusyBox without fancy
  # sleep takes the whole second instead of failing.
  sleep 0.3 2>/dev/null || sleep 1
  # shellcheck disable=SC2046  # same two fields, a second later
  set -- $(awk '/^cpu /{print $2+$3+$4+$7+$8, $5, $6, $9; exit}' /proc/stat)
  busy2=$1; idle2=$2; wait2=$3; steal2=$4
  total=$(( busy2 - busy1 + idle2 - idle1 + wait2 - wait1 + steal2 - steal1 ))
  [ "$total" -gt 0 ] 2>/dev/null || return 0
  emit cpu_load_pct "$(( (busy2 - busy1) * 100 / total ))"
  emit cpu_iowait_pct "$(( (wait2 - wait1) * 100 / total ))"
  emit cpu_steal_pct "$(( (steal2 - steal1) * 100 / total ))"
}

# ---------- how we look from here ----------
# On a host out on the internet this is the site's own public address, observed
# rather than asked of a third party: the only witness to what our packets look
# like after the provider is done with them is somebody outside.
common_peer() {
  [ -n "${SSH_CLIENT:-}" ] && emit ssh_peer "${SSH_CLIENT%% *}"
  return 0
}

# ---------- listening ports ----------
# The bind address matters: a backend on 127.0.0.1 is reachable only through
# whatever proxies it, so a link to it would go nowhere. UDP is collected too —
# a VPN endpoint never shows up over TCP.
common_listeners() {
  if command -v ss >/dev/null 2>&1; then
    # Sockets owned by root name their process only to root. Without that the
    # card shows a bare number for exactly the ports worth naming — the VPN,
    # the torrent daemon, the DHCP client. Passwordless sudo is used where it
    # exists; where it does not, nothing changes.
    ss_cmd="ss"
    if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      ss_cmd="sudo -n ss"
    fi
    ss -ulnH 2>/dev/null | awk '{
      addr = $4; port = addr; sub(/.*:/, "", port)
      host = addr; sub(/:[0-9]+$/, "", host)
      if (port !~ /^[0-9]+$/ || port == 0) next
      local = (host ~ /^\[?(::ffff:)?127\./ || host == "[::1]" || host == "::1") ? "local" : "any"
      print port "\t" local
    }' | sort -u | while IFS='	' read -r p scope; do
        [ "$scope" = "local" ] && continue
        proc=$($ss_cmd -ulnpH "sport = :$p" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -1)
        row "@udp	$p	${proc:-}	$scope"
      done
    ss -tlnH 2>/dev/null | awk '{
      addr = $4; port = addr; sub(/.*:/, "", port)
      host = addr; sub(/:[0-9]+$/, "", host)
      if (port !~ /^[0-9]+$/) next
      local = (host ~ /^\[?(::ffff:)?127\./ || host == "[::1]" || host == "::1") ? "local" : "any"
      print port "\t" local
    }' | sort -u | while IFS='	' read -r p scope; do
        proc=$($ss_cmd -tlnpH "sport = :$p" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -1)
        row "@listen	$p	${proc:-}	$scope"
      done
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {
      addr = $4; port = addr; sub(/.*:/, "", port)
      host = addr; sub(/:[0-9]+$/, "", host)
      if (port !~ /^[0-9]+$/) next
      local = (host ~ /^(::ffff:)?127\./ || host == "::1") ? "local" : "any"
      print "@listen\t" port "\t\t" local
    }' | sort -u
  fi
}

# ---------- the way out ----------
# Which of this host's traffic leaves through a tunnel and which goes straight
# out is written down in four different places and nowhere together: a curl
# option in one config, a JSON key in another, a systemd environment variable,
# or nothing at all — meaning direct. Remembering it is hopeless, and the cost
# of forgetting is finding out that the thing you thought was proxied was not.
#
# Two kinds of row: "@exit" is a way out that lives on this host, "@goesout" is
# somebody using one. Both carry the file they were read from, because a claim
# about routing is worth exactly as much as the evidence behind it.
common_egress() {
  read_cmd="cat"
  if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    read_cmd="sudo -n cat"
  fi

  # wireproxy: one file says both what it offers locally and where the tunnel
  # comes out. Keys are never read — only the three lines that describe a path.
  for conf in /etc/wireproxy/*.conf; do
    [ -e "$conf" ] || continue
    body=$($read_cmd "$conf" 2>/dev/null) || continue
    bind=$(printf '%s\n' "$body" | awk -F'=' '/^[ \t]*BindAddress/ {gsub(/[ \t]/, "", $2); print $2; exit}')
    endpoint=$(printf '%s\n' "$body" | awk -F'=' '/^[ \t]*Endpoint/ {gsub(/[ \t]/, "", $2); print $2; exit}')
    inside=$(printf '%s\n' "$body" | awk -F'=' '/^[ \t]*Address/ {gsub(/[ \t]/, "", $2); print $2; exit}')
    # The obfuscation parameters are what tell AmneziaWG from plain WireGuard,
    # and that difference is the whole reason this tunnel exists here.
    kind=wireguard
    printf '%s\n' "$body" | grep -q '^[ \t]*Jc[ \t]*=' && kind=amneziawg
    state=$(systemctl is-active wireproxy.service 2>/dev/null || echo "?")
    [ -n "$bind" ] && row "@exit	socks5	$bind	wireproxy.service	$state	$kind	$endpoint	$inside"
  done

  # telegram.sh keeps its proxy inside the curl options, so the setting that
  # decides how every notification in the house leaves is one word in one line.
  for conf in /etc/telegram.sh.conf "${HOME:-/root}/.telegram.sh.conf"; do
    [ -r "$conf" ] || continue
    via=$(sed -n 's/.*-x[ ]*\([a-z0-9]*:\/\/[^" ]*\).*/\1/p' "$conf" | head -1)
    row "@outbound	telegram.sh	api.telegram.org	${via:-прямо}	$conf"
    # Everything that sends a message does it through this one script, so the
    # tree has to show them as its users rather than as separate paths out.
    for dir in /opt/*/; do
      name=${dir#/opt/}; name=${name%/}
      case "$name" in *.bak*|*backup*|telegram.sh-repo) continue ;; esac
      if grep -rqs "telegram.sh-repo\|/opt/telegram" "$dir" 2>/dev/null; then
        row "@outbound	$name	api.telegram.org	${via:-прямо}	через telegram.sh"
      fi
    done
    break
  done

  # A proxy named in a service's own configuration.
  for conf in /opt/*/collector/config.json /opt/*/config.json /etc/*.json; do
    [ -r "$conf" ] || continue
    case "$conf" in *.bak*|*backup*) continue ;; esac
    who=${conf#/opt/}; who=${who%%/*}
    case "$conf" in /etc/*) who=$(basename "$conf" .json) ;; esac
    grep -oiE '"[a-z_]*proxy[a-z_]*"[ ]*:[ ]*"[^"]+"' "$conf" 2>/dev/null |
      while IFS= read -r hit; do
        keyname=$(printf '%s\n' "$hit" | sed 's/^"//; s/".*//')
        target=$(printf '%s\n' "$hit" | sed 's/.*:[ ]*"//; s/"$//')
        row "@outbound	$who	$keyname	$target	$conf"
      done
  done

  # A proxy handed to a unit as an environment variable applies to everything
  # that unit runs, which makes it the easiest one to set and forget.
  for unit in /etc/systemd/system/*.service; do
    [ -r "$unit" ] || continue
    grep -oiE 'Environment=[A-Z_]*_?proxy=[^ "]+' "$unit" 2>/dev/null |
      while IFS= read -r hit; do
        row "@outbound	$(basename "$unit" .service)	$(printf '%s' "$hit" | sed 's/Environment=//; s/=.*//')	$(printf '%s' "$hit" | sed 's/.*=//')	$unit"
      done
  done

  # And what each service talks to when nothing proxies it. Read from its own
  # code: a hostname in the source is the only place this exists at all.
  for dir in /opt/*/; do
    name=${dir#/opt/}; name=${name%/}
    case "$name" in *.bak*|*backup*|telegram.sh-repo) continue ;; esac
    # Only the service's own code. A vendored library carries the hostnames of
    # its own documentation, and reporting that meshtastic-zoo "talks to
    # android.stackexchange.com" would be worse than saying nothing.
    find "$dir" -maxdepth 3 \( -name .git -o -name vendor -o -name node_modules \
            -o -name '.venv' -o -name 'site-packages' -o -name docs \) -prune -o \
        -type f \( -name '*.py' -o -name '*.sh' -o -name '*.js' \) \
        -exec grep -hoE 'https://[a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-z]{2,}' {} + 2>/dev/null |
      sed 's|https://||' |
      grep -vE '^(localhost|127\.|schemas\.|www\.w3\.org|api\.telegram\.org)' |
      sort -u | head -6 |
      while IFS= read -r target; do
        row "@outbound	$name	$target	прямо	$dir"
      done
  done
  return 0
}
