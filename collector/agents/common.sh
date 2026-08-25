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
#
# One window, three views: what the processor did, what the disks did, and
# which process did it. Measuring them together is the point — a machine that
# is 90% busy and a disk that answers in 40 ms are the same event seen from
# two sides, and sampled a minute apart they cannot be told apart from two
# unrelated ones.
common_cpu() {
  [ -r /proc/stat ] || return 0
  procs1=$(_cpu_procs)
  disk1=$(_disk_counters)
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
  disk2=$(_disk_counters)
  procs2=$(_cpu_procs)
  total=$(( busy2 - busy1 + idle2 - idle1 + wait2 - wait1 + steal2 - steal1 ))
  [ "$total" -gt 0 ] 2>/dev/null || return 0
  busy=$(( (busy2 - busy1) * 100 / total ))
  iowait=$(( (wait2 - wait1) * 100 / total ))
  emit cpu_load_pct "$busy"
  emit cpu_iowait_pct "$iowait"
  emit cpu_steal_pct "$(( (steal2 - steal1) * 100 / total ))"

  # Ticks are counted per core, so the wall clock the window took is the total
  # divided by however many cores reported, ten milliseconds each.
  cores=$(grep -c '^cpu[0-9]' /proc/stat)
  [ "${cores:-0}" -gt 0 ] || cores=1
  window_ms=$(( total * 10 / cores ))
  [ "$window_ms" -gt 0 ] || window_ms=1
  _disk_io "$disk1" "$disk2" "$window_ms"

  stall=$(_io_pressure some)
  [ -n "$stall" ] && emit io_stall_pct "$stall"
  full=$(_io_pressure full)
  [ -n "$full" ] && emit io_stall_full_pct "$full"

  # Naming names costs a sort and a few reads, and is only interesting once
  # the processor is actually loaded.
  [ "$busy" -ge 50 ] && _cpu_blame "$procs1" "$procs2" "$total"
  # The other half of the question. A process stuck on the disk uses no
  # processor time at all, so it can never appear in the list above — and it
  # is exactly the one worth naming when the machine feels slow but nothing
  # seems to be running.
  stalled=${stall:-0}; stalled=${stalled%%.*}
  if [ "$iowait" -ge 5 ] || [ "${stalled:-0}" -ge 10 ]; then
    _io_stuck "$procs2"
  fi
  return 0
}

# One line per process: pid, processor ticks it has used, its state, its short
# name. ps would be the obvious tool and is the wrong one — the percentage it
# prints is an average over the whole life of the process, so a daemon that
# idled for a week and is pegged right now shows a fraction of a percent.
_cpu_procs() {
  awk '
    {
      # comm sits in parentheses and may contain them itself ("(sd-pam)"),
      # so the numeric fields are counted from the LAST ")" in the line.
      shut = 0
      while ((step = index(substr($0, shut + 1), ")")) > 0) shut += step
      open = index($0, "(")
      if (shut <= open) next
      split(FILENAME, path, "/")
      if (split(substr($0, shut + 1), f) >= 13)
        print path[3] "\t" f[12] + f[13] "\t" f[1] "\t" \
              substr($0, open + 1, shut - open - 1)
    }
  ' /proc/[0-9]*/stat 2>/dev/null
}

# Whole disks only: partitions repeat their parent's work, and loop, ram and
# device-mapper entries are not hardware anybody can buy a better one of.
_disk_counters() {
  [ -r /proc/diskstats ] || return 0
  whole=""
  for path in /sys/block/*; do
    name=${path##*/}
    case $name in loop*|ram*|zram*|dm-*|md*|sr*) continue ;; esac
    whole="$whole $name"
  done
  [ -n "$whole" ] || return 0
  # diskstats: 4 reads, 7 ms reading, 8 writes, 11 ms writing, 13 ms with the
  # queue non-empty.
  awk -v keep="$whole" '
    BEGIN { n = split(keep, k, " "); for (i = 1; i <= n; i++) want[k[i]] = 1 }
    want[$3] { print $3 "\t" $4 + $8 "\t" $7 + $11 "\t" $13 }
  ' /proc/diskstats
}

# How the disk behaved: how many operations it finished, how long each took,
# and how much of the time it had anything to do at all. The three together
# separate "our load is heavy" from "this storage is slow", which is the
# difference between a problem to fix and a bill to pay.
#
# Measured from the previous poll rather than over the third of a second the
# processor is measured over: a quiet-looking disk finishes nothing at all in
# a third of a second, and "no operations" is not an answer to "how fast does
# it answer". The short window is kept as a fallback for the first poll after
# a reboot, when there is nothing to compare against yet.
_disk_io() {
  cache=${TMPDIR:-/tmp}/health-zoo-diskstats
  # Uptime rather than the clock: it cannot jump, and it resets on a reboot,
  # which is exactly when the previous counters stop being comparable.
  now=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
  before=$1
  window_ms=$3
  if [ -r "$cache" ]; then
    was=$(head -1 "$cache")
    gap=$(( now - was ))
    if [ "$gap" -ge 20 ] && [ "$gap" -le 3600 ]; then
      before=$(tail -n +2 "$cache")
      window_ms=$(( gap * 1000 ))
    fi
  fi
  { echo "$now"; printf '%s\n' "$2"; } > "$cache" 2>/dev/null
  printf '%s\n@\n%s\n' "$before" "$2" | awk -F'\t' -v ms="$window_ms" '
    $1 == "@" { second = 1; next }
    !second   { ios[$1] = $2; spent[$1] = $3; busy[$1] = $4; next }
    {
      d_ios = $2 - ios[$1]; d_spent = $3 - spent[$1]; d_busy = $4 - busy[$1]
      if (d_ios <= 0 && d_busy <= 0) next
      # Tenths, not whole units: an SSD answering in 0.3 ms and one answering
      # in 0.9 ms are both "0 ms" as integers, and the difference between them
      # is the whole reason for measuring.
      printf "%s\t%.1f\t%.1f\t%.1f\t%d\n", $1, d_ios * 1000 / ms,
             (d_ios > 0 ? d_spent / d_ios : 0), d_busy * 100 / ms, d_ios
    }
  ' | while IFS='	' read -r dev iops await util ops; do
    # Fifty milliseconds is a stalled SSD and an ordinary afternoon for a
    # spinning disk, so the reader of these numbers is told which it is.
    rot=$(cat "/sys/block/$dev/queue/rotational" 2>/dev/null || echo 0)
    row "@diskio	$dev	$iops	$await	$util	$rot	$ops	$window_ms"
  done
}

# Pressure stall information, when the kernel keeps it: the share of the last
# ten seconds in which at least one task ("some") or every runnable task
# ("full") was waiting for storage. iowait answers the same question only when
# the processor has nothing else to do — on a busy box one stalled task hides
# behind the work the other cores are doing, and this number does not let it.
_io_pressure() {
  [ -r /proc/pressure/io ] || return 0
  awk -v kind="$1" '$1 == kind { sub("avg10=", "", $2); print $2; exit }' \
      /proc/pressure/io
}

# Processes in uninterruptible sleep: the ones the kernel will not even let be
# killed, because they are inside a call that has not come back. wchan names
# the call, which is usually the whole diagnosis.
_io_stuck() {
  printf '%s\n' "$1" | awk -F'\t' '$3 == "D" { print $1 "\t" $4 }' |
  head -5 | while IFS='	' read -r pid name; do
    wchan=$(tr -d '\000' < "/proc/$pid/wchan" 2>/dev/null | cut -c1-40)
    cmd=$(tr '\000\n\t\r' '    ' < "/proc/$pid/cmdline" 2>/dev/null |
          cut -c1-120 | sed 's/[[:space:]]*$//')
    row "@stuck	$pid	$name	${cmd:-[$name]}	${wchan:-?}"
  done
}

# The two snapshots, subtracted. Percentages are of the whole machine and of
# the same window the total above was measured over, so the parts named here
# add up under it rather than being a second, differently-scaled opinion.
_cpu_blame() {
  printf '%s\n@\n%s\n' "$1" "$2" | awk -F'\t' -v total="$3" '
    $1 == "@" { second = 1; next }
    !second   { was[$1] = $2; next }
    {
      # A process born inside the window spent everything it has inside it.
      used = ($1 in was) ? $2 - was[$1] : $2
      if (used > 0) printf "%s\t%d\t%s\n", $1, used * 100 / total, $4
    }
  ' | sort -t'	' -k2,2rn | head -4 | while IFS='	' read -r pid pct name; do
    [ "${pct:-0}" -ge 1 ] || continue
    # What it was started with answers "why", where the name only says "who".
    # Arguments are separated by NUL and may themselves contain newlines and
    # tabs — a python one-liner does — and a row that spans two lines is not a
    # row any more. Kernel threads have no command line at all; they keep
    # their bracketed name.
    cmd=$(tr '\000\n\t\r' '    ' < "/proc/$pid/cmdline" 2>/dev/null |
          cut -c1-160 | sed 's/[[:space:]]*$//')
    row "@proc	$pid	$pct	$name	${cmd:-[$name]}"
  done
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
        # The key names the setting, not the destination. "tgProxy" told the
        # reader nothing except that somebody had once typed it — where that
        # traffic actually goes is the whole question this view exists for.
        # The code that reads the key usually builds the request a few lines
        # later, and that URL answers both "where" and "what for": one service
        # here proxies its sending through another and polls for replies
        # itself, which looked like a duplicate until the endpoint said
        # otherwise.
        hint=$(grep -rh -A 8 "[\"']${keyname}[\"']" "$(dirname "$conf")"/*.py 2>/dev/null |
               grep -oE 'https://[a-zA-Z0-9._-]+(/[a-zA-Z0-9{}._-]*)*' | head -1)
        goes=$(printf '%s' "$hint" | sed 's|https://||; s|/.*||')
        what=$(printf '%s' "$hint" | sed 's|.*/||; s|?.*||')
        if [ -z "$goes" ]; then
          case $keyname in
            *[tT][gG]*|*[tT]elegram*) goes="api.telegram.org" ;;
          esac
        fi
        row "@outbound	$who	$goes	$target	$conf: $keyname${what:+ → $what}"
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
  #
  # Cached hard, and this is not an optimisation. Walking /opt costs real disk
  # on a host whose disk is the thing that is already sick — and a poll every
  # three minutes means the next walk starts before the last one finished,
  # until the box stops answering ssh altogether. That is not a theory: it is
  # what happened to the VPS an hour after this was first deployed. The answer
  # changes when somebody edits a service, which is not a three-minute event.
  cache=${TMPDIR:-/tmp}/health-zoo-outbound.cache
  stale=1
  if [ -f "$cache" ]; then
    then_ts=$(stat -c %Y "$cache" 2>/dev/null || stat -f %m "$cache" 2>/dev/null || echo 0)
    now_ts=$(date +%s 2>/dev/null || echo 0)
    [ "$(( now_ts - then_ts ))" -lt 86400 ] && stale=0
  fi
  # A machine already at its limit gets nothing extra: it keeps the last answer
  # rather than being asked to walk its disk again.
  if [ "$stale" = 1 ] && [ -r /proc/loadavg ]; then
    case $(cut -d. -f1 /proc/loadavg) in
      ''|*[!0-9]*) : ;;
      *) [ "$(cut -d. -f1 /proc/loadavg)" -ge 4 ] && stale=0 ;;
    esac
  fi
  if [ "$stale" = 1 ]; then
    scan_outbound > "$cache.new" 2>/dev/null && mv "$cache.new" "$cache" 2>/dev/null
  fi
  cat "$cache" 2>/dev/null
  return 0
}

scan_outbound() {
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
}
