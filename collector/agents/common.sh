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
