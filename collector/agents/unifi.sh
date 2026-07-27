#!/bin/sh
# health-zoo agent: UniFi access points (BusyBox, dropbear).
#
# An access point fails in ways a ping cannot see: a radio that stopped
# beaconing, a band nobody can associate to, an AP that quietly rebooted twice
# an hour. What matters here is per-radio state and client counts, not CPU.
#
# `mca-dump` is UniFi's own status dump and is present on every AP; where it is
# missing the agent falls back to /proc and iwconfig.

set -u
LC_ALL=C
export LC_ALL

emit() { printf '%s\t%s\n' "$1" "$2"; }
row() { printf '%s\n' "$*"; }

echo "kind	unifi"
echo "hostname	$(hostname 2>/dev/null)"
emit os_id unifi

# ---------- firmware and model ----------
if [ -r /etc/board.info ]; then
  # shellcheck disable=SC1091  # target-side file, not available to the linter
  . /etc/board.info 2>/dev/null
  emit model "${board_name:-${board_shortname:-UniFi}}"
fi
[ -r /usr/lib/version ] && emit os_name "UniFi $(cat /usr/lib/version 2>/dev/null)"
emit kernel "$(uname -r 2>/dev/null)"
emit arch "$(uname -m 2>/dev/null)"

# ---------- uptime / load / memory ----------
[ -r /proc/uptime ] && emit uptime "$(cut -d' ' -f1 /proc/uptime)"
if [ -r /proc/loadavg ]; then
  # shellcheck disable=SC2046  # word splitting is the point: three fields
  set -- $(cat /proc/loadavg)
  emit load1 "$1"; emit load5 "$2"; emit load15 "$3"
fi
emit cpus "$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
if [ -r /proc/meminfo ]; then
  awk '
    /^MemTotal:/     {print "mem_total\t"     $2*1024}
    /^MemAvailable:/ {print "mem_available\t" $2*1024}
    /^MemFree:/      {print "mem_free\t"      $2*1024}
  ' /proc/meminfo
fi

# ---------- radios and clients ----------
# mca-dump emits one JSON blob; parsing it with sed here beats requiring jq on
# a device with 16 MB of flash.
if command -v mca-dump >/dev/null 2>&1; then
  dump=$(mca-dump 2>/dev/null)
  if [ -n "$dump" ]; then
    # Controller adoption state: an unadopted AP still serves nothing useful.
    state=$(printf '%s' "$dump" | sed -n 's/.*"state"[ ]*:[ ]*\([0-9]*\).*/\1/p' | head -1)
    [ -n "$state" ] && emit unifi_state "$state"

    printf '%s' "$dump" \
    | tr '{' '\n' \
    | while IFS= read -r chunk; do
        case "$chunk" in
          *'"radio"'*|*'"name":"wifi'*)
            name=$(printf '%s' "$chunk" | sed -n 's/.*"name"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
            channel=$(printf '%s' "$chunk" | sed -n 's/.*"channel"[ ]*:[ ]*"\{0,1\}\([0-9]*\).*/\1/p')
            clients=$(printf '%s' "$chunk" | sed -n 's/.*"num_sta"[ ]*:[ ]*\([0-9]*\).*/\1/p')
            noise=$(printf '%s' "$chunk" | sed -n 's/.*"noisef\{0,1\}"[ ]*:[ ]*\(-\{0,1\}[0-9]*\).*/\1/p')
            util=$(printf '%s' "$chunk" | sed -n 's/.*"cu_total"[ ]*:[ ]*\([0-9]*\).*/\1/p')
            [ -n "$name" ] || continue
            row "@radio	$name	${channel:-}	${clients:-0}	${noise:-}	${util:-}"
            ;;
        esac
      done
  fi
fi

# Fallback: ask the wireless stack directly when mca-dump is unavailable.
if command -v iwconfig >/dev/null 2>&1; then
  for dev in $(iwconfig 2>/dev/null | awk '/IEEE 802.11/{print $1}'); do
    ssid=$(iwconfig "$dev" 2>/dev/null | sed -n 's/.*ESSID:"\([^"]*\)".*/\1/p')
    freq=$(iwconfig "$dev" 2>/dev/null | sed -n 's/.*Frequency:\([0-9.]*\).*/\1/p')
    stations=$(iw dev "$dev" station dump 2>/dev/null | grep -c '^Station')
    row "@radioiw	$dev	${ssid:-}	${freq:-}	${stations:-0}"
  done
fi

# ---------- listening ports ----------
netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {
  addr = $4
  port = addr; sub(/.*:/, "", port)
  host = addr; sub(/:[0-9]+$/, "", host)
  if (port !~ /^[0-9]+$/) next
  local = (host ~ /^(::ffff:)?127\./ || host == "::1") ? "local" : "any"
  print "@listen\t" port "\t\t" local
}' | sort -u

echo "ok	1"
