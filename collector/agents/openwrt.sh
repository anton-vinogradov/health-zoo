#!/bin/sh
# health-zoo agent: OpenWrt (BusyBox ash, procd, opkg/apk).
#
# Routers are flash-constrained, so this touches only /proc and the package
# manager's own metadata — no temp files, no heavy tooling.

set -u
LC_ALL=C
export LC_ALL

emit() { printf '%s\t%s\n' "$1" "$2"; }
row() { printf '%s\n' "$*"; }

echo "kind	openwrt"
echo "hostname	$(uname -n 2>/dev/null)"

# ---------- release ----------
if [ -r /etc/os-release ]; then
  . /etc/os-release 2>/dev/null
  emit os_name "${PRETTY_NAME:-OpenWrt}"
  emit os_version "${VERSION_ID:-}"
fi
emit os_id openwrt
emit kernel "$(uname -r 2>/dev/null)"
emit arch "$(uname -m 2>/dev/null)"
[ -r /tmp/sysinfo/model ] && emit model "$(cat /tmp/sysinfo/model 2>/dev/null)"

# ---------- uptime / load / cpu ----------
[ -r /proc/uptime ] && emit uptime "$(cut -d' ' -f1 /proc/uptime)"
if [ -r /proc/loadavg ]; then
  set -- $(cat /proc/loadavg)
  emit load1 "$1"; emit load5 "$2"; emit load15 "$3"
fi
emit cpus "$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"

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

# ---------- flash ----------
# On a router the overlay filling up is what bricks config writes, so both the
# overlay and root are reported like ordinary disks.
df -P -k 2>/dev/null | awk '
  NR>1 && ($6 == "/" || $6 == "/overlay" || $6 == "/tmp") {
    print "@disk\t" $6 "\t" $1 "\t" $2*1024 "\t" $3*1024
  }'

# ---------- temperature ----------
for hw in /sys/class/hwmon/hwmon* /sys/class/thermal/thermal_zone*; do
  [ -d "$hw" ] || continue
  for f in "$hw"/temp "$hw"/temp1_input; do
    [ -r "$f" ] || continue
    t=$(cat "$f" 2>/dev/null)
    lbl=$(cat "$hw/type" 2>/dev/null || cat "$hw/name" 2>/dev/null)
    [ -n "$t" ] && [ "$t" -gt 1000 ] 2>/dev/null && row "@temp	${lbl:-soc}	$((t / 1000))"
  done
done

# ---------- pending package updates ----------
# opkg on 23.x and earlier, apk on 24.10+. Both are listed read-only: upgrading
# packages on OpenWrt in place is a known way to brick a router, so health-zoo
# only reports and never touches them.
if command -v apk >/dev/null 2>&1; then
  emit pkg_manager apk
  apk list --upgradable 2>/dev/null | awk '
    /</ { split($1, a, "-"); print "@update\t" a[1] "\t" "" "\t" $1 "\t0\tapk" }' | head -100
elif command -v opkg >/dev/null 2>&1; then
  emit pkg_manager opkg
  opkg list-upgradable 2>/dev/null | awk -F' - ' '
    { print "@update\t" $1 "\t" $2 "\t" $3 "\t0\topkg" }' | head -100
fi

# ---------- services ----------
# procd init scripts: enabled ones are symlinked into /etc/rc.d/S*.
for init in /etc/init.d/*; do
  [ -x "$init" ] || continue
  name=$(basename "$init")
  case "$name" in done|boot|umount|sysfixtime|sysctl|led|gpio_switch) continue ;; esac
  enabled=disabled
  for link in /etc/rc.d/S*"$name"; do
    [ -L "$link" ] && { enabled=enabled; break; }
  done
  state=stopped
  if "$init" status >/dev/null 2>&1; then
    state=running
  elif pgrep -f "/usr/sbin/$name" >/dev/null 2>&1 || pgrep -x "$name" >/dev/null 2>&1; then
    state=running
  fi
  [ "$enabled" = disabled ] && [ "$state" = stopped ] && continue
  row "@service	$name	$state	$enabled	0	0	$init	OpenWrt init script"
done

# ---------- listening TCP ports ----------
netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {
  split($4, a, ":"); port = a[length(a)]
  if (port ~ /^[0-9]+$/) print "@listen\t" port "\t"
}' | sort -u

# ---------- WAN / interface state ----------
# What actually matters on a router: which links are up and how much they moved.
if [ -r /proc/net/dev ]; then
  awk -F'[: ]+' 'NR>2 {
    name=$2; if (name == "lo") next
    rx=$3; tx=$11
    print "@iface\t" name "\tup\t" rx "\t" tx "\t"
  }' /proc/net/dev
fi

echo "ok	1"
