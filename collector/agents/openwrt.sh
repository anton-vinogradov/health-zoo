#!/bin/sh
# health-zoo agent: OpenWrt (BusyBox ash, procd, opkg/apk).
#
# Routers are flash-constrained, so this touches only /proc and the package
# manager's own metadata — no temp files, no heavy tooling.

echo "kind	openwrt"
echo "hostname	$(uname -n 2>/dev/null)"

# ---------- release ----------
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091  # target-side file, not available to the linter
  . /etc/os-release 2>/dev/null
  emit os_name "${PRETTY_NAME:-OpenWrt}"
  emit os_version "${VERSION_ID:-}"
fi
emit os_id openwrt
emit kernel "$(uname -r 2>/dev/null)"
emit arch "$(uname -m 2>/dev/null)"
[ -r /tmp/sysinfo/model ] && emit model "$(cat /tmp/sysinfo/model 2>/dev/null)"

# ---------- uptime / load / cpu ----------
common_uptime_load
emit cpus "$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"

# ---------- memory ----------
common_memory

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
  # One-shot boot scripts sit at "stopped" by design; listing them as services
  # only invites false alarms.
  case "$name" in done|boot|umount|sysfixtime|sysctl|led|gpio_switch|\
                  urandom_seed|bootcount|packet_steering|ucitrack) continue ;; esac
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
  # What ships with OpenWrt and makes it a router, versus what somebody added.
  # There is no package metadata to ask here — opkg does not record which files
  # an init script came from in a form worth parsing on a 32 MB device — so the
  # base set is named. It only classifies; nothing is hidden by it.
  case "$name" in
    network|firewall|dnsmasq|odhcpd|dropbear|uhttpd|rpcd|ubus|log|system|\
    sysntpd|cron|led|dnsmasq6|urngd|ntpd|odhcp6c|wpad|hostapd|umdns|\
    dhcpd|dhcp6c|boot|sysctl|gpio_switch) scope=system ;;
    *) scope=user ;;
  esac
  row "@service	$name	$state	$enabled	0	0	$init	OpenWrt init script	$scope"
done

# ---------- listening ports ----------
common_cpu
common_links
common_peer
common_listeners

# ---------- WAN / interface state ----------
# What actually matters on a router: which links are up and how much they moved.
if [ -r /proc/net/dev ]; then
  awk -F'[: ]+' 'NR>2 {
    name=$2; if (name == "lo") next
    rx=$3; tx=$11
    print "@iface\t" name "\tup\t" rx "\t" tx "\t"
  }' /proc/net/dev
fi

# ---------- port forwards and the address they are published on ----------
# Whether anything behind this router is reachable from the internet is decided
# here and nowhere else: a forward counts only when the address it is published
# on is public. An uplink sitting behind the provider's own NAT forwards
# nothing to anybody, however many rules it carries.
if command -v uci >/dev/null 2>&1; then
  i=0
  while uci -q get "firewall.@redirect[$i]" >/dev/null 2>&1; do
    if [ "$(uci -q get "firewall.@redirect[$i].target")" = DNAT ]; then
      off=false
      [ "$(uci -q get "firewall.@redirect[$i].enabled")" = "0" ] && off=true
      # A rule with no destination address sends the traffic to the router
      # itself — the NTP hijack that keeps clients on the right clock. Naming
      # that "dst-nat" would send the check looking for a host called "".
      to_ip=$(uci -q get "firewall.@redirect[$i].dest_ip")
      how=dst-nat
      [ -z "$to_ip" ] && how=redirect
      row "@forward	$(uci -q get "firewall.@redirect[$i].src")	$how	$(uci -q get "firewall.@redirect[$i].src_dport")	$to_ip	$(uci -q get "firewall.@redirect[$i].dest_port")	$off	$(uci -q get "firewall.@redirect[$i].name")	0	$(uci -q get "firewall.@redirect[$i].proto")"
    fi
    i=$((i + 1))
  done
  # An input policy of ACCEPT on the wan zone means the router's own listeners
  # are offered to the internet too, not just the ports it forwards inward.
  z=0
  while uci -q get "firewall.@zone[$z]" >/dev/null 2>&1; do
    [ "$(uci -q get "firewall.@zone[$z].name")" = wan ] && \
      emit wan_input "$(uci -q get "firewall.@zone[$z].input")"
    z=$((z + 1))
  done
fi
wan=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$wan" ] && emit wan_addr "$wan"

echo "ok	1"
