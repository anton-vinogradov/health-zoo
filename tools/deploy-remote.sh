#!/usr/bin/env bash
# Called by deploy.sh after uploading a committed release. Never call from CI.
set -euo pipefail
stage=$1
dir=$2
config=$3
port=$4
service=health-zoo
backup="/var/backups/health-zoo/$(date -u +%Y%m%dT%H%M%SZ)-$(head -n1 "$stage/VERSION")"
user=$(systemctl show "$service" -p User --value)
user=${user:-root}
test -d "$dir"
test -f "$config"
test "$(systemctl show "$service" -p WorkingDirectory --value)" = "$dir"
HEALTH_ZOO_CONFIG="$config" python3 -B "$stage/collector/hub.py" --check-config
curl -fsS --max-time 10 "http://127.0.0.1:$port/api/job" | python3 -c '
import json, sys
j = json.load(sys.stdin)
if j.get("state") not in ("idle", "done"):
    sys.exit("A management job is active; retry deployment after it finishes")
'
install -d -m 700 "$backup"
cp -a "$dir" "$backup/code"
cp -a "$config" "$backup/config.json"
settings=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("settings_file", "/var/lib/health-zoo/settings.json"))' "$config")
dropin=/etc/systemd/system/health-zoo.service.d/20-durable-state.conf
if [ -f "$dropin" ]; then cp -a "$dropin" "$backup/dropin.conf"; fi

# The old process must no longer be able to write a stale settings snapshot.
systemctl stop "$service"
changed=0
rollback() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    echo "Deployment failed; restoring $backup" >&2
    systemctl stop "$service" || true
    if [ "$changed" = 1 ]; then
      mv "$dir" "$backup/failed-code"
      mv "$backup/code" "$dir"
      mv -f "$backup/config.json" "$config"
      if [ -d "$backup/state" ]; then
        mv /var/lib/health-zoo "$backup/failed-state"
        mv "$backup/state" /var/lib/health-zoo
      fi
      if [ -f "$backup/settings.json" ]; then mv -f "$backup/settings.json" "$settings"; fi
      if [ -f "$backup/dropin.conf" ]; then mv -f "$backup/dropin.conf" "$dropin";
      else rm -f "$dropin"; fi
      systemctl daemon-reload
    fi
    systemctl start "$service" || true
  fi
  exit "$result"
}
trap rollback EXIT
if [ -d /var/lib/health-zoo ]; then cp -a /var/lib/health-zoo "$backup/state"; fi
if [ -f "$settings" ]; then cp -a "$settings" "$backup/settings.json"; fi
changed=1
# Overlay tracked release files. Private local config/key files stay in place.
cp -a "$stage/collector" "$stage/ui" "$stage/tools" "$dir/"
cp "$stage/index.html" "$stage/style.css" "$stage/VERSION" "$stage/install.sh" \
   "$stage/deploy.sh" "$stage/sync-config.sh" "$stage/README.md" "$stage/README.ru.md" "$dir/"
chown -R "$user": "$dir/collector" "$dir/ui" "$dir/tools"
python3 -B "$dir/collector/migrate.py" "$config" "$user" --legacy-policy
runuser -u "$user" -- env HEALTH_ZOO_CONFIG="$config" python3 -B "$dir/collector/hub.py" --check-config
install -d -m 755 "$(dirname "$dropin")"
printf '[Service]\nStateDirectory=health-zoo\nStateDirectoryMode=0700\n' > "$dropin"
systemctl daemon-reload
systemctl start "$service"
ready=0
for _attempt in $(seq 1 20); do
  if systemctl is-active --quiet "$service" && curl -fsS --max-time 3 "http://127.0.0.1:$port/api/state" | python3 -c '
import json, sys
s = json.load(sys.stdin)
assert s.get("actions_enabled") and not s.get("storage_errors")
assert s.get("version", {}).get("commit") == sys.argv[1]
' "$(head -n1 "$stage/VERSION")"; then ready=1; break; fi
  sleep 1
done
test "$ready" = 1
echo "Deployed $(head -n1 "$stage/VERSION"); rollback backup: $backup"
