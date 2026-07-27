#!/usr/bin/env bash
# The deployed host owns the configuration; this only moves copies around.
#
# Keeping an editable copy in the repository was a mistake worth naming: it
# drifted from /etc/health-zoo.json every time either side was touched, and the
# copy with the real addresses does not belong in a public repository anyway.
#
#   ./sync-config.sh pull            # fetch a redacted copy for inspection
#   ./sync-config.sh push <file>     # install a config, keeping secrets intact
set -euo pipefail

HOST="${HZ_HOST:-watchcats}"
USER="${HZ_USER:-randoom}"
REMOTE=/etc/health-zoo.json

case "${1:-}" in
  pull)
    # Secrets are referenced, not stored, but redact anything inline just in
    # case an older config still holds a value.
    # shellcheck disable=SC2029  # $REMOTE is a constant here; expanding it
    # locally is exactly what is wanted.
    ssh "$USER@$HOST" "sudo -n cat $REMOTE" | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
for section in ("telegram", "unifi_controller"):
    for field in ("token", "password"):
        if cfg.get(section, {}).get(field):
            cfg[section][field] = "<redacted>"
json.dump(cfg, sys.stdout, ensure_ascii=False, indent=2)
print()
'
    ;;
  push)
    file="${2:?usage: sync-config.sh push <file>}"
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$file"
    # Never overwrite live secret references with a redacted placeholder.
    if grep -q '<redacted>' "$file"; then
      echo "✗ файл содержит <redacted> — сначала подставьте настоящие значения" >&2
      exit 1
    fi
    scp -q "$file" "$USER@$HOST:/tmp/health-zoo.json.new"
    # shellcheck disable=SC2029  # same: the path is a constant, not user input.
    ssh "$USER@$HOST" "sudo -n cp $REMOTE $REMOTE.bak && \
        sudo -n cp /tmp/health-zoo.json.new $REMOTE && \
        sudo -n chmod 600 $REMOTE && rm -f /tmp/health-zoo.json.new && \
        sudo -n systemctl restart health-zoo"
    echo "✓ конфиг применён, предыдущий сохранён как $REMOTE.bak"
    ;;
  *)
    echo "usage: $0 pull | push <file>" >&2
    exit 2
    ;;
esac
