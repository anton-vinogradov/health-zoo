#!/usr/bin/env bash
# Deploy a committed release with backup and automatic rollback on failure.
# Usage: ./deploy.sh user@dashboard (or HEALTH_ZOO_HOST=user@dashboard).
set -euo pipefail
HOST="${1:-${HEALTH_ZOO_HOST:-}}"
DIR="${HEALTH_ZOO_DIR:-/opt/health-zoo}"
CONFIG="${HEALTH_ZOO_CONFIG:-/etc/health-zoo.json}"
PORT="${HEALTH_ZOO_PORT:-8816}"
PYTHON="${HEALTH_ZOO_PYTHON:-python3}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ ! "$HOST" =~ ^[a-zA-Z0-9_@.:-]+$ || "$HOST" == -* ]]; then
  echo 'Set HEALTH_ZOO_HOST=user@host or pass the host as the first argument' >&2; exit 2
fi
if [[ ! "$DIR" =~ ^/[a-zA-Z0-9_./-]+$ || "$DIR" == / || "$DIR" == */../* ||
      ! "$CONFIG" =~ ^/[a-zA-Z0-9_./-]+$ || ! "$PORT" =~ ^[0-9]+$ ]]; then
  echo 'Invalid deployment path or port' >&2; exit 2
fi
if [ -n "$(git status --porcelain)" ]; then
  echo 'Commit all changes before deploying; only git archive HEAD is uploaded' >&2; exit 2
fi
shellcheck --shell=sh collector/agents/*.sh
shellcheck --shell=bash install.sh sync-config.sh deploy.sh tools/deploy-remote.sh
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m pytest tests/ -q -p no:cacheprovider
node --test tests/test_ui.js
for file in ui/*.js; do node --check "$file"; done
commit=$(git rev-parse HEAD)
stage=$(ssh -o BatchMode=yes "$HOST" 'mktemp -d /tmp/health-zoo.XXXXXXXX')
[[ "$stage" =~ ^/tmp/health-zoo\.[a-zA-Z0-9]+$ ]]
# All remote shell arguments are restricted above; file contents travel on stdin.
# shellcheck disable=SC2029
trap 'ssh -o BatchMode=yes "$HOST" "rm -rf -- $stage"' EXIT
# shellcheck disable=SC2029
git archive HEAD | ssh -o BatchMode=yes "$HOST" "tar xf - -C '$stage'"
# shellcheck disable=SC2029
printf '%s\n' "$commit" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | ssh -o BatchMode=yes "$HOST" "cat > '$stage/VERSION'"
# shellcheck disable=SC2029
ssh -o BatchMode=yes "$HOST" "sudo -n bash '$stage/tools/deploy-remote.sh' '$stage' '$DIR' '$CONFIG' '$PORT'"
