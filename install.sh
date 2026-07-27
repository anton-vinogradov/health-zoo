#!/usr/bin/env bash
# health-zoo — install/update as a systemd service on a Linux host.
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/anton-vinogradov/health-zoo/main/install.sh | sudo bash
#
# From a clone:
#   git clone <repo> health-zoo && cd health-zoo && sudo ./install.sh
#
# Re-running is the update path; it is idempotent and never overwrites
# /etc/health-zoo.json once it exists (that file holds your fleet).
set -euo pipefail

REPO_URL="${HZ_REPO:-https://github.com/anton-vinogradov/health-zoo.git}"
SVC=health-zoo
DIR="${HZ_DIR:-/opt/health-zoo}"
CONFIG=/etc/health-zoo.json
PORT="${HZ_PORT:-8816}"

# --- where the code lives: run from a clone, or fetch one ---
SELF="${BASH_SOURCE[0]:-}"
if [ -n "$SELF" ] && [ -f "$(dirname -- "$SELF")/collector/hub.py" ]; then
  SRC="$(cd "$(dirname -- "$SELF")" && pwd)"
else
  command -v git >/dev/null || { echo "✗ need git"; exit 1; }
  echo "→ code in $DIR"
  if [ -d "$DIR/.git" ]; then git -C "$DIR" pull --ff-only
  else git clone --depth 1 "$REPO_URL" "$DIR"; fi
  SRC="$DIR"
fi

# --- which user runs the service (it needs the ssh key to the fleet) ---
if [ "$(id -u)" -eq 0 ]; then RUN_USER="${SUDO_USER:-root}"; SUDO=""; else RUN_USER="$(id -un)"; SUDO="sudo"; fi
command -v python3 >/dev/null || { echo "✗ need python3"; exit 1; }

if [ "$SRC" != "$DIR" ]; then
  echo "→ installing to $DIR"
  $SUDO mkdir -p "$DIR"
  $SUDO cp -r "$SRC/collector" "$SRC/index.html" "$SRC/app.js" "$SRC/style.css" "$DIR/"
fi
$SUDO chown -R "$RUN_USER": "$DIR"

$SUDO mkdir -p /etc/health-zoo.d
$SUDO chmod 750 /etc/health-zoo.d

# --- config: created once from the example, then left alone ---
if [ ! -f "$CONFIG" ]; then
  echo "→ creating $CONFIG from the example — edit it, then restart the service"
  $SUDO cp "$DIR/collector/config.example.json" "$CONFIG"
  $SUDO chown "$RUN_USER": "$CONFIG"
  $SUDO chmod 600 "$CONFIG"
else
  echo "→ keeping existing $CONFIG"
fi

# --- ssh key for polling the fleet ---
KEY_PATH=$(python3 - "$CONFIG" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("ssh_key", "~/.ssh/id_health_zoo"))
except Exception:
    print("~/.ssh/id_health_zoo")
PY
)
KEY_REAL=$(eval echo "${KEY_PATH/#\~/$(getent passwd "$RUN_USER" | cut -d: -f6)}")
if [ ! -f "$KEY_REAL" ]; then
  echo "→ generating $KEY_REAL"
  $SUDO -u "$RUN_USER" ssh-keygen -t ed25519 -N "" -C "health-zoo@$(hostname)" -f "$KEY_REAL"
  echo
  echo "  Public key — install it on every host you want polled:"
  cat "$KEY_REAL.pub"
  echo
fi

# --- encrypted secrets, if any exist ---
# systemd refuses to start a service whose LoadCredentialEncrypted file is
# missing, so these lines are generated only for secrets that are actually
# there. Create one with:
#   printf %s 'secret' | sudo systemd-creds encrypt --name=telegram-token - \
#       /etc/health-zoo.d/telegram-token.cred
CREDS=""
for cred in telegram-token unifi-password; do
  if [ -f "/etc/health-zoo.d/$cred.cred" ]; then
    CREDS="${CREDS}LoadCredentialEncrypted=$cred:/etc/health-zoo.d/$cred.cred"$'\n'
  fi
done

# --- systemd unit ---
echo "→ systemd unit $SVC"
$SUDO tee "/etc/systemd/system/$SVC.service" >/dev/null <<UNIT
[Unit]
Description=health-zoo fleet dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
$CREDS
WorkingDirectory=$DIR
ExecStart=/usr/bin/python3 $DIR/collector/hub.py
Restart=always
RestartSec=5
# The dashboard reaches the fleet over ssh, so it needs the user's real \$HOME.
Environment=HOME=$(getent passwd "$RUN_USER" | cut -d: -f6)
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SVC" >/dev/null
$SUDO systemctl restart "$SVC"
sleep 1
if $SUDO systemctl is-active --quiet "$SVC"; then
  echo "✓ $SVC running"
else
  echo "✗ $SVC failed to start:"
  $SUDO journalctl -u "$SVC" -n 20 --no-pager
  exit 1
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "✓ dashboard: http://${IP:-localhost}:$PORT"
