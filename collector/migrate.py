#!/usr/bin/env python3
"""Provision durable management state while the hub is stopped (run as root)."""
import argparse
import json
import os
from pathlib import Path
import pwd

from configuration import validate
from storage import write_json


def prepare(config_path, user, legacy=False, state_dir='/var/lib/health-zoo'):
    path = Path(config_path)
    cfg = json.loads(path.read_text())
    validate(cfg)
    account = pwd.getpwnam(user)
    state = Path(state_dir)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(state, account.pw_uid, account.pw_gid)
    os.chmod(state, 0o700)

    settings_path = Path(cfg.get('settings_file', str(state / 'settings.json')))
    settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    if not isinstance(settings, dict) or any(not isinstance(v, dict) for v in settings.values()):
        raise ValueError('settings sections must be objects; restore a valid backup before upgrading')
    # Old installations opted in through the former default. Preserve that
    # effective policy once; new installations always start with explicit off.
    if 'enabled' not in (settings.get('auto_security') or {}):
        settings.setdefault('auto_security', {})['enabled'] = bool(legacy)
        write_json(settings_path, settings)
        os.chown(settings_path, account.pw_uid, account.pw_gid)

    if not any(cfg.get('action_token' + suffix) for suffix in ('', '_file', '_credential')):
        key_path = state / 'action-token'
        if not key_path.exists():
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(os.urandom(32).hex() + '\n')
                stream.flush()
                os.fsync(stream.fileno())
        if not key_path.read_text().strip():
            raise ValueError('existing management key is empty')
        os.chown(key_path, account.pw_uid, account.pw_gid)
        os.chmod(key_path, 0o600)
        cfg['action_token_file'] = str(key_path)
        write_json(path, cfg)
        # Atomic writes use mode 0600. A previously root-owned, world-readable
        # config must remain readable by the account that actually runs the hub.
        os.chown(path, account.pw_uid, account.pw_gid)
    return cfg


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config')
    parser.add_argument('user')
    parser.add_argument('--legacy-policy', action='store_true')
    args = parser.parse_args()
    prepare(args.config, args.user, args.legacy_policy)
    print('health-zoo: management state ready (key value is never printed)')
