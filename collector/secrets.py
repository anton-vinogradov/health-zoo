"""Secret loading for health-zoo.

A password in the config file is a password in every backup, every `cat`, and
every screen share. Three sources are supported, in order of preference:

1. `<field>_credential` — a systemd encrypted credential. The ciphertext on
   disk is bound to this machine (TPM where present), systemd decrypts it at
   service start and drops it in a tmpfs directory readable only by the
   service. Nothing readable ever sits on disk.
2. `<field>_file` — a path to a file, for setups without systemd credentials.
3. `<field>` — the plain value, kept working so existing configs do not break.

Nothing here logs a secret, and callers receive the value only as a return.
"""

from __future__ import annotations

import os
from pathlib import Path


def load(config: dict, field: str) -> str:
    """Resolve one secret from a config section."""
    name = config.get(f"{field}_credential")
    if name:
        directory = os.environ.get("CREDENTIALS_DIRECTORY")
        if directory:
            path = Path(directory) / name
            try:
                return path.read_text(encoding="utf-8").strip()
            except OSError:
                return ""
        return ""

    path_value = config.get(f"{field}_file")
    if path_value:
        try:
            return Path(os.path.expanduser(path_value)).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    return config.get(field) or ""


def describe(config: dict, field: str) -> str:
    """Where a secret comes from — for diagnostics that must not leak it."""
    if config.get(f"{field}_credential"):
        return f"systemd credential «{config[f'{field}_credential']}»"
    if config.get(f"{field}_file"):
        return f"файл {config[f'{field}_file']}"
    if config.get(field):
        return "значение в конфиге (открытым текстом)"
    return "не задан"
