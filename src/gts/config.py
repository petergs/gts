"""Non-secret configuration for gts, stored at ~/.config/gts/settings.json.

Precedence for every setting: environment variable > settings.json > built-in default.
This keeps existing env-var workflows working while allowing a persistent default.

Secrets (client secrets, tokens) are NEVER stored here — only benign configuration
such as the storage backend and 1Password item coordinates.
"""

import json
import os
import pathlib

# Known settings: dotted key -> (env var, default, help text).
KNOWN_SETTINGS: dict[str, dict] = {
    "storage_backend": {
        "env": "GTS_STORAGE_BACKEND",
        "default": "keyring",
        "help": "Secret storage backend: keyring | onepassword",
    },
    "onepassword.account": {
        "env": "OP_ACCOUNT",
        "default": None,
        "help": "1Password account name/URL for desktop-app auth",
    },
    "onepassword.vault": {
        "env": "GTS_OP_VAULT",
        "default": "Private",
        "help": "1Password vault name or id",
    },
    "onepassword.item": {
        "env": "GTS_OP_ITEM",
        "default": "graph-token-store",
        "help": "1Password document title holding the cache",
    },
}


def config_dir() -> pathlib.Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (pathlib.Path.home() / ".config")
    return pathlib.Path(base) / "gts"


def settings_path() -> pathlib.Path:
    return config_dir() / "settings.json"


def load_settings() -> dict:
    path = settings_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def write_settings(data: dict) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _dig(data: dict, key: str):
    """Return the value at a dotted key, or None if absent."""
    cur = data
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def setting(key: str, default=None, env: str | None = None):
    """Resolve a setting: env var, then settings.json, then default."""
    if env:
        val = os.environ.get(env)
        if val:
            return val
    val = _dig(load_settings(), key)
    return default if val is None else val


def effective(key: str):
    """Resolve a KNOWN setting using its registered env var and default."""
    spec = KNOWN_SETTINGS[key]
    return setting(key, default=spec["default"], env=spec["env"])


def source(key: str) -> str:
    """Where the effective value comes from: 'env' | 'settings' | 'default'."""
    spec = KNOWN_SETTINGS[key]
    if spec["env"] and os.environ.get(spec["env"]):
        return "env"
    if _dig(load_settings(), key) is not None:
        return "settings"
    return "default"


def set_setting(key: str, value: str) -> None:
    """Set a dotted key in settings.json, creating intermediate dicts."""
    data = load_settings()
    cur = data
    parts = key.split(".")
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value
    write_settings(data)


def unset_setting(key: str) -> bool:
    """Remove a dotted key from settings.json. Returns True if it existed."""
    data = load_settings()
    cur = data
    parts = key.split(".")
    for part in parts[:-1]:
        cur = cur.get(part) if isinstance(cur, dict) else None
        if not isinstance(cur, dict):
            return False
    if parts[-1] in cur:
        del cur[parts[-1]]
        write_settings(data)
        return True
    return False
