"""Pluggable secret-storage backends. Each backend stores a single opaque string
(the serialized token cache); the schema lives in gts.cache.

The active backend is chosen by the `storage_backend` setting (env var
GTS_STORAGE_BACKEND, or settings.json), one of:
  keyring       OS keyring (macOS Keychain / gnome-keyring)   [default]
  onepassword   1Password via the `op` CLI (session cached per terminal)
"""

from .base import StorageBackend
from .keyring_backend import KeyringBackend

# Accepted spellings for the 1Password (op CLI) backend.
_ONEPASSWORD_ALIASES = {"onepassword", "1password", "op", "op-cli", "1password-cli"}


def get_default_backend() -> StorageBackend:
    """Return the storage backend selected by configuration (default keyring)."""
    from .. import config

    choice = str(config.effective("storage_backend")).strip().lower()
    if choice in _ONEPASSWORD_ALIASES:
        from .onepassword_backend import OnePasswordBackend

        return OnePasswordBackend()
    return KeyringBackend()


__all__ = ["StorageBackend", "KeyringBackend", "get_default_backend"]
