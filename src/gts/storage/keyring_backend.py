"""Keyring-backed storage (macOS Keychain, gnome-keyring, and any other backend
the `keyring` library supports)."""

import keyring

SERVICE_NAME = "graph-token-store"
CACHE_USERNAME = "token-cache"


class KeyringBackend:
    """Stores the token cache blob as a single keyring password entry."""

    def __init__(self, service: str = SERVICE_NAME, username: str = CACHE_USERNAME):
        self.service = service
        self.username = username

    def get(self) -> str | None:
        return keyring.get_password(self.service, self.username)

    def set(self, value: str) -> None:
        keyring.set_password(self.service, self.username, value)

    def delete(self) -> None:
        try:
            keyring.delete_password(self.service, self.username)
        except keyring.errors.PasswordDeleteError:
            # Nothing stored; treat as a no-op.
            pass
