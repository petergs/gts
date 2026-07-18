"""The storage backend contract: a dumb key/value store for one opaque secret string."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class StorageBackend(Protocol):
    """Stores and retrieves a single opaque string (the serialized token cache).

    Backends know nothing about the cache schema. This keeps new backends
    (1Password, a plain file, etc.) trivial to add.
    """

    def get(self) -> str | None:
        """Return the stored blob, or None if nothing is stored."""
        ...

    def set(self, value: str) -> None:
        """Store (overwrite) the blob."""
        ...

    def delete(self) -> None:
        """Remove the blob. A no-op if nothing is stored."""
        ...
