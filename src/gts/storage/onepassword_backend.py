"""1Password storage backend that shells out to the `op` CLI.

The `op` CLI caches authorization per terminal session — one biometric prompt per
terminal, then quiet reuse for a ~10-minute idle window — which suits a one-shot CLI
far better than a per-process authorization model would.

The token-cache blob is stored as a 1Password *document* item. Reads stream over the
document's stdout and writes stream over stdin, so the secret is never placed on the
command line (where `ps` could observe it).

Configuration (env var > settings.json > default):
  onepassword.account   OP_ACCOUNT     account shorthand/URL   (optional; op default)
  onepassword.vault     GTS_OP_VAULT   vault name or id        (default: "Private")
  onepassword.item      GTS_OP_ITEM    document title          (default: "graph-token-store")
"""

import subprocess

from .. import config

FILE_NAME = "gts-token-cache.json"
_MISSING_MARKERS = (
    "isn't a document",
    "isn't an item",
    "no item",
    "not found",
    "doesn't exist",
    "no document",
)


class OnePasswordError(Exception):
    """Raised when an `op` CLI invocation fails."""


class OnePasswordBackend:
    """Stores the token cache blob as a 1Password document via the `op` CLI."""

    def __init__(
        self,
        account: str | None = None,
        vault: str | None = None,
        item: str | None = None,
    ):
        self.account = account or config.effective("onepassword.account")
        self.vault = vault or config.effective("onepassword.vault")
        self.item = item or config.effective("onepassword.item")

    def _flags(self, include_vault: bool = True) -> list[str]:
        flags: list[str] = []
        if self.account:
            flags += ["--account", str(self.account)]
        if include_vault and self.vault:
            flags += ["--vault", str(self.vault)]
        return flags

    def _run(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["op", *args],
                input=stdin,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as e:
            raise OnePasswordError(
                "The `op` CLI was not found on PATH. Install the 1Password CLI and "
                "enable its desktop-app integration: "
                "https://developer.1password.com/docs/cli/get-started/"
            ) from e

    @staticmethod
    def _is_missing(stderr: str) -> bool:
        return any(marker in (stderr or "").lower() for marker in _MISSING_MARKERS)

    @staticmethod
    def _is_ambiguous(stderr: str) -> bool:
        err = (stderr or "").lower()
        return "more than one" in err or "isn't unique" in err or "multiple items" in err

    def _item_exists(self) -> bool:
        """Whether *any* item (of any type) has this title."""
        proc = self._run(["item", "get", self.item, "--format", "json", *self._flags()])
        return proc.returncode == 0

    def get(self) -> str | None:
        proc = self._run(["document", "get", self.item, *self._flags()])
        if proc.returncode == 0:
            return proc.stdout
        if self._is_ambiguous(proc.stderr):
            raise OnePasswordError(self._ambiguous_msg())
        if self._is_missing(proc.stderr):
            return None
        raise OnePasswordError(
            proc.stderr.strip() or f"`op document get` failed ({proc.returncode})."
        )

    def set(self, value: str) -> None:
        probe = self._run(["document", "get", self.item, *self._flags()])
        if probe.returncode == 0:
            proc = self._run(
                ["document", "edit", self.item, "-", *self._flags()], stdin=value
            )
        else:
            if self._is_ambiguous(probe.stderr):
                raise OnePasswordError(self._ambiguous_msg())
            if not self._is_missing(probe.stderr):
                raise OnePasswordError(probe.stderr.strip() or "`op document get` failed.")
            # The title resolves to no document. If a non-document item (e.g. a Secure
            # Note) already has this title, creating a document with the same title
            # would make the title ambiguous, so refuse with a clear message.
            if self._item_exists():
                raise OnePasswordError(
                    f"A 1Password item named '{self.item}' exists but isn't a document. "
                    "Delete it, or set a different item title with "
                    "`gts config set onepassword.item <name>`."
                )
            proc = self._run(
                [
                    "document", "create", "-",
                    "--title", self.item,
                    "--file-name", FILE_NAME,
                    *self._flags(),
                ],
                stdin=value,
            )
        if proc.returncode != 0:
            raise OnePasswordError(proc.stderr.strip() or "`op` write failed.")

    def delete(self) -> None:
        proc = self._run(["document", "delete", self.item, *self._flags()])
        if proc.returncode == 0 or self._is_missing(proc.stderr):
            return
        raise OnePasswordError(proc.stderr.strip() or "`op document delete` failed.")

    def _ambiguous_msg(self) -> str:
        return (
            f"Multiple 1Password items named '{self.item}' exist. Remove the "
            "duplicate or set a unique title with `gts config set onepassword.item "
            "<name>`."
        )
