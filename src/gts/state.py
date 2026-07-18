"""Tracks the active identity (which cached token gts uses by default).

Stored at ~/.config/gts/state.json. This file never contains secrets — only a
pointer into the token cache.
"""

import json
import pathlib
from dataclasses import dataclass

from . import config


def _state_path() -> pathlib.Path:
    return config.config_dir() / "state.json"


@dataclass
class ActiveIdentity:
    kind: str  # "user" | "sp"
    key: str  # upn for users, client_id for SPs
    client_id: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "key": self.key, "client_id": self.client_id}


def get_active() -> ActiveIdentity | None:
    path = _state_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    active = data.get("active")
    if not active:
        return None
    return ActiveIdentity(
        kind=active["kind"], key=active["key"], client_id=active["client_id"]
    )


def set_active(identity: ActiveIdentity) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"active": identity.as_dict()}, indent=2))


def clear_active() -> None:
    path = _state_path()
    if path.exists():
        path.unlink()
