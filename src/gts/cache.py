"""The token cache: owns the on-disk/keyring JSON schema and all reads/writes.

Schema (serialized as a single JSON blob through a StorageBackend):

    {
      "users": {
        "<upn>": {
          "tenant_id": ..., "tenant_domain": ..., "user_id": ...,
          "applications": {
            "<client_id>": {
              "access_token": ..., "refresh_token": ...,
              "app_display_name": ..., "scopes": [...],
              "expires_on": <int>, "foci": <bool>
            }
          }
        }
      },
      "service_principals": {
        "<client_id>": {
          "access_token": ..., "expires_on": <int>,
          "service_principal_display_name": ..., "tenant_id": ...
        }
      }
    }

Users are keyed by UPN; service principals are keyed by client id. SP entries carry
no refresh token and no secret (client-credentials issues no refresh token).
"""

import json
from dataclasses import dataclass, field

from .storage import StorageBackend, get_default_backend


@dataclass
class UserAppToken:
    """A user's token for one client application."""

    access_token: str
    refresh_token: str | None = None
    app_display_name: str | None = None
    scopes: list[str] = field(default_factory=list)
    expires_on: int = 0
    foci: bool = False
    acquired_at: int = 0  # epoch when this token record was obtained/stored

    def as_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "app_display_name": self.app_display_name,
            "scopes": self.scopes,
            "expires_on": self.expires_on,
            "foci": self.foci,
            "acquired_at": self.acquired_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "UserAppToken":
        return cls(
            access_token=d["access_token"],
            refresh_token=d.get("refresh_token"),
            app_display_name=d.get("app_display_name"),
            scopes=d.get("scopes", []),
            expires_on=d.get("expires_on", 0),
            foci=d.get("foci", False),
            acquired_at=d.get("acquired_at", 0),
        )


@dataclass
class ServicePrincipalToken:
    """A service principal's access token (client-credentials flow)."""

    access_token: str
    expires_on: int = 0
    service_principal_display_name: str | None = None
    tenant_id: str | None = None

    def as_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "expires_on": self.expires_on,
            "service_principal_display_name": self.service_principal_display_name,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ServicePrincipalToken":
        return cls(
            access_token=d["access_token"],
            expires_on=d.get("expires_on", 0),
            service_principal_display_name=d.get("service_principal_display_name"),
            tenant_id=d.get("tenant_id"),
        )


@dataclass
class Identity:
    """A summary row for `status`/`switch` listings."""

    kind: str  # "user" | "sp"
    key: str  # upn for users, client_id for SPs
    client_id: str
    display_name: str | None
    tenant_id: str | None
    scopes: list[str]
    expires_on: int


def _empty() -> dict:
    return {"users": {}, "service_principals": {}}


class TokenCache:
    """Reads and writes the token cache through a StorageBackend."""

    def __init__(self, backend: StorageBackend | None = None):
        self.backend: StorageBackend = backend or get_default_backend()
        self.content: dict = self._load()

    def _load(self) -> dict:
        raw = self.backend.get()
        if not raw:
            return _empty()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return _empty()
        data.setdefault("users", {})
        data.setdefault("service_principals", {})
        return data

    def save(self) -> None:
        self.backend.set(json.dumps(self.content))

    # -- user tokens --
    def upsert_user_token(
        self,
        upn: str,
        client_id: str,
        token: UserAppToken,
        *,
        tenant_id: str | None = None,
        tenant_domain: str | None = None,
        user_id: str | None = None,
    ) -> None:
        user = self.content["users"].setdefault(upn, {"applications": {}})
        user.setdefault("applications", {})
        if tenant_id is not None:
            user["tenant_id"] = tenant_id
        if tenant_domain is not None:
            user["tenant_domain"] = tenant_domain
        if user_id is not None:
            user["user_id"] = user_id
        user["applications"][client_id] = token.as_dict()

    def get_user_token(self, upn: str, client_id: str) -> UserAppToken | None:
        app = self.content["users"].get(upn, {}).get("applications", {}).get(client_id)
        return UserAppToken.from_dict(app) if app else None

    def get_user(self, upn: str) -> dict | None:
        return self.content["users"].get(upn)

    # -- service principal tokens --
    def upsert_sp_token(self, client_id: str, token: ServicePrincipalToken) -> None:
        self.content["service_principals"][client_id] = token.as_dict()

    def get_sp_token(self, client_id: str) -> ServicePrincipalToken | None:
        sp = self.content["service_principals"].get(client_id)
        return ServicePrincipalToken.from_dict(sp) if sp else None

    # -- listing / removal --
    def list_identities(self) -> list[Identity]:
        out: list[Identity] = []
        for upn, user in self.content["users"].items():
            for client_id, app in user.get("applications", {}).items():
                out.append(
                    Identity(
                        kind="user",
                        key=upn,
                        client_id=client_id,
                        display_name=app.get("app_display_name"),
                        tenant_id=user.get("tenant_id"),
                        scopes=app.get("scopes", []),
                        expires_on=app.get("expires_on", 0),
                    )
                )
        for client_id, sp in self.content["service_principals"].items():
            out.append(
                Identity(
                    kind="sp",
                    key=client_id,
                    client_id=client_id,
                    display_name=sp.get("service_principal_display_name"),
                    tenant_id=sp.get("tenant_id"),
                    scopes=[],
                    expires_on=sp.get("expires_on", 0),
                )
            )
        return out

    def list_user_apps(self) -> list[dict]:
        """One row per (user, client application) with token-presence flags."""
        rows: list[dict] = []
        for upn, user in self.content["users"].items():
            for client_id, app in user.get("applications", {}).items():
                rows.append(
                    {
                        "user": upn,
                        "app_display_name": app.get("app_display_name"),
                        "client_id": client_id,
                        "has_access_token": bool(app.get("access_token")),
                        "has_refresh_token": bool(app.get("refresh_token")),
                    }
                )
        return rows

    def list_service_principals(self) -> list[dict]:
        """One row per cached service principal with token-presence flag."""
        rows: list[dict] = []
        for client_id, sp in self.content["service_principals"].items():
            rows.append(
                {
                    "service_principal_display_name": sp.get(
                        "service_principal_display_name"
                    ),
                    "client_id": client_id,
                    "tenant_id": sp.get("tenant_id"),
                    "has_access_token": bool(sp.get("access_token")),
                }
            )
        return rows

    def find_user_by_client(self, client_id: str) -> tuple[str, UserAppToken] | None:
        """Return the first (upn, token) whose application matches client_id."""
        for upn, user in self.content["users"].items():
            app = user.get("applications", {}).get(client_id)
            if app:
                return upn, UserAppToken.from_dict(app)
        return None

    def remove_user_app(self, upn: str, client_id: str) -> bool:
        user = self.content["users"].get(upn)
        if not user:
            return False
        removed = user.get("applications", {}).pop(client_id, None) is not None
        if not user.get("applications"):
            self.content["users"].pop(upn, None)
        return removed

    def remove_sp(self, client_id: str) -> bool:
        return self.content["service_principals"].pop(client_id, None) is not None

    def clear(self) -> None:
        self.content = _empty()
        self.backend.delete()
