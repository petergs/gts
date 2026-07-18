"""Minimal Microsoft Graph REST client: auth header from the cache, OData
pagination, and 429/Retry-After handling."""

import threading
import time

import requests

from . import auth
from . import constants as c
from .cache import TokenCache
from .state import ActiveIdentity, get_active

_MAX_RETRIES = 5


class GraphError(Exception):
    """Raised on a non-recoverable Graph API error."""


def _is_expired(expires_on: int, skew: int = 60) -> bool:
    return expires_on != 0 and time.time() >= (expires_on - skew)


def get_active_access_token(cache: TokenCache, active: ActiveIdentity) -> str:
    """Return a valid access token for the active identity, refreshing user tokens
    silently when possible. SP tokens cannot be refreshed (no refresh token)."""
    if active.kind == "user":
        token = cache.get_user_token(active.key, active.client_id)
        if token is None:
            raise GraphError(
                f"No token for user {active.key} / client {active.client_id}. "
                "Run `gts login` first."
            )
        if _is_expired(token.expires_on) and token.refresh_token:
            user = cache.get_user(active.key) or {}
            tenant = user.get("tenant_id") or c.DEFAULT_TENANT
            resp = auth.AuthClient(tenant).refresh_user_token(
                token.refresh_token, active.client_id
            )
            auth.persist_user_token(cache, resp, active.client_id)
            return resp.access_token
        return token.access_token

    sp = cache.get_sp_token(active.client_id)
    if sp is None:
        raise GraphError(
            f"No token for service principal {active.client_id}. "
            "Run `gts login --flow client-credentials` first."
        )
    if _is_expired(sp.expires_on):
        raise GraphError(
            "Service principal token expired. Re-run "
            "`gts login --flow client-credentials`."
        )
    return sp.access_token


class GraphClient:
    """Thin GET-oriented Graph client. Use `from_active` for the usual path."""

    def __init__(self, access_token: str):
        self.access_token = access_token
        # A requests.Session isn't guaranteed thread-safe, and get_all() is called
        # concurrently for the per-item fan-out in operations.py, so give each thread its
        # own lazily-built session.
        self._local = threading.local()

    @property
    def session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update(
                {"Authorization": f"Bearer {self.access_token}", "Accept": "application/json"}
            )
            self._local.session = s
        return s

    @classmethod
    def from_active(cls, cache: TokenCache | None = None) -> "GraphClient":
        cache = cache or TokenCache()
        active = get_active()
        if active is None:
            raise GraphError("No active identity. Run `gts login` or `gts switch`.")
        return cls(get_active_access_token(cache, active))

    def _request(self, url: str) -> dict:
        for attempt in range(_MAX_RETRIES):
            resp = self.session.get(url, timeout=60)
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                raise GraphError(f"{resp.status_code} {url}: {resp.text[:300]}")
            return resp.json()
        raise GraphError(f"Throttled after {_MAX_RETRIES} retries: {url}")

    def _abs_url(self, path: str, beta: bool) -> str:
        if path.startswith("http"):
            return path
        base = c.MS_GRAPH_BETA_URL if beta else c.MS_GRAPH_V1_URL
        return f"{base}/{path.lstrip('/')}"

    def get(self, path: str, beta: bool = False) -> dict:
        """Single GET returning the raw JSON body."""
        return self._request(self._abs_url(path, beta))

    def get_all(self, path: str, beta: bool = False) -> list[dict]:
        """GET following @odata.nextLink, returning the concatenated `value` array."""
        url = self._abs_url(path, beta)
        results: list[dict] = []
        while url:
            body = self._request(url)
            results.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        return results
