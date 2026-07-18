"""OAuth2 flows against Entra, implemented with plain `requests` (no MSAL).

Supported flows:
  - device code
  - interactive browser via loopback redirect + PKCE
  - nativeclient (manual auth-code paste via the nativeclient redirect) — legacy fallback
  - client credentials
  - FOCI refresh (refresh-token grant across family-of-client-ids apps)
  - silent user-token refresh
"""

import base64
import hashlib
import secrets
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
import readline  # noqa: F401  # enables long strings for input

import requests

from . import constants as c
from . import jwt_utils
from .cache import ServicePrincipalToken, TokenCache, UserAppToken
from .state import ActiveIdentity

DEFAULT_USER_SCOPE = (
    "openid profile offline_access https://graph.microsoft.com/.default"
)
CLIENT_CREDENTIALS_SCOPE = "https://graph.microsoft.com/.default"
_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": c.USER_AGENT,
}
_TOKEN_URL = c.MSO_LOGIN_URL + "/{tenant}/oauth2/v2.0/token"


class AuthError(Exception):
    """Raised when a token endpoint returns an error."""


@dataclass
class TokenResponse:
    """Normalized subset of an OAuth2 token response."""

    access_token: str
    refresh_token: str | None
    id_token: str | None
    scope: str
    foci: bool
    raw: dict

    @classmethod
    def from_json(cls, data: dict) -> "TokenResponse":
        if "access_token" not in data:
            err = data.get("error_description") or data.get("error") or str(data)
            raise AuthError(err)
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            scope=data.get("scope", ""),
            foci=str(data.get("foci", "0")) == "1",
            raw=data,
        )


# -- Browser (loopback + PKCE) internals --
def _generate_pkce() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for a PKCE S256 exchange."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _extract_auth_code(query: dict, expected_state: str) -> str:
    """Validate an OAuth redirect query and return the authorization code."""
    if "error" in query:
        desc = (query.get("error_description") or query["error"])[0]
        raise AuthError(desc)
    state = (query.get("state") or [None])[0]
    if state != expected_state:
        raise AuthError("State mismatch in browser redirect (possible CSRF).")
    code = (query.get("code") or [None])[0]
    if not code:
        raise AuthError("No authorization code in the browser redirect.")
    return code


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server API)
        self.server.last_query = urllib.parse.parse_qs(  # type: ignore[attr-defined]
            urllib.parse.urlparse(self.path).query
        )
        body = (
            b"<html><body style='font-family:sans-serif'>"
            b"<h2>Sign-in complete.</h2>"
            b"<p>You can close this tab and return to the terminal.</p>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence default request logging
        pass


class _RedirectServer(HTTPServer):
    last_query: dict | None = None


def _wait_for_redirect(
    server: _RedirectServer, expected_state: str, timeout: int
) -> str:
    """Serve requests until the OAuth redirect arrives (or we time out)."""
    server.timeout = 1
    deadline = time.time() + timeout
    while time.time() < deadline:
        server.last_query = None
        server.handle_request()
        query = server.last_query
        if query is None:
            continue  # 1s idle tick
        if "code" in query or "error" in query:
            return _extract_auth_code(query, expected_state)
        # Ignore stray requests (e.g. a browser favicon probe) and keep waiting.
    raise AuthError("Timed out waiting for the browser redirect.")


# -- Auth client --
class AuthClient:
    """OAuth2 token client for a single tenant.

    Holds the tenant (and its derived token endpoint) so the flows don't thread
    `tenant` through every call. Kept separate from GraphClient: this acquires
    tokens, GraphClient spends them.
    """

    def __init__(self, tenant: str = c.DEFAULT_TENANT):
        self.tenant = tenant
        self.token_url = _TOKEN_URL.format(tenant=tenant)

    def _post(self, data: dict) -> TokenResponse:
        """POST a form body to the token endpoint and parse the token response."""
        resp = requests.post(self.token_url, headers=_HEADERS, data=data, timeout=30)
        try:
            payload = resp.json()
        except ValueError:
            raise AuthError(f"Non-JSON response ({resp.status_code}): {resp.text[:200]}")
        return TokenResponse.from_json(payload)

    def device_code(
        self, client_id: str, scope: str = DEFAULT_USER_SCOPE
    ) -> TokenResponse:
        """RFC 8628 device authorization grant. Prints the code, polls until complete.

        Does its own posts rather than `_post`: the device-authorization request hits a
        different endpoint, and the poll needs the raw payload to handle
        authorization_pending / slow_down.
        """
        devicecode_data = {"client_id": client_id, "scope": scope}
        dc = requests.post(
            c.MSO_DEVICECODE_URL.format(tenant=self.tenant),
            headers=_HEADERS,
            data=devicecode_data,
            timeout=30,
        ).json()
        if "device_code" not in dc:
            raise AuthError(dc.get("error_description", str(dc)))

        print(dc["message"])
        interval = int(dc.get("interval", 5))
        expires_at = time.time() + int(dc.get("expires_in", 900))
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": dc["device_code"],
        }
        while time.time() < expires_at:
            time.sleep(interval)
            resp = requests.post(
                self.token_url, headers=_HEADERS, data=data, timeout=30
            )
            try:
                payload = resp.json()
            except ValueError:
                raise AuthError(f"Non-JSON response ({resp.status_code}): {resp.text[:200]}")
            error = payload.get("error")
            if error is None:
                return TokenResponse.from_json(payload)
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise AuthError(payload.get("error_description", error))
        raise AuthError("Device code expired before authorization completed.")

    def nativeclient(
        self, client_id: str, scope: str = DEFAULT_USER_SCOPE
    ) -> TokenResponse:
        """Manual authorization-code flow: print the authorize URL, user pastes the
        redirected URL back, we exchange the code for tokens."""
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": c.AUTH_CODE_REDIRECT_URI,
            "scope": scope,
            "response_mode": "query",
        }
        authorize_url = f"{c.MSO_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
        print("Open this URL in a browser and sign in:\n")
        print(authorize_url + "\n")
        response = input("Paste the full URL of the resulting page:\n").strip()

        query = urllib.parse.parse_qs(urllib.parse.urlparse(response).query)
        codes = query.get("code")
        if not codes:
            raise AuthError("No authorization 'code' found in the pasted URL.")
        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": codes[0],
            "redirect_uri": c.AUTH_CODE_REDIRECT_URI,
            "scope": scope,
        }
        return self._post(data)

    def browser_pkce(
        self,
        client_id: str,
        scope: str = DEFAULT_USER_SCOPE,
        timeout: int = 300,
        open_browser: bool = True,
    ) -> TokenResponse:
        """Interactive browser login using a loopback redirect and PKCE.

        Binds a localhost listener on an ephemeral port, opens the system browser to
        the authorize URL, captures the redirected authorization code, and exchanges
        it (with the PKCE verifier) for tokens. The client must have `http://localhost`
        registered as a redirect URI (true for azcli / azpowershell / vs).
        """
        verifier, challenge = _generate_pkce()
        state_val = secrets.token_urlsafe(24)
        server = _RedirectServer(("127.0.0.1", 0), _RedirectHandler)
        redirect_uri = f"http://localhost:{server.server_address[1]}"
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state_val,
            "response_mode": "query",
        }
        url = f"{c.MSO_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
        print("Opening your browser to sign in. If it doesn't open, paste this URL:\n")
        print(url + "\n")
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass  # headless: user uses the printed URL
        try:
            code = _wait_for_redirect(server, state_val, timeout)
        finally:
            server.server_close()

        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_verifier": verifier,
        }
        return self._post(data)

    def client_credentials(
        self, client_id: str, secret: str, scope: str = CLIENT_CREDENTIALS_SCOPE
    ) -> TokenResponse:
        """Client-credentials grant for a service principal. Issues no refresh token."""
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "scope": scope,
        }
        return self._post(data)

    def foci_refresh(
        self, refresh_token: str, new_client_id: str, scope: str = DEFAULT_USER_SCOPE
    ) -> TokenResponse:
        """Exchange a FOCI refresh token for tokens as another family client."""
        if not c.is_foci_client(new_client_id):
            raise AuthError(f"{new_client_id} is not a known FOCI client.")
        data = {
            "grant_type": "refresh_token",
            "client_id": new_client_id,
            "refresh_token": refresh_token,
            "scope": scope,
        }
        return self._post(data)

    def refresh_user_token(
        self, refresh_token: str, client_id: str, scope: str = DEFAULT_USER_SCOPE
    ) -> TokenResponse:
        """Silent refresh of a user's access token using its refresh token."""
        data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": scope,
        }
        return self._post(data)


# -- Persistence helpers (write a TokenResponse into the cache) --
def _claims_if_jwt(token: str | None) -> dict:
    """Decode JWT claims, or {} if the token is absent or not a JWT (opaque).

    Microsoft access tokens are opaque to clients by design, so never assume the
    access token is a JWT — fall back to the id_token / response fields instead.
    """
    if not token:
        return {}
    try:
        return jwt_utils.decode_claims(token)
    except Exception:
        return {}


def _upn_from(resp: TokenResponse) -> str:
    claims = _claims_if_jwt(resp.id_token) or _claims_if_jwt(resp.access_token)
    return (
        claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("unique_name")
        or claims.get("email")
        or claims.get("oid", "unknown")
    )


def _scopes_from(resp: TokenResponse) -> list[str]:
    """Scopes from the access token's `scp` when it's a JWT, else the response scope."""
    scp = _claims_if_jwt(resp.access_token).get("scp")
    if scp:
        return scp.split(" ")
    return resp.scope.split(" ") if resp.scope else []


def _expiry_from(resp: TokenResponse) -> int:
    """Expiry from the access token's `exp` when it's a JWT, else the response fields."""
    exp = _claims_if_jwt(resp.access_token).get("exp")
    if exp is not None:
        return int(exp)
    raw = resp.raw or {}
    if raw.get("expires_on"):
        return int(raw["expires_on"])
    if raw.get("expires_in"):
        return int(time.time()) + int(raw["expires_in"])
    return 0


def persist_user_token(
    cache: TokenCache, resp: TokenResponse, client_id: str
) -> ActiveIdentity:
    """Store a user TokenResponse and return the resulting active identity.

    Resilient to opaque (non-JWT) access tokens: identity comes from the id_token
    (or the access token when it is a JWT), and scope/expiry fall back to the
    token-response fields.
    """
    identity = _claims_if_jwt(resp.access_token) or _claims_if_jwt(resp.id_token)
    upn = _upn_from(resp)
    tenant_domain = upn.split("@")[-1] if "@" in upn else None
    token = UserAppToken(
        access_token=resp.access_token,
        refresh_token=resp.refresh_token,
        app_display_name=c.foci_app_name(client_id) or c.get_alias(client_id),
        scopes=_scopes_from(resp),
        expires_on=_expiry_from(resp),
        foci=resp.foci or c.is_foci_client(client_id),
        acquired_at=int(time.time()),
    )
    cache.upsert_user_token(
        upn,
        client_id,
        token,
        tenant_id=identity.get("tid"),
        tenant_domain=tenant_domain,
        user_id=identity.get("oid"),
    )
    cache.save()
    return ActiveIdentity(kind="user", key=upn, client_id=client_id)


def persist_sp_token(
    cache: TokenCache, resp: TokenResponse, client_id: str
) -> ActiveIdentity:
    """Store a service-principal TokenResponse and return the active identity."""
    claims = _claims_if_jwt(resp.access_token)
    token = ServicePrincipalToken(
        access_token=resp.access_token,
        expires_on=_expiry_from(resp),
        service_principal_display_name=claims.get("app_displayname"),
        tenant_id=claims.get("tid"),
    )
    cache.upsert_sp_token(client_id, token)
    cache.save()
    return ActiveIdentity(kind="sp", key=client_id, client_id=client_id)
