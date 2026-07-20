"""Offline unit tests for gts: no network, no real keyring."""

import jwt
import pytest

from gts import constants as c
from gts import jwt_utils
from gts.cache import (
    ServicePrincipalToken,
    TokenCache,
    UserAppToken,
)
from gts.graph import GraphClient, GraphError, _is_expired


class FakeBackend:
    """In-memory StorageBackend for tests."""

    def __init__(self):
        self.blob = None

    def get(self):
        return self.blob

    def set(self, value):
        self.blob = value

    def delete(self):
        self.blob = None


def make_jwt(**claims):
    return jwt.encode(claims, "secret", algorithm="HS256")


# -- jwt_utils --
def test_decode_claims_and_scopes_and_expiry():
    token = make_jwt(scp="Mail.Read Directory.Read.All", exp=1730000000, oid="abc")
    claims = jwt_utils.decode_claims(token)
    assert claims["oid"] == "abc"
    assert jwt_utils.get_scopes(token) == ["Mail.Read", "Directory.Read.All"]
    assert jwt_utils.get_expiry(token) == 1730000000


def test_get_scopes_empty():
    assert jwt_utils.get_scopes(make_jwt(oid="x")) == []


def test_humanize_expiry_future_and_past():
    import time

    future = jwt_utils.humanize_expiry(int(time.time()) + 3660)  # ~1h ahead
    assert future["expired"] is False
    assert future["expires_in"].startswith("1h")  # no "in " prefix
    assert not future["expires_in"].startswith("in ")
    assert future["expires_at"].endswith("UTC")

    past = jwt_utils.humanize_expiry(int(time.time()) - 300)  # 5m ago
    assert past["expired"] is True
    assert "ago" in past["expires_in"]


def test_format_utc():
    assert jwt_utils.format_utc(0) is None
    assert jwt_utils.format_utc(None) is None
    # 2021-01-01 00:00:00 UTC
    assert jwt_utils.format_utc(1609459200) == "2021-01-01 00:00:00 UTC"


def test_humanize_expiry_unknown():
    info = jwt_utils.humanize_expiry(0)
    assert info == {"expires_at": None, "expires_in": "unknown", "expired": None}
    assert jwt_utils.humanize_expiry(None)["expires_in"] == "unknown"


# -- constants helpers --
def test_alias_resolution_roundtrip():
    assert c.resolve_client_id("azcli") == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    assert c.get_alias("04b07795-8ddb-461a-bbee-02f9e1bf7b46") == "azcli"
    # A raw client id passes through unchanged.
    assert c.resolve_client_id("some-guid") == "some-guid"


def test_foci_validation():
    assert c.is_foci_client("1fec8e78-bce4-4aaf-ab1b-5451cc387264")  # Microsoft Teams
    assert not c.is_foci_client("not-a-foci-client")
    # Azure CLI / PowerShell were removed from the family.
    assert not c.is_foci_client("04b07795-8ddb-461a-bbee-02f9e1bf7b46")
    assert not c.is_foci_client("1950a258-227b-4e31-a9cf-717495945fc2")
    assert c.foci_app_name("1fec8e78-bce4-4aaf-ab1b-5451cc387264") == "Microsoft Teams"


# -- cache round trip --
def test_user_and_sp_roundtrip_multi_user():
    backend = FakeBackend()
    cache = TokenCache(backend)
    cache.upsert_user_token(
        "alice@contoso.com",
        "client-a",
        UserAppToken(
            access_token="at1",
            refresh_token="rt1",
            scopes=["Mail.Read"],
            expires_on=111,
            foci=True,
        ),
        tenant_id="t1",
        tenant_domain="contoso.com",
        user_id="oid-a",
    )
    cache.upsert_user_token(
        "bob@contoso.com",
        "client-b",
        UserAppToken(access_token="at2", refresh_token="rt2"),
        tenant_id="t1",
    )
    cache.upsert_sp_token(
        "sp-client",
        ServicePrincipalToken(access_token="sat", expires_on=222, tenant_id="t1"),
    )
    cache.save()

    # Reload from the same backend blob.
    reloaded = TokenCache(backend)
    alice = reloaded.get_user_token("alice@contoso.com", "client-a")
    assert alice is not None and alice.refresh_token == "rt1" and alice.foci
    assert reloaded.get_user_token("bob@contoso.com", "client-b").access_token == "at2"
    sp = reloaded.get_sp_token("sp-client")
    assert sp is not None and sp.access_token == "sat"
    # SP schema carries no refresh token key.
    assert "refresh_token" not in reloaded.content["service_principals"]["sp-client"]

    ids = reloaded.list_identities()
    kinds = sorted((i.kind, i.key) for i in ids)
    assert kinds == [
        ("sp", "sp-client"),
        ("user", "alice@contoso.com"),
        ("user", "bob@contoso.com"),
    ]


def test_list_user_apps_and_sps():
    backend = FakeBackend()
    cache = TokenCache(backend)
    # Full user app (both tokens).
    cache.upsert_user_token(
        "alice@contoso.com",
        "cid-a",
        UserAppToken(
            access_token="at", refresh_token="rt", app_display_name="Azure CLI"
        ),
    )
    # Refresh-only app (no access token).
    cache.upsert_user_token(
        "alice@contoso.com",
        "cid-b",
        UserAppToken(access_token="", refresh_token="rt2"),
    )
    cache.upsert_sp_token(
        "sp-cid",
        ServicePrincipalToken(
            access_token="sat", service_principal_display_name="My SP", tenant_id="t1"
        ),
    )

    apps = {r["client_id"]: r for r in cache.list_user_apps()}
    assert apps["cid-a"]["has_access_token"] and apps["cid-a"]["has_refresh_token"]
    assert apps["cid-a"]["app_display_name"] == "Azure CLI"
    assert apps["cid-a"]["user"] == "alice@contoso.com"
    # access_token="" reads as absent.
    assert apps["cid-b"]["has_access_token"] is False
    assert apps["cid-b"]["has_refresh_token"] is True

    sps = cache.list_service_principals()
    assert len(sps) == 1
    assert sps[0]["client_id"] == "sp-cid"
    assert sps[0]["service_principal_display_name"] == "My SP"
    assert sps[0]["has_access_token"] is True
    assert "has_refresh_token" not in sps[0]  # SPs never have refresh tokens


def test_find_and_remove():
    backend = FakeBackend()
    cache = TokenCache(backend)
    cache.upsert_user_token("a@x.com", "cid", UserAppToken(access_token="at"))
    found = cache.find_user_by_client("cid")
    assert found is not None and found[0] == "a@x.com"
    assert cache.remove_user_app("a@x.com", "cid") is True
    # User pruned once its last app is gone.
    assert cache.get_user("a@x.com") is None


def test_clear():
    backend = FakeBackend()
    cache = TokenCache(backend)
    cache.upsert_sp_token("sp", ServicePrincipalToken(access_token="x"))
    cache.save()
    cache.clear()
    assert backend.blob is None
    assert TokenCache(backend).list_identities() == []


# -- GraphClient pagination + throttling --
class FakeResp:
    def __init__(self, status, body=None, headers=None, text=""):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._body


def test_pagination_follows_nextlink(monkeypatch):
    pages = {
        "https://graph.microsoft.com/v1.0/users": FakeResp(
            200, {"value": [{"id": "1"}], "@odata.nextLink": "https://next/2"}
        ),
        "https://next/2": FakeResp(200, {"value": [{"id": "2"}]}),
    }
    client = GraphClient("tok")
    monkeypatch.setattr(client.session, "get", lambda url, timeout=60: pages[url])
    assert [u["id"] for u in client.get_all("users")] == ["1", "2"]


def test_429_retry_then_success(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, timeout=60):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResp(429, headers={"Retry-After": "0"})
        return FakeResp(200, {"value": []})

    monkeypatch.setattr("time.sleep", lambda *_: None)
    client = GraphClient("tok")
    monkeypatch.setattr(client.session, "get", fake_get)
    assert client.get_all("users") == []
    assert calls["n"] == 2


def test_graph_error_on_4xx(monkeypatch):
    client = GraphClient("tok")
    monkeypatch.setattr(
        client.session, "get", lambda url, timeout=60: FakeResp(403, text="Forbidden")
    )
    with pytest.raises(GraphError):
        client.get("users")


def test_is_expired():
    assert _is_expired(1) is True
    assert _is_expired(0) is False  # 0 means "unknown", never treated as expired


# -- enum enrichment (the tool's core value) --
def test_service_principal_risk_flagging(monkeypatch):
    from gts.enum import operations as ops

    graph_sp = {
        "appRoles": [
            {
                "id": "role-risky",
                "displayName": "Read/Write dir",
                "value": "RoleManagement.ReadWrite.Directory",
            },
            {"id": "role-safe", "displayName": "Read users", "value": "User.Read.All"},
        ]
    }
    responses = {
        "servicePrincipals?$filter=displayName eq 'Microsoft Graph'": [graph_sp],
        "organization": [{"id": "tenant-1"}],
        "servicePrincipals?$top=999": [
            {
                "id": "sp-bad",
                "displayName": "Bad App",
                "appOwnerOrganizationId": "tenant-1",
            },
            {
                "id": "sp-ok",
                "displayName": "OK App",
                "appOwnerOrganizationId": "tenant-1",
            },
            {
                "id": "sp-other",
                "displayName": "Foreign",
                "appOwnerOrganizationId": "other-tenant",
            },
        ],
        "servicePrincipals/sp-bad/appRoleAssignments?$top=999": [{"appRoleId": "role-risky"}],
        "servicePrincipals/sp-ok/appRoleAssignments?$top=999": [{"appRoleId": "role-safe"}],
    }

    class FakeClient:
        def get_all(self, path, beta=False):
            return responses[path]

    monkeypatch.setattr(ops, "GraphClient", FakeClient)
    result = ops.get_service_principals(FakeClient(), owned_only=True)

    # With owned_only, the foreign-tenant SP is filtered out; only tenant-owned remain.
    assert {sp["id"] for sp in result["service_principals"]} == {"sp-bad", "sp-ok"}
    # GUIDs resolved to permission names.
    bad = next(sp for sp in result["service_principals"] if sp["id"] == "sp-bad")
    assert bad["appRoleAssignments"] == ["RoleManagement.ReadWrite.Directory"]
    # Only the risky SP is flagged, and it carries its resolved appRoleAssignments.
    assert result["privileged_service_principals"] == [
        {
            "id": "sp-bad",
            "displayName": "Bad App",
            "appRoleAssignments": ["RoleManagement.ReadWrite.Directory"],
        }
    ]


def test_service_principals_include_all_by_default():
    """Default enumerates every SP (incl. foreign-owned) and never consults organization."""
    from gts.enum import operations as ops

    responses = {
        "servicePrincipals?$filter=displayName eq 'Microsoft Graph'": [{"appRoles": []}],
        "servicePrincipals?$top=999": [
            {"id": "sp-home", "appOwnerOrganizationId": "t1"},
            {"id": "sp-foreign", "appOwnerOrganizationId": "vendor-tenant"},
        ],
        "servicePrincipals/sp-home/appRoleAssignments?$top=999": [],
        "servicePrincipals/sp-foreign/appRoleAssignments?$top=999": [],
    }

    class FakeClient:
        def get_all(self, path, beta=False):
            # No "organization" entry: default must not call get_organization.
            return responses[path]

    result = ops.get_service_principals(FakeClient())
    assert {sp["id"] for sp in result["service_principals"]} == {"sp-home", "sp-foreign"}


def test_gather_preserves_input_order_under_concurrency():
    """Results align with input order even when items finish out of order."""
    import time

    from gts.enum import operations as ops

    def fn(n):
        time.sleep((5 - n) * 0.01)  # later items finish first
        return n * 10

    calls = []
    out = ops._gather(fn, [1, 2, 3, 4, 5], lambda: calls.append(1))
    assert out == [10, 20, 30, 40, 50]
    assert len(calls) == 5  # advance() once per item


def test_get_users_uses_max_page_size():
    from gts.enum import operations as ops

    seen = []

    class FakeClient:
        def get_all(self, path, beta=False):
            seen.append(path)
            return []

    ops.get_users(FakeClient())
    assert seen == ["users?$top=999"]


def test_service_principals_progress_advances_per_sp():
    """The injected progress is advanced exactly once per tenant-owned SP."""
    from contextlib import contextmanager

    from gts.enum import operations as ops

    responses = {
        "servicePrincipals?$filter=displayName eq 'Microsoft Graph'": [{"appRoles": []}],
        "servicePrincipals?$top=999": [
            {"id": "a", "appOwnerOrganizationId": "t1"},
            {"id": "b", "appOwnerOrganizationId": "t1"},
            {"id": "c", "appOwnerOrganizationId": "other"},
        ],
        "servicePrincipals/a/appRoleAssignments?$top=999": [],
        "servicePrincipals/b/appRoleAssignments?$top=999": [],
        "servicePrincipals/c/appRoleAssignments?$top=999": [],
    }

    class FakeClient:
        def get_all(self, path, beta=False):
            return responses[path]

    ticks = {"n": 0, "total": None}

    class SpyProgress:
        @contextmanager
        def task(self, description, total):
            ticks["total"] = total
            yield lambda: ticks.__setitem__("n", ticks["n"] + 1)

    # Default enumerates all SPs (no organization lookup, no ownership filter).
    ops.get_service_principals(FakeClient(), progress=SpyProgress())
    assert ticks["total"] == 3
    assert ticks["n"] == 3


def test_null_progress_is_a_noop():
    from gts.progress import NullProgress, for_stderr

    with NullProgress().task("x", total=3) as advance:
        advance()
        advance()  # no error, no output

    # Non-tty stderr under pytest -> silent NullProgress.
    assert isinstance(for_stderr(), NullProgress)


# -- Loopback + PKCE browser login --
def test_pkce_generation():
    import base64
    import hashlib

    from gts import auth

    verifier, challenge = auth._generate_pkce()
    # challenge must be base64url(sha256(verifier)) without padding
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert challenge == expected
    assert "=" not in verifier and "=" not in challenge


def test_extract_auth_code():
    from gts import auth

    assert auth._extract_auth_code({"code": ["abc"], "state": ["s1"]}, "s1") == "abc"
    with pytest.raises(auth.AuthError):  # state mismatch
        auth._extract_auth_code({"code": ["abc"], "state": ["bad"]}, "s1")
    with pytest.raises(auth.AuthError):  # provider error
        auth._extract_auth_code(
            {"error": ["access_denied"], "error_description": ["nope"]}, "s1"
        )
    with pytest.raises(auth.AuthError):  # no code
        auth._extract_auth_code({"state": ["s1"]}, "s1")


def test_browser_pkce_flow_loopback(monkeypatch):
    import threading
    import urllib.parse

    import requests

    from gts import auth

    # Simulate the browser: parse the authorize URL, then hit the loopback redirect.
    def fake_open(url):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        assert q["code_challenge_method"][0] == "S256"
        assert q["code_challenge"][0]
        redirect, state = q["redirect_uri"][0], q["state"][0]
        threading.Timer(
            0.2,
            lambda: requests.get(f"{redirect}?code=FAKE_CODE&state={state}", timeout=5),
        ).start()
        return True

    monkeypatch.setattr(auth.webbrowser, "open", fake_open)

    at = make_jwt(
        appid="cid", tid="t", oid="o", upn="a@b.com", scp="User.Read", exp=1730000000
    )
    captured = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"access_token": at, "refresh_token": "rt", "id_token": at}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"], captured["data"] = url, data
        return FakeResp()

    monkeypatch.setattr(auth.requests, "post", fake_post)

    resp = auth.AuthClient("tenant-1").browser_pkce("client-x", timeout=10)
    assert resp.access_token == at
    assert "tenant-1" in captured["url"]
    assert captured["data"]["grant_type"] == "authorization_code"
    assert captured["data"]["code"] == "FAKE_CODE"
    assert captured["data"]["code_verifier"]  # PKCE verifier included in exchange
    assert captured["data"]["redirect_uri"].startswith("http://localhost:")


# -- AuthClient (tenant held once, shared _post) --
def test_authclient_posts_to_tenant_token_url(monkeypatch):
    from gts import auth

    at = make_jwt(appid="cid", tid="t", oid="o", scp="User.Read", exp=1730000000)
    captured = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"access_token": at, "refresh_token": "rt2"}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"], captured["data"] = url, data
        return FakeResp()

    monkeypatch.setattr(auth.requests, "post", fake_post)
    teams = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    resp = auth.AuthClient("tenant-guid").foci_refresh("old-rt", teams)

    assert resp.refresh_token == "rt2"
    assert (
        captured["url"]
        == "https://login.microsoftonline.com/tenant-guid/oauth2/v2.0/token"
    )
    assert captured["data"]["client_id"] == teams
    assert captured["data"]["refresh_token"] == "old-rt"


def test_authclient_foci_refresh_rejects_non_foci_client():
    from gts import auth

    with pytest.raises(auth.AuthError):
        auth.AuthClient("t").foci_refresh("rt", "not-a-foci-client")


def test_authclient_post_raises_on_error_payload(monkeypatch):
    from gts import auth

    class FakeResp:
        status_code = 400

        def json(self):
            return {"error": "invalid_grant", "error_description": "AADSTS70000 nope"}

    monkeypatch.setattr(auth.requests, "post", lambda *a, **k: FakeResp())
    with pytest.raises(auth.AuthError, match="AADSTS70000"):
        auth.AuthClient("t").refresh_user_token("rt", "cid")


# -- opaque-access-token resilience --
def test_persist_user_token_jwt_access_token_unchanged():
    from gts import auth

    at = make_jwt(
        appid="cid",
        tid="t1",
        oid="o1",
        upn="a@b.com",
        scp="User.Read Mail.Read",
        exp=1730000000,
    )
    resp = auth.TokenResponse.from_json({"access_token": at, "refresh_token": "rt"})
    cache = TokenCache(FakeBackend())
    auth.persist_user_token(cache, resp, "cid")

    tok = cache.get_user_token("a@b.com", "cid")
    assert tok.scopes == ["User.Read", "Mail.Read"]  # from access-token scp
    assert tok.expires_on == 1730000000  # from access-token exp
    assert cache.get_user("a@b.com")["tenant_id"] == "t1"


def test_persist_user_token_opaque_access_token(monkeypatch):
    from gts import auth

    teams = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    idt = make_jwt(
        aud=teams,
        tid="t2",
        oid="o2",
        upn="peter@contoso.com",
    )
    resp = auth.TokenResponse.from_json(
        {
            "access_token": "PAQABAopaque-not-a-jwt",  # opaque
            "refresh_token": "rt2",
            "id_token": idt,
            "expires_on": "1784344350",
        }
    )
    cache = TokenCache(FakeBackend())
    active = auth.persist_user_token(cache, resp, teams)

    assert active.key == "peter@contoso.com"  # identity from id_token, no crash
    tok = cache.get_user_token("peter@contoso.com", teams)
    assert tok.access_token == "PAQABAopaque-not-a-jwt"  # opaque token stored verbatim
    assert tok.refresh_token == "rt2"
    assert tok.expires_on == 1784344350  # from response expires_on
    assert tok.foci is True  # Microsoft Teams is a FOCI client
    assert cache.get_user("peter@contoso.com")["tenant_id"] == "t2"


def test_insert_response_command(monkeypatch, tmp_path):
    import json

    import keyring
    from typer.testing import CliRunner

    from gts.cli import app

    class Mem(keyring.backend.KeyringBackend):
        priority = 1

        def __init__(self):
            super().__init__()
            self.store = {}

        def get_password(self, s, u):
            return self.store.get((s, u))

        def set_password(self, s, u, p):
            self.store[(s, u)] = p

        def delete_password(self, s, u):
            self.store.pop((s, u), None)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("GTS_STORAGE_BACKEND", raising=False)
    keyring.set_keyring(Mem())

    idt = make_jwt(
        aud="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        tid="t3",
        oid="o3",
        upn="alice@contoso.com",
    )
    blob = json.dumps(
        {
            "access_token": "PAQABAopaque",
            "refresh_token": "rt3",
            "id_token": idt,
            "expires_on": "1784344350",
        }
    )
    r = CliRunner().invoke(app, ["insert", "-t", "response", "-s", blob])
    assert r.exit_code == 0, r.output
    assert "alice@contoso.com" in r.output

    from gts.cache import TokenCache as TC

    tok = TC().get_user_token(
        "alice@contoso.com", "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    )
    assert tok.access_token == "PAQABAopaque" and tok.expires_on == 1784344350


def test_insert_response_bad_json():
    import json as _json

    from gts import auth

    # from_json rejects a blob with no access_token
    with pytest.raises(auth.AuthError):
        auth.TokenResponse.from_json(_json.loads('{"token_type": "Bearer"}'))


# -- interactive switch menu --
def test_menu_apply_key_navigation():
    from gts import menu

    # wraps around both directions
    assert menu._apply_key(0, "up", 3) == (2, None)
    assert menu._apply_key(2, "down", 3) == (0, None)
    assert menu._apply_key(1, "k", 3) == (0, None)
    assert menu._apply_key(1, "j", 3) == (2, None)
    # actions
    assert menu._apply_key(1, "enter", 3) == (1, "select")
    assert menu._apply_key(1, "q", 3) == (1, "cancel")
    assert menu._apply_key(1, "esc", 3) == (1, "cancel")
    # unknown keys are no-ops
    assert menu._apply_key(1, "x", 3) == (1, None)


def test_switch_entries_lists_users_and_sps():
    from gts.cli import _switch_entries

    backend = FakeBackend()
    cache = TokenCache(backend)
    cache.upsert_user_token(
        "alice@contoso.com",
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        UserAppToken(access_token="at"),
    )
    cache.upsert_sp_token("sp-cid", ServicePrincipalToken(access_token="sat"))

    entries = _switch_entries(cache)
    kinds = [(e["kind"], e["identity"].key, e["identity"].client_id) for e in entries]
    assert (
        "user",
        "alice@contoso.com",
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    ) in kinds
    assert ("sp", "sp-cid", "sp-cid") in kinds
    # alias resolved for known client
    user_entry = next(e for e in entries if e["kind"] == "user")
    assert user_entry["alias"] == "azcli"


def test_select_index_noninteractive_returns_none(monkeypatch):
    from gts import menu

    monkeypatch.setattr(menu, "is_interactive", lambda: False)
    assert menu.select_index(None, lambda idx: None, 3) is None


def test_select_index_loop(monkeypatch):
    from rich.console import Console

    from gts import menu

    class FakeTermios:
        ICANON, ECHO, VMIN, VTIME, TCSANOW = 2, 8, 6, 5, 0

        def tcgetattr(self, fd):
            return [0, 0, 0, 0, 0, 0, [0] * 32]

        def tcsetattr(self, fd, when, attrs):
            pass

    class FakeLive:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def update(self, *a, **k):
            pass

    class FakeStdin:
        def fileno(self):
            return 0

    monkeypatch.setattr(menu, "is_interactive", lambda: True)
    monkeypatch.setattr(menu, "termios", FakeTermios())
    monkeypatch.setattr(menu, "Live", FakeLive)
    monkeypatch.setattr(menu.sys, "stdin", FakeStdin())

    # down -> 1, down -> 2, up -> 1, enter -> select index 1
    keys = iter(["down", "down", "up", "enter"])
    monkeypatch.setattr(menu, "_read_key", lambda fd: next(keys))
    assert menu.select_index(Console(), lambda i: f"r{i}", 3, 0) == 1

    # cancel path
    monkeypatch.setattr(menu, "_read_key", lambda fd: "q")
    assert menu.select_index(Console(), lambda i: f"r{i}", 3, 0) is None


def test_backend_selection(monkeypatch):
    from gts import storage

    from gts.storage.onepassword_backend import OnePasswordBackend

    monkeypatch.setenv("GTS_STORAGE_BACKEND", "keyring")
    assert isinstance(storage.get_default_backend(), storage.KeyringBackend)

    # canonical name and legacy aliases all select the 1Password backend
    for value in ("onepassword", "op", "1password"):
        monkeypatch.setenv("GTS_STORAGE_BACKEND", value)
        assert isinstance(storage.get_default_backend(), OnePasswordBackend)


# -- settings.json config --
def test_config_precedence_and_roundtrip(monkeypatch, tmp_path):
    from gts import config

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("GTS_STORAGE_BACKEND", raising=False)

    # default when nothing set
    assert config.effective("storage_backend") == "keyring"
    assert config.source("storage_backend") == "default"

    # settings.json value takes over the default
    config.set_setting("storage_backend", "1password")
    assert config.effective("storage_backend") == "1password"
    assert config.source("storage_backend") == "settings"
    assert config.settings_path().exists()

    # env var overrides settings.json
    monkeypatch.setenv("GTS_STORAGE_BACKEND", "keyring")
    assert config.effective("storage_backend") == "keyring"
    assert config.source("storage_backend") == "env"

    # dotted keys and unset
    config.set_setting("onepassword.vault", "Work")
    assert config.effective("onepassword.vault") == "Work"
    assert config.unset_setting("onepassword.vault") is True
    assert config.effective("onepassword.vault") == "Private"  # back to default
    assert config.unset_setting("onepassword.vault") is False  # already gone


def test_config_backend_selection_via_settings(monkeypatch, tmp_path):
    from gts import config, storage
    from gts.storage.onepassword_backend import OnePasswordBackend

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("GTS_STORAGE_BACKEND", raising=False)
    monkeypatch.delenv("OP_ACCOUNT", raising=False)

    config.set_setting("storage_backend", "onepassword")
    config.set_setting("onepassword.account", "my.1password.com")
    backend = storage.get_default_backend()
    assert isinstance(backend, OnePasswordBackend)
    assert backend.account == "my.1password.com"  # resolved from settings.json


# -- 1Password (op CLI) backend --
class FakeOp:
    """Simulates the `op` CLI over a dict; records commands and flags argv leaks."""

    def __init__(self):
        self.store = {}  # document title -> contents
        self.notes = (
            set()
        )  # titles that exist as NON-document items (e.g. a Secure Note)
        self.commands = []  # list of (argv, stdin)

    def run(self, argv, input=None, capture_output=True, text=True):
        from subprocess import CompletedProcess

        assert argv[0] == "op"
        self.commands.append((argv, input))
        args = argv[1:]

        def result(rc, out="", err=""):
            return CompletedProcess(argv, rc, stdout=out, stderr=err)

        # item title is the 3rd positional after the subcommand pair
        if args[:2] == ["item", "get"]:
            title = args[2]
            exists = title in self.store or title in self.notes
            return result(0, "{}") if exists else result(1, err="isn't an item")
        if args[:2] == ["document", "get"]:
            title = args[2]
            if title in self.store:
                return result(0, self.store[title])
            if title in self.notes:
                return result(1, err="isn't a document")
            return result(1, err="isn't an item")
        if args[:2] == ["document", "create"]:
            title = args[args.index("--title") + 1]
            self.store[title] = input
            return result(0, '{"id":"doc1"}')
        if args[:2] == ["document", "edit"]:
            self.store[args[2]] = input
            return result(0)
        if args[:2] == ["document", "delete"]:
            self.store.pop(args[2], None)
            return result(0)
        return result(1, err="unexpected command")


def test_onepassword_backend_roundtrip(monkeypatch):
    from gts.storage import onepassword_backend as opb

    fake = FakeOp()
    monkeypatch.setattr(opb.subprocess, "run", fake.run)

    b = opb.OnePasswordBackend(account="me", vault="Private", item="graph-token-store")
    assert b.get() is None  # nothing stored
    b.set('{"users":{}}')  # create path (item didn't exist)
    assert b.get() == '{"users":{}}'
    b.set('{"users":{"x":1}}')  # edit path (item exists now)
    assert b.get() == '{"users":{"x":1}}'
    b.delete()
    assert b.get() is None

    # account/vault flags are threaded through
    getcmd = next(argv for argv, _ in fake.commands if argv[1:3] == ["document", "get"])
    assert "--account" in getcmd and "me" in getcmd
    assert "--vault" in getcmd and "Private" in getcmd


def test_onepassword_backend_secret_never_in_argv(monkeypatch):
    from gts.storage import onepassword_backend as opb

    fake = FakeOp()
    monkeypatch.setattr(opb.subprocess, "run", fake.run)
    secret = "SUPER-SECRET-TOKEN-BLOB"

    b = opb.OnePasswordBackend(account="me", vault="Private", item="graph-token-store")
    b.set(secret)  # create
    b.set(secret + "2")  # edit
    # the blob must travel via stdin, never on the command line
    for argv, stdin in fake.commands:
        assert not any(secret in str(a) for a in argv), (
            f"secret leaked into argv: {argv}"
        )
    writes = [
        stdin
        for argv, stdin in fake.commands
        if argv[1:3] in (["document", "create"], ["document", "edit"])
    ]
    assert secret in writes[0] and (secret + "2") in writes[1]


def test_onepassword_backend_rejects_nondocument_collision(monkeypatch):
    from gts.storage import onepassword_backend as opb

    fake = FakeOp()
    fake.notes.add("graph-token-store")  # a leftover Secure Note with the same title
    monkeypatch.setattr(opb.subprocess, "run", fake.run)

    b = opb.OnePasswordBackend(account="me", vault="Private", item="graph-token-store")
    assert b.get() is None  # a note isn't a document -> treated as empty
    with pytest.raises(opb.OnePasswordError, match="isn't a document"):
        b.set('{"users":{}}')  # refuses to create a duplicate-titled document


def test_onepassword_backend_missing_cli(monkeypatch):
    from gts.storage import onepassword_backend as opb

    def boom(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(opb.subprocess, "run", boom)
    with pytest.raises(opb.OnePasswordError):
        opb.OnePasswordBackend(item="graph-token-store").get()


def test_config_bad_json_falls_back(monkeypatch, tmp_path):
    from gts import config

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("GTS_STORAGE_BACKEND", raising=False)
    config.settings_path().parent.mkdir(parents=True, exist_ok=True)
    config.settings_path().write_text("{ not valid json")
    assert config.load_settings() == {}
    assert config.effective("storage_backend") == "keyring"


# -- resources/ permission maps --------------------------------------------------
# These guard against the generated resources drifting from the CLI. Pure data
# checks: no network, no Graph calls.


def _resource(name: str) -> dict:
    import json
    import pathlib

    path = pathlib.Path(__file__).resolve().parent.parent / "resources" / name
    return json.loads(path.read_text())


def test_command_permissions_cover_every_enum_subcommand():
    from gts.cli import enum_app

    commands = {c.name for c in enum_app.registered_commands}
    documented = set(_resource("enum_command_permissions.json")) - {"_meta"}
    assert commands == documented


def test_command_endpoints_all_exist_in_endpoint_map():
    endpoints = set(_resource("graph_endpoint_permissions.json")) - {"_meta"}
    commands = _resource("enum_command_permissions.json")
    for name, spec in commands.items():
        if name == "_meta":
            continue
        for entry in spec["endpoints"]:
            assert entry["endpoint"] in endpoints, f"{name}: {entry['endpoint']}"


def test_me_endpoints_are_marked_app_only_unsupported():
    """/me can never be reached with a client-credentials token, so the switching
    logic must not offer to 'fix' it by picking another app."""
    endpoints = _resource("graph_endpoint_permissions.json")
    for path in ("GET /me", "GET /me/transitiveMemberOf"):
        assert endpoints[path]["app_only_supported"] is False
        assert endpoints[path]["effective_least_privileged"]["application"] is None

    commands = _resource("enum_command_permissions.json")
    assert commands["current-user"]["app_only"] == "unsupported"
    assert commands["all"]["app_only"] == "partial"
    assert commands["all"]["app_only_skipped_commands"] == [
        "current-user",
        "current-user-memberships",
    ]


def test_enum_all_endpoints_are_union_of_other_commands():
    commands = _resource("enum_command_permissions.json")
    union = {
        e["endpoint"]
        for name, spec in commands.items()
        if name not in ("_meta", "all")
        for e in spec["endpoints"]
    }
    assert {e["endpoint"] for e in commands["all"]["endpoints"]} == union


# -- FOCI minimum-set analysis ---------------------------------------------------


def _load_foci_analyzer():
    import importlib
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    return importlib.import_module("analyze_foci_min_set")


def test_min_set_cover_finds_all_smallest_solutions():
    """Self-contained: no network, no gitignored data. A synthetic family where the
    smallest cover is two clients, reachable two equally-good ways."""
    mod = _load_foci_analyzer()
    accepted_by = {
        "ep_dir": ["Directory.Read.All"],       # broad scope
        "ep_pol": ["Policy.Read.All"],           # only the two 'pol' clients have it
    }
    scopes_by = {
        "broad_a": {"directory.read.all"},
        "broad_b": {"directory.read.all"},
        "pol_1": {"policy.read.all"},
        "irrelevant": {"mail.read"},
    }
    names = {k: k for k in scopes_by}

    size, solutions = mod.min_set_cover(
        ["ep_dir", "ep_pol"], accepted_by, scopes_by, names
    )
    assert size == 2
    # two ways: {broad_a, pol_1} or {broad_b, pol_1}; irrelevant never appears
    assert sorted(solutions) == [["broad_a", "pol_1"], ["broad_b", "pol_1"]]
    for sol in solutions:
        union = set().union(*(scopes_by[c] for c in sol))
        assert all(mod.covers(union, accepted_by[ep]) for ep in accepted_by)


def test_covers_filters_junk_scope_tokens():
    mod = _load_foci_analyzer()
    # "Not available." is a doc parse artifact, never a real scope a client can hold
    assert mod.covers({"policy.read.all"}, ["Policy.Read.All"]) == "Policy.Read.All"
    assert mod.covers(set(), ["Policy.Read.All"]) is None


def test_published_foci_min_set_solutions_actually_cover():
    """If the analysis has been generated and the entrascopes data is present, every
    published minimal set must genuinely cover its stated endpoints, all ties share the
    reported size, and the excluded pools are disjoint from the candidates."""
    import json
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    out = root / "resources" / "foci_min_set.json"
    data = root / "resources" / "entrascopes" / "firstpartyscopes.json"
    if not out.exists() or not data.exists():
        import pytest

        pytest.skip("run scripts/analyze_foci_min_set.py with firstpartyscopes.json present")

    mod = _load_foci_analyzer()
    res = json.loads(out.read_text())
    apps = json.loads(data.read_text())["apps"]
    accepted = res["accepted_scopes"]

    for block in ("minimum_set", "minimum_set_with_optional"):
        section = res[block]
        for sol in section["solutions"]:
            ids = [c["client_id"] for c in sol["clients"]]
            assert len(ids) == section["size"]
            union = set()
            for cid in ids:
                union |= mod.client_graph_scopes(apps, cid) or set()
            for ep in section["covers"]:
                assert mod.covers(union, accepted[ep]), f"{ids} misses {ep}"

    # the chosen clients must never be one the analysis excluded
    excluded_ids = {
        c["client_id"]
        for group in res["excluded_clients"].values()
        for c in group
    }
    covered_ids = {
        c["client_id"]
        for sol in res["minimum_set"]["solutions"]
        for c in sol["clients"]
    }
    assert covered_ids.isdisjoint(excluded_ids)


# -- CLIENTS table / clients module / enum guard ---------------------------------
# All data is static in constants.CLIENTS now, so these need no firstpartyscopes.json.

_AZCLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
_TEAMS = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
_WHITEBOARD = "57336123-6e14-4acc-8dcf-287b6088aa28"
_MSOFFICE = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # holds Directory.AccessAsUser.All


def test_version_flag_matches_package_version():
    """`gts --version` prints the single-sourced package version (from dist metadata)."""
    from typer.testing import CliRunner

    import gts
    from gts.cli import app

    res = CliRunner().invoke(app, ["--version"])
    assert res.exit_code == 0
    assert res.output.strip() == gts.__version__
    assert gts.__version__ != "0.0.0+unknown"  # installed, so metadata resolved


def test_clients_schema_is_wellformed():
    from gts import constants as c

    keys = {"alias", "display_name", "client_id", "foci", "localhost", "nativeclient", "graph_scopes"}
    aliases = []
    for e in c.CLIENTS:
        assert set(e) == keys, e
        assert isinstance(e["display_name"], str) and e["display_name"]
        assert isinstance(e["foci"], bool)
        assert all(isinstance(s, str) and s == s.lower() for s in e["graph_scopes"])
        if e["alias"] is not None:
            aliases.append(e["alias"])
    assert len(aliases) == len(set(aliases)), "aliases must be unique"


def test_foci_and_redirect_are_data_authoritative():
    from gts import constants as c

    # Azure CLI is no longer FOCI, but supports localhost + nativeclient.
    assert c.is_foci_client(_AZCLI) is False
    assert c.redirect_support(_AZCLI) == (True, True)
    # Teams is FOCI, nativeclient only.
    assert c.is_foci_client(_TEAMS) is True
    assert c.redirect_support(_TEAMS) == (False, True)


def test_curated_directory_read_aliases_carry_the_scope():
    """The pivot-target aliases we curate for enum must actually hold Directory.Read.All."""
    from gts import constants as c

    for alias in ("whiteboard", "planner", "sharepoint", "onedrive-app"):
        cid = c.get_client_id_from_alias(alias)
        assert cid is not None
        assert "directory.read.all" in c.client_graph_scopes(cid), alias


def test_clients_query_by_scope_returns_foci_directory_readers():
    import json

    from typer.testing import CliRunner

    from gts.cli import app

    res = CliRunner().invoke(app, ["clients", "query", "--scope", "Directory.Read.All", "-f", "json"])
    assert res.exit_code == 0, res.output
    rows = json.loads(res.stdout)
    found = {r["client_id"] for r in rows}
    assert _WHITEBOARD in found          # holds Directory.Read.All
    assert _AZCLI not in found           # searched, but lacks Directory.Read.All
    # JSON is the raw CLIENTS representation.
    assert set(rows[0]) == {
        "alias", "display_name", "client_id", "foci", "localhost", "nativeclient", "graph_scopes"
    }


def test_clients_query_searches_all_clients_including_non_foci():
    """The search space is the whole CLIENTS table, so a non-FOCI aliased client (Azure CLI)
    is findable by client id."""
    import json

    from typer.testing import CliRunner

    from gts.cli import app

    res = CliRunner().invoke(app, ["clients", "query", "--client-id", "04b07795", "-f", "json"])
    rows = json.loads(res.stdout)
    assert [r["client_id"] for r in rows] == [_AZCLI]
    assert rows[0]["foci"] is False


def test_clients_query_name_and_client_id_filters_combine():
    import json

    from typer.testing import CliRunner

    from gts.cli import app

    res = CliRunner().invoke(
        app, ["clients", "query", "--name", "whiteboard", "--client-id", _WHITEBOARD, "-f", "json"]
    )
    rows = json.loads(res.stdout)
    assert [r["client_id"] for r in rows] == [_WHITEBOARD]


def test_enum_guard_flags_missing_scopes():
    """The guard's detection helper reports endpoints the active client can't cover, honours
    the Directory.AccessAsUser.All wildcard, and never flags on unknown clients."""
    from gts import cli

    # Whiteboard has Directory.Read.All (covers users) but not Policy.Read.All (conditional-access).
    assert cli._enum_insufficient_endpoints("users", _WHITEBOARD) == []
    assert cli._enum_insufficient_endpoints("conditional-access", _WHITEBOARD) == [
        "GET /identity/conditionalAccess/policies"
    ]
    # A Directory.AccessAsUser.All holder is treated as sufficient for everything.
    assert cli._enum_insufficient_endpoints("conditional-access", _MSOFFICE) == []
    # Unknown client / no data -> never flag.
    assert cli._enum_insufficient_endpoints("users", "unknown-client-id") == []


def test_enum_preflight_confirms_interactively(monkeypatch):
    """Insufficient client: interactive prompts (abort on N, proceed on Y); non-interactive
    warns and proceeds; a sufficient client never prompts."""
    import pytest
    import typer

    from gts import cli, state

    def active(cid):
        return state.ActiveIdentity(kind="user", key="u@x", client_id=cid)

    monkeypatch.setattr(cli.state, "get_active", lambda: active(_WHITEBOARD))

    # interactive + decline -> abort
    monkeypatch.setattr(cli.menu, "is_interactive", lambda: True)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit):
        cli._enum_preflight("conditional-access")

    # interactive + accept -> proceed (no raise)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    cli._enum_preflight("conditional-access")

    # non-interactive -> warn + proceed (no prompt, no raise)
    def _no_prompt(*a, **k):
        raise AssertionError("must not prompt when non-interactive")

    monkeypatch.setattr(cli.menu, "is_interactive", lambda: False)
    monkeypatch.setattr(cli.typer, "confirm", _no_prompt)
    cli._enum_preflight("conditional-access")

    # sufficient client (wildcard) -> never prompts even when interactive
    monkeypatch.setattr(cli.state, "get_active", lambda: active(_MSOFFICE))
    monkeypatch.setattr(cli.menu, "is_interactive", lambda: True)
    cli._enum_preflight("conditional-access")


def test_enum_all_skips_conditional_access_for_insufficient_client():
    """`enum all` skips conditional-access unless the client has Policy.Read.All or
    Directory.AccessAsUser.All (req #2)."""
    from gts import cli

    assert cli._conditional_access_blocked(_WHITEBOARD) is True   # no Policy.Read.All
    assert cli._conditional_access_blocked(_MSOFFICE) is False    # Directory.AccessAsUser.All
    assert cli._conditional_access_blocked("unknown-client-id") is False  # no data -> attempt


def test_build_clients_merge_is_idempotent():
    """build_clients.build() is a fixed point: feeding its own output back yields the same
    table. Needs the raw dump; skips if it isn't on disk."""
    import json
    import pathlib
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    dump = root / "resources" / "entrascopes" / "firstpartyscopes.json"
    if not dump.exists():
        import pytest

        pytest.skip("firstpartyscopes.json absent; see resources/entrascopes/README.md")

    sys.path.insert(0, str(root / "scripts"))
    import build_clients

    from gts import constants as c

    apps = json.loads(dump.read_text())["apps"]
    excl = c.EXCLUDED_CLIENT_IDS
    r1 = build_clients.build(apps, [dict(e) for e in c.CLIENTS], excl)
    r2 = build_clients.build(apps, [dict(e) for e in r1], excl)
    assert r1 == r2
    # and it matches what's committed in constants.py (generator was run)
    assert r1 == c.CLIENTS


def test_excluded_client_ids_absent_from_clients():
    from gts import constants as c

    present = {e["client_id"] for e in c.CLIENTS}
    for cid in c.EXCLUDED_CLIENT_IDS:
        assert cid not in present, cid


def test_build_clients_exclusion_and_alias_override():
    """Excluded clients are dropped, but an alias on an excluded client overrides the denylist."""
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import build_clients

    apps = {
        "aaaa": {"name": "Noise ZTNA App", "foci": True, "scopes": {}},
        "bbbb": {"name": "Useful App", "foci": True, "scopes": {}},
    }
    # aaaa is excluded and unaliased -> dropped; bbbb excluded but aliased -> kept.
    existing = [{"alias": "keepme", "display_name": "Useful App", "client_id": "bbbb",
                 "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": []}]
    out = build_clients.build(apps, existing, excluded={"aaaa", "bbbb"})
    ids = {e["client_id"]: e["alias"] for e in out}
    assert "aaaa" not in ids            # excluded, no alias -> gone
    assert ids.get("bbbb") == "keepme"  # excluded but aliased -> kept
