# graph-token-tools PLAN-v2.md

> **Note:** this is a historical design record. The package was later renamed from
> `graph_token_tools` / `gtt` to `gts` (Graph Token Store); names below are unchanged.

## Context

`gtt` consolidates two existing personal security tools — `mgc-token-tools` (`mtt`) and
`mgc-enum` — into one CLI whose goal is **identifying risky users and applications in an
Azure/Entra environment**. Both existing tools are coupled to `mgc` (the now-deprecated
Microsoft Graph CLI): `mtt` stores tokens in mgc's MSAL-format keychain entry and shells out
to `mgc login`/`logout`; `mgc-enum` shells out to `mgc`/`mgc-beta` for **every** Graph call.
`gtt` reimplements the needed functionality natively and drops the `mgc` dependency entirely.

This document supersedes PLAN-v1.md. The changes from v1 are recorded below so the reasoning
is not lost.

## What changed from PLAN-v1 (and why)

1. **Added a `login` subcommand.** v1's subcommand list had no entry point for the three
   required auth flows (client-credentials, device-code, interactive-browser). `login --flow`
   provides them; `refresh-to` remains separate as the FOCI refresh flow.
2. **Introduced an explicit "active identity" concept.** `status`/`switch` relied on mgc's
   `~/.mgc/authRecord`. Decoupled, `gtt` keeps its own `state.json` pointer.
3. **Defined how `enum` gets a token.** It previously shelled to mgc. Now it reads an access
   token from the cache, silently refreshes expired user tokens, and calls Graph directly —
   including `@odata.nextLink` pagination and 429/`Retry-After` handling.
4. **Fixed the service-principal schema.** Client-credentials issues no refresh token, so SP
   entries store only `access_token` + `expires_on` and are re-acquired on expiry. No secrets
   are persisted in the cache blob.
5. **Split storage into two layers:** a dumb `StorageBackend` (opaque get/set/delete of one
   string) and a `TokenCache` that owns the JSON schema.
6. **Deferred 1Password.** Its SDK is async and needs a service-account token. Ship the
   interface plus `keyring`-based macOS Keychain + gnome-keyring first; add 1Password later.
7. **Relaxed `requires-python`** from `>=3.14` to `>=3.12`.
8. **Interactive-browser login uses the manual auth-code paste flow** initially (ported from
   `mtt`), with a loopback+PKCE listener as a later enhancement.
9. **Added the `gtt` entry point** to `pyproject.toml`.

## Goal

A single `gtt` CLI, decoupled from `mgc`, that authenticates to Microsoft Graph natively,
stores tokens in a pluggable secret backend using a clean multi-user/multi-SP schema, and
enumerates risky users and applications in Entra.

## Dependencies (approved)

`typer` (CLI), `keyring` (macOS Keychain + gnome-keyring), `pyjwt` (JWT parsing),
`requests` (HTTP). `onepassword-sdk` is deferred to a later phase. Confirm before adding
anything else. `requires-python = ">=3.12"`.

## Package layout (`src/graph_token_tools/`)

- `cli.py` — Typer app, `main()`, wires subcommands (Typer sub-app for `enum`).
- `constants.py` — port `FOCI_CLIENTS`, `CLIENT_ALIASES`, endpoint URLs,
  `RISKY_APP_PERMISSIONS`, `DEFAULT_PRIVILEGED_ROLES` from the old repos verbatim.
- `jwt_utils.py` — decode claims via `pyjwt` (`oid`, `tid`, `appid`,
  `upn`/`preferred_username`, `scp`, `exp`). Replaces the manual base64 `_parse_jwt_claims`.
- `storage/` — `base.py` (`StorageBackend` protocol: `get() -> str | None`, `set(str)`,
  `delete()`), `keyring_backend.py` (single blob under service `graph-token-tools`, username
  `token-cache`), `onepassword_backend.py` stubbed for later.
- `cache.py` — `TokenCache`: owns the JSON schema (below), (de)serializes the blob through a
  `StorageBackend`. Methods: `get_user_token`, `get_sp_token`, `upsert_*`, `list_identities`,
  `remove`.
- `state.py` — active-identity pointer at `~/.config/gtt/state.json`
  (`{"active": {"kind": "user|sp", "key": ..., "client_id": ...}}`). Never stores secrets.
- `auth.py` — the flows (below), each returning a normalized token record for the cache.
- `graph.py` — `GraphClient(access_token)`: `get(path, beta=False)` with `@odata.nextLink`
  pagination and 429/`Retry-After` retry; pulls/refreshes the token from cache + active state.
- `enum/` — one module per enumeration, ported from `mgc-enum` but calling `GraphClient`
  instead of `run_mgc_cmd`.

## Token cache schema

```json
{
  "users": {
    "first.last@contoso.com": {
      "tenant_id": "...", "tenant_domain": "...", "user_id": "<oid>",
      "applications": {
        "<client_id>": {
          "access_token": "...", "refresh_token": "...",
          "app_display_name": "...", "scopes": ["..."],
          "expires_on": 0, "foci": true
        }
      }
    }
  },
  "service_principals": {
    "<client_id>": {
      "access_token": "...", "expires_on": 0,
      "service_principal_display_name": "...", "tenant_id": "..."
    }
  }
}
```

Notes: users are keyed by UPN (tenant_id stored inside; guest accounts carry `#EXT#` UPNs).
SP entries have **no** `refresh_token` and **no** secret.

## Auth flows (`auth.py`) — all pure `requests`, no MSAL

- **Device code:** POST `/{tenant}/oauth2/v2.0/devicecode` → show
  `user_code`/`verification_uri` → poll `/token` (`grant_type=device_code`) until success.
- **Interactive browser (manual paste):** port `mtt.cache.auth_token_login` — print the
  authorize URL, user pastes the redirected URL, exchange `code` at `/token`. (Loopback+PKCE
  listener is a documented later enhancement.)
- **Client credentials:** POST `/{tenant}/oauth2/v2.0/token`
  (`grant_type=client_credentials`, `scope=.../.default`, secret **or** cert). Store the SP
  access token + expiry only.
- **FOCI refresh (`refresh-to`):** port `mtt.cache.foci_login` almost verbatim (already pure
  HTTP) — validate `new_client_id` against `FOCI_CLIENTS`, refresh, store the new
  access+refresh under the user.
- **Silent refresh helper:** for user tokens, if `expires_on` is past and a refresh token
  exists, refresh transparently before Graph calls.

## Subcommands (`gtt ...`)

- `login --flow {device|browser|client-credentials} [--client-id/-c] [--tenant]
  [--secret/--cert]` — default client = Azure PowerShell alias; on success upsert into cache
  and set active state.
- `logout [--all]` — remove the active (or all) identities from the cache + clear state.
  **No** mgc keychain manipulation.
- `status` — print the active identity: user/SP, client_id, tenant, alias, scopes (decoded
  from the active access token). Reads cache + state, not `~/.mgc`.
- `switch -c <client-id|alias>` — set the active identity to a cached one; error if no valid
  token.
- `aliases [-f json|table]` — print `CLIENT_ALIASES` (port directly).
- `dump -c <client-id|alias> -t {access|refresh}` — print a stored secret (port `dump_token`).
- `insert` — insert an externally-sourced token. Access tokens: derive metadata from JWT
  claims (as today). Refresh tokens: **require** `-c/--client-id` and `--user`, since refresh
  tokens are opaque.
- `refresh-to -c <foci-client-id|alias>` — FOCI login using the active user's cached refresh
  token.
- `enum <sub>` — Typer sub-app; each pulls a Graph token via active state and calls
  `GraphClient`.

## `enum` sub-subcommands (ported from `mgc-enum`, Graph REST direct)

`organization`, `current-user` (`/me`), `current-user-memberships`
(`/me/transitiveMemberOf`), `users` (`/users`, paginated), `groups` (`/groups`, paginated),
`service-principals` (list SPs in tenant, map appRole GUIDs→values via the Microsoft Graph SP
appRoles, flag `RISKY_APP_PERMISSIONS`), `privileged-role-assignments` (role-management
directory role definitions + assignments, expand principal, resolve group members),
`conditional-access`, and `all -d <dir>` (write each to JSON).

- Fix the v1 `all` bug: honor `-d`/`--directory` instead of hardcoding `./output`, and don't
  crash when the directory already exists (`exist_ok=True`).
- Reuse the enrichment logic (appRole GUID→value map, risky-permission flagging, group-member
  resolution for privileged roles) — that is the tool's real value.
- Consider the beta `role-management/directory/roleDefinitions?$filter=isPrivileged eq true`
  endpoint to replace the hardcoded `DEFAULT_PRIVILEGED_ROLES` list (optional improvement).

## Cross-cutting concerns

- **Pagination:** a central `_paged_get` following `@odata.nextLink`.
- **Throttling:** honor `Retry-After` on 429 with bounded retries.
- **Secrets hygiene:** never log tokens; keep secrets out of `state.json`.
- **Errors:** clear message + non-zero exit on a missing/expired token with no refresh path.

## Implementation order

1. `pyproject.toml`: deps, `requires-python = ">=3.12"`, `[project.scripts] gtt = "graph_token_tools.cli:main"`.
2. `constants.py`, `jwt_utils.py` (port + pyjwt).
3. `storage/` interface + keyring backend; `cache.py` (new schema); `state.py`.
4. `auth.py` flows + `login`/`logout`/`refresh-to`/`insert`.
5. `status`/`switch`/`aliases`/`dump`.
6. `graph.py` client (pagination + throttling).
7. `enum/` subcommands + `all`.

## Verification

- **Unit (offline):** mock `requests`; feed sample JWTs to assert claim parsing, cache
  round-trip through a fake in-memory backend, schema upsert/lookup for multi-user + SP,
  alias/FOCI validation, pagination follows `nextLink`, 429 retry.
- **Manual (live, authorized tenant):** `gtt login --flow device` → `gtt status` shows the
  identity → `gtt enum current-user`/`users` return data → `gtt refresh-to -c azcli` switches
  the FOCI client → `gtt login --flow client-credentials` then `gtt enum service-principals`
  flags risky SPs. Confirm the keyring blob is written (macOS Keychain / gnome-keyring) and
  that `logout` clears it.

## Open items to confirm during build

- Loopback+PKCE browser login (upgrade from manual paste) — later phase.
- 1Password backend — later phase behind the storage interface.
