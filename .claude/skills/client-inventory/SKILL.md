---
name: client-inventory
description: Refresh the CLIENTS table in src/gts/constants.py (first-party / FOCI clients) from the entrascopes scope dump, so refresh-to's FOCI check, `gts clients query`, the enum guard, and the FOCI/redirect columns stay current. Use when FOCI membership may have changed, after an entrascopes refresh, or when refresh-to wrongly accepts/rejects a client.
---

# Client inventory

`constants.CLIENTS` is the single, static, offline source of truth for first-party and FOCI
clients. `refresh-to`'s FOCI check (`is_foci_client`), `gts clients query`, the `enum` guard,
and the FOCI/localhost/nativeclient columns all read it — nothing reads `firstpartyscopes.json`
at runtime. This skill regenerates `CLIENTS` from that dump so the data stays current.

## Run it

```bash
uv run python scripts/build_clients.py
```

- Downloads `resources/entrascopes/firstpartyscopes.json` (gitignored) if it isn't already on
  disk; otherwise uses the local copy as-is. The script never touches the network when the
  file is present.
- Prints a summary: clients added / dropped / FOCI flips.
- Rewrites only the text between the `# ==== BEGIN/END GENERATED: CLIENTS ====` sentinels in
  `src/gts/constants.py`. Everything else in that file is hand-written and untouched.
- Deterministic and **idempotent**: a second run produces no diff.

After running, `uv run pytest -q -k "clients or foci or guard or CLIENTS"` and `ruff check .`.

## The merge rule (what the script guarantees)

- **`alias` is the only curated field** — it's preserved by `client_id` from the existing
  table. `display_name`, `foci`, `localhost`, `nativeclient`, and `graph_scopes` are always
  overwritten from the dump (the dump's `name` matches the curated display names; no FOCI
  name has underscores, so no cleanup is needed).
- **Entry set** = every `foci == True` client in the dump **plus** every currently-aliased
  `client_id`. So aliased-but-not-FOCI clients (Azure CLI / PowerShell / VS) are retained with
  `foci=False`; new FOCI clients are added with `alias=None`.
- **Dropped:** an entry that is neither FOCI nor aliased (a former pivot target that left the
  family), or any `client_id` in `constants.EXCLUDED_CLIENT_IDS`. Aliased entries are never
  dropped — an alias overrides the denylist.
- **Aliased but absent from the dump:** the existing entry is kept verbatim and a warning is
  printed — the script can't refresh data it doesn't have.
- **Ordering:** by `display_name` (case-insensitive), tie-break `client_id`; fixed key order;
  scopes lowercased and sorted.

## To exclude a client

Add its `client_id` to `EXCLUDED_CLIENT_IDS` in `constants.py` (hand-maintained, above the
generated block) and re-run the script. It's removed from `CLIENTS` entirely, so it won't show
in `clients query` and `refresh-to <it>` is rejected (no longer tracked as FOCI). To un-exclude
for a specific client, give it an alias — the alias always wins.

Each run also prints `0-scope (not excluded): […]` — FOCI clients with no Graph scopes that
survived. They aren't dropped automatically (denylist-only by design); use the list to decide
which `client_id`s to add to `EXCLUDED_CLIENT_IDS`.

## To add an alias

Add or edit the `alias` on the relevant entry in `constants.CLIENTS` (or add a minimal entry
with just `alias` + `client_id`), then run the script — it fills the rest and re-sorts. Alias
names must stay unique (a test enforces this).

## Related

The permission maps the enum guard uses come from a different generator — see the
`graph-permissions` skill (`scripts/build_permission_resources.py`, which emits
`src/gts/enum/scopes.py`). This skill only owns `CLIENTS`.
