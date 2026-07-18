"""Regenerate the CLIENTS table in src/gts/constants.py from the entrascopes scope dump.

Keeps `constants.CLIENTS` the single, static, offline source of truth for first-party /
FOCI clients. `alias` is the only hand-maintained field; display_name, foci, redirect
capability, and graph_scopes are refreshed from resources/entrascopes/firstpartyscopes.json.

Deterministic and idempotent: entries are sorted and formatted the same way every run, so a
second run is a no-op. Only the text between the CLIENTS sentinels is touched.

Usage:  uv run python scripts/build_clients.py
"""

import json
import pathlib
import re
import sys

import requests

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CONSTANTS = REPO_ROOT / "src" / "gts" / "constants.py"
FIRSTPARTY = REPO_ROOT / "resources" / "entrascopes" / "firstpartyscopes.json"
FIRSTPARTY_URL = "https://entrascopes.com/firstpartyscopes.json"
GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"

NATIVECLIENT_URI = "https://login.microsoftonline.com/common/oauth2/nativeclient"
_LOCALHOST_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?(/.*)?$", re.I)

BEGIN = "# ==== BEGIN GENERATED: CLIENTS (managed by the client-inventory skill) ===="
END = "# ==== END GENERATED: CLIENTS ===="
KEY_ORDER = ["alias", "display_name", "client_id", "foci", "localhost", "nativeclient", "graph_scopes"]


def ensure_dump() -> dict:
    """Load the scope dump, downloading it once if not already on disk."""
    if not FIRSTPARTY.exists():
        print(f"downloading {FIRSTPARTY_URL}", file=sys.stderr)
        FIRSTPARTY.parent.mkdir(parents=True, exist_ok=True)
        resp = requests.get(FIRSTPARTY_URL, timeout=60)
        resp.raise_for_status()
        FIRSTPARTY.write_bytes(resp.content)
    return json.loads(FIRSTPARTY.read_text())["apps"]


def redirect_support(rec: dict) -> tuple[bool, bool]:
    uris = list(rec.get("redirect_uris") or [])
    for key in ("preferred_interactive_redirurl", "preferred_noninteractive_redirurl"):
        if rec.get(key):
            uris.append(rec[key])
    localhost = any(_LOCALHOST_RE.match(u) for u in uris)
    nativeclient = any(u.rstrip("/") == NATIVECLIENT_URI for u in uris)
    return localhost, nativeclient


def graph_scopes(rec: dict) -> list[str]:
    scopes = {s.lower() for s in rec.get("scopes", {}).get(GRAPH_RESOURCE_ID, [])}
    return sorted(scopes)


def current_clients() -> list[dict]:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from gts import constants  # noqa: E402

    return [dict(e) for e in constants.CLIENTS]


def build(apps: dict, existing: list[dict], excluded: set[str] = frozenset()) -> list[dict]:
    """Merge the dump with the existing table. Preserves `alias`; refreshes everything else.

    Entry set = FOCI clients (from the dump) + every currently-aliased client id, so
    aliased-but-not-FOCI clients (azcli/azps/vs) are retained with foci=False. Entries that
    are neither FOCI nor aliased are dropped, as are any in `excluded` -- unless they carry an
    alias, which always wins.
    """
    alias_of = {e["client_id"]: e["alias"] for e in existing if e["alias"]}
    existing_by_id = {e["client_id"]: e for e in existing}

    ids = {cid for cid, rec in apps.items() if rec.get("foci")} | set(alias_of)
    ids -= {cid for cid in excluded if cid not in alias_of}
    out: list[dict] = []
    for cid in ids:
        rec = apps.get(cid)
        if rec is None:
            # Aliased client absent from the dump -- keep the existing entry verbatim.
            print(f"warning: {alias_of.get(cid)} ({cid}) not in dump; keeping existing entry",
                  file=sys.stderr)
            out.append(existing_by_id[cid])
            continue
        localhost, nativeclient = redirect_support(rec)
        out.append(
            {
                "alias": alias_of.get(cid),
                "display_name": rec.get("name", ""),
                "client_id": cid,
                "foci": bool(rec.get("foci")),
                "localhost": localhost,
                "nativeclient": nativeclient,
                "graph_scopes": graph_scopes(rec),
            }
        )
    out.sort(key=lambda e: (e["display_name"].lower(), e["client_id"]))
    return out


def _fmt_scalar(v) -> str:
    if isinstance(v, bool):
        return "True" if v else "False"
    if v is None:
        return "None"
    return json.dumps(v)


def format_entry(entry: dict) -> str:
    parts = []
    for key in KEY_ORDER:
        v = entry[key]
        if key == "graph_scopes":
            inner = ", ".join(json.dumps(s) for s in v)
            parts.append(f'"{key}": [{inner}]')
        else:
            parts.append(f'"{key}": {_fmt_scalar(v)}')
    return "    {" + ", ".join(parts) + "},"


def render_block(clients: list[dict]) -> str:
    lines = [BEGIN, "# Regenerate with: uv run python scripts/build_clients.py", "CLIENTS = ["]
    lines += [format_entry(e) for e in clients]
    lines += ["]", END]
    return "\n".join(lines)


def summarize(old: list[dict], new: list[dict]) -> None:
    old_by, new_by = {e["client_id"]: e for e in old}, {e["client_id"]: e for e in new}
    added = [new_by[c]["display_name"] for c in new_by.keys() - old_by.keys()]
    dropped = [old_by[c]["display_name"] for c in old_by.keys() - new_by.keys()]
    foci_flips = [
        f"{new_by[c]['display_name']}: {old_by[c].get('foci')}->{new_by[c]['foci']}"
        for c in old_by.keys() & new_by.keys()
        if old_by[c].get("foci") != new_by[c]["foci"]
    ]
    print(f"clients: {len(old)} -> {len(new)}", file=sys.stderr)
    if added:
        print(f"  added:   {sorted(added)}", file=sys.stderr)
    if dropped:
        print(f"  dropped: {sorted(dropped)}", file=sys.stderr)
    for flip in sorted(foci_flips):
        print(f"  foci:    {flip}", file=sys.stderr)
    # Curation aid: clients that made the cut but have no Graph scopes -- candidates for the
    # EXCLUDED_CLIENT_IDS denylist. Not dropped automatically (denylist-only by design).
    zero_scope = sorted(e["display_name"] for e in new if not e["graph_scopes"])
    if zero_scope:
        print(f"  0-scope (not excluded): {zero_scope}", file=sys.stderr)


def main() -> int:
    apps = ensure_dump()
    existing = current_clients()  # also puts src/ on sys.path for the import below
    from gts import constants

    new = build(apps, existing, constants.EXCLUDED_CLIENT_IDS)
    summarize(existing, new)

    text = CONSTANTS.read_text()
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        print("error: CLIENTS sentinels not found in constants.py", file=sys.stderr)
        return 1
    CONSTANTS.write_text(pattern.sub(lambda _: render_block(new), text))
    print(f"wrote {CONSTANTS.relative_to(REPO_ROOT)} ({len(new)} clients)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
