"""Compute the minimum set of FOCI clients whose combined delegated Graph scopes cover
`gts enum all`.

gts pivots between family-of-client-ids apps with `.default` (src/gts/auth.py), so each
FOCI client unlocks the delegated Graph scopes it is pre-authorized for. This finds the
fewest clients that, combined, satisfy every endpoint enum all touches -- under the
"any accepted scope" model: a client covers an endpoint if it holds ANY scope the call
accepts (least or any higher-privileged alternative), per resources/graph_endpoint_permissions.json.

Candidate pool = constants.foci_clients() minus any client holding Directory.AccessAsUser.All
(full directory access as the signed-in user -- would trivially cover everything and mask the
answer). Azure CLI / PowerShell are already excluded by virtue of no longer being FOCI.

Client scope data comes from the gitignored resources/entrascopes/firstpartyscopes.json;
download it first (see resources/entrascopes/README.md). This script never fetches it.

Usage:  uv run python scripts/analyze_foci_min_set.py
"""

import datetime
import itertools
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from gts import constants as c  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESOURCES = REPO_ROOT / "resources"
FIRSTPARTY = RESOURCES / "entrascopes" / "firstpartyscopes.json"
GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"

DYNAMIC_EXCLUDE_SCOPE = "directory.accessasuser.all"

# A real Graph delegated scope: no spaces. Filters parse artifacts like "Not available."
SCOPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9.\-]*$")


def load_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def accepted_scopes(endpoint_perms: dict, endpoint: str) -> list[str]:
    """Full set of delegated scopes a call accepts (least + higher), junk filtered."""
    row = endpoint_perms[endpoint]["documented"]["delegated_work_school"]
    out: list[str] = []
    for scope in row["least"] + row["higher"]:
        if SCOPE_RE.match(scope) and scope not in out:
            out.append(scope)
    return out


def client_graph_scopes(apps: dict, client_id: str) -> set[str] | None:
    """Lowercased Graph delegated scopes for a client, or None if absent from data."""
    app = apps.get(client_id)
    if app is None:
        return None
    return {s.lower() for s in app.get("scopes", {}).get(GRAPH_RESOURCE_ID, [])}


def covers(client_scopes: set[str], accepted: list[str]) -> str | None:
    """Return the (first) accepted scope the client holds, or None."""
    for scope in accepted:
        if scope.lower() in client_scopes:
            return scope
    return None


def min_set_cover(
    targets: list[str],
    accepted_by: dict[str, list[str]],
    scopes_by: dict[str, set[str]],
    names: dict[str, str],
) -> tuple[int, list[list[str]]]:
    """All minimum-cardinality client subsets covering every target endpoint.

    Exhaustive by increasing k over only the clients that cover >=1 target (the pruned
    pool is small). Returns (size, [sorted client-id lists]); (0, []) if nothing to cover.
    """
    if not targets:
        return 0, []
    pool = [
        cid
        for cid in scopes_by
        if any(covers(scopes_by[cid], accepted_by[t]) for t in targets)
    ]
    # deterministic order: broadest scope sets first, then by name
    pool.sort(key=lambda cid: (-len(scopes_by[cid]), names[cid]))

    def satisfied(combo: tuple[str, ...]) -> bool:
        union: set[str] = set().union(*(scopes_by[cid] for cid in combo))
        return all(covers(union, accepted_by[t]) for t in targets)

    for k in range(1, len(pool) + 1):
        solutions = [
            sorted(combo) for combo in itertools.combinations(pool, k) if satisfied(combo)
        ]
        if solutions:
            return k, solutions
    return len(pool) + 1, []  # unreachable when every target is individually coverable


def attribute(clients: list[str], accepted_by, scopes_by, names) -> dict:
    out = {}
    for endpoint, accepted in accepted_by.items():
        for cid in clients:
            hit = covers(scopes_by[cid], accepted)
            if hit:
                out[endpoint] = {"client_id": cid, "app_name": names[cid], "via_scope": hit}
                break
        else:
            out[endpoint] = None
    return out


def main() -> int:
    if not FIRSTPARTY.exists():
        print(
            f"missing {FIRSTPARTY.relative_to(REPO_ROOT)} -- download it first:\n"
            "  cd resources/entrascopes && wget https://entrascopes.com/firstpartyscopes.json",
            file=sys.stderr,
        )
        return 1

    apps = load_json(FIRSTPARTY)["apps"]
    endpoint_perms = load_json(RESOURCES / "graph_endpoint_permissions.json")
    commands = load_json(RESOURCES / "enum_command_permissions.json")

    all_entries = commands["all"]["endpoints"]
    required_eps = [e["endpoint"] for e in all_entries if e.get("required", True)]
    optional_eps = [e["endpoint"] for e in all_entries if not e.get("required", True)]
    accepted_by = {
        e["endpoint"]: accepted_scopes(endpoint_perms, e["endpoint"]) for e in all_entries
    }

    # -- Build candidate pool, recording every exclusion and data gap ------------
    foci = c.foci_clients()
    names = {x["client_id"]: x["display_name"] for x in foci}
    scopes_by: dict[str, set[str]] = {}
    excluded = {"directory_access_as_user": [], "absent_from_data": []}
    for client in foci:
        cid, name = client["client_id"], client["display_name"]
        sc = client_graph_scopes(apps, cid)
        if sc is None:
            excluded["absent_from_data"].append({"client_id": cid, "app_name": name})
            continue
        if DYNAMIC_EXCLUDE_SCOPE in sc:
            excluded["directory_access_as_user"].append({"client_id": cid, "app_name": name})
            continue
        scopes_by[cid] = sc

    # -- Which required endpoints can any candidate cover at all? ----------------
    coverable, uncoverable = [], []
    for ep in required_eps:
        if any(covers(scopes_by[cid], accepted_by[ep]) for cid in scopes_by):
            coverable.append(ep)
        else:
            uncoverable.append(ep)

    # Attribute each hole: would an excluded (Directory.AccessAsUser.All) client have covered it?
    excluded_scopes = {}
    for entry in excluded["directory_access_as_user"]:
        sc = client_graph_scopes(apps, entry["client_id"])
        if sc:
            excluded_scopes[entry["client_id"]] = (entry["app_name"], sc)

    uncoverable_detail = []
    for ep in uncoverable:
        by_excluded = [
            nm for _, (nm, sc) in excluded_scopes.items() if covers(sc, accepted_by[ep])
        ]
        uncoverable_detail.append(
            {
                "endpoint": ep,
                "accepted": accepted_by[ep],
                "coverable_only_by_excluded": sorted(by_excluded) or None,
                "note": (
                    "no family client (incl. excluded) carries an accepted scope"
                    if not by_excluded
                    else "excluded clients would have covered this"
                ),
            }
        )

    # -- Minimum set over the coverable required endpoints ----------------------
    size, solutions = min_set_cover(coverable, accepted_by, scopes_by, names)
    with_optional = [ep for ep in coverable + optional_eps]
    opt_coverable = [
        ep for ep in with_optional
        if any(covers(scopes_by[cid], accepted_by[ep]) for cid in scopes_by)
    ]
    size_opt, solutions_opt = min_set_cover(opt_coverable, accepted_by, scopes_by, names)

    def render(sols: list[list[str]]) -> list[dict]:
        return [
            {
                "clients": [{"client_id": cid, "app_name": names[cid]} for cid in sol],
                "scope_attribution": attribute(sol, accepted_by, scopes_by, names),
            }
            for sol in sols
        ]

    result = {
        "_meta": {
            "command": "enum all",
            "coverage_model": "any-accepted-scope (least or any higher-privileged alternative)",
            "candidate_count": len(scopes_by),
            "data_source": "entrascopes firstpartyscopes.json (Graph resource "
            f"{GRAPH_RESOURCE_ID})",
            "generated_by": "scripts/analyze_foci_min_set.py",
            "generated": datetime.date.today().isoformat(),
            "caveats": [
                "Capability, not guarantee: .default yields the app's pre-authorized "
                "scopes intersected with what the user/tenant consented; this says which "
                "clients CAN carry the scopes, not that a given sign-in will.",
                "Delegated effective permission = app scope AND the signed-in user's "
                "directory privilege. A token bearing Directory.Read.All still returns "
                "data only if the user actually has that access.",
                "/me endpoints stay in the required set (they need only User.Read). "
                "GroupMember.Read.All (groups/{id}/members) is optional -- reported "
                "separately -- since it is only reached when a group holds a privileged role.",
            ],
        },
        "excluded_clients": excluded,
        "required_endpoints": required_eps,
        "optional_endpoints": optional_eps,
        "accepted_scopes": accepted_by,
        "uncoverable_required_endpoints": uncoverable_detail,
        "minimum_set": {
            "covers": coverable,
            "size": size,
            "note": (
                "covers the coverable required endpoints; uncoverable ones listed separately"
                if uncoverable
                else "covers all required endpoints"
            ),
            "solutions": render(solutions),
        },
        "minimum_set_with_optional": {
            "covers": opt_coverable,
            "size": size_opt,
            "solutions": render(solutions_opt),
        },
    }

    out_path = RESOURCES / "foci_min_set.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n")

    # -- Human summary to stderr ------------------------------------------------
    print(f"candidates: {len(scopes_by)} "
          f"(excluded {len(excluded['directory_access_as_user'])} directory-access, "
          f"{len(excluded['absent_from_data'])} absent)", file=sys.stderr)
    print(f"required endpoints: {len(required_eps)}  "
          f"coverable: {len(coverable)}  uncoverable: {len(uncoverable)}", file=sys.stderr)
    if uncoverable:
        for u in uncoverable_detail:
            print(f"  UNCOVERABLE {u['endpoint']}  "
                  f"(excluded-only: {u['coverable_only_by_excluded']})", file=sys.stderr)
    print(f"minimum set size (coverable required): {size}, "
          f"{len(solutions)} tied solution(s)", file=sys.stderr)
    if solutions:
        for sol in solutions[:5]:
            print(f"  - {', '.join(names[cid] for cid in sol)}", file=sys.stderr)
        if len(solutions) > 5:
            print(f"  ... and {len(solutions) - 5} more", file=sys.stderr)
    print(f"wrote {out_path.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
