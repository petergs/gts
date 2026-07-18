"""Generate resources/graph_endpoint_permissions.json and
resources/enum_command_permissions.json from the Microsoft Graph docs.

Source: https://github.com/microsoftgraph/microsoft-graph-docs-contrib, pinned to
SOURCE_REF so regeneration is reproducible. Bump SOURCE_REF deliberately to pick up
upstream changes.

Permission tables are parsed deterministically from markdown -- the tables are regular
and machine-generated, so there is nothing to interpret. The script fails loudly on a
404 or a missing table rather than emitting an empty entry: a silent gap here would
later read as "this client has sufficient permissions" when it does not.

Usage:  uv run python scripts/build_permission_resources.py
"""

import datetime
import json
import pathlib
import re
import sys

import requests

from permission_overrides import APP_ONLY_UNSUPPORTED, OVERRIDES

SOURCE_REPO = "microsoftgraph/microsoft-graph-docs-contrib"
SOURCE_REF = "62224816c538d192a2f3630c797a6b2171034bee"
RAW = f"https://raw.githubusercontent.com/{SOURCE_REPO}/{SOURCE_REF}"

API_DIR = "api-reference/v1.0/api"
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "resources"
ENUM_SCOPES_PY = REPO_ROOT / "src" / "gts" / "enum" / "scopes.py"

# Delegated scope that reads the directory as the signed-in user -- treated as a wildcard
# by the enum guard (we don't verify the user's actual privilege).
WILDCARD_SCOPE = "directory.accessasuser.all"
CONDITIONAL_ACCESS_ENDPOINT = "GET /identity/conditionalAccess/policies"

# -- Endpoint inventory ------------------------------------------------------------
# Extracted from src/gts/enum/operations.py. Endpoint key -> doc page under API_DIR.
ENDPOINT_DOCS: dict[str, str] = {
    "GET /organization": "organization-list.md",
    "GET /me": "user-get.md",
    "GET /me/transitiveMemberOf": "user-list-transitivememberof.md",
    "GET /users": "user-list.md",
    "GET /groups": "group-list.md",
    "GET /groups/{id}/members": "group-list-members.md",
    "GET /identity/conditionalAccess/policies": "conditionalaccessroot-list-policies.md",
    "GET /servicePrincipals": "serviceprincipal-list.md",
    "GET /servicePrincipals/{id}/appRoleAssignments": (
        "serviceprincipal-list-approleassignments.md"
    ),
    "GET /roleManagement/directory/roleDefinitions": (
        "rbacapplication-list-roledefinitions.md"
    ),
    "GET /roleManagement/directory/roleAssignments": (
        "rbacapplication-list-roleassignments.md"
    ),
}

# -- Subcommand -> endpoints -------------------------------------------------------
# Mirrors the enum sub-app in src/gts/cli.py. Kept as an explicit literal: deriving it
# by static analysis of operations.py would be fragile and silently wrong when calls move.
COMMAND_ENDPOINTS: dict[str, list[dict]] = {
    "organization": [
        {"endpoint": "GET /organization", "required": True},
    ],
    "current-user": [
        {"endpoint": "GET /me", "required": True},
    ],
    "current-user-memberships": [
        {"endpoint": "GET /me/transitiveMemberOf", "required": True},
    ],
    "users": [
        {"endpoint": "GET /users", "required": True},
    ],
    "groups": [
        {"endpoint": "GET /groups", "required": True},
    ],
    "conditional-access": [
        {"endpoint": "GET /identity/conditionalAccess/policies", "required": True},
    ],
    "service-principals": [
        {
            "endpoint": "GET /servicePrincipals",
            "required": True,
            "purpose": (
                "listed twice: filtered by displayName eq 'Microsoft Graph' to resolve "
                "appRole GUIDs, then unfiltered to enumerate tenant-owned SPs"
            ),
        },
        {
            "endpoint": "GET /organization",
            "required": True,
            "purpose": "resolve tenant id for the appOwnerOrganizationId filter",
        },
        {
            "endpoint": "GET /servicePrincipals/{id}/appRoleAssignments",
            "required": True,
            "per_item": True,
            "purpose": "resolve granted app roles per service principal",
        },
    ],
    "privileged-role-assignments": [
        {
            "endpoint": "GET /roleManagement/directory/roleDefinitions",
            "required": True,
            "purpose": (
                "v1.0 filtered client-side against DEFAULT_PRIVILEGED_ROLES; with --beta, "
                "the beta endpoint with $filter=isPrivileged eq true"
            ),
        },
        {
            "endpoint": "GET /roleManagement/directory/roleAssignments",
            "required": True,
            "purpose": "$expand=principal per privileged role definition",
        },
        {
            "endpoint": "GET /groups/{id}/members",
            "required": False,
            "conditional": "only when a group is assigned a privileged role",
            "purpose": "resolve group members of group principals",
        },
    ],
}
COMMAND_ENDPOINTS["all"] = []  # filled in below as the union

# Pages that document several permission tables -- one per RBAC provider -- require a
# heading to disambiguate. gts only ever calls the directory provider. Without this the
# parser silently picks the last table on the page (entitlement management), which is wrong.
DOC_SECTIONS: dict[str, str] = {
    "GET /roleManagement/directory/roleDefinitions": (
        "For the directory (Microsoft Entra ID) provider"
    ),
    "GET /roleManagement/directory/roleAssignments": (
        "For the directory (Microsoft Entra ID) provider"
    ),
}

ROW_LABELS = {
    "Delegated (work or school account)": "delegated_work_school",
    "Delegated (personal Microsoft account)": "delegated_personal",
    "Application": "application",
}

INCLUDE_RE = re.compile(r"\[!INCLUDE\s*\[[^\]]*\]\(([^)]*permissions/[^)]+\.md)\)\]")

_session = requests.Session()


def fetch(path: str) -> str:
    """Fetch a raw file from the pinned ref. Raises on any non-200."""
    url = f"{RAW}/{path}"
    resp = _session.get(url, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code} fetching {url}")
    return resp.text


def parse_permission_table(md: str) -> dict | None:
    """Parse the permission table out of markdown. None if absent.

    Two upstream formats exist and both are in active use:

    * 3-column (autogenerated `includes/permissions/*.md`):
      |Permission type|Least privileged permissions|Higher privileged permissions|
    * 2-column (legacy, hand-maintained inline tables marked `blockType: ignored`):
      |Permission type|Permissions (from least to most privileged)|
      -- ordered least to most, so the first entry is the least privileged.
    """
    rows: dict[str, dict] = {}
    for line in md.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        key = ROW_LABELS.get(cells[0]) if cells else None
        if key is None:
            continue
        if len(cells) == 3:
            rows[key] = {
                "least": split_perms(cells[1]),
                "higher": split_perms(cells[2]),
            }
        elif len(cells) == 2:
            perms = split_perms(cells[1])
            rows[key] = {
                "least": perms[:1],
                "higher": perms[1:],
                "format": "legacy-ordered",
            }
    return rows or None


def split_perms(cell: str) -> list[str]:
    """Split a comma-separated permission cell. 'Not supported.' -> []."""
    cell = cell.strip()
    if not cell or cell.rstrip(".").strip().lower() in {"not supported", "none"}:
        return []
    return [p.strip() for p in cell.split(",") if p.strip()]


def select_section(md: str, heading: str) -> str:
    """Return just the markdown under `heading`, up to the next same-or-higher heading."""
    lines = md.splitlines()
    start = None
    level = 0
    for i, line in enumerate(lines):
        if line.lstrip("#").strip() == heading and line.startswith("#"):
            start = i + 1
            level = len(line) - len(line.lstrip("#"))
            break
    if start is None:
        raise RuntimeError(f"section not found: {heading!r}")
    for j in range(start, len(lines)):
        line = lines[j]
        if line.startswith("#"):
            depth = len(line) - len(line.lstrip("#"))
            if depth <= level:
                return "\n".join(lines[start:j])
    return "\n".join(lines[start:])


def count_tables(md: str) -> int:
    """How many permission tables the markdown contains (by header row)."""
    return sum(
        1 for line in md.splitlines() if line.strip().startswith("|Permission type")
    )


def resolve_permissions(doc_page: str, section: str | None) -> tuple[dict, str | None]:
    """Return (table, include_path). Follows an {INCLUDE} to the permissions file if
    present, otherwise parses the inline table on the API page.

    Raises when a page holds multiple permission tables and no section was given --
    picking one arbitrarily would produce confidently wrong permissions.
    """
    page_path = f"{API_DIR}/{doc_page}"
    md = fetch(page_path)

    m = INCLUDE_RE.search(md)
    if m:
        # Include paths are relative to API_DIR, e.g. ../includes/permissions/x.md
        include_path = normalize(f"{API_DIR}/{m.group(1)}")
        table = parse_permission_table(fetch(include_path))
        if table is None:
            raise RuntimeError(f"no permission table in include {include_path}")
        return table, include_path

    if section:
        md = select_section(md, section)
    elif count_tables(md) > 1:
        raise RuntimeError(
            f"{page_path} has {count_tables(md)} permission tables and no section "
            f"filter; add one to DOC_SECTIONS to disambiguate"
        )

    table = parse_permission_table(md)
    if table is None:
        raise RuntimeError(f"no permission table found in {page_path}")
    return table, None


def normalize(path: str) -> str:
    """Collapse '..' segments in a POSIX-style repo path (no filesystem access)."""
    parts: list[str] = []
    for part in path.split("/"):
        if part == "..":
            if not parts:
                raise ValueError(f"path escapes repo root: {path}")
            parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def build_endpoints() -> dict:
    out: dict = {}
    for endpoint, doc_page in ENDPOINT_DOCS.items():
        table, include_path = resolve_permissions(doc_page, DOC_SECTIONS.get(endpoint))
        override = OVERRIDES.get(endpoint)
        app_supported = endpoint not in APP_ONLY_UNSUPPORTED

        if override:
            effective = {
                "delegated": override["delegated"],
                "application": override["application"],
            }
            note = override["note"]
            curation = "overridden"
        else:
            effective = {
                "delegated": table.get("delegated_work_school", {}).get("least", []),
                "application": (
                    table.get("application", {}).get("least", [])
                    if app_supported
                    else None
                ),
            }
            note = None
            curation = "verbatim"

        out[endpoint] = {
            "doc_page": f"{API_DIR}/{doc_page}",
            "doc_section": DOC_SECTIONS.get(endpoint),
            "permissions_include": include_path,
            "documented": table,
            "effective_least_privileged": effective,
            "app_only_supported": app_supported,
            "note": note,
            "curation": curation,
        }
        print(f"  {endpoint}  ({curation})", file=sys.stderr)
    return out


def build_commands(endpoints: dict) -> dict:
    # 'all' runs every other subcommand; union their endpoint entries, de-duplicated
    # on endpoint name while keeping the first (most specific) description.
    seen: dict[str, dict] = {}
    for name, entries in COMMAND_ENDPOINTS.items():
        if name == "all":
            continue
        for entry in entries:
            seen.setdefault(entry["endpoint"], entry)
    COMMAND_ENDPOINTS["all"] = list(seen.values())

    out: dict = {}
    for name, entries in COMMAND_ENDPOINTS.items():
        delegated: list[list[str]] = []
        application: list[list[str]] = []
        optional_delegated: list[list[str]] = []
        optional_application: list[list[str]] = []
        blockers: list[str] = []

        for entry in entries:
            info = endpoints[entry["endpoint"]]
            eff = info["effective_least_privileged"]
            required = entry.get("required", True)
            d_bucket = delegated if required else optional_delegated
            a_bucket = application if required else optional_application

            if eff["delegated"] and eff["delegated"] not in d_bucket:
                d_bucket.append(eff["delegated"])
            if info["app_only_supported"]:
                if eff["application"] and eff["application"] not in a_bucket:
                    a_bucket.append(eff["application"])
            elif required:
                blockers.append(entry["endpoint"])

        # `all` runs each subcommand independently and skips failures (see enum_all in
        # cli.py), so an app-only token still completes the endpoints it can reach.
        # A single-endpoint command with a blocker, by contrast, simply cannot run.
        if not blockers:
            app_only = "supported"
        elif name == "all":
            app_only = "partial"
        else:
            app_only = "unsupported"

        entry_app_perms = application if app_only != "unsupported" else None

        out[name] = {
            "endpoints": entries,
            "required_permissions": {
                "delegated": delegated,
                "application": entry_app_perms,
            },
            "optional_permissions": {
                "delegated": optional_delegated,
                "application": optional_application,
            }
            if optional_delegated or optional_application
            else None,
            "app_only": app_only,
            "app_only_blocked_by": blockers or None,
        }

    # Which whole subcommands an app-only token has to skip during `enum all`.
    out["all"]["app_only_skipped_commands"] = sorted(
        n
        for n, v in out.items()
        if n != "all" and v.get("app_only") == "unsupported"
    )
    return out


def _accepted_delegated(endpoints: dict, endpoint: str) -> list[str]:
    """Lowercased delegated scopes a call accepts (least + higher), junk tokens dropped,
    order preserved (least first)."""
    row = endpoints[endpoint]["documented"]["delegated_work_school"]
    out: list[str] = []
    for scope in row["least"] + row["higher"]:
        s = scope.lower()
        if " " not in s and s not in out:
            out.append(s)
    return out


def build_enum_scopes(endpoints: dict) -> dict:
    """Per enum command, the accepted delegated scopes for each *required* endpoint. This
    is what the runtime guard checks against a client's baked scopes, so it ships as a
    static module (src/gts/enum/scopes.py) -- no runtime read of resources/."""
    required: dict[str, list[dict]] = {}
    for name, entries in COMMAND_ENDPOINTS.items():
        rows = []
        for entry in entries:
            if not entry.get("required", True):
                continue
            rows.append(
                {"endpoint": entry["endpoint"],
                 "accepted": _accepted_delegated(endpoints, entry["endpoint"])}
            )
        required[name] = rows

    ca = sorted(set(_accepted_delegated(endpoints, CONDITIONAL_ACCESS_ENDPOINT)) | {WILDCARD_SCOPE})
    return {
        "ENUM_REQUIRED_SCOPES": required,
        "CONDITIONAL_ACCESS_SCOPES": ca,
        "WILDCARD_SCOPE": WILDCARD_SCOPE,
    }


def write_enum_scopes_module(data: dict) -> None:
    """Emit src/gts/enum/scopes.py deterministically. json.dumps produces a valid Python
    literal here (only str/list/dict, no bool/None)."""
    header = (
        '"""Static enum-guard scope data. GENERATED by '
        "scripts/build_permission_resources.py -- do not edit by hand.\n\n"
        "ENUM_REQUIRED_SCOPES[command] lists each required endpoint and the delegated Graph\n"
        "scopes that satisfy it (any one suffices). The guard warns/prompts when the active\n"
        "client holds none of them (and not the WILDCARD_SCOPE) for some required endpoint.\n"
        '"""\n\n'
    )
    body = (
        f"ENUM_REQUIRED_SCOPES = {json.dumps(data['ENUM_REQUIRED_SCOPES'], indent=4)}\n\n"
        f"CONDITIONAL_ACCESS_SCOPES = {json.dumps(data['CONDITIONAL_ACCESS_SCOPES'], indent=4)}\n\n"
        f"WILDCARD_SCOPE = {json.dumps(data['WILDCARD_SCOPE'])}\n"
    )
    ENUM_SCOPES_PY.write_text(header + body)
    print(f"wrote {ENUM_SCOPES_PY.relative_to(REPO_ROOT)}", file=sys.stderr)


def main() -> None:
    print(f"fetching from {SOURCE_REPO}@{SOURCE_REF[:12]}", file=sys.stderr)
    endpoints = build_endpoints()
    commands = build_commands(endpoints)

    meta = {
        "source_repo": f"https://github.com/{SOURCE_REPO}",
        "source_ref": SOURCE_REF,
        "graph_version": "v1.0",
        "generated_by": "scripts/build_permission_resources.py",
        "generated": datetime.date.today().isoformat(),
        "semantics": (
            "effective_least_privileged lists ALTERNATIVES: any one satisfies the call. "
            "required_permissions is a list of alternative-sets: every inner list must be "
            "satisfied by at least one of its members (an AND of ORs). A null application "
            "value means no app-only token can make the call."
        ),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for filename, payload in (
        ("graph_endpoint_permissions.json", endpoints),
        ("enum_command_permissions.json", commands),
    ):
        path = OUT_DIR / filename
        path.write_text(json.dumps({"_meta": meta, **payload}, indent=2) + "\n")
        print(f"wrote {path.relative_to(REPO_ROOT)}", file=sys.stderr)

    write_enum_scopes_module(build_enum_scopes(endpoints))


if __name__ == "__main__":
    main()
