"""Enumeration operations. Each takes a GraphClient and returns plain JSON-able data.

The value here is the enrichment: mapping appRole GUIDs to permission names, flagging
risky Graph permissions, and resolving group members of privileged role assignments.

The slow commands (service-principals, privileged-role-assignments) make one independent
Graph call per item, so those loops fan out across a bounded thread pool via `_gather`.
Only the network fetch runs in threads; enrichment stays single-threaded, so there are no
shared-state races.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

from .. import constants as c
from ..graph import GraphClient
from ..progress import NullProgress

MAX_WORKERS = 8

_T = TypeVar("_T")
_R = TypeVar("_R")


def _gather(
    fn: Callable[[_T], _R], items: list[_T], advance: Callable[[], None]
) -> list[_R]:
    """Run `fn` over `items` concurrently, returning results in input order and calling
    `advance()` as each completes."""
    if not items:
        return []
    results: list[_R] = [None] * len(items)  # type: ignore[list-item]
    workers = min(MAX_WORKERS, len(items))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, item): i for i, item in enumerate(items)}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
            advance()
    return results


def get_organization(client: GraphClient) -> list[dict]:
    return client.get_all("organization")


def get_current_user(client: GraphClient) -> dict:
    return client.get("me")


def get_current_user_memberships(client: GraphClient) -> list[dict]:
    return client.get_all("me/transitiveMemberOf")


def get_users(client: GraphClient) -> list[dict]:
    # $top=999 (max page size) cuts sequential pagination round-trips; same fields returned.
    return client.get_all("users?$top=999")


def get_groups(client: GraphClient) -> list[dict]:
    return client.get_all("groups")


def get_group_members(client: GraphClient, group_id: str) -> list[dict]:
    return client.get_all(f"groups/{group_id}/members?$top=999")


def get_conditional_access_policies(client: GraphClient) -> list[dict]:
    return client.get_all("identity/conditionalAccess/policies")


def get_app_roles(client: GraphClient) -> list[dict]:
    """appRole id -> {id, displayName, value} for the Microsoft Graph SP. Needed to
    translate appRoleAssignment GUIDs into human-readable permission names."""
    sps = client.get_all("servicePrincipals?$filter=displayName eq 'Microsoft Graph'")
    if not sps:
        return []
    return [
        {"id": r["id"], "displayName": r["displayName"], "value": r["value"]}
        for r in sps[0].get("appRoles", [])
    ]


def get_service_principals(
    client: GraphClient, *, owned_only: bool = False, progress=NullProgress()
) -> dict:
    """Service principals with resolved Graph permissions and a separate list of those
    holding risky permissions.

    Enumerates ALL service principals by default -- third-party / multi-tenant apps holding
    risky app-roles are usually the interesting ones. Pass owned_only=True to restrict to
    apps owned by this tenant (appOwnerOrganizationId == tenant_id)."""
    approles = get_app_roles(client)
    role_by_id = {r["id"]: r["value"] for r in approles}

    sps = client.get_all("servicePrincipals?$top=999")
    if owned_only:
        org = get_organization(client)
        tenant_id = org[0]["id"] if org else None
        sps = [sp for sp in sps if sp.get("appOwnerOrganizationId") == tenant_id]

    # One appRoleAssignments call per SP -- the slow part; fan out across threads.
    def _assignments(sp: dict) -> list[dict]:
        return client.get_all(
            f"servicePrincipals/{sp['id']}/appRoleAssignments?$top=999"
        )

    with progress.task("Service principals", total=len(sps)) as advance:
        per_sp = _gather(_assignments, sps, advance)

    result: list[dict] = []
    privileged: list[dict] = []
    for sp, assignments in zip(sps, per_sp):
        assigned_ids = [a.get("appRoleId") for a in assignments]
        sp["appRoleAssignments"] = [
            role_by_id[rid] for rid in assigned_ids if rid in role_by_id
        ]
        result.append(sp)
        if any(perm in sp["appRoleAssignments"] for perm in c.RISKY_APP_PERMISSIONS):
            privileged.append(
                {
                    "id": sp["id"],
                    "displayName": sp.get("displayName"),
                    "appRoleAssignments": sp["appRoleAssignments"],
                }
            )

    return {
        "service_principals": result,
        "privileged_service_principals": privileged,
    }


def get_privileged_roles(client: GraphClient, use_beta: bool = False) -> list[dict]:
    """Directory role definitions considered privileged."""
    if use_beta:
        return client.get_all(
            "roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true",
            beta=True,
        )
    roles = client.get_all("roleManagement/directory/roleDefinitions")
    return [r for r in roles if r.get("displayName") in c.DEFAULT_PRIVILEGED_ROLES]


def _process_role(client: GraphClient, role: dict) -> dict:
    """Resolve one privileged role's assignments (with group members / user UPNs). Builds a
    fresh dict and only reads via the client, so it's safe to run concurrently per role."""
    results = client.get_all(
        "roleManagement/directory/roleAssignments"
        f"?$filter=roleDefinitionId eq '{role['id']}'&$expand=principal&$top=999"
    )
    assignees: list[dict] = []
    for r in results:
        principal = r.get("principal") or {}
        ptype = principal.get("@odata.type", "")
        assignee = {
            "principalId": principal.get("id"),
            "type": ptype,
            "displayName": principal.get("displayName"),
        }
        if ptype == "#microsoft.graph.group":
            assignee["members"] = get_group_members(client, principal["id"])
        if ptype == "#microsoft.graph.user":
            assignee["userPrincipalName"] = principal.get("userPrincipalName")
        assignees.append(assignee)
    return {
        "roleId": role["id"],
        "roleName": role.get("displayName"),
        "assignees": assignees,
    }


def get_privileged_role_assignments(
    client: GraphClient, use_beta: bool = False, *, progress=NullProgress()
) -> list[dict]:
    """Assignments to privileged roles, resolving group members and user UPNs."""
    roles = get_privileged_roles(client, use_beta=use_beta)
    with progress.task("Privileged roles", total=len(roles)) as advance:
        return _gather(lambda role: _process_role(client, role), roles, advance)
