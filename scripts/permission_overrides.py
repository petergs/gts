"""Hand-curated corrections to Microsoft's auto-generated permission tables.

The upstream include files under `includes/permissions/` carry the header
`description: "Automatically generated file. DO NOT MODIFY"`, and some of their
least-privileged cells are not what you would actually grant. Rather than editing the
scrape, `build_permission_resources.py` keeps the verbatim values under `documented` and
layers these on top as `effective_least_privileged`.

Every override needs a `note` explaining *why* it diverges, so the divergence stays
auditable when the upstream docs change. Endpoints absent from this table are emitted
with `curation: "verbatim"` and their documented least-privileged values.
"""

# endpoint -> {delegated: [...], application: [...] | None, note: str}
# Each list holds ALTERNATIVES: any single one of them satisfies the endpoint.
OVERRIDES: dict[str, dict] = {
    "GET /groups": {
        "delegated": ["Group.Read.All", "Directory.Read.All"],
        "application": ["Group.Read.All", "Directory.Read.All"],
        "note": (
            "Upstream lists Group-NestingSupport.ReadWrite.All as least privileged, an "
            "artifact of the auto-generated table; it is a nesting-support scope, not a "
            "read scope. Group.Read.All is the practical minimum for listing groups."
        ),
    },
    "GET /me": {
        "delegated": ["User.Read"],
        "application": None,
        "note": (
            "Application permissions aren't supported when using the /me endpoint "
            "(api-reference/v1.0/includes/me-apis-sign-in-note.md). No app-only client "
            "can satisfy this call at any permission level."
        ),
    },
    "GET /me/transitiveMemberOf": {
        "delegated": ["User.Read"],
        "application": None,
        "note": (
            "Same /me app-only restriction as GET /me. The documented application "
            "permissions apply only to the /users/{id}/transitiveMemberOf form."
        ),
    },
}

# Endpoints that cannot be served by a client-credentials (app-only) token, regardless of
# granted permissions. Drives `app_only_supported` in the generated resource.
APP_ONLY_UNSUPPORTED: set[str] = {
    "GET /me",
    "GET /me/transitiveMemberOf",
}
