"""Static configuration: endpoints, first-party clients, and privilege/risk reference
data. Ported from mgc-token-tools and mgc-enum."""

# -- Endpoints --
MS_GRAPH_API_BASE_URL = "https://graph.microsoft.com"
MS_GRAPH_V1_URL = "https://graph.microsoft.com/v1.0"
MS_GRAPH_BETA_URL = "https://graph.microsoft.com/beta"
MSO_LOGIN_URL = "https://login.microsoftonline.com"
MSO_AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MSO_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MSO_DEVICECODE_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
AUTH_CODE_REDIRECT_URI = "https://login.microsoftonline.com/common/oauth2/nativeclient"

# Default client used when none is supplied (Microsoft Azure PowerShell).
DEFAULT_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"
DEFAULT_TENANT = "organizations"

# Common User-Agent so token endpoints treat us like a normal client.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)

# -- Risky Graph application (app-role) permissions --
RISKY_APP_PERMISSIONS = [
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "ServicePrincipalEndpoint.ReadWrite.All",
    "Directory.AccessAsUser.All",
]

# -- Privileged directory roles (fallback when the beta isPrivileged filter is unused) --
DEFAULT_PRIVILEGED_ROLES = [
    "Application Administrator",
    "Application Developer",
    "Authentication Administrator",
    "Authentication Extensibility Administrator",
    "B2C IEF Keyset Administrator",
    "Cloud Application Administrator",
    "Cloud Device Administrator",
    "Conditional Access Administrator",
    "Directory Writers",
    "Domain Name Administrator",
    "External Identity Provider Administrator",
    "Global Administrator",
    "Global Reader",
    "Helpdesk Administrator",
    "Hybrid Identity Administrator",
    "Intune Administrator",
    "Lifecycle Workflows Administrator",
    "Password Administrator",
    "Privileged Authentication Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Security Operator",
    "Security Reader",
    "User Administrator",
]

# fmt: off
# -- First-party clients (aliases + FOCI family, unified) --
# `alias` is the only hand-maintained field; the rest are regenerated from the entrascopes
# scope dump so FOCI membership, redirect capability, and scopes stay current -- with no
# runtime dependency on that (gitignored) file. See the `client-inventory` skill.

# Clients to keep OUT of CLIENTS (ZTNA / limited-use / noise). Hand-maintained; consulted by
# scripts/build_clients.py at generation time. Aliasing a client overrides this. Excluded
# clients are not tracked as FOCI, so `refresh-to` will reject them.
EXCLUDED_CLIENT_IDS = {
    "cde6adac-58fd-4b78-8d6d-9beaf1b0d668",  # Global Secure Access Client (ZTNA)
    "a40d7d7d-59aa-447e-a655-679a4107e548",  # Accounts Control UI
    "be1918be-3fe3-4be9-b32b-b542fc27f02e",  # M365 Compliance Drive Client
    "844cca35-0656-46ce-b636-13f48b0eecbd",  # Microsoft Stream Mobile Native
    "87749df4-7ccf-48f8-aa87-704bad0e0e16",  # Microsoft Teams - Device Admin Agent
    "e9cee14e-f26a-4349-886f-10048e3ef4b8",  # Yammer Android
    "b87b6fc6-536c-411d-9005-110ee6db77dc",  # Yammer iPad 
    "a569458c-7f2b-45cb-bab9-b7dee514d112",  # Yammer iPhone
    "038ddad9-5bbe-4f64-b0cd-12434d1e633b",  # ZTNA Network Access Client
    "d5e23a82-d7e1-4886-af25-27037a0fdc2a",  # ZTNA Network Access Client -- M365
    "760282b4-0cfc-4952-b467-c8e0298fee16",  # ZTNA Network Access Client -- Private
    "ca01d00c-bfd6-46d6-ae7d-be5b5267d037",  # ZTNA Policy Service Client
}

#
# ==== BEGIN GENERATED: CLIENTS (managed by the client-inventory skill) ====
# Regenerate with: uv run python scripts/build_clients.py
CLIENTS = [
    {"alias": "copilot", "display_name": "Copilot App", "client_id": "14638111-3389-403d-b206-a6a71d9f8f16", "foci": True, "localhost": True, "nativeclient": True, "graph_scopes": ["email", "openid", "profile", "profilephoto.read.all", "user.read"]},
    {"alias": None, "display_name": "Designer App", "client_id": "598ab7bb-a59c-4d31-ba84-ded22c220dbd", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["chat.read", "email", "files.readwrite.all", "mail.readwrite", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Loop", "client_id": "0922ef46-e1b9-4f7e-9134-9ad00547eb41", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["contacts.read", "email", "files.readwrite.all", "filestoragecontainer.selected", "informationprotectionpolicy.read", "mail.send", "openid", "organization.read.all", "people.read", "profile", "recordsmanagement.read.all", "tasks.readwrite", "user.invite.all", "user.read", "user.read.all", "user.readbasic.all"]},
    {"alias": None, "display_name": "Managed Meeting Rooms", "client_id": "eb20f3e3-3dce-4d2c-b721-ebb8d4414067", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["devicemanagementserviceconfig.read.all", "email", "group.read.all", "licenseassignment.readwrite.all", "openid", "organization.read.all", "place.readwrite.all", "profile", "rolemanagement.read.directory", "user.manageidentities.all", "user.read", "user.read.all"]},
    {"alias": None, "display_name": "Microsoft 365 Copilot", "client_id": "0ec893e0-5785-4de6-99da-4ed124e5296c", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["calendars.readbasic", "contacts.read", "email", "family.read", "files.readwrite.all", "filestoragecontainer.selected", "groupmember.read.all", "informationprotectionpolicy.read", "notes.create", "notes.readwrite.all", "openid", "organization.read.all", "people.read", "presence.read", "presence.read.all", "profile", "sensitivitylabel.read", "tasks.readwrite", "user.read", "user.readbasic.all"]},
    {"alias": None, "display_name": "Microsoft Authenticator App", "client_id": "4813382a-8fa7-425e-ab75-3b753aab3abb", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "organization.read.all", "profile", "userauthenticationmethod.read", "userauthenticationmethod.readwrite", "userauthmethodauthapp-msauthapp.delete", "userauthmethodauthapp-passkey.create", "userauthmethodauthapp-passkey.delete", "userauthmethodauthapp-policy.read"]},
    {"alias": "azcli", "display_name": "Microsoft Azure CLI", "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "foci": False, "localhost": True, "nativeclient": True, "graph_scopes": ["application.readwrite.all", "approleassignment.readwrite.all", "auditlog.read.all", "delegatedpermissiongrant.readwrite.all", "directory.accessasuser.all", "email", "group.readwrite.all", "openid", "profile", "user.read.all", "user.readwrite.all"]},
    {"alias": "azpowershell", "display_name": "Microsoft Azure PowerShell", "client_id": "1950a258-227b-4e31-a9cf-717495945fc2", "foci": False, "localhost": True, "nativeclient": True, "graph_scopes": ["application.readwrite.all", "approleassignment.readwrite.all", "auditlog.read.all", "delegatedpermissiongrant.readwrite.all", "directory.accessasuser.all", "email", "group.readwrite.all", "openid", "profile", "user.read.all"]},
    {"alias": None, "display_name": "Microsoft Bing Search", "client_id": "cf36b471-5b44-428c-9ce7-313bf84528de", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "profile", "sites.read.all", "user.read"]},
    {"alias": None, "display_name": "Microsoft Defender for Mobile", "client_id": "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Microsoft Defender Platform", "client_id": "cab96880-db5b-4e15-90a7-f3f1d62ffe39", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["device.read.all", "email", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Microsoft Edge", "client_id": "e9c51622-460d-4d3d-952d-966a5b1da34c", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["eduroster.readbasic", "email", "group.read.all", "openid", "profile", "user.read", "user.readbasic.all", "useractivity.readwrite.createdbyapp"]},
    {"alias": None, "display_name": "Microsoft Edge", "client_id": "ecd6b820-32c2-49b6-98a6-444530e5a77a", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["calendars.read", "content.process.user", "email", "files.readwrite", "files.readwrite.all", "notes.create", "notes.readwrite", "notes.readwrite.all", "openid", "people.read", "profile", "protectionscopes.compute.user", "user.read", "user.readbasic.all"]},
    {"alias": None, "display_name": "Microsoft Edge", "client_id": "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Microsoft Edge Enterprise New Tab Page", "client_id": "d7b530a4-7680-4c23-a8bf-c52c121d2e87", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["calendars.read", "calendars.read.shared", "contacts.read", "email", "files.read", "files.read.all", "files.readwrite", "mail.read", "openid", "profile", "tasks.readwrite", "user.read", "user.read.all", "user.readbasic.all"]},
    {"alias": None, "display_name": "Microsoft Edge MSAv2", "client_id": "82864fa0-ed49-4711-8395-a0e6003dca1f", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["email", "family.read", "files.readwrite", "files.readwrite.all", "notes.create", "notes.readwrite", "notes.readwrite.all", "openid", "people.read", "profile", "user.read"]},
    {"alias": None, "display_name": "Microsoft Flow Mobile PROD-GCCH-CN", "client_id": "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "group.readbasic.all", "openid", "profile", "user.readbasic.all"]},
    {"alias": None, "display_name": "Microsoft Intune Company Portal", "client_id": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["device.read.all", "email", "openid", "profile", "serviceprincipalendpoint.read.all", "user.read"]},
    {"alias": None, "display_name": "Microsoft Lists App on Android", "client_id": "a670efe7-64b6-454f-9ae9-4f1cf27aba58", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "groupmember.read.all", "openid", "people.read", "profile", "user.read.all", "user.readbasic.all"]},
    {"alias": "msoffice", "display_name": "Microsoft Office", "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["auditlog.create", "calendar.readwrite", "calendars.read.shared", "calendars.readwrite", "channel.create", "channel.readbasic.all", "channelmember.readwrite.all", "channelmessage.read.all", "channelmessage.send", "channelsettings.readwrite.all", "chat.create", "chat.readwrite", "chatmember.readwrite", "contacts.readwrite", "datalosspreventionpolicy.evaluate", "directory.accessasuser.all", "directory.read.all", "email", "files.read", "files.read.all", "files.readwrite.all", "filestoragecontainer.selected", "group.read.all", "group.readwrite.all", "informationprotectionpolicy.read", "mail.readwrite", "mail.send", "notes.create", "openid", "organization.read.all", "people.read", "people.read.all", "printer.read.all", "printershare.readbasic.all", "printjob.create", "printjob.readwritebasic", "profile", "reports.read.all", "sensitiveinfotype.detect", "sensitiveinfotype.read.all", "sensitivitylabel.evaluate", "tasks.readwrite", "team.readbasic.all", "teammember.readwrite.all", "teamstab.readwriteforchat", "user.read.all", "user.readbasic.all", "user.readwrite", "users.read"]},
    {"alias": "planner", "display_name": "Microsoft Planner", "client_id": "66375f6b-983f-4c2c-9701-d680650f588f", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["directory.read.all", "email", "files.readwrite", "files.readwrite.all", "group.readwrite.all", "openid", "profile", "user.read.all"]},
    {"alias": None, "display_name": "Microsoft Power BI", "client_id": "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["email", "openid", "profile", "user_impersonation"]},
    {"alias": "msteams", "display_name": "Microsoft Teams", "client_id": "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["appcatalog.read.all", "calendars.read", "calendars.read.shared", "calendars.readwrite", "calendars.readwrite.shared", "channel.readbasic.all", "chatmessage.send", "contacts.readwrite.shared", "email", "files.readwrite.all", "filestoragecontainer.selected", "group.read.all", "informationprotectionpolicy.read", "mail.readwrite", "mail.send", "mailboxsettings.readwrite", "notes.readwrite.all", "openid", "organization.read.all", "people.read", "place.read.all", "profile", "sites.readwrite.all", "tasks.readwrite", "team.readbasic.all", "teamsappinstallation.readforteam", "teamstab.create", "user.readbasic.all"]},
    {"alias": None, "display_name": "Microsoft Teams-T4L", "client_id": "8ec6bc83-69c8-4392-8f08-b3c986009232", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "files.readwrite.all", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Microsoft To-Do client", "client_id": "22098786-6e16-43cc-a27d-191a01a1e3b5", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "profile", "user.read"]},
    {"alias": "whiteboard", "display_name": "Microsoft Whiteboard Client", "client_id": "57336123-6e14-4acc-8dcf-287b6088aa28", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["application.read.all", "calendars.read", "channel.readbasic.all", "channelmessage.send", "contacts.read", "device.read.all", "directory.read.all", "eduroster.readbasic", "email", "files.readwrite.all", "group.read.all", "mail.readwrite", "mail.send", "notes.create", "notes.read", "notes.readwrite", "openid", "organization.read.all", "orgcontact.read.all", "people.read", "profile", "rolemanagement.read.directory", "user.read", "user.read.all", "user.readbasic.all"]},
    {"alias": "teams-powershell", "display_name": "MS Teams Powershell Cmdlets", "client_id": "12128f48-ec9e-42f0-b203-ea49fb6af367", "foci": False, "localhost": True, "nativeclient": False, "graph_scopes": ["appcatalog.readwrite.all", "channel.delete.all", "channelmember.readwrite.all", "channelsettings.readwrite.all", "email", "group.readwrite.all", "openid", "profile", "reports.read.all", "teamsappinstallation.readwriteforuser", "teamsettings.readwrite.all", "user.read.all"]},
    {"alias": None, "display_name": "ODSP Mobile Lists App", "client_id": "540d4ff4-b4c0-44c1-bd06-cab1782d582a", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["calendars.read", "contacts.read", "directory.read.all", "email", "group.read.all", "openid", "people.read", "profile", "sites.fullcontrol.all", "user.read.all", "user.readbasic.all"]},
    {"alias": None, "display_name": "Office 365 Management", "client_id": "00b41c95-dab0-4487-9791-b9d2c32c80f2", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["contacts.read", "contacts.readwrite", "directory.accessasuser.all", "email", "mail.readwrite", "mail.readwrite.all", "openid", "people.read", "people.readwrite", "profile", "tasks.readwrite", "user.readwrite", "user.readwrite.all"]},
    {"alias": "onedrive-app", "display_name": "OneDrive", "client_id": "b26aadf8-566f-4478-926f-589f601d9c74", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["contacts.read", "directory.read.all", "email", "family.read", "files.readwrite.all", "group.read.all", "openid", "people.read", "profile", "sites.read.all", "user.read.all"]},
    {"alias": "onedrive-ios", "display_name": "OneDrive iOS App", "client_id": "af124e86-4e96-495a-b70a-90f90ab96707", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["contacts.read", "directory.read.all", "email", "files.readwrite", "group.read.all", "openid", "people.read", "profile", "sites.read.all", "user.read.all"]},
    {"alias": "onedrive", "display_name": "OneDrive SyncEngine", "client_id": "ab9b8c07-8f02-4f72-87fa-80105867a763", "foci": True, "localhost": False, "nativeclient": True, "graph_scopes": ["email", "files.read", "openid", "profile", "sites.read.all", "user.read"]},
    {"alias": None, "display_name": "Outlook Lite", "client_id": "e9b154d0-7658-433b-bb25-6b8e0a8a7c59", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "profile", "user.read"]},
    {"alias": "outlook", "display_name": "Outlook Mobile", "client_id": "27922004-5251-4030-b22d-91ecd9a37ea4", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "files.readwrite.all", "filestoragecontainer.selected", "mail.read", "mail.read.shared", "openid", "people.read", "people.read.all", "presence.read.all", "profile", "sites.readwrite.all", "user.read", "user.readbasic.all", "userauthenticationmethod.readwrite"]},
    {"alias": None, "display_name": "PowerApps", "client_id": "4e291c71-d680-4d0e-9640-0a3358e31177", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "openid", "profile", "user.read"]},
    {"alias": "sharepoint", "display_name": "SharePoint", "client_id": "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["contacts.read", "directory.read.all", "email", "files.readwrite", "group.read.all", "openid", "people.read", "profile", "sites.read.all", "user.read.all"]},
    {"alias": "sharepoint-android", "display_name": "SharePoint Android", "client_id": "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["contacts.read", "directory.read.all", "email", "group.read.all", "member.read.hidden", "openid", "organization.read.all", "people.read", "profile", "sites.read.all", "user.read.all"]},
    {"alias": "vs", "display_name": "Visual Studio - Legacy", "client_id": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", "foci": False, "localhost": True, "nativeclient": True, "graph_scopes": ["application.readwrite.all", "directory.read.all", "email", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Windows Search", "client_id": "26a7ee05-5602-4d76-a7ba-eae8b7b67941", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["email", "files.read.all", "files.readwrite", "openid", "profile", "user.read"]},
    {"alias": None, "display_name": "Yammer Web", "client_id": "c1c74fed-04c9-4704-80dc-9f79a2e515cb", "foci": True, "localhost": False, "nativeclient": False, "graph_scopes": ["appcatalog.read.all", "email", "files.read.all", "openid", "profile", "teamsappinstallation.readforuser"]},
]
# ==== END GENERATED: CLIENTS ====
# fmt: on


def _record(client_id: str) -> dict | None:
    for entry in CLIENTS:
        if entry["client_id"] == client_id:
            return entry
    return None


def client_record(client_id: str) -> dict | None:
    """The full CLIENTS entry for a client id, or None if unknown."""
    return _record(client_id)


def get_client_id_from_alias(alias: str) -> str | None:
    """Resolve an alias (e.g. 'azcli') to a client id, or None if unknown."""
    for entry in CLIENTS:
        if entry["alias"] == alias:
            return entry["client_id"]
    return None


def get_alias(client_id: str) -> str | None:
    """Reverse lookup: client id -> alias, or None."""
    rec = _record(client_id)
    return rec["alias"] if rec else None


def resolve_client_id(value: str) -> str:
    """Accept either an alias or a raw client id and return a client id."""
    return get_client_id_from_alias(value) or value


def foci_app_name(client_id: str) -> str | None:
    """Friendly name for a FOCI client id, or None if not a known FOCI client."""
    rec = _record(client_id)
    return rec["display_name"] if rec and rec["foci"] else None


def is_foci_client(client_id: str) -> bool:
    """Whether the client is a current member of the FOCI family (data-authoritative)."""
    rec = _record(client_id)
    return bool(rec and rec["foci"])


def foci_clients() -> list[dict]:
    """All FOCI client records."""
    return [e for e in CLIENTS if e["foci"]]


def aliased_clients() -> list[dict]:
    """All client records that have an alias."""
    return [e for e in CLIENTS if e["alias"]]


def client_graph_scopes(client_id: str) -> set[str]:
    """Lowercased delegated Graph scopes the client is pre-authorized for; empty if unknown."""
    rec = _record(client_id)
    return set(rec["graph_scopes"]) if rec else set()


def redirect_support(client_id: str) -> tuple[bool, bool]:
    """(localhost, nativeclient) redirect capability; (False, False) if unknown."""
    rec = _record(client_id)
    return (rec["localhost"], rec["nativeclient"]) if rec else (False, False)
