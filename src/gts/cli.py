"""gts — Graph Token Store CLI.

Consolidates token management (login/dump/switch/refresh-to/insert) and Entra
enumeration (enum ...) into one tool, decoupled from the deprecated `mgc` CLI.
"""

import json
import pathlib
import sys
import time
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import auth
from . import config
from . import constants as c
from . import jwt_utils
from . import menu
from . import progress
from . import state
from .cache import TokenCache
from .enum import operations as ops
from .enum import scopes as enum_scopes
from .graph import GraphClient, GraphError

app = typer.Typer(
    add_completion=False,
    help="A cli for managing Graph API tokens",
    no_args_is_help=True,
)
enum_app = typer.Typer(
    add_completion=False,
    help="Enumerate Entra directory objects.",
    no_args_is_help=True,
)
app.add_typer(enum_app, name="enum")
config_app = typer.Typer(
    add_completion=False,
    help="View and edit non-secret settings (~/.config/gts/settings.json).",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")
clients_app = typer.Typer(
    add_completion=False,
    help="Search and reference first-party / FOCI clients.",
    no_args_is_help=True,
)
app.add_typer(clients_app, name="clients")


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """A cli for managing Graph API tokens"""


def _err(msg: str) -> None:
    typer.secho(f"Error: {msg}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


def _print_json(data) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


console = Console()


def _yesno(flag: bool) -> str:
    return "[green]yes[/]" if flag else "[dim]no[/]"


def _conditional_access_blocked(client_id: str) -> bool:
    """True when we know the client cannot read conditional-access policies (so `enum all`
    skips it instead of making a call that 403s). False when it can, or when we lack scope
    data for the client (then we attempt the call and let the API be the arbiter)."""
    scopes = c.client_graph_scopes(client_id)
    return bool(scopes) and scopes.isdisjoint(enum_scopes.CONDITIONAL_ACCESS_SCOPES)


def _enum_insufficient_endpoints(command: str, client_id: str) -> list[str]:
    """Required endpoints of an enum subcommand the active client cannot cover.

    Returns [] when we can't tell (the client isn't in CLIENTS / has no scope data) so the
    guard never blocks on missing reference data. Directory.AccessAsUser.All covers everything.
    """
    available = c.client_graph_scopes(client_id)
    if not available or enum_scopes.WILDCARD_SCOPE in available:
        return []
    missing = []
    for entry in enum_scopes.ENUM_REQUIRED_SCOPES.get(command, []):
        accepted = set(entry["accepted"])
        if accepted and available.isdisjoint(accepted):
            missing.append(entry["endpoint"])
    return missing


def _enum_preflight(command: str) -> None:
    """Guard against running `enum <command>` with an insufficient client.

    When the active client is positively known to lack an accepted scope for a required
    endpoint (a predicted 403), prompt for confirmation interactively and abort on 'no'. In a
    non-interactive session there's no one to prompt, so warn and proceed (don't hang a script).
    """
    active = state.get_active()
    if active is None:
        return
    missing = _enum_insufficient_endpoints(command, active.client_id)
    if not missing:
        return
    who = c.get_alias(active.client_id) or active.client_id
    msg = (
        f"active client '{who}' likely can't read {len(missing)} endpoint(s) for "
        f"'enum {command}' (will 403): {', '.join(missing)}.\n"
        f"Try `gts clients query --scope Directory.Read.All` then `gts refresh-to`."
    )
    if not menu.is_interactive():
        typer.secho(f"warning: {msg}", fg=typer.colors.YELLOW, err=True)
        return
    typer.secho(msg, fg=typer.colors.YELLOW, err=True)
    if not typer.confirm("Proceed anyway?", default=False):
        raise typer.Exit(1)


# -- login / logout --
@app.command()
def login(
    flow: str = typer.Option(
        "browser", "--flow", help="device | browser | nativeclient | client-credentials"
    ),
    client_id: Optional[str] = typer.Option(
        None, "--client-id", "-c", help="Client id or alias"
    ),
    tenant: str = typer.Option(
        c.DEFAULT_TENANT, "--tenant", help="Tenant id or 'organizations'/'common'"
    ),
    secret: Optional[str] = typer.Option(
        None, "--secret", help="Client secret (client-credentials)"
    ),
):
    """Authenticate and store the resulting token(s), setting the active identity."""
    cache = TokenCache()
    cid = c.resolve_client_id(client_id) if client_id else c.DEFAULT_CLIENT_ID
    client = auth.AuthClient(tenant)
    try:
        if flow == "client-credentials":
            if not secret:
                _err("--secret is required for client-credentials")
            if tenant in (c.DEFAULT_TENANT, "common"):
                _err("--tenant must be a concrete tenant id for client-credentials")
            resp = client.client_credentials(cid, secret)  # type: ignore[arg-type]
            active = auth.persist_sp_token(cache, resp, cid)
        elif flow == "device":
            resp = client.device_code(cid)
            active = auth.persist_user_token(cache, resp, cid)
        elif flow == "browser":
            resp = client.browser_pkce(cid)
            active = auth.persist_user_token(cache, resp, cid)
        elif flow == "nativeclient":
            resp = client.nativeclient(cid)
            active = auth.persist_user_token(cache, resp, cid)
        else:
            _err(
                f"Unknown flow '{flow}'. Use device | browser | nativeclient | "
                "client-credentials."
            )
    except auth.AuthError as e:
        _err(str(e))
    state.set_active(active)
    typer.secho(f"Logged in as {active.key} ({active.kind}).", fg=typer.colors.GREEN)


@app.command()
def logout(
    all_: bool = typer.Option(False, "--all", help="Remove every cached identity"),
):
    """Remove the active identity (or all) from the cache and clear active state."""
    cache = TokenCache()
    if all_:
        cache.clear()
        state.clear_active()
        typer.secho("Cleared all cached identities.", fg=typer.colors.GREEN)
        return
    active = state.get_active()
    if active is None:
        _err("No active identity to log out.")
    if active.kind == "user":  # type: ignore[union-attr]
        cache.remove_user_app(active.key, active.client_id)  # type: ignore[union-attr]
    else:
        cache.remove_sp(active.client_id)  # type: ignore[union-attr]
    cache.save()
    state.clear_active()
    typer.secho("Logged out.", fg=typer.colors.GREEN)


# -- status / switch --
@app.command()
def status():
    """Show the active identity, client, tenant, and scopes."""
    active = state.get_active()
    if active is None:
        _err("No active identity. Run `gts login`.")
    cache = TokenCache()
    out = {
        "kind": active.kind,  # type: ignore[union-attr]
        "identity": active.key,  # type: ignore[union-attr]
        "client_id": active.client_id,  # type: ignore[union-attr]
        "alias": c.get_alias(active.client_id),  # type: ignore[union-attr]
    }
    if active.kind == "user":  # type: ignore[union-attr]
        user = cache.get_user(active.key) or {}  # type: ignore[union-attr]
        out["tenant_id"] = user.get("tenant_id")
        out["tenant_domain"] = user.get("tenant_domain")
        token = cache.get_user_token(active.key, active.client_id)  # type: ignore[union-attr]
        out["app_display_name"] = token.app_display_name if token else None
        out["scopes"] = token.scopes if token else []
        out["access_token"] = jwt_utils.humanize_expiry(
            token.expires_on if token else None
        )
        # Refresh tokens are opaque (no readable expiry); report when we acquired it.
        out["refresh_token"] = {
            "present": bool(token and token.refresh_token),
            "acquired_at": jwt_utils.format_utc(token.acquired_at)
            if token and token.refresh_token
            else None,
        }
    else:
        sp = cache.get_sp_token(active.client_id)  # type: ignore[union-attr]
        out["tenant_id"] = sp.tenant_id if sp else None
        out["app_display_name"] = sp.service_principal_display_name if sp else None
        out["scopes"] = jwt_utils.get_scopes(sp.access_token) if sp else []
        out["access_token"] = jwt_utils.humanize_expiry(sp.expires_on if sp else None)
        # Client-credentials service principals never receive a refresh token.
        out["refresh_token"] = {"present": False, "acquired_at": None}
    _print_json(out)


def _switch_entries(cache: TokenCache) -> list[dict]:
    """All cached identities as selectable rows (users first, then SPs)."""
    entries: list[dict] = []
    for r in cache.list_user_apps():
        entries.append(
            {
                "identity": state.ActiveIdentity(
                    kind="user", key=r["user"], client_id=r["client_id"]
                ),
                "kind": "user",
                "who": r["user"],
                "app": r["app_display_name"] or "",
                "client_id": r["client_id"],
                "alias": c.get_alias(r["client_id"]) or "",
            }
        )
    for r in cache.list_service_principals():
        entries.append(
            {
                "identity": state.ActiveIdentity(
                    kind="sp", key=r["client_id"], client_id=r["client_id"]
                ),
                "kind": "sp",
                "who": "(service principal)",
                "app": r["service_principal_display_name"] or "",
                "client_id": r["client_id"],
                "alias": c.get_alias(r["client_id"]) or "",
            }
        )
    return entries


def _switch_table(entries: list[dict], cursor: int, active) -> Table:
    table = Table(
        title="Select an identity   [dim](↑/↓ move · Enter select · q cancel)[/]",
        header_style="bold cyan",
    )
    table.add_column("", width=1)
    table.add_column("kind", no_wrap=True)
    table.add_column("identity", no_wrap=True)
    table.add_column("app_display_name")
    table.add_column("client_id", no_wrap=True)
    table.add_column("alias", style="yellow")
    for i, e in enumerate(entries):
        is_active = (
            active is not None
            and active.kind == e["kind"]
            and active.key == e["identity"].key
            and active.client_id == e["client_id"]
        )
        who = e["who"] + (" [dim](current)[/]" if is_active else "")
        table.add_row(
            "❯" if i == cursor else " ",
            e["kind"],
            who,
            e["app"],
            e["client_id"],
            e["alias"],
            style="reverse" if i == cursor else None,
        )
    return table


@app.command()
def switch(
    client_id: Optional[str] = typer.Option(
        None,
        "--client-id",
        "-c",
        help="Client id or alias (omit for an interactive menu)",
    ),
):
    """Switch the active identity. With no client id, pick from an interactive menu."""
    cache = TokenCache()
    if client_id:
        cid = c.resolve_client_id(client_id)
        if cache.get_sp_token(cid) is not None:
            state.set_active(state.ActiveIdentity(kind="sp", key=cid, client_id=cid))
            typer.secho(f"Switched to service principal {cid}.", fg=typer.colors.GREEN)
            return
        found = cache.find_user_by_client(cid)
        if found is None:
            _err(f"No valid token cached for client_id={cid}")
        upn, _token = found  # type: ignore[misc]
        state.set_active(state.ActiveIdentity(kind="user", key=upn, client_id=cid))
        typer.secho(f"Switched to {upn} ({cid}).", fg=typer.colors.GREEN)
        return

    # Interactive selection.
    entries = _switch_entries(cache)
    if not entries:
        _err("No cached identities. Run `gts login` first.")
    if not menu.is_interactive():
        _err("Interactive switch needs a terminal; pass --client-id.")
    active = state.get_active()
    start = next(
        (i for i, e in enumerate(entries) if active and e["identity"] == active), 0
    )
    choice = menu.select_index(
        console, lambda idx: _switch_table(entries, idx, active), len(entries), start
    )
    if choice is None:
        typer.echo("Cancelled.")
        raise typer.Exit(0)
    ident = entries[choice]["identity"]
    state.set_active(ident)
    typer.secho(f"Switched to {ident.key} ({ident.client_id}).", fg=typer.colors.GREEN)


# -- aliases / dump --
def _render_aliases(fmt: str) -> None:
    """Render the aliased first-party clients (table or JSON) with FOCI status and
    localhost/nativeclient redirect support (all from the static CLIENTS table)."""
    rows = c.aliased_clients()
    if fmt == "json":
        _print_json(rows)
        return
    caption = "[dim]● = default login client[/]"
    table = Table(
        title="First-party client aliases", header_style="bold cyan", caption=caption
    )
    table.add_column("", width=1)
    table.add_column("alias", style="yellow", no_wrap=True)
    table.add_column("client_id", no_wrap=True)
    table.add_column("display_name")
    table.add_column("foci", justify="center")
    table.add_column("localhost", justify="center")
    table.add_column("nativeclient", justify="center")
    for r in rows:
        is_default = r["client_id"] == c.DEFAULT_CLIENT_ID
        table.add_row(
            "[bold green]●[/]" if is_default else "",
            r["alias"],
            r["client_id"],
            r["display_name"],
            _yesno(r["foci"]),
            _yesno(r["localhost"]),
            _yesno(r["nativeclient"]),
            style="bold" if is_default else None,
        )
    console.print(table)


@app.command()
def aliases(fmt: str = typer.Option("table", "--format", "-f", help="table | json")):
    """List first-party client aliases."""
    _render_aliases(fmt)


@clients_app.command("aliases")
def clients_aliases(
    fmt: str = typer.Option("table", "--format", "-f", help="table | json"),
):
    """List first-party client aliases (also available as top-level `gts aliases`)."""
    _render_aliases(fmt)


@clients_app.command("query")
def clients_query(
    scope: Optional[str] = typer.Option(
        None,
        "--scope",
        help="Graph delegated scope substring (e.g. Directory.Read.All)",
    ),
    name: Optional[str] = typer.Option(None, "--name", help="Display name substring"),
    client_id: Optional[str] = typer.Option(
        None, "--client-id", help="Client id substring/prefix"
    ),
    fmt: str = typer.Option("table", "--format", "-f", help="table | json"),
):
    """Query the CLIENTS table by scope, display name, or client id (filters combine with
    AND). With no filters, it's the whole table.

    JSON is the raw CLIENTS entries; use it to find which client id carries a scope you need
    before `gts refresh-to`.
    """
    scope_l = scope.lower() if scope else None
    name_l = name.lower() if name else None
    cid_l = client_id.lower() if client_id else None

    results = []
    for entry in c.CLIENTS:
        if scope_l and not any(scope_l in s for s in entry["graph_scopes"]):
            continue
        if name_l and name_l not in entry["display_name"].lower():
            continue
        if cid_l and cid_l not in entry["client_id"].lower():
            continue
        results.append(entry)

    if fmt == "json":
        _print_json(results)
        return
    if not results:
        typer.echo("No matching clients.")
        return
    table = Table(title=f"Clients ({len(results)})", header_style="bold cyan")
    table.add_column("client_id", no_wrap=True)
    table.add_column("alias", style="yellow")
    table.add_column("display_name")
    table.add_column("foci", justify="center")
    table.add_column("localhost", justify="center")
    table.add_column("nativeclient", justify="center")
    # When searching by scope show the matching scopes; otherwise a scope count.
    table.add_column("scopes match" if scope_l else "scopes", justify="left")
    for r in results:
        scope_cell = (
            ", ".join(s for s in r["graph_scopes"] if scope_l in s)
            if scope_l
            else str(len(r["graph_scopes"]))
        )
        table.add_row(
            r["client_id"],
            r["alias"] or "",
            r["display_name"],
            _yesno(r["foci"]),
            _yesno(r["localhost"]),
            _yesno(r["nativeclient"]),
            scope_cell,
        )
    console.print(table)


@app.command(name="list")
def list_apps(fmt: str = typer.Option("table", "--format", "-f", help="table | json")):
    """List all cached user client applications."""
    cache = TokenCache()
    rows = cache.list_user_apps()
    for r in rows:
        r["alias"] = c.get_alias(r["client_id"])
        r["foci"] = c.is_foci_client(r["client_id"])
    if fmt == "json":
        _print_json(rows)
        return
    if not rows:
        typer.echo("No cached user applications.")
        return
    active = state.get_active()
    table = Table(
        title="Cached user applications",
        header_style="bold cyan",
        caption="[dim]● = active[/]",
    )
    table.add_column("", width=1)
    table.add_column("user", no_wrap=True)
    table.add_column("app_display_name")
    table.add_column("client_id", no_wrap=True)
    table.add_column("alias", style="yellow")
    table.add_column("foci", justify="center")
    table.add_column("access", justify="center")
    table.add_column("refresh", justify="center")
    for r in rows:
        is_active = (
            active is not None
            and active.kind == "user"
            and active.key == r["user"]
            and active.client_id == r["client_id"]
        )
        table.add_row(
            "[bold green]●[/]" if is_active else "",
            r["user"],
            r["app_display_name"] or "",
            r["client_id"],
            r["alias"] or "",
            _yesno(r["foci"]),
            _yesno(r["has_access_token"]),
            _yesno(r["has_refresh_token"]),
            style="bold green" if is_active else None,
        )
    console.print(table)


@app.command(name="list-sps")
def list_sps(fmt: str = typer.Option("table", "--format", "-f", help="table | json")):
    """List all cached service principals."""
    cache = TokenCache()
    rows = cache.list_service_principals()
    for r in rows:
        r["alias"] = c.get_alias(r["client_id"])
    if fmt == "json":
        _print_json(rows)
        return
    if not rows:
        typer.echo("No cached service principals.")
        return
    active = state.get_active()
    table = Table(
        title="Cached service principals",
        header_style="bold cyan",
        caption="[dim]● = active[/]",
    )
    table.add_column("", width=1)
    table.add_column("display_name")
    table.add_column("client_id", no_wrap=True)
    table.add_column("alias", style="yellow")
    table.add_column("tenant_id", no_wrap=True)
    table.add_column("access", justify="center")
    for r in rows:
        is_active = (
            active is not None
            and active.kind == "sp"
            and active.client_id == r["client_id"]
        )
        table.add_row(
            "[bold green]●[/]" if is_active else "",
            r["service_principal_display_name"] or "",
            r["client_id"],
            r["alias"] or "",
            r["tenant_id"] or "",
            _yesno(r["has_access_token"]),
            style="bold green" if is_active else None,
        )
    console.print(table)


@app.command()
def dump(
    client_id: Optional[str] = typer.Option(
        None, "--client-id", "-c", help="Client id or alias"
    ),
    token_type: str = typer.Option(
        "access", "--token-type", "-t", help="access | refresh"
    ),
):
    """Print a stored access or refresh token secret."""
    cache = TokenCache()
    active = state.get_active()
    cid = (
        c.resolve_client_id(client_id)
        if client_id
        else (active.client_id if active else None)
    )
    if cid is None:
        _err("No client id given and no active identity.")

    # Service principals have only access tokens.
    sp = cache.get_sp_token(cid)  # type: ignore[arg-type]
    if sp is not None:
        if token_type == "refresh":
            _err("Service principals have no refresh token.")
        typer.echo(sp.access_token)
        return

    found = cache.find_user_by_client(cid)  # type: ignore[arg-type]
    if found is None:
        _err(f"No token found for client_id={cid} (alias={c.get_alias(cid)})")  # type: ignore[arg-type]
    _upn, token = found  # type: ignore[misc]
    secret = token.refresh_token if token_type == "refresh" else token.access_token
    if not secret:
        _err(f"No {token_type} token stored for client_id={cid}")
    typer.echo(secret)


# -- refresh-to (FOCI) --
@app.command(name="refresh-to")
def refresh_to(
    client_id: str = typer.Option(
        ..., "--client-id", "-c", help="FOCI client id or alias"
    ),
):
    """Use the active user's cached refresh token to log in as another FOCI client."""
    new_cid = c.resolve_client_id(client_id)
    if not c.is_foci_client(new_cid):
        _err(f"{new_cid} is not a known FOCI client.")
    active = state.get_active()
    if active is None or active.kind != "user":
        _err("refresh-to requires an active user identity.")
    cache = TokenCache()
    token = cache.get_user_token(active.key, active.client_id)  # type: ignore[union-attr]
    if token is None or not token.refresh_token:
        _err("Active user has no cached refresh token.")
    user = cache.get_user(active.key) or {}  # type: ignore[union-attr]
    tenant = user.get("tenant_id") or c.DEFAULT_TENANT
    try:
        resp = auth.AuthClient(tenant).foci_refresh(token.refresh_token, new_cid)  # type: ignore[union-attr]
    except auth.AuthError as e:
        _err(str(e))
    new_active = auth.persist_user_token(cache, resp, new_cid)
    state.set_active(new_active)
    typer.secho(f"Refreshed to {new_cid} as {new_active.key}.", fg=typer.colors.GREEN)


# -- insert --
@app.command()
def insert(
    secret: Optional[str] = typer.Option(
        None, "--secret", "-s", help="Token or JSON blob (or read from stdin)"
    ),
    token_type: str = typer.Option(
        "access", "--token-type", "-t", help="access | refresh | response"
    ),
    client_id: Optional[str] = typer.Option(
        None, "--client-id", "-c", help="Client id (required for refresh)"
    ),
    user: Optional[str] = typer.Option(
        None, "--user", help="UPN (required for refresh)"
    ),
):
    """Insert an externally sourced token into the cache.

    `-t response` accepts a full JSON token response (as emitted by an OAuth flow):
    identity is taken from the id_token and expiry from the response fields, so an
    opaque (non-JWT) access token is handled fine.
    """
    if secret is None:
        if sys.stdin.isatty():
            _err("Provide --secret or pipe the token on stdin.")
        secret = sys.stdin.read().rstrip()  # read() so multi-line JSON blobs work
    cache = TokenCache()
    from .cache import UserAppToken

    if token_type == "access":
        # Access tokens are JWTs; derive all metadata from claims.
        try:
            claims = jwt_utils.decode_claims(secret)
        except Exception as e:
            _err(f"Could not parse access token as JWT: {e}")
        cid = claims.get("appid") or (
            c.resolve_client_id(client_id) if client_id else None
        )
        if cid is None:
            _err("Access token has no appid claim; pass --client-id.")
        upn = (
            claims.get("upn")
            or claims.get("preferred_username")
            or claims.get("unique_name")
            or claims.get("oid", "unknown")
        )
        token = UserAppToken(
            access_token=secret,
            app_display_name=c.foci_app_name(cid) or c.get_alias(cid),
            scopes=jwt_utils.get_scopes(secret),
            expires_on=jwt_utils.get_expiry(secret) or 0,
            foci=c.is_foci_client(cid),
            acquired_at=int(time.time()),
        )
        upn_domain = upn.split("@")[-1] if "@" in upn else None
        cache.upsert_user_token(
            upn,
            cid,
            token,
            tenant_id=claims.get("tid"),
            tenant_domain=upn_domain,
            user_id=claims.get("oid"),
        )
        cache.save()
        typer.secho(f"Inserted access token for {upn} ({cid}).", fg=typer.colors.GREEN)

    elif token_type == "refresh":
        # Refresh tokens are opaque; require identifying metadata.
        if not client_id or not user:
            _err("--client-id and --user are required when inserting a refresh token.")
        cid = c.resolve_client_id(client_id)
        existing = cache.get_user_token(user, cid)
        token = existing or UserAppToken(access_token="")
        token.refresh_token = secret
        token.foci = c.is_foci_client(cid)
        token.acquired_at = int(time.time())
        cache.upsert_user_token(user, cid, token)
        cache.save()
        typer.secho(
            f"Inserted refresh token for {user} ({cid}).", fg=typer.colors.GREEN
        )

    elif token_type == "response":
        # A full JSON token response: access token may be opaque, so identify the
        # user from the id_token and take expiry from the response fields.
        try:
            blob = json.loads(secret)
        except json.JSONDecodeError as e:
            _err(f"--token-type response expects a JSON token response: {e}")
        try:
            resp = auth.TokenResponse.from_json(blob)
        except auth.AuthError as e:
            _err(str(e))
        id_claims = auth._claims_if_jwt(resp.id_token)
        at_claims = auth._claims_if_jwt(resp.access_token)
        if not id_claims and not at_claims:
            _err(
                "`-t response` needs an id_token (or a JWT access token) to identify the user."
            )
        cid = (
            (c.resolve_client_id(client_id) if client_id else None)
            or id_claims.get("aud")
            or at_claims.get("appid")
        )
        if cid is None:
            _err("Could not determine the client id; pass --client-id.")
        active = auth.persist_user_token(cache, resp, cid)
        typer.secho(
            f"Inserted token response for {active.key} ({cid}).", fg=typer.colors.GREEN
        )
        typer.echo("Run `gts switch -c <client-id|alias>` to make it active.")

    else:
        _err(f"Unknown --token-type '{token_type}'. Use access | refresh | response.")


# -- config --
_VALID_BACKENDS = {
    "keyring",
    "onepassword",
    "1password",
    "op",
    "op-cli",
    "1password-cli",
}


@config_app.command("path")
def config_path():
    """Print the settings file path."""
    typer.echo(str(config.settings_path()))


@config_app.command("show")
def config_show():
    """Show effective settings and where each value comes from."""
    table = Table(
        title="gts settings",
        header_style="bold cyan",
        caption=f"[dim]{config.settings_path()}[/]",
    )
    table.add_column("setting", no_wrap=True)
    table.add_column("value")
    table.add_column("source", style="yellow")
    table.add_column("env var", style="dim")
    for key, spec in config.KNOWN_SETTINGS.items():
        val = config.effective(key)
        table.add_row(
            key,
            "[dim]—[/]" if val is None else str(val),
            config.source(key),
            spec["env"] or "",
        )
    console.print(table)


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Setting key (see `gts config show`)"),
    value: str = typer.Argument(..., help="Value to store"),
):
    """Set a non-secret setting in settings.json."""
    if key not in config.KNOWN_SETTINGS:
        _err(f"Unknown setting '{key}'. Known: {', '.join(config.KNOWN_SETTINGS)}")
    if key == "storage_backend" and value.strip().lower() not in _VALID_BACKENDS:
        _err("storage_backend must be 'keyring' or '1password'.")
    config.set_setting(key, value)
    typer.secho(f"Set {key} = {value}", fg=typer.colors.GREEN)
    if config.source(key) == "env":
        typer.secho(
            f"Note: env var {config.KNOWN_SETTINGS[key]['env']} is set and overrides this.",
            fg=typer.colors.YELLOW,
        )


@config_app.command("unset")
def config_unset(key: str = typer.Argument(..., help="Setting key to remove")):
    """Remove a setting from settings.json (reverting to its default)."""
    if config.unset_setting(key):
        typer.secho(f"Unset {key}.", fg=typer.colors.GREEN)
    else:
        _err(f"'{key}' is not set in {config.settings_path()}")


# -- enum subcommands --
def _client(command: Optional[str] = None) -> GraphClient:
    # Soft guard: warn if the active client looks insufficient for this command.
    if command:
        _enum_preflight(command)
    try:
        return GraphClient.from_active()
    except GraphError as e:
        _err(str(e))
        raise  # unreachable; keeps type checker happy


@enum_app.command("organization")
def enum_organization():
    """Tenant organization details."""
    _print_json(ops.get_organization(_client("organization")))


@enum_app.command("current-user")
def enum_current_user():
    """The signed-in user (/me)."""
    _print_json(ops.get_current_user(_client("current-user")))


@enum_app.command("current-user-memberships")
def enum_current_user_memberships():
    """The signed-in user's transitive group and role memberships."""
    _print_json(ops.get_current_user_memberships(_client("current-user-memberships")))


@enum_app.command("users")
def enum_users():
    """All directory users."""
    _print_json(ops.get_users(_client("users")))


@enum_app.command("groups")
def enum_groups():
    """All directory groups."""
    _print_json(ops.get_groups(_client("groups")))


@enum_app.command("service-principals")
def enum_service_principals(
    owned_only: bool = typer.Option(
        False, "--owned-only", help="Only service principals owned by this tenant"
    ),
):
    """Service principals with resolved Graph permissions and risk flags.

    Enumerates all service principals by default; --owned-only restricts to tenant-owned.
    """
    client = _client("service-principals")
    _print_json(
        ops.get_service_principals(
            client, owned_only=owned_only, progress=progress.for_stderr()
        )
    )


@enum_app.command("privileged-role-assignments")
def enum_privileged_role_assignments(
    beta: bool = typer.Option(False, "--beta", help="Use the beta isPrivileged filter"),
):
    """User, group, and SP assignments to privileged directory roles."""
    client = _client("privileged-role-assignments")
    _print_json(
        ops.get_privileged_role_assignments(
            client, use_beta=beta, progress=progress.for_stderr()
        )
    )


@enum_app.command("conditional-access")
def enum_conditional_access():
    """Conditional access policies."""
    _print_json(ops.get_conditional_access_policies(_client("conditional-access")))


@enum_app.command("all")
def enum_all(
    directory: str = typer.Option(..., "--directory", "-d", help="Output directory"),
    beta: bool = typer.Option(False, "--beta", help="Use the beta isPrivileged filter"),
):
    """Run all enumerations and write each to a JSON file in the given directory."""
    out = pathlib.Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    client = _client("all")
    tasks = {
        "organization.json": lambda: ops.get_organization(client),
        "current-user.json": lambda: ops.get_current_user(client),
        "current-user-memberships.json": lambda: ops.get_current_user_memberships(
            client
        ),
        "users.json": lambda: ops.get_users(client),
        "groups.json": lambda: ops.get_groups(client),
        "service-principals.json": lambda: ops.get_service_principals(client),
        "privileged-role-assignments.json": lambda: ops.get_privileged_role_assignments(
            client, use_beta=beta
        ),
    }
    # Conditional-access needs Policy.Read.All, which most FOCI clients lack. Skip it up
    # front (rather than making a call we know 403s) unless the active client is known to
    # carry an accepted scope. When we have no scope data for the client, attempt it.
    active = state.get_active()
    if active and _conditional_access_blocked(active.client_id):
        who = c.get_alias(active.client_id) or active.client_id
        typer.secho(
            f"skipped conditional-access.json: client '{who}' lacks Policy.Read.All "
            "(or Directory.AccessAsUser.All); `gts refresh-to` a client that has it.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    else:
        tasks["conditional-access.json"] = lambda: ops.get_conditional_access_policies(
            client
        )

    for filename, fn in tasks.items():
        try:
            (out / filename).write_text(json.dumps(fn(), indent=2, default=str))
            typer.secho(f"wrote {filename}", fg=typer.colors.GREEN)
        except GraphError as e:
            typer.secho(f"skipped {filename}: {e}", fg=typer.colors.YELLOW, err=True)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
