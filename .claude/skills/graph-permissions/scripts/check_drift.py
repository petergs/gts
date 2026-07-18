"""Check the generated permission resources against the code they describe.

Answers "is there work to do?" with no network calls and minimal output, so it is cheap
to run before touching anything. Three checks:

  1. Every Graph endpoint called in src/gts/enum/operations.py appears in the generator's
     ENDPOINT_DOCS map (and vice versa).
  2. Every enum subcommand registered in the CLI appears in
     resources/enum_command_permissions.json (and vice versa).
  3. Every endpoint referenced by that file exists in graph_endpoint_permissions.json.

Endpoints are recovered with `ast`, not regex: several call sites span multiple lines.
This is a *drift detector*, not a source of truth -- the authoritative subcommand-to-
endpoint mapping is the COMMAND_ENDPOINTS literal, since which calls a command actually
makes depends on branches the AST cannot resolve.

Exit code 1 means drift. Usage: check_drift.py
"""

import ast
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "src"))

import build_permission_resources as gen  # noqa: E402

OPERATIONS = REPO_ROOT / "src" / "gts" / "enum" / "operations.py"
RESOURCES = REPO_ROOT / "resources"


def endpoint_from_arg(node: ast.expr) -> str | None:
    """Recover a Graph path from a call's first argument.

    Handles plain string literals and f-strings; f-string placeholders collapse to {id}
    to match the endpoint map's path templates.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        raw = node.value
    elif isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{id}")
        raw = "".join(parts)
    else:
        return None

    path = raw.split("?", 1)[0].strip("/")  # drop $filter/$expand query strings
    path = re.sub(r"\{[^}]*\}", "{id}", path)
    return f"GET /{path}" if path else None


def called_endpoints() -> set[str]:
    """Graph paths reached via the GraphClient in operations.py.

    Matches on the receiver name, not just the method name: `dict.get("displayName")`
    is all over this module and would otherwise be mistaken for a Graph call.
    """
    tree = ast.parse(OPERATIONS.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ("get", "get_all") or not node.args:
            continue
        receiver = node.func.value
        if not isinstance(receiver, ast.Name) or "client" not in receiver.id.lower():
            continue
        endpoint = endpoint_from_arg(node.args[0])
        if endpoint:
            found.add(endpoint)
    return found


def registered_subcommands() -> set[str]:
    from gts.cli import enum_app

    return {c.name for c in enum_app.registered_commands}


def load(name: str) -> dict:
    data = json.loads((RESOURCES / name).read_text())
    data.pop("_meta", None)
    return data


def report(label: str, missing: set[str], extra: set[str]) -> bool:
    if not missing and not extra:
        print(f"ok    {label}")
        return True
    print(f"DRIFT {label}")
    for m in sorted(missing):
        print(f"        missing from resources: {m}")
    for e in sorted(extra):
        print(f"        documented but not in code: {e}")
    return False


def main() -> int:
    endpoints = load("graph_endpoint_permissions.json")
    commands = load("enum_command_permissions.json")

    called = called_endpoints()
    mapped = set(gen.ENDPOINT_DOCS)
    ok = report("operations.py calls vs ENDPOINT_DOCS", called - mapped, mapped - called)

    cli = registered_subcommands()
    documented = set(commands)
    ok &= report("CLI subcommands vs enum_command_permissions", cli - documented,
                 documented - cli)

    referenced = {
        e["endpoint"] for spec in commands.values() for e in spec["endpoints"]
    }
    ok &= report("referenced endpoints vs endpoint map", referenced - set(endpoints),
                 set())

    if not ok:
        print("\nSee .claude/skills/graph-permissions/SKILL.md for how to resolve drift.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
