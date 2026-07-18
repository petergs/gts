"""Read a Microsoft Graph permission table without pulling the doc page into context.

Graph API doc pages run to thousands of lines of request/response samples; the permission
table is ~6 of them. Fetching a page with WebFetch/curl to read that table wastes a large
amount of context and has produced wrong cell attributions when summarized. This prints
just the table.

Parsing is delegated to scripts/build_permission_resources.py so there is one source of
truth for the format quirks (2- vs 3-column tables, {INCLUDE} indirection, provider
sections).

    # print the permission table for a doc page
    lookup_permissions.py --page group-list.md
    lookup_permissions.py --page rbacapplication-list-roleassignments.md \
        --section "For the directory (Microsoft Entra ID) provider"

    # find the real doc page filename for a resource (the naming is irregular)
    lookup_permissions.py --find conditionalaccess
"""

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_permission_resources as gen  # noqa: E402


def show(page: str, section: str | None) -> int:
    try:
        table, include = gen.resolve_permissions(page, section)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"page:    {gen.API_DIR}/{page}")
    if include:
        print(f"include: {include}")
    if section:
        print(f"section: {section}")
    fmt = {v.get("format", "3-column") for v in table.values()}
    print(f"format:  {', '.join(sorted(fmt))}")
    print()
    for key in ("delegated_work_school", "delegated_personal", "application"):
        row = table.get(key)
        if row is None:
            continue
        least = ", ".join(row["least"]) or "(not supported)"
        higher = ", ".join(row["higher"]) or "-"
        print(f"  {key}")
        print(f"      least : {least}")
        print(f"      higher: {higher}")
    return 0


def find(term: str) -> int:
    """Probe plausible doc page filenames. The GitHub contents API truncates this
    directory at 1000 entries, so absence from a listing is not proof; probe directly."""
    term = term.lower().removesuffix(".md")
    suffixes = [
        "",
        "-list",
        "-get",
        "root-list-policies",
        "-list-members",
        "-list-approleassignments",
        "-list-transitivememberof",
    ]
    candidates = [f"{term}{s}.md" for s in suffixes]
    print(f"probing {len(candidates)} candidates under {gen.API_DIR}/\n")
    hits = 0
    for name in candidates:
        try:
            gen.fetch(f"{gen.API_DIR}/{name}")
        except RuntimeError:
            print(f"  404  {name}")
            continue
        hits += 1
        print(f"  200  {name}   <-- exists")
    if not hits:
        print(
            "\nno candidate matched. Search the repo tree directly:\n"
            "  https://github.com/microsoftgraph/microsoft-graph-docs-contrib/"
            f"tree/{gen.SOURCE_REF[:12]}/{gen.API_DIR}"
        )
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--page", help="doc page filename, e.g. group-list.md")
    group.add_argument("--find", help="probe doc page filenames for a resource name")
    ap.add_argument("--section", help="heading to scope parsing to, for multi-table pages")
    args = ap.parse_args()

    if args.find:
        return find(args.find)
    return show(args.page, args.section)


if __name__ == "__main__":
    raise SystemExit(main())
