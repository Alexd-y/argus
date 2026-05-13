"""Verify Alembic migrations — parses all versions, checks revision chain integrity.

Usage: python backend/scripts/verify_alembic_chain.py [--alembic-dir backend/alembic]
"""

import argparse
import ast
import sys
from pathlib import Path


def parse_migration(filepath: Path) -> dict | None:
    """Parse a single Alembic migration file and extract revision metadata."""
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (SyntaxError, OSError) as exc:
        print(f"ERROR: Cannot parse {filepath.name}: {exc}")
        return None

    revision = None
    down_revision = None
    for node in ast.walk(tree):
        # Plain assignment: revision = "001"
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                    if target.id == "revision":
                        revision = node.value.value
                    elif target.id == "down_revision":
                        down_revision = node.value.value
        # Annotated assignment: revision: str = "001"
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Constant):
            if node.target.id == "revision":
                revision = node.value.value
            elif node.target.id == "down_revision":
                down_revision = node.value.value

    if revision is None:
        print(f"WARNING: No revision found in {filepath.name}")
        return None

    return {"file": filepath.name, "revision": revision, "down_revision": down_revision}


def verify_chain(alembic_dir: Path) -> tuple[int, list[str]]:
    """Verify Alembic revision chain integrity."""
    versions_dir = alembic_dir / "versions"
    if not versions_dir.exists():
        return 0, [f"ERROR: {versions_dir} does not exist"]

    migrations = []
    for f in sorted(versions_dir.glob("*.py")):
        if f.name.startswith("__"):
            continue
        meta = parse_migration(f)
        if meta:
            migrations.append(meta)

    errors = []
    seen_revisions = set()

    for m in migrations:
        rev = m["revision"]
        if rev in seen_revisions:
            errors.append(f"DUPLICATE revision '{rev}' in {m['file']}")
        seen_revisions.add(rev)

        down = m["down_revision"]
        if down and down != "None":
            if down not in seen_revisions and down not in {x["revision"] for x in migrations}:
                errors.append(f"BROKEN CHAIN: {m['file']} (rev {rev}) references unknown down_revision '{down}'")

    # Check chain continuity (each non-head revision is referenced by another as down_revision)
    tail_revs = {m["revision"] for m in migrations} - {
        m["down_revision"] for m in migrations if m["down_revision"] and m["down_revision"] != "None"
    }
    if len(tail_revs) > 1:
        errors.append(f"MULTIPLE HEAD revisions: {tail_revs}")

    # First revision check
    first = [m for m in migrations if not m["down_revision"] or m["down_revision"] == "None"]
    if len(first) == 0:
        errors.append("NO first revision (down_revision=None) found")
    elif len(first) > 1:
        errors.append(f"MULTIPLE root revisions: {[f['revision'] for f in first]}")

    if not errors:
        print(f"OK: {len(migrations)} migrations, chain integrity verified.")
        print(f"  First: {first[0]['file']} (rev {first[0]['revision']})" if first else "  First: NOT FOUND")
        print(f"  Last (head): {sorted(tail_revs)}" if len(tail_revs) == 1 else f"  Heads: {sorted(tail_revs)}")
        return 0, []
    else:
        for err in errors:
            print(f"ERROR: {err}")
        return 1, errors


def main():
    parser = argparse.ArgumentParser(description="Verify Alembic migration chain")
    parser.add_argument("--alembic-dir", default="backend/alembic", help="Path to alembic directory")
    parser.add_argument("--check", action="store_true", help="Exit 1 on errors (CI mode)")
    args = parser.parse_args()

    alembic_dir = Path(args.alembic_dir)
    code, errors = verify_chain(alembic_dir)

    if code != 0 and args.check:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
