"""CLI: print a human-readable summary of the loaded ARGUS tool catalog.

Loads via :class:`src.sandbox.tool_registry.ToolRegistry` (so signature
verification is exercised exactly as the application does at startup) and
prints one row per tool plus a phase / category breakdown. Outputs JSON when
``--json`` is given so the script is CI-friendly.

Exit codes:
* ``0`` — registry loaded successfully (any tool count, including zero).
* ``1`` — registry load failed (signatures, schema, allow-list, …). The
    error is emitted as a one-line JSON record on stderr; no stack traces.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow ``python backend/scripts/tools_list.py`` to import the ``src.*`` tree.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.sandbox.tool_registry import RegistryLoadError, ToolRegistry  # noqa: E402


def _default_tools_dir() -> Path:
    return _BACKEND_ROOT / "config" / "tools"


def _print_table(registry: ToolRegistry) -> None:
    descriptors = registry.all_descriptors()
    if not descriptors:
        print("0 tools loaded.")
        return

    rows: list[tuple[str, str, str, str, str]] = [
        (
            "tool_id",
            "phase",
            "category",
            "risk_level",
            "approval",
        )
    ]
    for d in descriptors:
        rows.append(
            (
                d.tool_id,
                d.phase.value,
                d.category.value,
                d.risk_level.value,
                "yes" if d.requires_approval else "no",
            )
        )

    widths = [max(len(row[col]) for row in rows) for col in range(len(rows[0]))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*rows[0]))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows[1:]:
        print(fmt.format(*row))
    print()
    print(f"{len(descriptors)} tools loaded.")


def _print_json(registry: ToolRegistry) -> None:
    summary_payload = {
        "total": len(registry),
        "tools": [
            {
                "tool_id": d.tool_id,
                "phase": d.phase.value,
                "category": d.category.value,
                "risk_level": d.risk_level.value,
                "requires_approval": d.requires_approval,
                "image": d.image,
                "default_timeout_s": d.default_timeout_s,
            }
            for d in registry.all_descriptors()
        ],
    }
    print(json.dumps(summary_payload, sort_keys=True, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tools_list",
        description="List the ARGUS sandbox tool catalog as loaded by ToolRegistry.",
    )
    parser.add_argument(
        "--tools-dir",
        type=Path,
        default=_default_tools_dir(),
        help="Tools YAML directory (default: backend/config/tools/).",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="Public keys directory (default: <tools-dir>/_keys/).",
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        default=None,
        help="SIGNATURES manifest path (default: <tools-dir>/SIGNATURES).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    args = parser.parse_args(argv)

    registry = ToolRegistry(
        tools_dir=args.tools_dir,
        keys_dir=args.keys_dir,
        signatures_path=args.signatures,
    )
    try:
        registry.load()
    except RegistryLoadError as exc:
        sys.stderr.write(
            json.dumps({"event": "tool_registry.load_failed", "reason": str(exc)})
            + "\n"
        )
        return 1

    if args.json:
        _print_json(registry)
    else:
        _print_table(registry)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
