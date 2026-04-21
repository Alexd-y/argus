"""CLI: print a human-readable summary of the loaded ARGUS payload catalog.

Loads via :class:`src.payloads.registry.PayloadRegistry` (so signature
verification is exercised exactly as the application does at startup) and
prints one row per family plus a risk / approval / OAST breakdown. Outputs
JSON when ``--json`` is given so the script is CI-friendly.

Exit codes:
* ``0`` — registry loaded successfully (any family count, including zero).
* ``1`` — registry load failed (signatures, schema, allow-list, …). The
    error is emitted as a one-line JSON record on stderr; no stack traces.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python backend/scripts/payloads_list.py ...` invocation.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.payloads.registry import PayloadRegistry, RegistryLoadError  # noqa: E402


def _default_payloads_dir() -> Path:
    return _BACKEND_ROOT / "config" / "payloads"


def _print_table(registry: PayloadRegistry) -> None:
    families = registry.list_families()
    if not families:
        print("0 payload families loaded.")
        return

    rows: list[tuple[str, str, str, str, str, str]] = [
        (
            "family_id",
            "risk_level",
            "approval",
            "oast",
            "payloads",
            "owasp",
        )
    ]
    for f in families:
        rows.append(
            (
                f.family_id,
                f.risk_level.value,
                "yes" if f.requires_approval else "no",
                "yes" if f.oast_required else "no",
                str(len(f.payloads)),
                ",".join(f.owasp_top10),
            )
        )

    widths = [max(len(row[col]) for row in rows) for col in range(len(rows[0]))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*rows[0]))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows[1:]:
        print(fmt.format(*row))
    print()
    print(f"{len(families)} payload families loaded.")


def _print_json(registry: PayloadRegistry) -> None:
    payload = {
        "total": len(registry),
        "families": [
            {
                "family_id": f.family_id,
                "risk_level": f.risk_level.value,
                "requires_approval": f.requires_approval,
                "oast_required": f.oast_required,
                "cwe_ids": list(f.cwe_ids),
                "owasp_top10": list(f.owasp_top10),
                "payload_count": len(f.payloads),
                "mutation_count": len(f.mutations),
                "encoding_count": len(f.encodings),
                "description": f.description,
            }
            for f in registry.list_families()
        ],
    }
    print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="payloads_list",
        description="List the ARGUS payload catalog as loaded by PayloadRegistry.",
    )
    parser.add_argument(
        "--payloads-dir",
        type=Path,
        default=_default_payloads_dir(),
        help="Payloads YAML directory (default: backend/config/payloads/).",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="Public keys directory (default: <payloads-dir>/_keys/).",
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        default=None,
        help="SIGNATURES manifest path (default: <payloads-dir>/SIGNATURES).",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of a table."
    )
    args = parser.parse_args(argv)

    registry = PayloadRegistry(
        payloads_dir=args.payloads_dir,
        keys_dir=args.keys_dir,
        signatures_path=args.signatures,
    )
    try:
        registry.load()
    except RegistryLoadError as exc:
        sys.stderr.write(
            json.dumps({"event": "payload_registry.load_failed", "reason": str(exc)})
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
