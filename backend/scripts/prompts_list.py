"""CLI: print a human-readable summary of the loaded ARGUS prompt catalog.

Loads via :class:`src.orchestrator.prompt_registry.PromptRegistry` (so signature
verification is exercised exactly as the application does at startup) and
prints one row per prompt plus a per-role breakdown. Outputs JSON when
``--json`` is given so the script is CI-friendly.

Exit codes:
* ``0`` — registry loaded successfully (any prompt count, including zero).
* ``1`` — registry load failed (signatures, schema, allow-list, ...). The
    error is emitted as a one-line JSON record on stderr; no stack traces.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python backend/scripts/prompts_list.py ...` invocation.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.orchestrator.prompt_registry import (  # noqa: E402
    PromptRegistry,
    PromptRegistryError,
)


def _default_prompts_dir() -> Path:
    return _BACKEND_ROOT / "config" / "prompts"


def _print_table(registry: PromptRegistry) -> None:
    prompts = registry.list_all()
    if not prompts:
        print("0 prompts loaded.")
        return

    rows: list[tuple[str, str, str, str, str, str]] = [
        (
            "prompt_id",
            "version",
            "agent_role",
            "model_id",
            "max_tokens",
            "temperature",
        )
    ]
    for p in prompts:
        rows.append(
            (
                p.prompt_id,
                p.version,
                p.agent_role.value,
                p.default_model_id,
                str(p.default_max_tokens),
                f"{p.default_temperature:.2f}",
            )
        )

    widths = [max(len(row[col]) for row in rows) for col in range(len(rows[0]))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*rows[0]))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows[1:]:
        print(fmt.format(*row))
    print()
    print(f"{len(prompts)} prompts loaded.")


def _print_json(registry: PromptRegistry) -> None:
    payload = {
        "total": len(registry),
        "prompts": [
            {
                "prompt_id": p.prompt_id,
                "version": p.version,
                "agent_role": p.agent_role.value,
                "default_model_id": p.default_model_id,
                "default_max_tokens": p.default_max_tokens,
                "default_temperature": p.default_temperature,
                "expected_schema_ref": p.expected_schema_ref,
                "description": p.description,
            }
            for p in registry.list_all()
        ],
    }
    print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prompts_list",
        description="List the ARGUS prompt catalog as loaded by PromptRegistry.",
    )
    parser.add_argument(
        "--prompts-dir",
        type=Path,
        default=_default_prompts_dir(),
        help="Prompts YAML directory (default: backend/config/prompts/).",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="Public keys directory (default: <prompts-dir>/_keys/).",
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        default=None,
        help="SIGNATURES manifest path (default: <prompts-dir>/SIGNATURES).",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of a table."
    )
    args = parser.parse_args(argv)

    registry = PromptRegistry(
        prompts_dir=args.prompts_dir,
        public_keys_dir=args.keys_dir,
        signatures_path=args.signatures,
    )
    try:
        registry.load()
    except PromptRegistryError as exc:
        sys.stderr.write(
            json.dumps({"event": "prompt_registry.load_failed", "reason": str(exc)})
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
