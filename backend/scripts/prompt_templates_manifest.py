"""CLI to manage the runtime prompt-template integrity manifest (F-M04).

Unlike :mod:`prompts_sign` (which Ed25519-signs the ``config/prompts`` YAML
catalog), this tool maintains a SHA-256 manifest for the Jinja2 templates that
drive the *live* scan pipeline under ``src/orchestration/prompts/``. The
manifest gives the opt-in, fail-closed :class:`PromptLoader` integrity gate
something to verify against.

Sub-commands (argparse-driven so CI can call them):

* ``generate [--prompts-dir <dir>]``
    Recompute and rewrite ``<dir>/MANIFEST.sha256`` (atomic, sorted).

* ``verify [--prompts-dir <dir>]``
    Verify on-disk templates against the committed manifest. Exit non-zero on a
    missing manifest or any drift; emit one JSON line describing the outcome.

Stack traces are never leaked — only structured JSON events.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.orchestration.prompt_integrity import (  # noqa: E402  (sys.path tweak)
    PromptIntegrityError,
    compute_manifest,
    diff_manifest,
    load_manifest,
    write_manifest,
)

_DEFAULT_PROMPTS_DIR = _BACKEND_ROOT / "src" / "orchestration" / "prompts"


def _emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True, ensure_ascii=False))


def _fail(event: str, **fields: object) -> int:
    print(
        json.dumps({"event": event, **fields}, sort_keys=True, ensure_ascii=False),
        file=sys.stderr,
    )
    return 1


def _cmd_generate(prompts_dir: Path) -> int:
    if not prompts_dir.is_dir():
        return _fail("generate.error", reason="prompts dir does not exist",
                     prompts_dir=str(prompts_dir))
    path = write_manifest(prompts_dir)
    entries = compute_manifest(prompts_dir)
    _emit("generate.ok", manifest_path=str(path), template_count=len(entries))
    return 0


def _cmd_verify(prompts_dir: Path) -> int:
    if not prompts_dir.is_dir():
        return _fail("verify.error", reason="prompts dir does not exist",
                     prompts_dir=str(prompts_dir))
    try:
        expected = load_manifest(prompts_dir)
    except PromptIntegrityError as exc:
        return _fail("verify.error", reason=str(exc), prompts_dir=str(prompts_dir))
    actual = compute_manifest(prompts_dir)
    missing, extra, mismatched = diff_manifest(expected, actual)
    if missing or extra or mismatched:
        return _fail(
            "verify.failed",
            reason="template integrity drift",
            missing=missing,
            extra=extra,
            mismatched=mismatched,
        )
    _emit("verify.ok", verified_count=len(expected))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompt_templates_manifest",
        description="Manage the SHA-256 manifest for runtime prompt templates.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Recompute the template manifest.")
    gen.add_argument("--prompts-dir", type=Path, default=_DEFAULT_PROMPTS_DIR)

    ver = sub.add_parser("verify", help="Verify templates against the manifest.")
    ver.add_argument("--prompts-dir", type=Path, default=_DEFAULT_PROMPTS_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.command == "generate":
        return _cmd_generate(args.prompts_dir)
    if args.command == "verify":
        return _cmd_verify(args.prompts_dir)
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
