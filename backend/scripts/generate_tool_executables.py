"""Generate ``infra/sandbox/expected_executables.json`` from the signed tool catalog.

The single source of truth for "which executable must exist on ``PATH`` inside
which sandbox image" is the set of 162 signed YAML descriptors under
``backend/config/tools/``. This script loads them through the Ed25519-verified
:class:`~src.sandbox.tool_registry.ToolRegistry`, extracts the leading token of
every descriptor's ``command_template`` (the executable the sandbox invokes),
groups it by declared image profile, and emits a deterministic JSON manifest.

``infra/validate_tools.sh`` consumes that manifest at image-build time to fail
the build when a REQUIRED binary is missing from ``PATH`` (P0.3 of the ARGUS
overhaul prompt: "проверка наличия каждого исполняемого файла из списка 162
дескрипторов через ``command -v``").

Executable classification
-------------------------
* ``binary``  — a real system/toolchain executable expected on ``PATH``
  (apt / go / pip / gem provisioned). Missing ⇒ hard build failure.
* ``wrapper`` — an ARGUS-provided wrapper/launcher script whose name ends in
  ``-wrapper`` / ``-runner`` / ``-cli`` or begins with ``playwright`` and which
  must be materialised as a real script in the image. Missing ⇒ warning (the
  wrapper-script backfill is tracked separately; see the prompt's P0.4).

CLI (run from ``backend/``)::

    python -m scripts.generate_tool_executables            # write manifest
    python -m scripts.generate_tool_executables --check    # CI drift guard

Exit codes:
    0 — manifest written (or ``--check`` confirmed in-sync)
    1 — registry load failed, or drift detected in ``--check`` mode
    2 — output path could not be written / read (filesystem error)
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Final

from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.tool_registry import RegistryLoadError, ToolRegistry

_logger = logging.getLogger("generate_tool_executables")

_BACKEND_DIR: Final[Path] = Path(__file__).resolve().parents[1]
_REPO_ROOT: Final[Path] = _BACKEND_DIR.parent
_DEFAULT_TOOLS_DIR: Final[Path] = _BACKEND_DIR / "config" / "tools"
_DEFAULT_OUTPUT: Final[Path] = _REPO_ROOT / "infra" / "sandbox" / "expected_executables.json"

_SCHEMA_VERSION: Final[int] = 1

# Command tokens matching these markers are ARGUS wrapper/launcher scripts, not
# upstream binaries. Kept intentionally small + explicit so a genuinely missing
# real binary is never silently downgraded to a non-fatal "wrapper" warning.
_WRAPPER_SUFFIXES: Final[tuple[str, ...]] = ("-wrapper", "-runner", "-cli")
_WRAPPER_PREFIXES: Final[tuple[str, ...]] = ("playwright",)


def _classify(executable: str) -> str:
    """Return ``"wrapper"`` for ARGUS launcher scripts, else ``"binary"``."""
    if executable.endswith(_WRAPPER_SUFFIXES) or executable.startswith(_WRAPPER_PREFIXES):
        return "wrapper"
    return "binary"


def _image_profile(image: str) -> str:
    """Strip the ``:tag`` suffix from a descriptor image reference."""
    return image.partition(":")[0]


def build_executable_index(descriptors: list[ToolDescriptor]) -> dict[str, Any]:
    """Build the deterministic executable → {kind, tools, images} manifest.

    Groups every descriptor's leading ``command_template`` token by executable
    name, recording the classification, the ``tool_id``s that invoke it, and the
    image profiles that must provision it.
    """
    grouped: dict[str, dict[str, set[str]]] = {}
    for descriptor in descriptors:
        executable = descriptor.command_template[0]
        entry = grouped.setdefault(executable, {"tools": set(), "images": set()})
        entry["tools"].add(descriptor.tool_id)
        entry["images"].add(_image_profile(descriptor.image))

    executables: list[dict[str, Any]] = [
        {
            "name": name,
            "kind": _classify(name),
            "tools": sorted(data["tools"]),
            "images": sorted(data["images"]),
        }
        for name, data in sorted(grouped.items())
    ]
    return {
        "schema_version": _SCHEMA_VERSION,
        "generated_by": "scripts/generate_tool_executables.py",
        "total_tools": len(descriptors),
        "total_executables": len(executables),
        "binary_count": sum(1 for e in executables if e["kind"] == "binary"),
        "wrapper_count": sum(1 for e in executables if e["kind"] == "wrapper"),
        "executables": executables,
    }


def _load_descriptors(tools_dir: Path) -> list[ToolDescriptor]:
    registry = ToolRegistry(tools_dir=tools_dir)
    registry.load()
    return registry.all_descriptors()


def _render(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-dir", type=Path, default=_DEFAULT_TOOLS_DIR)
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if the committed manifest is out of sync.",
    )
    args = parser.parse_args(argv)

    try:
        descriptors = _load_descriptors(args.tools_dir)
    except RegistryLoadError as exc:
        _logger.error(json.dumps({"event": "registry_load_failed", "error": str(exc)}))
        return 1

    rendered = _render(build_executable_index(descriptors))

    if args.check:
        try:
            existing = args.out.read_text(encoding="utf-8")
        except OSError as exc:
            _logger.error(json.dumps({"event": "read_failed", "error": str(exc)}))
            return 2
        if existing != rendered:
            _logger.error(
                json.dumps(
                    {
                        "event": "drift_detected",
                        "path": str(args.out),
                        "hint": "run: python -m scripts.generate_tool_executables",
                    }
                )
            )
            return 1
        return 0

    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        _logger.error(json.dumps({"event": "write_failed", "error": str(exc)}))
        return 2
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    raise SystemExit(main())
