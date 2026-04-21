"""CLI for exporting / verifying the ARGUS MCP OpenAPI 3.1 spec (ARG-039).

The committed ``docs/mcp-server-openapi.yaml`` is the byte-for-byte
output of this script. The ``mcp-openapi-drift`` CI gate runs the
``--check`` mode and fails the build when the on-disk spec diverges
from what the live FastMCP registry would produce.

Run from ``backend/`` (so ``src.*`` and ``scripts.*`` resolve):

.. code-block:: powershell

    # regenerate the spec on disk
    python -m scripts.export_mcp_openapi --out ../docs/mcp-server-openapi.yaml

    # CI drift guard — exit 1 on mismatch
    python -m scripts.export_mcp_openapi --check

Exit codes:
    0 — spec written (or ``--check`` passed)
    1 — drift detected in ``--check`` mode, or required input missing
    2 — output path could not be written (filesystem error)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Final

import yaml

from src.mcp.openapi_emitter import build_openapi_spec
from src.mcp.server import build_app

_logger = logging.getLogger("export_mcp_openapi")

DEFAULT_OUT_PATH: Final[Path] = Path("../docs/mcp-server-openapi.yaml")


def render_spec_yaml() -> str:
    """Build the spec from a fresh FastMCP app and serialise it to YAML."""
    app = build_app(name="argus-openapi-emit", log_level="WARNING")
    spec = build_openapi_spec(app)
    return yaml.safe_dump(
        spec,
        sort_keys=True,
        allow_unicode=False,
        default_flow_style=False,
        width=120,
    )


def write_spec(out_path: Path) -> int:
    """Write the freshly-generated spec to `out_path`. Returns exit code."""
    rendered = render_spec_yaml()
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8", newline="\n")
    except OSError as exc:
        _logger.error("Failed to write %s: %s", out_path, exc)
        return 2
    print(f"OK — wrote {out_path} ({len(rendered)} bytes)")
    return 0


def check_spec(out_path: Path) -> int:
    """Compare on-disk spec with freshly-generated one. Returns exit code."""
    if not out_path.exists():
        print(
            f"FAIL — {out_path} does not exist; run without --check to generate.",
            file=sys.stderr,
        )
        return 1
    try:
        on_disk = out_path.read_text(encoding="utf-8")
    except OSError as exc:
        _logger.error("Failed to read %s: %s", out_path, exc)
        return 2

    rendered = render_spec_yaml()
    if on_disk != rendered:
        print(
            f"FAIL — drift detected: {out_path} is out of sync with src/mcp.\n"
            "       Regenerate via: python -m scripts.export_mcp_openapi "
            "--out ../docs/mcp-server-openapi.yaml",
            file=sys.stderr,
        )
        return 1
    print(f"OK — {out_path} is in sync with src/mcp ({len(rendered)} bytes).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="export_mcp_openapi",
        description=(
            "Export the ARGUS MCP server's OpenAPI 3.1 spec, or verify the "
            "committed copy is in sync with source."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Verify the committed spec matches the freshly-generated one. "
            "Exit 1 on drift. Used by the mcp-openapi-drift CI gate."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_PATH,
        help="Output path (default: ../docs/mcp-server-openapi.yaml).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if args.check:
        return check_spec(args.out)
    return write_spec(args.out)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["check_spec", "main", "render_spec_yaml", "write_spec"]
