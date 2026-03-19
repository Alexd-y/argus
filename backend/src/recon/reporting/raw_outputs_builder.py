"""Raw tool outputs aggregation — copy subfinder, httpx, nuclei outputs to raw_tool_outputs/."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

RAW_OUTPUTS_DIR = "raw_tool_outputs"

# Source locations: (recon_subdir, candidate_filenames) -> output_filename
SUBFINDER_SOURCES = [
    ("02_subdomains", ["subdomains_raw.txt", "subfinder_raw.txt", "subfinder_output.json"]),
]
HTTPX_SOURCES = [
    ("04_live_hosts", ["httpx_output.json", "httpx_raw.json", "httpx_raw.txt"]),
]
NUCLEI_SOURCES = [
    ("04_live_hosts", ["nuclei_output_initial.json", "nuclei_output.json"]),
    ("14_content", ["nuclei_output_initial.json", "nuclei_output.json"]),
]


def _is_json_lines(content: str) -> bool:
    """Check if content looks like JSON lines (one JSON object per line)."""
    if not content or not content.strip():
        return False
    first_line = content.strip().split("\n")[0].strip()
    if not first_line:
        return False
    try:
        json.loads(first_line)
        return True
    except json.JSONDecodeError:
        return False


def _copy_subfinder_output(recon_dir: Path, output_dir: Path) -> Path | None:
    """Copy subfinder output from 02_subdomains to raw_tool_outputs. Returns path if written."""
    for subdir, candidates in SUBFINDER_SOURCES:
        src_dir = recon_dir / subdir
        if not src_dir.is_dir():
            continue
        for fname in candidates:
            src = src_dir / fname
            if not src.is_file():
                continue
            try:
                content = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logger.warning("Failed to read subfinder source", extra={"path": str(src)})
                continue
            if not content.strip():
                continue
            ext = ".json" if _is_json_lines(content) else ".txt"
            dest = output_dir / f"subfinder_output{ext}"
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                return dest
            except OSError:
                logger.warning("Failed to write subfinder output", extra={"path": str(dest)})
                return None
    return None


def _copy_httpx_output(recon_dir: Path, output_dir: Path) -> Path | None:
    """Copy httpx output from 04_live_hosts to raw_tool_outputs. Returns path if written."""
    for subdir, candidates in HTTPX_SOURCES:
        src_dir = recon_dir / subdir
        if not src_dir.is_dir():
            continue
        for fname in candidates:
            src = src_dir / fname
            if not src.is_file():
                continue
            try:
                content = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logger.warning("Failed to read httpx source", extra={"path": str(src)})
                continue
            if not content.strip():
                continue
            dest = output_dir / "httpx_output.json"
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                return dest
            except OSError:
                logger.warning("Failed to write httpx output", extra={"path": str(dest)})
                return None
    return None


def _copy_nuclei_output(recon_dir: Path, output_dir: Path) -> Path | None:
    """Copy nuclei output when safe mode run exists. Returns path if written."""
    for subdir, candidates in NUCLEI_SOURCES:
        src_dir = recon_dir / subdir
        if not src_dir.is_dir():
            continue
        for fname in candidates:
            src = src_dir / fname
            if not src.is_file():
                continue
            try:
                content = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logger.warning("Failed to read nuclei source", extra={"path": str(src)})
                continue
            if not content.strip():
                continue
            dest = output_dir / "nuclei_output_initial.json"
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                return dest
            except OSError:
                logger.warning("Failed to write nuclei output", extra={"path": str(dest)})
                return None
    return None


def aggregate_raw_tool_outputs(recon_dir: Path, output_dir: Path) -> list[Path]:
    """Aggregate raw tool outputs from recon dir into raw_tool_outputs/.

    Copies from known locations:
    - 02_subdomains: subfinder output -> subfinder_output.json or .txt
    - 04_live_hosts: httpx output -> httpx_output.json
    - 04_live_hosts / 14_content: nuclei output -> nuclei_output_initial.json (when safe mode)

    Args:
        recon_dir: Path to recon directory (e.g. .../recon/svalbard-stage1/).
        output_dir: Base output directory; raw_tool_outputs/ will be created under it.

    Returns:
        List of written file paths.
    """
    recon_dir = Path(recon_dir)
    output_dir = Path(output_dir)
    raw_dir = output_dir / RAW_OUTPUTS_DIR
    written: list[Path] = []

    if not recon_dir.is_dir():
        logger.warning("Recon dir does not exist", extra={"path": str(recon_dir)})
        return written

    for copy_fn in (_copy_subfinder_output, _copy_httpx_output, _copy_nuclei_output):
        result = copy_fn(recon_dir, raw_dir)
        if result is not None:
            written.append(result)

    return written
