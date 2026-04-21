#!/usr/bin/env python3
"""Optional CycloneDX SBOM fingerprint check for sandbox images (T09).

Compares the SBOM extracted from a built image (CI or local ``docker build``)
against an optional committed baseline under ``sandbox/images/sbom-baselines/``.

Baselines are operator-maintained: when intentional dependency drift is merged,
update the per-profile JSON using the fingerprint emitted by this tool or from
CI logs. Without a baseline, the tool exits 0 and prints an advisory — useful
for bootstrapping and non-blocking CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Must match matrix profiles in .github/workflows/sandbox-images.yml (not workflow_dispatch "all").
SANDBOX_SBOM_PROFILES: frozenset[str] = frozenset(
    ("web", "cloud", "browser", "full", "recon", "network")
)


def _fingerprint_sbom(doc: dict[str, Any]) -> tuple[str, int]:
    components = doc.get("components")
    if not isinstance(components, list):
        return hashlib.sha256(b"").hexdigest(), 0
    lines: list[str] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "")
        version = str(c.get("version") or "")
        purl = str(c.get("purl") or "")
        ctype = str(c.get("type") or "")
        lines.append(f"{ctype}|{name}|{version}|{purl}")
    lines.sort()
    payload = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        required=True,
        help=f"Image profile (allowed: {', '.join(sorted(SANDBOX_SBOM_PROFILES))}).",
    )
    parser.add_argument(
        "--built-sbom",
        type=Path,
        required=True,
        help="Path to CycloneDX JSON extracted from the image.",
    )
    parser.add_argument(
        "--baselines-dir",
        type=Path,
        default=Path("sandbox/images/sbom-baselines"),
        help="Directory containing <profile>.json baselines (default: sandbox/images/sbom-baselines).",
    )
    args = parser.parse_args()

    if args.profile not in SANDBOX_SBOM_PROFILES:
        allowed = ", ".join(sorted(SANDBOX_SBOM_PROFILES))
        print(
            f"[sbom-drift] invalid --profile {args.profile!r}; allowed: {allowed}",
            file=sys.stderr,
        )
        return 2

    baseline_path = args.baselines_dir / f"{args.profile}.json"
    try:
        baselines_root = args.baselines_dir.resolve()
        baseline_resolved = baseline_path.resolve()
    except OSError as exc:
        print(f"[sbom-drift] cannot resolve baseline paths: {exc}", file=sys.stderr)
        return 2

    if not baseline_resolved.is_relative_to(baselines_root):
        print(
            "[sbom-drift] baseline path escapes --baselines-dir "
            f"(resolved={baseline_resolved}, baselines_dir={baselines_root})",
            file=sys.stderr,
        )
        return 2

    try:
        text = args.built_sbom.read_text(encoding="utf-8")
        doc = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[sbom-drift] cannot read built SBOM: {exc}", file=sys.stderr)
        return 3

    if not isinstance(doc, dict):
        print("[sbom-drift] built SBOM root must be a JSON object", file=sys.stderr)
        return 3

    fp, count = _fingerprint_sbom(doc)

    if not baseline_path.is_file():
        print(
            f"[sbom-drift-advisory] profile={args.profile}: no baseline at {baseline_path}. "
            f"fingerprint_sha256={fp} component_count={count}. "
            "See ai_docs/develop/sandbox-sbom-renovate.md to commit a baseline after review."
        )
        return 0

    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[sbom-drift] cannot read baseline: {exc}", file=sys.stderr)
        return 3

    exp_fp = baseline.get("fingerprint_sha256")
    exp_count = baseline.get("component_count")
    if exp_fp == fp:
        print(
            f"[sbom-drift] profile={args.profile}: OK "
            f"(fingerprint matches baseline; components={count})."
        )
        return 0

    print(
        f"[sbom-drift-advisory] profile={args.profile}: DRIFT vs committed baseline.\n"
        f"  built:   fingerprint_sha256={fp!r} component_count={count}\n"
        f"  baseline fingerprint_sha256={exp_fp!r} component_count={exp_count}\n"
        "  Action: if Renovate/apt drift is expected, rebuild, re-scan, and update the baseline JSON; "
        "otherwise investigate supply-chain changes before merge.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
