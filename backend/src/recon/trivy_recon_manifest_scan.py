"""Optional Trivy filesystem scan over dependency manifests collected during recon (MinIO)."""

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
from pathlib import Path
from typing import Any

from src.core.config import settings
from src.recon.adapters.security.trivy_adapter import TrivyAdapter
from src.recon.raw_artifact_sink import sink_raw_json
from src.storage.s3 import download_by_key, list_scan_artifacts

logger = logging.getLogger(__name__)


def raw_trivy_vuln_to_intel_row(tr: dict[str, Any]) -> dict[str, Any]:
    """Map raw Trivy vulnerability dict to intel row shape for ``handlers._normalize_intel_finding``."""
    vid = str(tr.get("VulnerabilityID") or tr.get("ID") or "unknown").strip()
    pkg = str(tr.get("PkgName") or tr.get("PackageName") or "").strip()
    sev_in = str(tr.get("Severity") or "HIGH").lower()
    if sev_in not in {"critical", "high", "medium", "low", "info"}:
        sev_in = "high"
    title = str(tr.get("Title") or f"{pkg} — {vid}").strip() or vid
    target_t = str(tr.get("_target") or "").strip()
    cvss_f: float | None = None
    cvss_block = tr.get("CVSS")
    if isinstance(cvss_block, dict):
        for sub in cvss_block.values():
            if not isinstance(sub, dict):
                continue
            for key in ("V3Score", "v3Score", "V2Score", "BaseScore"):
                v = sub.get(key)
                if isinstance(v, (int, float)):
                    cvss_f = float(v)
                    break
            if cvss_f is not None:
                break
    cwe_first = ""
    cwes = tr.get("CweIDs") or tr.get("CweID")
    if isinstance(cwes, list) and cwes:
        cwe_first = str(cwes[0] or "")
    elif isinstance(cwes, str):
        cwe_first = cwes
    return {
        "source_tool": "trivy",
        "data": {
            "type": "trivy_fs",
            "name": title[:300],
            "severity": sev_in,
            "url": target_t,
            "cvss_score": cvss_f,
            "cwe": cwe_first[:20] if cwe_first else None,
        },
    }


_REQ_MARKER = "dependency_requirements_txt"
_PKG_MARKER = "dependency_package_json"


def _key_matches_manifest(key: str) -> str | None:
    k = (key or "").lower()
    if _REQ_MARKER in k and k.endswith(".txt"):
        return "requirements.txt"
    if _PKG_MARKER in k and k.endswith(".json"):
        return "package.json"
    return None


async def run_trivy_fs_on_recon_manifests(
    tenant_id: str,
    scan_id: str,
) -> list[dict[str, Any]]:
    """
    When ``settings.trivy_enabled`` and recon raw artifacts include dependency manifests,
    download them to a temp dir and run ``trivy fs`` (host PATH, not sandbox — files are local).

    Does not log manifest body contents.
    """
    if not settings.trivy_enabled:
        return []
    if not (tenant_id or "").strip() or not (scan_id or "").strip():
        return []

    rows = list_scan_artifacts(tenant_id, scan_id, phase="recon", raw_only=True)
    if not rows:
        return []

    files: list[tuple[str, bytes]] = []
    for row in rows:
        key = row.get("key") or ""
        fname = _key_matches_manifest(key)
        if not fname:
            continue
        body = await asyncio.to_thread(download_by_key, key)
        if not body or len(body) > 512_000:
            continue
        if fname == "package.json" and not _looks_like_package_json(body):
            continue
        if fname == "requirements.txt" and not _looks_like_requirements(body):
            continue
        files.append((fname, body))

    if not files:
        return []

    adapter = TrivyAdapter()
    if not adapter.is_available():
        logger.info(
            "trivy_recon_manifest_skipped",
            extra={"reason": "trivy_not_on_path", "scan_id": scan_id},
        )
        return []

    with tempfile.TemporaryDirectory(prefix="argus_trivy_fs_") as tmp:
        base = Path(tmp)
        for name, data in files:
            (base / name).write_bytes(data)
        try:
            findings = await adapter.run(
                str(base),
                {"scan_type": "fs", "sandbox": False, "severity": "HIGH,CRITICAL"},
            )
        except Exception:
            logger.warning(
                "trivy_recon_manifest_failed",
                extra={"scan_id": scan_id},
                exc_info=True,
            )
            return []

    logger.info(
        "trivy_recon_manifest_complete",
        extra={
            "scan_id": scan_id,
            "findings_count": len(findings),
            "manifest_files": sorted({f[0] for f in files}),
        },
    )
    try:
        sink_raw_json(
            tenant_id=tenant_id,
            scan_id=scan_id,
            phase="recon",
            artifact_type="recon_trivy_fs_json",
            payload={
                "schema_version": "trivy_recon_fs_v1",
                "findings": findings[:500],
            },
        )
    except Exception:
        logger.warning(
            "trivy_recon_json_sink_failed",
            extra={"event": "trivy_recon_json_sink_failed", "scan_id": scan_id},
        )
    return findings


def _looks_like_package_json(body: bytes) -> bool:
    try:
        text = body.decode("utf-8", errors="replace").lstrip()
    except Exception:
        return False
    if not text.startswith("{"):
        return False
    return ("dependencies" in text) or ('"name"' in text)


def _looks_like_requirements(body: bytes) -> bool:
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return False
    if not text.strip():
        return False
    for line in text.splitlines()[:40]:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^[\w\-\[\]]", s):
            return True
    return False
