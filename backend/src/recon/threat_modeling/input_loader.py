"""Threat model input loader — aggregates recon artifacts into ThreatModelInputBundle.

Supports file-based recon_dir and DB-backed artifact_service.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.schemas.threat_modeling.schemas import (
    CriticalAsset,
    EntryPoint,
    ThreatModelInputBundle,
    TrustBoundary,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Artifact filenames for TM input
TM_ARTIFACT_FILES: tuple[str, ...] = (
    "stage2_structured.json",
    "stage2_inputs.md",
    "ai_stage2_preparation_summary_normalized.json",
    "anomalies_structured.json",
    "intel_findings.json",
    "endpoint_inventory.csv",
    "api_surface.csv",
    "route_inventory.csv",
    "subdomain_classification.csv",
    "live_hosts_detailed.csv",
    "tech_profile.csv",
)


def _stable_id(text: str, prefix: str = "x") -> str:
    """Generate stable id from text (hash-based, max 16 chars)."""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{h}"


def _load_json_from_bytes(data: bytes) -> dict | list | None:
    """Parse JSON from bytes. Returns None on error."""
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse JSON", extra={"error": str(e)})
        return None


def _load_csv_from_bytes(data: bytes) -> list[dict[str, Any]]:
    """Parse CSV from bytes into list of dicts."""
    if not data:
        return []
    try:
        text = data.decode("utf-8", errors="replace")
        return list(csv.DictReader(StringIO(text)))
    except csv.Error as e:
        logger.warning("Failed to parse CSV", extra={"error": str(e)})
        return []


def _structured_item_to_critical_asset(item: dict[str, Any], idx: int) -> CriticalAsset:
    """Map StructuredItem to CriticalAsset."""
    text = (item.get("text") or "").strip() or f"asset_{idx}"
    return CriticalAsset(
        id=_stable_id(text, "ca"),
        name=text[:500],
        asset_type=(item.get("type") or "observation")[:100],
        description=(item.get("source") or "")[:2000] or None,
    )


def _structured_item_to_trust_boundary(item: dict[str, Any], idx: int) -> TrustBoundary:
    """Map StructuredItem to TrustBoundary."""
    text = (item.get("text") or "").strip() or f"boundary_{idx}"
    return TrustBoundary(
        id=_stable_id(text, "tb"),
        name=text[:500],
        description=(item.get("source") or "")[:2000] or None,
        components=[],
    )


def _structured_item_to_entry_point(item: dict[str, Any], idx: int) -> EntryPoint:
    """Map StructuredItem to EntryPoint."""
    text = (item.get("text") or "").strip() or f"entry_{idx}"
    return EntryPoint(
        id=_stable_id(text, "ep"),
        name=text[:500],
        entry_type=(item.get("type") or "hypothesis")[:100],
        host_or_component=text[:500] if ("://" in text or "." in text) else None,
        description=(item.get("source") or "")[:2000] or None,
    )


def _build_bundle_from_contents(
    contents: dict[str, bytes | str],
    engagement_id: str,
    target_id: str | None,
) -> ThreatModelInputBundle:
    """Build ThreatModelInputBundle from artifact contents (filename -> raw bytes/str)."""

    def _get_json(name: str) -> dict | list | None:
        raw = contents.get(name)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return _load_json_from_bytes(raw)
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None
        return None

    def _get_csv(name: str) -> list[dict[str, Any]]:
        raw = contents.get(name)
        if raw is None:
            return []
        if isinstance(raw, bytes):
            return _load_csv_from_bytes(raw)
        if isinstance(raw, str):
            try:
                return list(csv.DictReader(StringIO(raw)))
            except csv.Error:
                return []
        return []

    def _get_text(name: str) -> str:
        raw = contents.get(name)
        if raw is None:
            return ""
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)

    # stage2_structured.json -> priority_hypotheses, critical_assets, trust_boundaries, entry_points
    stage2 = _get_json("stage2_structured.json")
    priority_hypotheses: list[dict[str, Any]] = []
    critical_assets: list[CriticalAsset] = []
    trust_boundaries: list[TrustBoundary] = []
    entry_points: list[EntryPoint] = []

    if isinstance(stage2, dict):
        for _i, item in enumerate(stage2.get("priority_hypotheses") or []):
            if isinstance(item, dict):
                priority_hypotheses.append(item)
        for i, item in enumerate(stage2.get("critical_assets") or []):
            if isinstance(item, dict) and (item.get("text") or item.get("name")):
                critical_assets.append(_structured_item_to_critical_asset(item, i))
        for i, item in enumerate(stage2.get("trust_boundaries") or []):
            if isinstance(item, dict) and (item.get("text") or item.get("name")):
                trust_boundaries.append(_structured_item_to_trust_boundary(item, i))
        for i, item in enumerate(stage2.get("entry_points") or []):
            if isinstance(item, dict) and (item.get("text") or item.get("name")):
                entry_points.append(_structured_item_to_entry_point(item, i))

    # anomalies_structured.json
    anomalies_raw = _get_json("anomalies_structured.json")
    anomalies: list[dict[str, Any]] | dict[str, Any] = []
    if anomalies_raw is not None and isinstance(anomalies_raw, (list, dict)):
        anomalies = anomalies_raw

    # intel_findings.json
    intel_raw = _get_json("intel_findings.json")
    intel_findings: list[dict[str, Any]] = []
    if isinstance(intel_raw, list):
        intel_findings = intel_raw
    elif isinstance(intel_raw, dict):
        items = intel_raw.get("findings") or intel_raw.get("items") or []
        if isinstance(items, list):
            intel_findings = items

    # CSV artifacts
    api_surface = _get_csv("api_surface.csv")
    endpoint_inventory = _get_csv("endpoint_inventory.csv")
    route_inventory = _get_csv("route_inventory.csv")
    subdomain_rows = _get_csv("subdomain_classification.csv")
    live_hosts = _get_csv("live_hosts_detailed.csv")
    tech_profile = _get_csv("tech_profile.csv")

    # dns_summary: use subdomain_classification as structured summary
    dns_summary: dict[str, Any] | None = None
    if subdomain_rows:
        dns_summary = {"rows": subdomain_rows, "source": "subdomain_classification.csv"}

    artifact_refs: list[str] = list(contents.keys())

    return ThreatModelInputBundle(
        engagement_id=engagement_id,
        target_id=target_id,
        critical_assets=critical_assets,
        trust_boundaries=trust_boundaries,
        entry_points=entry_points,
        artifact_refs=artifact_refs,
        priority_hypotheses=priority_hypotheses,
        anomalies=anomalies,
        intel_findings=intel_findings,
        api_surface=api_surface,
        endpoint_inventory=endpoint_inventory,
        route_inventory=route_inventory,
        dns_summary=dns_summary,
        live_hosts=live_hosts,
        tech_profile=tech_profile,
    )


def _gather_file_contents(base: Path) -> dict[str, bytes]:
    """Gather artifact file contents from recon_dir. Missing files are skipped with warning."""
    contents: dict[str, bytes] = {}
    for filename in TM_ARTIFACT_FILES:
        path = base / filename
        if not path.exists() or not path.is_file():
            logger.debug(
                "TM artifact missing",
                extra={"filename": filename, "recon_dir": str(base)},
            )
            continue
        try:
            data = path.read_bytes()
            contents[filename] = data
        except OSError as e:
            logger.warning(
                "Failed to read artifact",
                extra={"filename": filename, "error": str(e)},
            )
    return contents


def load_threat_model_input_bundle(
    recon_dir: Path | str,
    engagement_id: str,
    target_id: str | None = None,
) -> ThreatModelInputBundle:
    """Load ThreatModelInputBundle from file-based recon directory.

    Reads stage2_structured.json, stage2_inputs.md, ai_stage2_preparation_summary_normalized.json,
    anomalies_structured.json, intel_findings.json, endpoint_inventory.csv, api_surface.csv,
    route_inventory.csv, subdomain_classification.csv, live_hosts_detailed.csv, tech_profile.csv.
    Missing files result in empty lists/dicts and logged warnings.

    Args:
        recon_dir: Path to recon directory.
        engagement_id: Engagement ID.
        target_id: Optional target ID.

    Returns:
        ThreatModelInputBundle with mapped and raw recon data.
    """
    base = Path(recon_dir)
    if not base.is_dir():
        logger.warning(
            "Recon dir does not exist",
            extra={"engagement_id": engagement_id, "path": str(base)},
        )
        return ThreatModelInputBundle(
            engagement_id=engagement_id,
            target_id=target_id,
        )

    contents = _gather_file_contents(base)
    return _build_bundle_from_contents(contents, engagement_id, target_id)


async def load_threat_model_input_bundle_from_artifacts(
    db: AsyncSession,
    engagement_id: str,
    target_id: str | None = None,
) -> ThreatModelInputBundle:
    """Load ThreatModelInputBundle from artifact_service (DB + storage).

    Fetches artifacts for engagement via get_artifacts_for_engagement, downloads
    content from storage, and parses into ThreatModelInputBundle. When target_id
    is provided, prefers artifacts linked to that target or shared (target_id=None).

    Args:
        db: AsyncSession for artifact lookup.
        engagement_id: Engagement ID.
        target_id: Optional target ID to filter artifacts.

    Returns:
        ThreatModelInputBundle with mapped and raw recon data.
    """
    from src.recon.services.artifact_service import get_artifacts_for_engagement
    from src.recon.storage import download_artifact

    artifacts = await get_artifacts_for_engagement(db, engagement_id)
    contents: dict[str, bytes] = {}

    for a in artifacts:
        if target_id is not None and a.target_id is not None and a.target_id != target_id:
            continue
        if a.filename not in TM_ARTIFACT_FILES:
            continue
        data = download_artifact(a.object_key)
        if data:
            contents[a.filename] = data
        else:
            logger.warning(
                "Failed to download artifact",
                extra={"filename": a.filename, "engagement_id": engagement_id},
            )

    return _build_bundle_from_contents(contents, engagement_id, target_id)
