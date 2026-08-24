"""Payload taxonomy mapping (R10).

Payload families are matched to a *normalized finding taxonomy* (vulnerability
category + CWE + sink type + technology + oracle), NOT by keyword search on
title/description. Profile policy (quick/light/deep) then filters candidates by
risk level, approval and destructiveness. Selection is deterministic,
deduplicated, and content-addressed with a stable manifest hash for
replayability + provenance.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from src.core.structured_events import (
    EVENT_PAYLOAD_FAMILY_DENIED,
    EVENT_PAYLOAD_FAMILY_SELECTED,
    emit_event,
)
from src.pipeline.contracts.finding_dto import FindingCategory

logger = logging.getLogger(__name__)

# Canonical CWE anchors per normalized vulnerability category (taxonomy, not keywords).
CATEGORY_CWE_ANCHORS: Final[dict[str, tuple[int, ...]]] = {
    FindingCategory.SQLI.value: (89,),
    FindingCategory.XSS.value: (79,),
    FindingCategory.RCE.value: (94, 78),
    FindingCategory.LFI.value: (22, 98),
    FindingCategory.SSRF.value: (918,),
    FindingCategory.SSTI.value: (1336, 94),
    FindingCategory.XXE.value: (611,),
    FindingCategory.NOSQLI.value: (943,),
    FindingCategory.LDAPI.value: (90,),
    FindingCategory.CMDI.value: (77, 78),
    FindingCategory.OPEN_REDIRECT.value: (601,),
    FindingCategory.CSRF.value: (352,),
    FindingCategory.CORS.value: (942,),
    FindingCategory.IDOR.value: (639,),
    FindingCategory.JWT.value: (347,),
    FindingCategory.AUTH.value: (287, 306),
    FindingCategory.CRYPTO.value: (327, 326),
    FindingCategory.SECRET_LEAK.value: (798, 200),
}

_RISK_RANK: Final[dict[str, int]] = {
    "passive": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "destructive": 4,
}


class FamilyLike(Protocol):
    family_id: str
    cwe_ids: list[int]
    risk_level: Any
    requires_approval: bool
    oast_required: bool


@dataclass(frozen=True, slots=True)
class PayloadProfilePolicy:
    """Per-profile payload gating (R10 profile rules)."""

    scan_profile: str
    max_risk_rank: int
    allow_requires_approval: bool
    allow_destructive: bool
    allow_oast: bool

    @classmethod
    def for_profile(cls, scan_profile: str) -> PayloadProfilePolicy:
        p = str(scan_profile).strip().lower()
        if p == "quick":
            # safe / low / allowed-medium; no approval-gated, no destructive.
            return cls("quick", max_risk_rank=2, allow_requires_approval=False,
                       allow_destructive=False, allow_oast=True)
        if p == "light":
            # safe active; higher risk only via explicit approval; no destructive.
            return cls("light", max_risk_rank=2, allow_requires_approval=True,
                       allow_destructive=False, allow_oast=True)
        if p == "deep":
            # LAB catalog: high-risk always, approvals always, OAST allowed.
            return cls("deep", max_risk_rank=4, allow_requires_approval=True,
                       allow_destructive=True, allow_oast=True)
        # Fail-closed default: most restrictive.
        return cls(p, max_risk_rank=1, allow_requires_approval=False,
                   allow_destructive=False, allow_oast=False)


@dataclass(frozen=True, slots=True)
class PayloadTaxonomyQuery:
    """Normalized taxonomy describing what to test (never keyword search)."""

    vuln_category: str | None = None
    cwe_ids: tuple[int, ...] = ()
    sink_type: str | None = None
    technology: str | None = None
    oracle: str | None = None
    scan_profile: str = "quick"

    def canonical(self) -> dict[str, Any]:
        return {
            "vuln_category": self.vuln_category,
            "cwe_ids": sorted(self.cwe_ids),
            "sink_type": self.sink_type,
            "technology": self.technology,
            "oracle": self.oracle,
            "scan_profile": self.scan_profile,
        }


@dataclass(frozen=True, slots=True)
class PayloadSelection:
    """Deterministic, deduplicated payload-family selection with provenance."""

    family_ids: tuple[str, ...]
    provenance: dict[str, dict[str, Any]]
    manifest_hash: str
    denied: dict[str, str] = field(default_factory=dict)


def _risk_rank(risk_level: Any) -> int:
    value = getattr(risk_level, "value", risk_level)
    return _RISK_RANK.get(str(value).strip().lower(), 4)


def _anchor_cwes(query: PayloadTaxonomyQuery) -> set[int]:
    anchors: set[int] = set(query.cwe_ids)
    if query.vuln_category:
        anchors.update(CATEGORY_CWE_ANCHORS.get(str(query.vuln_category).lower(), ()))
    return anchors


def _matches_taxonomy(family: FamilyLike, anchors: set[int]) -> bool:
    if not anchors:
        return False
    return bool(anchors.intersection(set(family.cwe_ids)))


def _policy_allows(
    family: FamilyLike, policy: PayloadProfilePolicy
) -> tuple[bool, str | None]:
    rank = _risk_rank(family.risk_level)
    risk_value = str(getattr(family.risk_level, "value", family.risk_level)).lower()
    if risk_value == "destructive" and not policy.allow_destructive:
        return False, "risk_destructive_denied"
    if rank > policy.max_risk_rank:
        return False, "risk_ceiling_exceeded"
    if family.requires_approval and not policy.allow_requires_approval:
        return False, "approval_required_denied"
    if family.oast_required and not policy.allow_oast:
        return False, "oast_denied"
    return True, None


def map_taxonomy_to_families(
    query: PayloadTaxonomyQuery,
    families: list[FamilyLike],
    *,
    emit: bool = False,
    scan_id: str | None = None,
    tenant_id: str | None = None,
) -> PayloadSelection:
    """Map a taxonomy query to allowed payload families (deterministic + provenance)."""
    policy = PayloadProfilePolicy.for_profile(query.scan_profile)
    anchors = _anchor_cwes(query)

    selected: dict[str, dict[str, Any]] = {}
    denied: dict[str, str] = {}

    for family in families:
        fid = str(family.family_id)
        if not _matches_taxonomy(family, anchors):
            continue  # taxonomy mismatch — not a denial, just not applicable
        allowed, reason = _policy_allows(family, policy)
        if allowed:
            selected[fid] = {
                "matched_cwes": sorted(anchors.intersection(set(family.cwe_ids))),
                "risk_level": str(getattr(family.risk_level, "value", family.risk_level)),
                "requires_approval": bool(family.requires_approval),
                "oast_required": bool(family.oast_required),
                "scan_profile": policy.scan_profile,
            }
            if emit:
                emit_event(
                    EVENT_PAYLOAD_FAMILY_SELECTED,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    scan_profile=policy.scan_profile,
                    payload_family_id=fid,
                )
        else:
            denied[fid] = reason or "denied"
            if emit:
                emit_event(
                    EVENT_PAYLOAD_FAMILY_DENIED,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    scan_profile=policy.scan_profile,
                    payload_family_id=fid,
                    reason_code=reason,
                    level=logging.WARNING,
                )

    family_ids = tuple(sorted(selected))  # dedup (dict) + deterministic order
    manifest_hash = compute_manifest_hash(query, family_ids)
    return PayloadSelection(
        family_ids=family_ids,
        provenance={fid: selected[fid] for fid in family_ids},
        manifest_hash=manifest_hash,
        denied=denied,
    )


def families_allowed_by_profile(
    families: list[FamilyLike], scan_profile: str
) -> frozenset[str]:
    """Return family ids permitted by the profile policy (ignoring taxonomy match).

    This is the payload allow-list used to build an intent-compiler context — the
    taxonomy match is applied separately when actually selecting families.
    """
    policy = PayloadProfilePolicy.for_profile(scan_profile)
    allowed: set[str] = set()
    for family in families:
        ok, _reason = _policy_allows(family, policy)
        if ok:
            allowed.add(str(family.family_id))
    return frozenset(allowed)


def compute_manifest_hash(query: PayloadTaxonomyQuery, family_ids: tuple[str, ...]) -> str:
    """Stable SHA-256 over the query taxonomy + sorted selected families (replayable)."""
    payload = {"query": query.canonical(), "families": sorted(family_ids)}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


__all__ = [
    "CATEGORY_CWE_ANCHORS",
    "FamilyLike",
    "PayloadProfilePolicy",
    "PayloadSelection",
    "PayloadTaxonomyQuery",
    "compute_manifest_hash",
    "families_allowed_by_profile",
    "map_taxonomy_to_families",
]
