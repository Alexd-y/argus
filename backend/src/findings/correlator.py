"""MITRE ATT&CK kill-chain correlation across :class:`FindingDTO`.

Groups findings on the same asset and chains them whenever their
``mitre_attack`` techniques follow a known kill-chain progression
(initial access → execution → privilege escalation → exfiltration). Lone
findings (no chainable peer) are deliberately omitted from the result —
single-step "chains" of length 1 add no signal.

The output is purely descriptive: it does NOT mutate the source findings
and it carries no I/O. Callers (reporting, prioritisation) consume the
:class:`FindingChain` records to build attack narratives.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from enum import StrEnum
from typing import Final
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.pipeline.contracts.finding_dto import FindingDTO


class ChainSeverity(StrEnum):
    """Composite severity for a multi-step attack chain."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingChain(BaseModel):
    """Ordered chain of findings forming a coherent attack narrative."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: UUID
    asset_id: UUID
    findings: tuple[UUID, ...] = Field(min_length=2, max_length=32)
    attack_techniques: tuple[StrictStr, ...] = Field(min_length=2, max_length=32)
    severity: ChainSeverity
    rationale: StrictStr = Field(min_length=1, max_length=2000)


# Kill-chain ordering (subset of MITRE ATT&CK Enterprise matrix v15). The
# numeric value reflects the typical position in an end-to-end intrusion;
# techniques sharing a value are interchangeable. We deliberately keep the
# map small (~25 entries) — adding a technique here is a conscious design
# decision, not a passive expansion.
_KILL_CHAIN_ORDER: Final[dict[str, int]] = {
    # Reconnaissance / Resource Development
    "T1595": 0,
    "T1592": 0,
    "T1589": 0,
    # Initial Access
    "T1190": 1,
    "T1133": 1,
    "T1078": 1,
    "T1566": 1,
    # Execution
    "T1059": 2,
    "T1203": 2,
    "T1106": 2,
    # Persistence
    "T1098": 3,
    "T1136": 3,
    "T1505": 3,
    # Privilege Escalation
    "T1068": 4,
    "T1548": 4,
    "T1611": 4,
    # Defense Evasion / Credential Access
    "T1003": 5,
    "T1110": 5,
    "T1212": 5,
    # Discovery / Lateral Movement
    "T1083": 6,
    "T1018": 6,
    "T1021": 6,
    # Collection / Exfiltration
    "T1005": 7,
    "T1041": 7,
    "T1567": 7,
    # Impact
    "T1486": 8,
    "T1499": 8,
}


_NAMESPACE_CHAIN: Final[UUID] = UUID("8b1d4f54-3a8d-49e7-9c3a-7f1a0b3e2233")


class Correlator:
    """Build :class:`FindingChain` records from a list of findings."""

    def correlate(self, findings: Sequence[FindingDTO]) -> list[FindingChain]:
        """Return every multi-step attack chain present in ``findings``.

        Output ordering is deterministic: chains sorted by ``asset_id`` then
        by the ordered ``attack_techniques`` tuple.
        """
        if not findings:
            return []

        per_asset: dict[UUID, list[FindingDTO]] = defaultdict(list)
        for finding in findings:
            if not finding.mitre_attack:
                continue
            per_asset[finding.asset_id].append(finding)

        chains: list[FindingChain] = []
        for asset_id, asset_findings in per_asset.items():
            chain = self._chain_for_asset(asset_id, asset_findings)
            if chain is not None:
                chains.append(chain)

        chains.sort(key=lambda c: (str(c.asset_id), c.attack_techniques))
        return chains

    def _chain_for_asset(
        self, asset_id: UUID, findings: Sequence[FindingDTO]
    ) -> FindingChain | None:
        """Return a chain for ``asset_id`` if at least 2 ordered steps exist."""
        ordered: list[tuple[int, str, FindingDTO]] = []
        for finding in findings:
            for technique in finding.mitre_attack:
                position = _KILL_CHAIN_ORDER.get(technique)
                if position is None:
                    continue
                ordered.append((position, technique, finding))

        if len(ordered) < 2:
            return None

        ordered.sort(key=lambda triple: (triple[0], triple[1], str(triple[2].id)))

        seen_findings: set[UUID] = set()
        seen_techniques: set[str] = set()
        chain_finding_ids: list[UUID] = []
        chain_techniques: list[str] = []
        for _, technique, finding in ordered:
            if technique in seen_techniques:
                continue
            seen_techniques.add(technique)
            chain_techniques.append(technique)
            if finding.id in seen_findings:
                continue
            seen_findings.add(finding.id)
            chain_finding_ids.append(finding.id)

        if len(chain_techniques) < 2 or len(chain_finding_ids) < 2:
            return None

        severity = _severity_from_findings(
            [f for _, _, f in ordered if f.id in seen_findings]
        )
        rationale = (
            f"{len(chain_techniques)} kill-chain steps observed on asset {asset_id}: "
            f"{' → '.join(chain_techniques)}"
        )
        chain_id = uuid5(
            _NAMESPACE_CHAIN,
            f"{asset_id}|{'|'.join(chain_techniques)}",
        )
        return FindingChain(
            chain_id=chain_id,
            asset_id=asset_id,
            findings=tuple(chain_finding_ids),
            attack_techniques=tuple(chain_techniques),
            severity=severity,
            rationale=rationale[:2000],
        )


def _severity_from_findings(findings: Sequence[FindingDTO]) -> ChainSeverity:
    """Map the maximum CVSS base score of ``findings`` to a chain severity."""
    if not findings:
        return ChainSeverity.LOW
    max_score = max(f.cvss_v3_score for f in findings)
    if max_score >= 9.0:
        return ChainSeverity.CRITICAL
    if max_score >= 7.0:
        return ChainSeverity.HIGH
    if max_score >= 4.0:
        return ChainSeverity.MEDIUM
    return ChainSeverity.LOW


__all__ = [
    "ChainSeverity",
    "Correlator",
    "FindingChain",
]
