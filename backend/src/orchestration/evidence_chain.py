"""Court-grade evidence chain — immutable audit trail from scan to remediation.

Creates a tamper-evident chain linking: commit hash → scan run → tool argv
→ stdout hash → finding → PoC → remediation. Each link is SHA-256 chained
to the previous, making it impossible to alter evidence without detection.

Ось E п.3 из Развитие2.md: court-grade evidence chain.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvidenceLink:
    """A single link in the evidence chain."""

    link_type: str
    identifier: str
    content_hash: str
    parent_hash: str
    timestamp: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_type": self.link_type,
            "identifier": self.identifier,
            "content_hash": self.content_hash,
            "parent_hash": self.parent_hash,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class EvidenceChain:
    """Tamper-evident chain of custody for scan evidence.

    Each step in the pentest pipeline creates an EvidenceLink
    that chains to the previous link via SHA-256 hash. This produces
    an immutable audit trail suitable for legal/compliance review.
    """

    def __init__(self, scan_id: str, tenant_id: str) -> None:
        self.scan_id = scan_id
        self.tenant_id = tenant_id
        self._links: list[EvidenceLink] = []
        self._genesis_hash = self._compute_genesis(scan_id, tenant_id)

    @staticmethod
    def _compute_genesis(scan_id: str, tenant_id: str) -> str:
        return hashlib.sha256(f"EVIDENCE_CHAIN:{scan_id}:{tenant_id}".encode()).hexdigest()

    def _current_hash(self) -> str:
        if not self._links:
            return self._genesis_hash
        return self._links[-1].content_hash

    @staticmethod
    def _hash_content(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def add_scan_link(self, commit_hash: str = "", target_url: str = "") -> EvidenceLink:
        link = EvidenceLink(
            link_type="scan_start",
            identifier=self.scan_id,
            content_hash=self._hash_content(f"{self.scan_id}:{commit_hash}:{target_url}"),
            parent_hash=self._current_hash(),
            timestamp=time.time(),
            metadata={"commit_hash": commit_hash, "target_url": target_url},
        )
        self._links.append(link)
        return link

    def add_tool_invocation_link(
        self,
        tool_name: str,
        argv: list[str],
        stdout_hash: str = "",
    ) -> EvidenceLink:
        content = json.dumps({
            "tool": tool_name,
            "argv": argv,
            "stdout_hash": stdout_hash,
        }, sort_keys=True, default=str)
        link = EvidenceLink(
            link_type="tool_invocation",
            identifier=f"{tool_name}:{self._links[-1].identifier if self._links else self.scan_id}",
            content_hash=self._hash_content(content),
            parent_hash=self._current_hash(),
            timestamp=time.time(),
            metadata={"tool": tool_name, "argv": argv, "stdout_hash": stdout_hash},
        )
        self._links.append(link)
        return link

    def add_finding_link(
        self,
        finding_id: str,
        title: str,
        severity: str,
        evidence_tier: int = 0,
    ) -> EvidenceLink:
        content = json.dumps({
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
            "evidence_tier": evidence_tier,
        }, sort_keys=True)
        link = EvidenceLink(
            link_type="finding",
            identifier=finding_id,
            content_hash=self._hash_content(content),
            parent_hash=self._current_hash(),
            timestamp=time.time(),
            metadata={"finding_id": finding_id, "severity": severity},
        )
        self._links.append(link)
        return link

    def add_poc_link(
        self,
        finding_id: str,
        poc_type: str,
        poc_hash: str,
    ) -> EvidenceLink:
        link = EvidenceLink(
            link_type="poc",
            identifier=f"poc:{finding_id}",
            content_hash=self._hash_content(f"{finding_id}:{poc_type}:{poc_hash}"),
            parent_hash=self._current_hash(),
            timestamp=time.time(),
            metadata={"finding_id": finding_id, "poc_type": poc_type},
        )
        self._links.append(link)
        return link

    def add_remediation_link(
        self,
        finding_id: str,
        recommendation: str,
    ) -> EvidenceLink:
        link = EvidenceLink(
            link_type="remediation",
            identifier=f"remediation:{finding_id}",
            content_hash=self._hash_content(f"{finding_id}:{recommendation}"),
            parent_hash=self._current_hash(),
            timestamp=time.time(),
            metadata={"finding_id": finding_id},
        )
        self._links.append(link)
        return link

    def verify_chain(self) -> bool:
        """Verify the chain is intact — each link's parent_hash matches previous content_hash."""
        expected_parent = self._genesis_hash
        for link in self._links:
            if link.parent_hash != expected_parent:
                logger.error(
                    "Chain broken at link %s: expected parent %s, got %s",
                    link.identifier,
                    expected_parent[:16],
                    link.parent_hash[:16],
                )
                return False
            expected_parent = link.content_hash
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "genesis_hash": self._genesis_hash,
            "links": [link.to_dict() for link in self._links],
            "chain_intact": self.verify_chain(),
        }

    @property
    def link_count(self) -> int:
        return len(self._links)


__all__ = [
    "EvidenceChain",
    "EvidenceLink",
]