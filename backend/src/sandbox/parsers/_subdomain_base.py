"""Shared building blocks for ARG-032 subdomain-discovery parsers.

The recon batch (``amass_passive`` / ``subfinder`` / ``assetfinder`` /
``dnsrecon`` / ``fierce`` / ``findomain`` / ``chaos``) all flatten to a
single primitive: one INFO finding per discovered subdomain.

* :func:`is_valid_hostname` — RFC-1035 hostname syntax check (defends
  against arbitrary log-line capture when a tool prints noisy diagnostic
  output instead of the expected one-host-per-line shape).
* :func:`build_subdomain_finding` — single-place FindingDTO factory with
  the canonical CWE / OWASP wiring.
"""

from __future__ import annotations

import re
from typing import Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
)


_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def is_valid_hostname(value: str) -> bool:
    """Return True iff ``value`` is a syntactically valid DNS hostname.

    The check is intentionally strict (RFC-1035 + max-length 253) so a
    log line like ``[+] processing target...`` cannot accidentally be
    captured as a finding.
    """
    if not value:
        return False
    candidate = value.strip().rstrip(".").lower()
    if not candidate or " " in candidate or "/" in candidate:
        return False
    return _HOSTNAME_RE.match(candidate) is not None


def build_subdomain_finding(*, owasp_extra: tuple[str, ...] = ()) -> FindingDTO:
    """Build the canonical INFO finding for a discovered subdomain.

    ``owasp_extra`` lets a per-tool parser stack its own WSTG markers
    (e.g. ``WSTG-INFO-04`` for fierce's zone-transfer hits) on top of
    the baseline ``WSTG-INFO-02`` / ``WSTG-INFO-08`` pair.
    """
    owasp = ["WSTG-INFO-02", "WSTG-INFO-08", *owasp_extra]
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=owasp,
    )


__all__ = [
    "build_subdomain_finding",
    "is_valid_hostname",
]
