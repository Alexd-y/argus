"""Findings module — normalisation, correlation, enrichment, prioritisation.

Public surface (re-exported here so callers can write
``from src.findings import Normalizer`` instead of importing every submodule):

* :class:`Normalizer` — tool output → :class:`FindingDTO` list.
* :class:`Correlator` — :class:`FindingDTO` list → :class:`FindingChain` list.
* :class:`Prioritizer` + :class:`PriorityScore` — score / tier per finding.
* :class:`EpssClient` — exploit-prediction lookups (FIRST.org).
* :class:`KevClient` — CISA known-exploited-vulnerabilities lookups.
* :class:`CVSSScore`, :func:`parse_cvss_vector`, :func:`severity_label` — CVSS utilities.
* :func:`ssvc_decide` and the four SSVC enums.
"""

from src.findings.correlator import ChainSeverity, Correlator, FindingChain
from src.findings.cvss import CVSSScore, parse_cvss_vector, severity_label
from src.findings.epss_client import (
    EpssClient,
    HttpClientProtocol,
    HttpResponse,
    RedisLike,
)
from src.findings.kev_client import KevClient
from src.findings.normalizer import (
    SUPPORTED_STRATEGIES,
    NormalizationContext,
    NormalizedFinding,
    Normalizer,
    ParseStrategy,
)
from src.findings.prioritizer import (
    Prioritizer,
    PriorityComponent,
    PriorityScore,
    PriorityTier,
)
from src.findings.ssvc import (
    SSVCDecision,
    SSVCExploitation,
    SSVCExposure,
    SSVCMissionImpact,
    SSVCTechnicalImpact,
    ssvc_decide,
)

__all__ = [
    "SUPPORTED_STRATEGIES",
    "CVSSScore",
    "ChainSeverity",
    "Correlator",
    "EpssClient",
    "FindingChain",
    "HttpClientProtocol",
    "HttpResponse",
    "KevClient",
    "NormalizationContext",
    "NormalizedFinding",
    "Normalizer",
    "ParseStrategy",
    "Prioritizer",
    "PriorityComponent",
    "PriorityScore",
    "PriorityTier",
    "RedisLike",
    "SSVCDecision",
    "SSVCExploitation",
    "SSVCExposure",
    "SSVCMissionImpact",
    "SSVCTechnicalImpact",
    "parse_cvss_vector",
    "severity_label",
    "ssvc_decide",
]
