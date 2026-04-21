"""End-to-end wiring of :mod:`src.findings`.

Exercises ``Normalizer → enrichment (EPSS / KEV via fakes) → Prioritizer →
Correlator`` to verify the modules compose as advertised.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from src.findings.correlator import Correlator
from src.findings.epss_client import EpssClient, HttpResponse
from src.findings.kev_client import KevClient
from src.findings.normalizer import Normalizer, ParseStrategy
from src.findings.prioritizer import Prioritizer, PriorityTier
from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO


@dataclass
class _StubResponse:
    status_code: int
    payload: object

    def json(self) -> Any:
        return self.payload

    @property
    def text(self) -> str:
        return json.dumps(self.payload)


@dataclass
class _StubHttp:
    epss_payload: dict[str, object] = field(default_factory=dict)
    kev_payload: dict[str, object] = field(default_factory=dict)

    async def get(self, url: str, *, timeout: float) -> HttpResponse:
        if "epss" in url:
            return _StubResponse(200, self.epss_payload)
        return _StubResponse(200, self.kev_payload)


@dataclass
class _StubRedis:
    store: dict[str, str] = field(default_factory=dict)

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def setex(self, key: str, seconds: int, value: str) -> None:
        self.store[key] = value


def _enrich_finding(
    finding: FindingDTO,
    *,
    epss: float | None,
    kev: bool,
) -> FindingDTO:
    return finding.model_copy(
        update={
            "epss_score": epss,
            "kev_listed": kev,
            "mitre_attack": _attack_for_category(finding.category),
        }
    )


def _attack_for_category(category: FindingCategory) -> list[str]:
    mapping = {
        FindingCategory.SQLI: ["T1190"],
        FindingCategory.RCE: ["T1059"],
        FindingCategory.XSS: ["T1059"],
        FindingCategory.SSRF: ["T1190"],
    }
    return mapping.get(category, [])


def _nuclei_payload(
    template_id: str,
    severity: str,
    matched_at: str,
    tags: list[str],
    cve: str | None = None,
) -> bytes:
    payload: dict[str, object] = {
        "template-id": template_id,
        "info": {"severity": severity, "tags": tags, "name": template_id},
        "matched-at": matched_at,
    }
    if cve is not None:
        payload["info"] = {
            **payload["info"],  # type: ignore[dict-item]
            "classification": {"cve-id": [cve]},
        }
    return json.dumps(payload).encode("utf-8")


async def test_normalize_enrich_prioritize_and_correlate() -> None:
    tenant_id = uuid4()
    scan_id = uuid4()
    asset_id = uuid4()
    tool_run_id = uuid4()

    raw = b"\n".join(
        [
            _nuclei_payload(
                "sqli-error",
                "high",
                "https://target.example/api?id=1",
                ["sqli"],
                cve="CVE-2024-12345",
            ),
            _nuclei_payload(
                "rce-eval",
                "critical",
                "https://target.example/admin?cmd=ls",
                ["rce"],
            ),
            _nuclei_payload(
                "info-headers",
                "info",
                "https://target.example/",
                ["misconfig"],
            ),
        ]
    )

    normalizer = Normalizer()
    findings = normalizer.normalize(
        tool_run_id=tool_run_id,
        tool_id="nuclei",
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert len(findings) == 3
    cats = {f.category for f in findings}
    assert {FindingCategory.SQLI, FindingCategory.RCE} <= cats

    epss_client = EpssClient(
        _StubHttp(epss_payload={"data": [{"epss": "0.9"}]}),
        _StubRedis(),
    )
    kev_client = KevClient(
        _StubHttp(kev_payload={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}),
        _StubRedis(),
    )

    sqli_epss = await epss_client.get("CVE-2024-12345")
    sqli_kev = await kev_client.is_listed("CVE-2024-12345")
    assert sqli_epss == 0.9
    assert sqli_kev is True

    enriched: list[FindingDTO] = []
    for f in findings:
        if f.category is FindingCategory.SQLI:
            enriched.append(_enrich_finding(f, epss=sqli_epss, kev=sqli_kev))
        elif f.category is FindingCategory.RCE:
            enriched.append(_enrich_finding(f, epss=0.5, kev=False))
        else:
            enriched.append(_enrich_finding(f, epss=None, kev=False))

    prioritizer = Prioritizer()
    scores = {f.id: prioritizer.prioritize(f) for f in enriched}
    by_tier = {f.id: scores[f.id].tier for f in enriched}
    sqli_finding = next(f for f in enriched if f.category is FindingCategory.SQLI)
    info_finding = next(f for f in enriched if f.category is FindingCategory.MISCONFIG)
    assert by_tier[sqli_finding.id] in {PriorityTier.P1_HIGH, PriorityTier.P2_MEDIUM}
    assert by_tier[info_finding.id] in {PriorityTier.P3_LOW, PriorityTier.P4_INFO}

    correlator = Correlator()
    chains = correlator.correlate(enriched)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.asset_id == asset_id
    assert "T1190" in chain.attack_techniques
    assert "T1059" in chain.attack_techniques
    assert {f for f in chain.findings} >= {
        sqli_finding.id,
        next(f.id for f in enriched if f.category is FindingCategory.RCE),
    }


async def test_findings_pipeline_idempotent_across_runs() -> None:
    tenant_id = uuid4()
    scan_id = uuid4()
    asset_id = uuid4()
    tool_run_id = uuid4()
    raw = _nuclei_payload(
        "sqli", "high", "https://x.invalid/api?id=1", ["sqli"], cve="CVE-2024-1"
    )

    normalizer = Normalizer()
    a = normalizer.normalize(
        tool_run_id=tool_run_id,
        tool_id="nuclei",
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    b = normalizer.normalize(
        tool_run_id=tool_run_id,
        tool_id="nuclei",
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert [f.id for f in a] == [f.id for f in b]


async def test_correlator_only_returns_multi_step_chains() -> None:
    tenant_id = uuid4()
    scan_id = uuid4()
    asset_id = uuid4()
    tool_run_id = uuid4()
    raw = _nuclei_payload(
        "sqli", "high", "https://x.invalid/api?id=1", ["sqli"], cve="CVE-2024-1"
    )
    normalizer = Normalizer()
    findings = normalizer.normalize(
        tool_run_id=tool_run_id,
        tool_id="nuclei",
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    enriched = [_enrich_finding(f, epss=0.5, kev=False) for f in findings]
    chains = Correlator().correlate(enriched)
    assert chains == []


def _findings_assert_isinstance(findings: list[FindingDTO]) -> None:
    """Helper sanity check used by manual REPL runs (no test value here)."""
    for f in findings:
        assert isinstance(f.id, UUID)
