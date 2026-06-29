"""Tests for evidence pack contracts (Part B3)."""

from src.llm.evidence_contracts import (
    EVIDENCE_CONTRACTS,
    build_evidence_pack,
    build_exploit_candidate_pack,
    build_vuln_evidence_pack,
)


def _findings():
    return [
        {
            "finding_id": "F1",
            "id": "ignored",
            "title": "Reflected XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "url": "https://t/x?q=1",
            "parameter": "q",
            "confidence": 0.8,
            "evidence": "x" * 5000,
        },
        "not-a-dict",
        {"id": "raw-2", "type": "sqli", "affected_url": "https://t/y"},
    ]


def test_vuln_evidence_pack_projects_and_truncates():
    pack = build_vuln_evidence_pack(_findings())
    assert pack["schema_version"] == "vuln_evidence_pack_v2"
    assert pack["count"] == 2  # non-dict dropped
    first = pack["findings"][0]
    assert first["finding_id"] == "F1"
    assert len(first["evidence"]) <= 400


def test_exploit_candidate_pack_target_and_finding_id_aliases():
    pack = build_exploit_candidate_pack(_findings())
    cands = pack["candidates"]
    assert cands[0]["finding_id"] == "F1"
    assert cands[0]["target"] == "https://t/x?q=1"
    # second finding uses id + affected_url aliases
    assert cands[1]["finding_id"] == "raw-2"
    assert cands[1]["target"] == "https://t/y"
    assert cands[1]["vuln_type"] == "sqli"


def test_build_evidence_pack_dispatch_and_unknown():
    assert build_evidence_pack("vuln_evidence_pack_v2", findings=_findings()) is not None
    assert build_evidence_pack("does_not_exist", findings=[]) is None
    assert build_evidence_pack(None) is None


def test_all_contracts_callable_defensively():
    for name in EVIDENCE_CONTRACTS:
        out = build_evidence_pack(name, findings=_findings(), recon={}, exploits=[])
        assert isinstance(out, dict)
        assert out.get("schema_version")
