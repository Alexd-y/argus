"""Part II Phases K (attack narrative / chains) and L (engagement metadata)."""

from __future__ import annotations

from src.reports.engagement_builder import build_engagement_metadata, engagement_is_empty
from src.reports.report_document import ReportFinding
from src.reports.valhalla_narrative_builder import (
    build_attack_narrative,
    build_exploit_chains,
)


def _f(fid, status, cls=None, ev=None, downgrade=None):
    return ReportFinding(
        finding_id=fid,
        title=f"Finding {fid}",
        severity="high",
        verification_status=status,
        evidence_ids=ev or [],
        confirmation_class=cls,
        downgrade_reason=downgrade,
    )


# ---- Phase K ----


def test_narrative_only_includes_proven_findings():
    findings = [
        _f("F-1", "confirmed", cls="auth_bypass", ev=["E1"]),
        _f("F-2", "confirmed", cls="sqli", ev=["E2"]),
        _f("F-3", "suspected", cls="xss"),  # not proven → excluded
        _f("F-4", "confirmed", cls="rce"),  # confirmed but no evidence → excluded
    ]
    steps = build_attack_narrative(findings)
    ids = [s.description for s in steps]
    assert any("F-1" in d for d in ids)
    assert any("F-2" in d for d in ids)
    assert not any("F-3" in d for d in ids)
    assert not any("F-4" in d for d in ids)
    # Ordered by phase: entry (auth_bypass) before data_access (sqli).
    assert steps[0].phase == "entry"
    assert steps[-1].phase == "data_access"


def test_narrative_maps_mitre_where_justified():
    steps = build_attack_narrative([_f("F-1", "confirmed", cls="sqli", ev=["E1"])])
    assert steps[0].technique_id == "T1190"
    assert steps[0].tactic


def test_chains_separate_proven_from_hypothetical():
    findings = [
        _f("F-1", "confirmed", cls="auth_bypass", ev=["E1"]),
        _f("F-2", "confirmed", cls="sqli", ev=["E2"]),
        _f("F-3", "suspected", cls="xss", downgrade="reflection is not execution"),
    ]
    chains = build_exploit_chains(findings)
    kinds = {c.kind for c in chains}
    assert "proven" in kinds
    assert "hypothetical" in kinds
    proven = [c for c in chains if c.kind == "proven"][0]
    hyp = [c for c in chains if c.kind == "hypothetical"][0]
    assert len(proven.steps) >= 2
    # Hypothetical chains never merge independent hypotheses (one finding each).
    assert len(hyp.steps) == 1
    assert hyp.to_verify  # explicit "what to prove"


def test_single_proven_finding_is_not_a_chain():
    chains = build_exploit_chains([_f("F-1", "confirmed", cls="sqli", ev=["E1"])])
    assert not any(c.kind == "proven" for c in chains)


# ---- Phase L ----


def test_engagement_extracts_fields_and_redacts_passwords():
    meta = {
        "engagement": {
            "testing_windows": ["2026-01-01T00:00Z/01:00Z"],
            "source_ips": ["10.0.0.5", "10.0.0.6"],
            "user_agents": ["ARGUS/1.0"],
            "canaries": ["argus-canary-1"],
            "oast_domains": ["x.oast.pro"],
            "test_accounts": [
                {"alias": "tester1", "role": "user", "password": "secret"},
            ],
            "execution_mode": "production",
            "roe_restrictions": ["no DoS"],
            "incidents": ["WAF block at 00:30Z"],
            "time_source": "NTP pool.ntp.org",
        },
        "scan_profile": "deep",
    }
    e = build_engagement_metadata(meta)
    assert e.source_ips == ["10.0.0.5", "10.0.0.6"]
    assert e.canaries == ["argus-canary-1"]
    assert e.test_accounts == ["tester1 (user)"]
    # Password must never leak.
    assert all("secret" not in acc for acc in e.test_accounts)
    assert e.run_profile == "deep"
    assert e.execution_mode == "production"
    assert not engagement_is_empty(e)


def test_engagement_empty_when_no_data():
    assert engagement_is_empty(build_engagement_metadata({}))
    assert engagement_is_empty(build_engagement_metadata(None))
