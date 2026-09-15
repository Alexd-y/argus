"""Optional live-LLM smoke test for the Valhalla remediation deliverable.

Gated: runs only when ``ARGUS_LIVE_LLM_SMOKE=1`` and a report LLM provider is
configured. In CI (no provider) it is skipped rather than mocked, so a green
suite never implies a real LLM call was made (prompt §15: state clearly when no
live access was exercised).

To run against a real provider::

    ARGUS_LIVE_LLM_SMOKE=1 OPENAI_API_KEY=... \
        python -m pytest tests/unit/reports/llm_remediation/test_live_smoke.py -q
"""

import os

import pytest
from src.reports.llm_remediation.bundle import GenerationStatus
from src.reports.llm_remediation.facade_binding import build_facade_llm_callable
from src.reports.llm_remediation.integration import generate_valhalla_llm_release

_LIVE = os.getenv("ARGUS_LIVE_LLM_SMOKE") == "1"

pytestmark = pytest.mark.skipif(
    not _LIVE,
    reason="live LLM smoke disabled (set ARGUS_LIVE_LLM_SMOKE=1 + a report LLM provider)",
)


def test_live_valhalla_llm_release_smoke():
    findings = [
        {
            "finding_id": "F-LIVE-1",
            "title": "Exposed .env configuration file",
            "severity": "high",
            "verification_status": "confirmed",
            "description": "The application serves /.env exposing configuration and secrets.",
            "evidence_refs": ["E1"],
        }
    ]
    report_meta = {
        "report_id": "R-LIVE",
        "report_version": "live-smoke",
        "tenant_id": "T-LIVE",
        "scan_id": "S-LIVE",
        "target": "example.test",
    }
    doc, release = generate_valhalla_llm_release(
        findings,
        report_meta=report_meta,
        llm_callable=build_facade_llm_callable(scan_id="S-LIVE", tenant_id="T-LIVE"),
        formats=["json", "md", "xml", "html"],
        provider="facade",
        model="report_writer",
    )
    # A real provider should yield a validated analysis; at minimum the pipeline
    # must produce a coherent document + release without fabricating a fix.
    assert doc.findings and doc.findings[0].finding_id == "F-LIVE-1"
    assert release.manifest.generation_status in {
        GenerationStatus.READY,
        GenerationStatus.DRAFT,
        GenerationStatus.FAILED,
    }
    node = doc.findings[0]
    if node.closure is not None:
        # No retest was performed → the model must not claim a verified fix.
        assert node.closure.permitted_closure_status.value != "fixed_verified"
