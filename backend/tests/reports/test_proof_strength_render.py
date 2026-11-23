"""WP B — the proof-strength + stale-evidence partials render through the real
Valhalla Jinja environment (existing theme, no colour change).

Pure/offline: uses the report Jinja ``FileSystemLoader`` env; no DB/LLM/network.
"""

from __future__ import annotations

from src.reports.proof_strength import (
    build_finding_proof_strength,
    stale_banner,
)
from src.reports.template_env import get_report_jinja_environment

_PROOF = "partials/valhalla/proof_strength.html.j2"
_BANNER = "partials/valhalla/stale_evidence_banner.html.j2"


def _render(template: str, **ctx) -> str:
    env = get_report_jinja_environment()
    return env.get_template(template).render(**ctx)


def test_present_proof_strength_renders_poe_and_counterevidence() -> None:
    ps = build_finding_proof_strength(
        {
            "evidence_classification": "observed",
            "evidence_refs": ["E-1"],
            "unconfirmed_reason": "time-based payload timed out at 30s",
        },
        known_evidence_ids={"E-1"},
    ).as_dict()
    html = _render(_PROOF, row={"proof_strength": ps})
    assert "Proof strength" in html
    assert "PoE" in html
    assert "time-based payload timed out at 30s" in html
    assert "Bound evidence: 1" in html


def test_unavailable_proof_strength_never_renders_not_vulnerable() -> None:
    ps = build_finding_proof_strength(
        {"evidence_classification": "validated"},
        lookup_error=RuntimeError("evidence store down"),
    ).as_dict()
    html = _render(_PROOF, row={"proof_strength": ps}).lower()
    assert "proof strength unavailable" in html
    assert "not vulnerable" not in html
    assert "unverified" not in html


def test_proof_strength_partial_empty_without_block() -> None:
    html = _render(_PROOF, row={})
    assert html.strip() == ""


def test_stale_banner_renders_when_stale_and_is_empty_when_not() -> None:
    banner = stale_banner("v7", "v9")
    html = _render(_BANNER, evidence_stale_banner=banner)
    assert "older evidence" in html.lower()
    assert "v7" in html and "v9" in html

    clean = _render(_BANNER, evidence_stale_banner=stale_banner("v9", "v9"))
    assert clean.strip() == ""
