"""Wave 4 / Stage 4 — cross-cutting observation id end-to-end (R-6.2.1).

The observation id (content fingerprint) ties one observed thing across phases and must
reach the report, with a provenance flag when first contact is undefined.
"""

from __future__ import annotations

from src.reports.snapshot_builder import _observation_identity


class _F:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_fingerprint_key_becomes_observation_id() -> None:
    obs, prov = _observation_identity(_F(fingerprint_key="fp-abc", provenance={"source": "recon:httpx"}))
    assert obs == "fp-abc"
    assert prov == "recon:httpx"


def test_dict_finding_supported() -> None:
    obs, prov = _observation_identity(
        {"fingerprint_key": "fp-1", "provenance": {"first_contact": "quick_fuzz"}}
    )
    assert obs == "fp-1"
    assert prov == "quick_fuzz"


def test_first_contact_undefined_flag_when_no_provenance() -> None:
    obs, prov = _observation_identity(_F(fingerprint_key="fp-x"))
    assert obs == "fp-x"
    assert prov == "first_contact_undefined"


def test_plain_string_provenance_preserved() -> None:
    obs, prov = _observation_identity(_F(observation_id="obs-9", provenance="tool_output"))
    assert obs == "obs-9"
    assert prov == "tool_output"


def test_no_identity_leaves_both_none() -> None:
    obs, prov = _observation_identity(_F(title="x"))
    assert obs is None
    assert prov is None
