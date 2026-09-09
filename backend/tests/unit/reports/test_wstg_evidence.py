"""ARGUS-WSTG-COV-1 — evidence validation tests (spec §14 scenarios 9, 10, 11, 15)."""

from __future__ import annotations

from src.reports.wstg_evidence import (
    ArtifactKind,
    ResolvedArtifact,
    StaticEvidenceResolver,
    any_validated,
    validate_evidence,
)


def _resolve(resolver: StaticEvidenceResolver, refs, **kw):
    resolved = resolver.resolve(refs)
    return validate_evidence(resolved, **kw)


def test_scenario9_bare_string_without_artifact_is_not_validated():
    resolver = StaticEvidenceResolver({})  # nothing resolves
    v = _resolve(resolver, ["EV-TLS-001"], expected_scan_id="scan-1")
    assert v["EV-TLS-001"].validated is False


def test_scenario10_artifact_from_another_scan_rejected():
    resolver = StaticEvidenceResolver(
        {
            "k1": ResolvedArtifact(
                "k1",
                exists=True,
                kind=ArtifactKind.TOOL_OUTPUT,
                scan_id="other",
                content_present=True,
            )
        }
    )
    v = _resolve(resolver, ["k1"], expected_scan_id="scan-1")
    assert v["k1"].validated is False
    assert "another scan" in v["k1"].reason


def test_foreign_scan_allowed_when_explicitly_permitted():
    resolver = StaticEvidenceResolver(
        {
            "k1": ResolvedArtifact(
                "k1",
                exists=True,
                kind=ArtifactKind.TOOL_OUTPUT,
                scan_id="prior",
                content_present=True,
            )
        }
    )
    v = _resolve(
        resolver,
        ["k1"],
        expected_scan_id="scan-1",
        allowed_foreign_scans=frozenset({"prior"}),
    )
    assert v["k1"].validated is True


def test_scenario11_unsuitable_type_does_not_validate():
    resolver = StaticEvidenceResolver(
        {
            "k1": ResolvedArtifact(
                "k1",
                exists=True,
                kind=ArtifactKind.SCREENSHOT,
                scan_id="scan-1",
                content_present=True,
            )
        }
    )
    v = _resolve(
        resolver,
        ["k1"],
        expected_scan_id="scan-1",
        allowed_kinds=frozenset({ArtifactKind.HTTP_EXCHANGE}),
    )
    assert v["k1"].validated is False


def test_target_mismatch_rejected():
    resolver = StaticEvidenceResolver(
        {
            "k1": ResolvedArtifact(
                "k1",
                exists=True,
                kind=ArtifactKind.TOOL_OUTPUT,
                scan_id="scan-1",
                target_ref="https://a.example",
                content_present=True,
            )
        }
    )
    v = _resolve(resolver, ["k1"], expected_scan_id="scan-1", expected_target="https://b.example")
    assert v["k1"].validated is False


def test_empty_content_rejected():
    resolver = StaticEvidenceResolver(
        {"k1": ResolvedArtifact("k1", exists=True, scan_id="scan-1", content_present=False)}
    )
    v = _resolve(resolver, ["k1"], expected_scan_id="scan-1")
    assert v["k1"].validated is False


def test_finding_ref_requires_resolved_finding():
    resolver = StaticEvidenceResolver(
        {
            "FINDING:1": ResolvedArtifact(
                "FINDING:1",
                exists=True,
                kind=ArtifactKind.FINDING,
                scan_id="scan-1",
                content_present=True,
                finding_resolved=False,
            )
        }
    )
    v = _resolve(resolver, ["FINDING:1"], expected_scan_id="scan-1")
    assert v["FINDING:1"].validated is False


def test_valid_artifact_validates_and_any_validated_true():
    resolver = StaticEvidenceResolver(
        {
            "k1": ResolvedArtifact(
                "k1",
                exists=True,
                kind=ArtifactKind.TOOL_OUTPUT,
                scan_id="scan-1",
                content_present=True,
            )
        }
    )
    v = _resolve(resolver, ["k1"], expected_scan_id="scan-1")
    assert v["k1"].validated is True
    assert any_validated(v) is True
