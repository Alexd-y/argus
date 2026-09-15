"""VH-LLM-09: atomic multi-format release + manifest."""

import pytest
from src.reports.llm_remediation.bundle import (
    GenerationStatus,
    UnknownFormatError,
    build_valhalla_release,
)
from src.reports.llm_remediation.document import AssessmentCompleteness


def test_release_ready_when_complete(complete_document):
    release = build_valhalla_release(complete_document, formats=["json", "md", "xml", "html"])
    assert release.is_ready
    assert release.manifest.generation_status is GenerationStatus.READY
    assert release.manifest.xml_valid
    assert release.manifest.parity_ok
    assert set(release.manifest.artifact_hashes) == {"json", "md", "xml", "html"}
    assert all(len(h) == 64 for h in release.manifest.artifact_hashes.values())
    assert release.manifest.errors == []
    # A content/artifact hash is integrity, not a signature.
    assert release.manifest.hash_is_signature is False


def test_unknown_format_raises(complete_document):
    with pytest.raises(UnknownFormatError):
        build_valhalla_release(complete_document, formats=["docx"])


def test_incomplete_analysis_blocks_release(complete_document):
    incomplete = complete_document.model_copy(
        update={"assessment_completeness": AssessmentCompleteness.INCOMPLETE}
    )
    # Not ready without an explicit draft opt-in.
    release = build_valhalla_release(incomplete, formats=["json", "md", "xml", "html"])
    assert not release.is_ready
    assert release.manifest.generation_status is GenerationStatus.FAILED

    # Explicit draft is allowed, but still not "ready".
    draft = build_valhalla_release(
        incomplete, formats=["json", "md", "xml", "html"], allow_incomplete_draft=True
    )
    assert draft.manifest.generation_status is GenerationStatus.DRAFT
    assert not draft.is_ready


def test_one_format_failure_not_masked(complete_document, monkeypatch):
    # Force the XML to be reported invalid; the whole release must fail even
    # though the other formats render fine (prompt §12).
    monkeypatch.setattr(
        "src.reports.llm_remediation.bundle.validate_valhalla_xml",
        lambda _xml: ["forced_error"],
    )
    release = build_valhalla_release(complete_document, formats=["json", "md", "xml", "html"])
    assert release.manifest.generation_status is GenerationStatus.FAILED
    assert not release.manifest.xml_valid
    assert any("xml:forced_error" in e for e in release.manifest.errors)
