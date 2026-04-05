"""Test evidence collector."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.recon.vulnerability_analysis.evidence_collector import (
    EvidenceBundle,
    EvidenceCollector,
    HttpEvidence,
    _determine_verification,
    _extract_finding_url,
)


def test_http_evidence_model() -> None:
    e = HttpEvidence(request_method="GET", request_url="https://example.com")
    assert e.request_method == "GET"
    assert e.request_url == "https://example.com"
    assert e.response_status is None
    assert e.error is None


def test_evidence_bundle_model() -> None:
    b = EvidenceBundle(finding_id="F-001")
    assert b.finding_id == "F-001"
    assert b.http_evidence is None
    assert b.screenshot_evidence is None
    assert b.verification_result == ""


def test_evidence_bundle_defaults() -> None:
    b = EvidenceBundle()
    assert b.finding_id == ""
    assert b.collected_at  # auto-generated


@pytest.mark.asyncio
async def test_capture_http_evidence_success() -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html>test</html>"
    mock_response.headers = MagicMock()
    mock_response.headers.items.return_value = [("content-type", "text/html")]

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch(
        "src.recon.vulnerability_analysis.evidence_collector.httpx.AsyncClient",
        return_value=mock_client,
    ):
        collector = EvidenceCollector()
        evidence = await collector.capture_http_evidence("https://example.com")

    assert evidence.request_method == "GET"
    assert evidence.response_status == 200
    assert evidence.error is None


def test_extract_finding_url_from_data() -> None:
    finding = {"data": {"affected_url": "https://target.com/path"}}
    url = _extract_finding_url(finding, "https://fallback.com")
    assert url == "https://target.com/path"


def test_extract_finding_url_fallback() -> None:
    finding = {"data": {}}
    url = _extract_finding_url(finding, "https://fallback.com")
    assert url == "https://fallback.com"


def test_determine_verification_confirmed() -> None:
    ev = HttpEvidence(request_method="GET", request_url="https://x.com", response_status=200)
    assert _determine_verification(ev) == "confirmed"


def test_determine_verification_error() -> None:
    ev = HttpEvidence(request_method="GET", request_url="https://x.com", error="timeout")
    assert _determine_verification(ev) == "error"


def test_determine_verification_not_confirmed_403() -> None:
    ev = HttpEvidence(request_method="GET", request_url="https://x.com", response_status=403)
    assert _determine_verification(ev) == "not_confirmed"


def test_determine_verification_server_error() -> None:
    ev = HttpEvidence(request_method="GET", request_url="https://x.com", response_status=500)
    assert _determine_verification(ev) == "confirmed"
