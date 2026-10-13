"""Wave 3 / etap 2 — paired negative-control capture."""

from __future__ import annotations

from src.recon.vulnerability_analysis.evidence_collector import (
    EvidenceCollector,
    HttpEvidence,
    negative_control_summary,
)


async def test_capture_with_negative_control_pairs_payload_and_benign() -> None:
    collector = EvidenceCollector()
    seen: list[str] = []

    async def _fake(url, method="GET", headers=None, body=None):
        seen.append(url)
        benign = "SAFE123" in url
        return HttpEvidence(
            request_method=method,
            request_url=url,
            response_status=200,
            response_body_size=100 if benign else 900,
        )

    collector.capture_http_evidence = _fake  # type: ignore[assignment]

    positive, control = await collector.capture_with_negative_control(
        "https://t.example/search", "q", "<script>alert(1)</script>", benign_value="SAFE123"
    )
    # Two distinct requests: the payload one and the benign one.
    assert len(seen) == 2
    assert "SAFE123" in control.request_url
    assert "SAFE123" not in positive.request_url
    assert positive.request_url != control.request_url
    # The observable difference (900b vs 100b) is what proves causation.
    assert positive.response_body_size != control.response_body_size


async def test_negative_control_summary_is_human_readable() -> None:
    ctrl = HttpEvidence(
        request_method="GET",
        request_url="https://t.example/s?q=SAFE123",
        response_status=200,
        response_body_size=100,
    )
    s = negative_control_summary(ctrl)
    assert "benign value" in s and "200" in s and "100b" in s


async def test_negative_control_summary_reports_error() -> None:
    ctrl = HttpEvidence(
        request_method="GET", request_url="https://t.example/s?q=x", error="timeout"
    )
    assert "error" in negative_control_summary(ctrl)
