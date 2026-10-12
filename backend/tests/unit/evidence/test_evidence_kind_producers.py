"""Wave 2a / stage 7 — every EvidenceKind has a producer; arbiter ladder reachable."""

from __future__ import annotations

from uuid import uuid4

import pytest
from src.evidence.pcap_capture import (
    CaptureScopeError,
    CaptureSpec,
    build_bpf_filter,
    build_tcpdump_argv,
)
from src.pipeline.contracts.evidence_arbiter import DowngradeReason, adjudicate
from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind, EvidenceTier

# Producer for each EvidenceKind. Value = (producer reference, external condition
# or None). A kind added later without an entry fails the coverage assertion;
# condition-gated kinds are RECORDED, never silently skipped.
_PRODUCERS: dict[EvidenceKind, tuple[str, str | None]] = {
    EvidenceKind.RAW_OUTPUT: ("src.evidence.raw_evidence.gather_workdir_evidence", None),
    EvidenceKind.PARSED: ("src.orchestration.state_machine (finding PoC JSON)", None),
    EvidenceKind.DIFF: ("src.playbooks.evidence.build_evidence_bundle", None),
    EvidenceKind.HAR: ("src.evidence.har_export.export_har", None),
    EvidenceKind.SCREENSHOT: ("src.evidence.browser_session.browser_context", "browser"),
    EvidenceKind.VIDEO: ("src.evidence.browser_session.browser_context", "browser"),
    EvidenceKind.PCAP: ("src.evidence.pcap_capture", "tcpdump"),
    EvidenceKind.OAST_CALLBACK: ("src.oast (wave 3)", "oast_listener"),
}


def _ev(kind: EvidenceKind) -> EvidenceDTO:
    return EvidenceDTO(
        id=uuid4(),
        finding_id=uuid4(),
        tool_run_id=uuid4(),
        kind=kind,
        s3_key=f"t/s/evidence/{kind.value}.bin",
        sha256="a" * 64,
    )


def test_every_evidence_kind_has_a_producer() -> None:
    assert set(_PRODUCERS) == set(EvidenceKind)


def test_unconditional_producers_are_importable() -> None:
    from src.evidence.har_export import export_har
    from src.evidence.raw_evidence import gather_workdir_evidence
    from src.playbooks.evidence import build_evidence_bundle

    assert callable(export_har)
    assert callable(gather_workdir_evidence)
    assert callable(build_evidence_bundle)


def test_condition_gated_kinds_record_their_condition() -> None:
    gated = {EvidenceKind.SCREENSHOT, EvidenceKind.VIDEO, EvidenceKind.PCAP, EvidenceKind.OAST_CALLBACK}
    for kind in gated:
        _ref, condition = _PRODUCERS[kind]
        assert condition, f"{kind} must record its external condition, not skip silently"


def test_arbiter_ladder_confirmed_and_exploited_reachable() -> None:
    # HAR (a saved raw exchange, now produced by har_export) → CONFIRMED.
    assert adjudicate(artifacts=[_ev(EvidenceKind.HAR)]).tier is EvidenceTier.CONFIRMED
    assert adjudicate(artifacts=[_ev(EvidenceKind.PCAP)]).tier is EvidenceTier.CONFIRMED
    # HAR + SCREENSHOT (raw exchange + achieved effect) → EXPLOITED.
    assert (
        adjudicate(artifacts=[_ev(EvidenceKind.HAR), _ev(EvidenceKind.SCREENSHOT)]).tier
        is EvidenceTier.EXPLOITED
    )
    assert (
        adjudicate(artifacts=[_ev(EvidenceKind.HAR), _ev(EvidenceKind.VIDEO)]).tier
        is EvidenceTier.EXPLOITED
    )
    # All four tiers reachable with real producer kinds.
    tiers = {
        adjudicate(artifacts=[]).tier,
        adjudicate(artifacts=[_ev(EvidenceKind.RAW_OUTPUT)]).tier,
        adjudicate(artifacts=[_ev(EvidenceKind.HAR)]).tier,
        adjudicate(artifacts=[_ev(EvidenceKind.HAR), _ev(EvidenceKind.SCREENSHOT)]).tier,
    }
    assert tiers == set(EvidenceTier)


def test_browser_unavailable_caps_level_with_visible_reason() -> None:
    # Etap 1 degradation: without a browser no impact artifact is produced, so a
    # browser-confirmed class cannot reach EXPLOITED; the reason is explicit.
    from src.evidence.browser_session import playwright_available

    assert playwright_available() in (True, False)  # importable, no silent crash
    # With only a raw exchange (no browser impact proof) the tier caps at
    # CONFIRMED and records WHY it is not higher.
    verdict = adjudicate(artifacts=[_ev(EvidenceKind.HAR)])
    assert verdict.tier is EvidenceTier.CONFIRMED
    assert DowngradeReason.NO_IMPACT_PROOF in verdict.reasons


def test_pcap_filter_is_scoped_to_target() -> None:
    spec = CaptureSpec(target_host="10.0.0.5", ports=(80, 443))
    bpf = build_bpf_filter(spec)
    assert bpf == "host 10.0.0.5 and (port 80 or port 443)"
    # A neighbour address is not in the filter → its traffic is not captured.
    assert "10.0.0.6" not in bpf


def test_pcap_argv_has_limits_and_is_headers_only() -> None:
    from pathlib import Path

    spec = CaptureSpec(target_host="t.example", ports=(443,), max_seconds=30, max_bytes=10 * 1024 * 1024)
    argv = build_tcpdump_argv(spec, output_path=Path("/tmp/c.pcap"))
    assert "tcpdump" in argv[0]
    assert "-s" in argv and "96" in argv  # headers-only snaplen (payload excluded)
    assert "-C" in argv and "10" in argv  # 10 MiB size cap
    assert spec.payload_excluded is True


def test_pcap_scope_validation_rejects_bad_input() -> None:
    with pytest.raises(CaptureScopeError):
        build_bpf_filter(CaptureSpec(target_host=""))
    with pytest.raises(CaptureScopeError):
        build_bpf_filter(CaptureSpec(target_host="t.example", ports=(0,)))
    with pytest.raises(CaptureScopeError):
        build_bpf_filter(CaptureSpec(target_host="bad host!"))
