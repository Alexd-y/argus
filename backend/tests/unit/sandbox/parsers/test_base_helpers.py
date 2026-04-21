"""Unit tests for :mod:`src.sandbox.parsers._base` helpers (ARG-011).

The shared parser utilities are the choke-point every concrete tool parser
under :mod:`src.sandbox.parsers` reuses, so their failure-mode contract
needs its own pinned test surface independent of any specific parser:

* :func:`safe_load_jsonl`
    - empty / whitespace bytes → empty iterator
    - mix of valid + malformed lines → only the valid dicts are yielded;
      malformed line is logged at WARNING (not propagated)
    - ``strict=True`` + malformed line → :class:`ParseError`
    - oversized input → empty iterator + warning (defence-in-depth size cap)
    - non-dict JSON values → silently skipped (per-record dict contract)

* :func:`safe_load_json`
    - empty bytes → ``None`` (regardless of ``strict``)
    - well-formed dict / list → returned verbatim
    - malformed text → ``None`` with ``strict=False``, raises with strict
    - non-UTF-8 bytes → decoded with ``errors="replace"``; the resulting
      replacement-char document fails to parse → ``None`` / raises per
      ``strict`` flag

* :func:`make_finding_dto`
    - minimal args produce a fully populated :class:`FindingDTO` with
      every sentinel populated and the contract-required fields filled
    - empty ``cwe`` is rejected with :class:`ParseError`
    - optional fields (``owasp_wstg``, ``mitre_attack``, ``epss_score``,
      ``kev_listed``) round-trip through the factory

These tests never touch the disk, the network, or the dispatch registry.
"""

from __future__ import annotations

import logging

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
    ParseError,
    make_finding_dto,
    safe_decode,
    safe_load_json,
    safe_load_jsonl,
)


# ---------------------------------------------------------------------------
# safe_load_jsonl
# ---------------------------------------------------------------------------


def test_safe_load_jsonl_empty_bytes_returns_empty() -> None:
    """``b""`` and ``None`` both yield no records."""
    assert list(safe_load_jsonl(b"", tool_id="x")) == []
    assert list(safe_load_jsonl(None, tool_id="x")) == []


def test_safe_load_jsonl_whitespace_only_returns_empty() -> None:
    """Blank lines and trailing whitespace yield no records."""
    assert list(safe_load_jsonl(b"\n\n   \n\t\n", tool_id="x")) == []


def test_safe_load_jsonl_valid_plus_malformed_keeps_valid(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A bad line in the middle must not poison the surrounding records.

    The valid records are still yielded; the malformed line is logged at
    WARNING with the structured event ``parsers.jsonl.malformed``.
    """
    raw = b'{"a": 1}\nthis is not valid json\n{"a": 2}\n'
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers._base"):
        records = list(safe_load_jsonl(raw, tool_id="my_tool"))

    assert records == [{"a": 1}, {"a": 2}]
    assert any(
        "parsers.jsonl.malformed" in rec.getMessage()
        or getattr(rec, "event", "") == "parsers_jsonl_malformed"
        for rec in caplog.records
    )


def test_safe_load_jsonl_strict_raises_on_malformed() -> None:
    """In ``strict=True`` mode the first malformed line surfaces an error.

    Iterators are lazy, so the iteration must be forced (``list``) for
    the exception to fire — that's the documented contract.
    """
    raw = b'{"a": 1}\nnot json\n{"a": 2}\n'
    with pytest.raises(ParseError, match="malformed JSONL line"):
        list(safe_load_jsonl(raw, tool_id="x", strict=True))


def test_safe_load_jsonl_drops_non_dict_records() -> None:
    """JSON arrays / scalars must be silently skipped — parsers expect dicts."""
    raw = b'{"a": 1}\n[1, 2, 3]\n42\n"naked string"\n{"b": 2}\n'
    records = list(safe_load_jsonl(raw, tool_id="x"))
    assert records == [{"a": 1}, {"b": 2}]


def test_safe_load_jsonl_oversized_input_returns_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Inputs above ``limit`` short-circuit to an empty iterator + warning."""
    raw = b"a" * (MAX_STDOUT_BYTES + 1)
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers._base"):
        records = list(safe_load_jsonl(raw, tool_id="x"))

    assert records == []
    assert any(
        "parsers.safe_decode.oversize" in rec.getMessage()
        or getattr(rec, "event", "") == "parsers_safe_decode_oversize"
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# safe_load_json
# ---------------------------------------------------------------------------


def test_safe_load_json_empty_bytes_returns_none() -> None:
    """Empty / ``None`` input → ``None`` regardless of strict mode."""
    assert safe_load_json(b"", tool_id="x") is None
    assert safe_load_json(None, tool_id="x") is None
    assert safe_load_json(b"", tool_id="x", strict=True) is None
    assert safe_load_json(None, tool_id="x", strict=True) is None


def test_safe_load_json_dict_round_trips() -> None:
    """A well-formed JSON object is returned verbatim."""
    payload = safe_load_json(b'{"k": "v", "n": 1}', tool_id="x")
    assert payload == {"k": "v", "n": 1}


def test_safe_load_json_list_round_trips() -> None:
    """A well-formed JSON array is returned verbatim (parsers may want it)."""
    payload = safe_load_json(b"[1, 2, 3]", tool_id="x")
    assert payload == [1, 2, 3]


def test_safe_load_json_malformed_returns_none_default() -> None:
    """Default mode degrades to ``None`` on parse failure (with WARNING log)."""
    payload = safe_load_json(b"{not valid json", tool_id="x")
    assert payload is None


def test_safe_load_json_malformed_strict_raises() -> None:
    """``strict=True`` surfaces a :class:`ParseError`."""
    with pytest.raises(ParseError, match="malformed JSON document"):
        safe_load_json(b"{not valid json", tool_id="x", strict=True)


def test_safe_load_json_non_utf8_bytes_returns_none() -> None:
    """Invalid UTF-8 sequences are decoded with ``errors="replace"``.

    The resulting replacement-character document is not valid JSON, so
    ``strict=False`` returns ``None`` with a structured WARNING.
    """
    raw = b"\xff\xfe\xfd"  # not a valid UTF-8 prefix
    assert safe_load_json(raw, tool_id="x") is None


def test_safe_load_json_non_utf8_bytes_strict_raises() -> None:
    """In strict mode the replacement-char document raises ``ParseError``."""
    raw = b"\xff\xfe\xfd"
    with pytest.raises(ParseError, match="malformed JSON document"):
        safe_load_json(raw, tool_id="x", strict=True)


# ---------------------------------------------------------------------------
# safe_decode (defence-in-depth — the JSONL helper relies on it)
# ---------------------------------------------------------------------------


def test_safe_decode_returns_empty_for_falsy_input() -> None:
    assert safe_decode(b"", limit=10) == ""
    assert safe_decode(None, limit=10) == ""
    assert safe_decode(bytearray(), limit=10) == ""


def test_safe_decode_oversized_returns_empty_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw = b"x" * 11
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers._base"):
        out = safe_decode(raw, limit=10)
    assert out == ""
    assert any(
        "parsers.safe_decode.oversize" in rec.getMessage()
        or getattr(rec, "event", "") == "parsers_safe_decode_oversize"
        for rec in caplog.records
    )


def test_safe_decode_replaces_invalid_utf8_does_not_raise() -> None:
    """``errors="replace"`` is the documented decode strategy."""
    out = safe_decode(b"hello\xff", limit=10)
    assert out.startswith("hello")
    assert "\ufffd" in out


# ---------------------------------------------------------------------------
# make_finding_dto
# ---------------------------------------------------------------------------


def test_make_finding_dto_minimal_args_populates_all_required_fields() -> None:
    """``category`` + ``cwe`` is enough; sentinels fill the rest.

    The downstream Normalizer replaces every ``SENTINEL_UUID`` and bumps
    severity once the finding has a real scan / asset context — but the
    DTO must still satisfy its Pydantic contract immediately on creation.
    """
    finding = make_finding_dto(category=FindingCategory.INFO, cwe=[200])

    assert isinstance(finding, FindingDTO)
    assert finding.id == SENTINEL_UUID
    assert finding.tenant_id == SENTINEL_UUID
    assert finding.scan_id == SENTINEL_UUID
    assert finding.asset_id == SENTINEL_UUID
    assert finding.tool_run_id == SENTINEL_UUID
    assert finding.category is FindingCategory.INFO
    assert finding.cwe == [200]
    assert finding.cvss_v3_vector == SENTINEL_CVSS_VECTOR
    assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
    assert finding.epss_score is None
    assert finding.kev_listed is False
    assert finding.confidence is ConfidenceLevel.SUSPECTED
    assert finding.status is FindingStatus.NEW
    assert finding.ssvc_decision is SSVCDecision.TRACK
    assert finding.owasp_wstg == []
    assert finding.mitre_attack == []
    assert finding.first_seen == finding.last_seen


def test_make_finding_dto_optional_fields_round_trip() -> None:
    """OWASP / MITRE / EPSS / KEV passthroughs land on the DTO unchanged."""
    finding = make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 16],
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
        mitre_attack=["T1592"],
        epss_score=0.42,
        kev_listed=True,
        confidence=ConfidenceLevel.LIKELY,
        status=FindingStatus.NEW,
        ssvc_decision=SSVCDecision.TRACK_STAR,
    )

    assert finding.cwe == [200, 16]
    assert finding.owasp_wstg == ["WSTG-INFO-02", "WSTG-INFO-08"]
    assert finding.mitre_attack == ["T1592"]
    assert finding.epss_score == pytest.approx(0.42)
    assert finding.kev_listed is True
    assert finding.confidence is ConfidenceLevel.LIKELY
    assert finding.ssvc_decision is SSVCDecision.TRACK_STAR


def test_make_finding_dto_empty_cwe_is_rejected() -> None:
    """``cwe=[]`` violates the FindingDTO contract — we surface ParseError."""
    with pytest.raises(ParseError, match="cwe must contain at least one"):
        make_finding_dto(category=FindingCategory.INFO, cwe=[])


def test_make_finding_dto_returns_immutable_dto() -> None:
    """The Pydantic model is frozen — direct mutation must raise."""
    finding = make_finding_dto(category=FindingCategory.INFO, cwe=[200])
    with pytest.raises(Exception):
        finding.kev_listed = True
