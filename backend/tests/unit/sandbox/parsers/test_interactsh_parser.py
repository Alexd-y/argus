"""Unit tests for :mod:`src.sandbox.parsers.interactsh_parser` (Backlog/dev1_md §4.11).

Each test pins one contract documented in the parser:

* ``parse_interactsh_jsonl`` resolves the canonical artifact first
  (``artifacts_dir/interactsh.jsonl``) and merges with ``stdout`` (both
  paths are valid: operator may pass ``-o`` AND ``-v``).
* ``protocol=http``/``https``/``smtp``/``smtps`` → :class:`FindingCategory.SSRF`
  / :class:`ConfidenceLevel.CONFIRMED`.
* ``protocol=dns`` → :class:`FindingCategory.INFO` /
  :class:`ConfidenceLevel.LIKELY`.
* Records collapse on
  ``(unique_id_or_synth, protocol, remote_address, minute_bucket)`` so a
  duplicate poll-loop replay collapses into one finding.
* Output ordering is deterministic (severity_rank desc → protocol →
  remote_address → full_id → timestamp).
* Hard cap at 5 000 findings — defends the worker against a runaway
  wildcard SSRF campaign.
* Malformed JSON lines are skipped fail-soft; one structured WARNING is
  emitted and no finding is produced for that line.
* Sidecar ``interactsh_findings.jsonl`` carries one compact record per
  emitted finding, with truncated ``raw-request`` / ``raw-response``.
* Synthetic IDs derived from SHA-256 stay stable across reruns and
  Python interpreters (PYTHONHASHSEED-safe).
* CWE / WSTG anchors: every emitted finding carries CWE-918 / WSTG-INPV-19.
* OS errors writing the sidecar are swallowed; the FindingDTO list still
  flows back to the worker.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.interactsh_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_interactsh_jsonl,
)

# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _record(
    *,
    protocol: str = "http",
    full_id: str = "c2vhx10sxxx.oast.argus.local",
    unique_id: str = "c2vhx10sxxx",
    remote_address: str = "203.0.113.55:48372",
    timestamp: str = "2026-04-19T12:34:56.123456789Z",
    raw_request: str | None = "GET /tok HTTP/1.1\r\nHost: oast.argus.local\r\n\r\n",
    raw_response: str | None = "HTTP/1.1 200 OK\r\n\r\n",
    q_type: str | None = None,
    smtp_from: str | None = None,
) -> dict[str, Any]:
    """Build a canonical interactsh JSONL record."""
    record: dict[str, Any] = {
        "protocol": protocol,
        "full-id": full_id,
        "unique-id": unique_id,
        "remote-address": remote_address,
        "timestamp": timestamp,
    }
    if raw_request is not None:
        record["raw-request"] = raw_request
    if raw_response is not None:
        record["raw-response"] = raw_response
    if q_type is not None:
        record["q-type"] = q_type
    if smtp_from is not None:
        record["smtp-from"] = smtp_from
    return record


def _to_jsonl(records: list[dict[str, Any]]) -> bytes:
    """Encode records as JSONL (one JSON object per line)."""
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Resolution: canonical artifact, stdout fallback, merge
# ---------------------------------------------------------------------------


def test_canonical_artifact_alone_emits_findings(tmp_path: Path) -> None:
    """Canonical ``interactsh.jsonl`` is picked up when present."""
    canonical = _to_jsonl([_record(unique_id="abcd")])
    (tmp_path / "interactsh.jsonl").write_bytes(canonical)

    findings = parse_interactsh_jsonl(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "abcd" in sidecar


def test_stdout_fallback_when_canonical_missing(tmp_path: Path) -> None:
    """No canonical artifact → fall back to stdout."""
    stdout_payload = _to_jsonl([_record(unique_id="from_stdout")])

    findings = parse_interactsh_jsonl(
        stdout=stdout_payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "from_stdout" in sidecar


def test_canonical_and_stdout_merge_with_dedup(tmp_path: Path) -> None:
    """Both sources may legitimately carry the same callback (operator passed
    ``-o`` AND ``-v``); the dedup pass collapses them into one finding.
    """
    record = _record(unique_id="merged")
    (tmp_path / "interactsh.jsonl").write_bytes(_to_jsonl([record]))

    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1


def test_empty_inputs_return_empty_list(tmp_path: Path) -> None:
    """No artifact + no stdout → empty list, no sidecar written."""
    findings = parse_interactsh_jsonl(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_stderr_is_ignored(tmp_path: Path) -> None:
    """interactsh stderr is banner / poll status only — must not feed parser."""
    findings = parse_interactsh_jsonl(
        stdout=b"",
        stderr=b'{"protocol": "http", "unique-id": "leak"}',
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Severity / confidence ladder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol", ["http", "https", "smtp", "smtps"])
def test_active_protocol_emits_ssrf_confirmed(tmp_path: Path, protocol: str) -> None:
    """HTTP / HTTPS / SMTP / SMTPS callbacks are CONFIRMED SSRF findings."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record(protocol=protocol)]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.SSRF
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_dns_protocol_emits_info_likely(tmp_path: Path) -> None:
    """DNS-only callbacks → INFO / LIKELY (passive resolvers are noisy)."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record(protocol="dns", q_type="A")]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_unknown_protocol_falls_back_to_info(tmp_path: Path) -> None:
    """Unknown protocols (e.g. ``smb`` / ``ftp``) fall onto INFO/LIKELY."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record(protocol="smb")]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


# ---------------------------------------------------------------------------
# CWE / WSTG anchors
# ---------------------------------------------------------------------------


def test_findings_carry_cwe918_and_wstg_inpv19(tmp_path: Path) -> None:
    """Every emitted finding carries CWE-918 and WSTG-INPV-19."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record()]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert findings[0].cwe == [918]
    assert findings[0].owasp_wstg == ["WSTG-INPV-19"]


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_dedup_collapses_same_unique_id_minute(tmp_path: Path) -> None:
    """Two records with the same (unique_id, protocol, remote_address,
    minute) collapse into one finding.
    """
    base = _record()
    later = _record(timestamp="2026-04-19T12:34:59Z")  # same minute
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([base, later]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1


def test_dedup_keeps_distinct_minutes(tmp_path: Path) -> None:
    """Same (unique_id, protocol, remote_address) but different minutes
    must produce two distinct findings.
    """
    base = _record(timestamp="2026-04-19T12:34:00Z")
    later = _record(timestamp="2026-04-19T12:35:00Z")  # next minute
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([base, later]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 2


def test_dedup_keeps_distinct_unique_ids(tmp_path: Path) -> None:
    """Different unique-ids must produce distinct findings even when every
    other field matches.
    """
    a = _record(unique_id="alpha")
    b = _record(unique_id="bravo")
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([a, b]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 2


def test_synthetic_id_when_unique_id_missing(tmp_path: Path) -> None:
    """Records without ``unique-id`` get a deterministic synthetic id —
    different (full_id, raw_request) tuples therefore stay distinct.
    """
    a = _record(unique_id="", full_id="aaa.oast.argus.local")
    b = _record(unique_id="", full_id="bbb.oast.argus.local")
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([a, b]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Determinism: stable sort + stable synthetic IDs
# ---------------------------------------------------------------------------


def test_output_order_is_severity_then_protocol(tmp_path: Path) -> None:
    """Higher severity ranks render first; ties broken by
    (protocol, remote_address, full_id, timestamp).
    """
    dns = _record(
        protocol="dns",
        unique_id="dns_id",
        remote_address="198.51.100.10:53",
        timestamp="2026-04-19T12:00:00Z",
    )
    http = _record(
        protocol="http",
        unique_id="http_id",
        remote_address="203.0.113.55:48372",
        timestamp="2026-04-19T12:30:00Z",
    )
    # Insert DNS first so we can check the parser re-orders to put HTTP first.
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([dns, http]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 2
    assert findings[0].category is FindingCategory.SSRF
    assert findings[1].category is FindingCategory.INFO


def test_synthetic_id_is_stable_across_calls(tmp_path: Path) -> None:
    """Same input must produce the same synthetic id across reruns
    (PYTHONHASHSEED-safe; we use SHA-256 not :func:`hash`)."""
    record = _record(unique_id="", full_id="stable.oast.argus.local")
    parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    sidecar1 = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")

    # Wipe sidecar and rerun.
    (tmp_path / EVIDENCE_SIDECAR_NAME).unlink()
    parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    sidecar2 = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")

    assert sidecar1 == sidecar2


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------


def test_max_findings_cap_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hard cap of 5 000 — defends against runaway SSRF campaigns.

    We monkey-patch ``_MAX_FINDINGS`` to a small value so the test stays
    fast; the contract (cap is enforced) is unchanged.
    """
    monkeypatch.setattr("src.sandbox.parsers.interactsh_parser._MAX_FINDINGS", 5)
    records = [_record(unique_id=f"id_{i}") for i in range(20)]
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl(records),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 5


def test_evidence_truncation_for_oversized_bodies(tmp_path: Path) -> None:
    """``raw-request`` / ``raw-response`` are truncated at 4 KiB UTF-8."""
    huge = "A" * 10_000
    record = _record(raw_request=huge, raw_response=huge)
    parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    sidecar = json.loads(sidecar_text.strip())
    assert "...[truncated]" in sidecar["raw_request"]
    assert "...[truncated]" in sidecar["raw_response"]
    # Truncation cap is 4096 bytes; +12 chars suffix.
    assert len(sidecar["raw_request"]) <= 4 * 1024 + 32
    assert len(sidecar["raw_response"]) <= 4 * 1024 + 32


# ---------------------------------------------------------------------------
# Fail-soft on malformed input
# ---------------------------------------------------------------------------


def test_malformed_json_line_skipped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A malformed JSON line emits a structured warning and is skipped;
    well-formed siblings still produce findings.
    """
    good = json.dumps(_record(unique_id="good"))
    bad = "this is not json"
    payload = (good + "\n" + bad + "\n").encode("utf-8")

    with caplog.at_level(logging.WARNING):
        findings = parse_interactsh_jsonl(
            stdout=payload,
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="interactsh_client",
        )

    assert len(findings) == 1
    assert any("malformed" in rec.message for rec in caplog.records)


def test_record_without_attribution_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A record with NO unique-id, NO full-id, NO remote-address is
    dropped with a structured warning.
    """
    raw = json.dumps({"protocol": "http", "timestamp": "2026-04-19T12:00:00Z"}).encode(
        "utf-8"
    )

    with caplog.at_level(logging.WARNING):
        findings = parse_interactsh_jsonl(
            stdout=raw,
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="interactsh_client",
        )

    assert findings == []
    assert any("record_skipped" in rec.message for rec in caplog.records)


def test_record_without_protocol_skipped_silently(tmp_path: Path) -> None:
    """A record without ``protocol`` (e.g. interactsh poll keepalive) is
    silently dropped — not an error.
    """
    raw = json.dumps({"unique-id": "keepalive"}).encode("utf-8")

    findings = parse_interactsh_jsonl(
        stdout=raw,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert findings == []


def test_top_level_non_dict_lines_dropped(tmp_path: Path) -> None:
    """JSON lines containing arrays / scalars are silently dropped — every
    record must be a per-callback dict.
    """
    payload = (json.dumps([1, 2, 3]) + "\n" + json.dumps("scalar") + "\n").encode(
        "utf-8"
    )

    findings = parse_interactsh_jsonl(
        stdout=payload,
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert findings == []


# ---------------------------------------------------------------------------
# Sidecar persistence
# ---------------------------------------------------------------------------


def test_sidecar_records_carry_required_fields(tmp_path: Path) -> None:
    """Sidecar JSONL carries protocol / full-id / remote-address /
    timestamp / synthetic_id for every emitted finding.
    """
    parse_interactsh_jsonl(
        stdout=_to_jsonl([_record()]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["protocol"] == "http"
    assert sidecar["full_id"] == "c2vhx10sxxx.oast.argus.local"
    assert sidecar["remote_address"] == "203.0.113.55:48372"
    assert sidecar["kind"] == "oast_callback"
    assert sidecar["tool_id"] == "interactsh_client"
    assert sidecar["synthetic_id"]


def test_sidecar_smtp_from_carried_when_present(tmp_path: Path) -> None:
    """SMTP envelope carries ``smtp-from`` for victim-side attribution."""
    record = _record(protocol="smtp", smtp_from="attacker@example.com")
    parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["smtp_from"] == "attacker@example.com"


def test_sidecar_sorted_deterministically(tmp_path: Path) -> None:
    """Sidecar records render in stable order (sort key reproducible)."""
    records = [
        _record(unique_id=f"id_{i}", remote_address=f"198.51.100.{i}:48000")
        for i in (3, 1, 2)
    ]
    parse_interactsh_jsonl(
        stdout=_to_jsonl(records),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    first = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")

    # Wipe and rerun with a different input order — output must match.
    (tmp_path / EVIDENCE_SIDECAR_NAME).unlink()
    parse_interactsh_jsonl(
        stdout=_to_jsonl(list(reversed(records))),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    second = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")

    assert first == second


# ---------------------------------------------------------------------------
# Path traversal / safety on canonical artifact lookup
# ---------------------------------------------------------------------------


def test_canonical_lookup_resilient_to_missing_dir(tmp_path: Path) -> None:
    """Non-existent canonical artifact path falls back gracefully."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record()]),
        stderr=b"",
        artifacts_dir=tmp_path / "does_not_exist",
        tool_id="interactsh_client",
    )
    # Stdout still produced one finding.
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# OAST receiver / oastify alias
# ---------------------------------------------------------------------------


def test_works_for_oastify_client_tool_id(tmp_path: Path) -> None:
    """oastify-client emits the same wire shape as interactsh — same parser."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record()]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="oastify_client",
    )

    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["tool_id"] == "oastify_client"


# ---------------------------------------------------------------------------
# Timestamp parsing edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-04-19T12:34:56Z",
        "2026-04-19T12:34:56.123456789Z",
        "2026-04-19T12:34:56+00:00",
        "2026-04-19T12:34:56-05:00",
        "2026-04-19T12:34:56+0500",
    ],
)
def test_timestamp_variants_parse_into_minute_bucket(
    tmp_path: Path, timestamp: str
) -> None:
    """All RFC-3339 variants the OAST plane can emit parse cleanly."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([_record(timestamp=timestamp)]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1


def test_unparseable_timestamp_falls_back_to_literal(tmp_path: Path) -> None:
    """An unparseable timestamp does NOT crash; the literal becomes the
    minute-bucket so dedup still groups identical lines.
    """
    record_a = _record(timestamp="garbage")
    record_b = _record(timestamp="garbage")  # identical → dedup
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record_a, record_b]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# raw-request / raw-response tolerant of legacy interactsh shapes
# ---------------------------------------------------------------------------


def test_raw_request_as_int_list_decodes_to_string(tmp_path: Path) -> None:
    """Older interactsh builds emit ``raw-request`` as a list of byte ints."""
    record = _record(
        raw_request=None,
        raw_response=None,
    )
    record["raw-request"] = [71, 69, 84, 32, 47]  # "GET /"
    record["raw-response"] = [72, 84, 84, 80]  # "HTTP"

    parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )

    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["raw_request"].startswith("GET /")
    assert sidecar["raw_response"].startswith("HTTP")


def test_raw_request_as_invalid_int_list_falls_back_to_empty(
    tmp_path: Path,
) -> None:
    """If a list contains non-int garbage (some interactsh fork bug), the
    decoder must NOT crash — it returns "" and the finding is still emitted.
    """
    record = _record(raw_request=None, raw_response=None)
    record["raw-request"] = ["not", "an", "int"]
    record["raw-response"] = []  # empty list → also "" through different branch

    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar.get("raw_request", "") == ""
    assert sidecar.get("raw_response", "") == ""


def test_raw_request_as_unexpected_type_coerces_to_str(tmp_path: Path) -> None:
    """Numeric ``raw-request`` (unexpected, but defensively handled): the
    parser stringifies via ``str(value)`` rather than crashing.
    """
    record = _record(raw_request=None, raw_response=None)
    record["raw-request"] = 12345
    record["raw-response"] = 67890

    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar.get("raw_request") == "12345"
    assert sidecar.get("raw_response") == "67890"


def test_record_without_timestamp_uses_empty_minute_bucket(
    tmp_path: Path,
) -> None:
    """A record missing ``timestamp`` is allowed; it lands in the ``""``
    minute-bucket so dedup still groups identical entries.
    """
    record_a = _record(timestamp="")
    record_b = _record(timestamp="")
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record_a, record_b]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1


def test_canonical_artifact_oserror_falls_back_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If ``Path.read_bytes`` on the canonical artifact raises ``OSError``
    (locked file, race with sandbox cleanup, …) the parser logs and
    continues with stdout — it must NOT abort the worker.
    """
    canonical = tmp_path / "interactsh.jsonl"
    canonical.write_bytes(_to_jsonl([_record()]))

    original_read_bytes = Path.read_bytes

    def _flaky(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if self.name == "interactsh.jsonl":
            raise OSError("simulated lock contention")
        return original_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", _flaky)

    with caplog.at_level(logging.WARNING):
        findings = parse_interactsh_jsonl(
            stdout=_to_jsonl(
                [
                    _record(
                        unique_id="stdout_only",
                        full_id="stdout-only.oast.argus.local",
                    )
                ]
            ),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="interactsh_client",
        )

    assert len(findings) == 1, "stdout fallback must still produce one finding"
    assert any(
        "interactsh_parser_canonical_read_failed" in rec.getMessage()
        or "canonical_read_failed" in rec.getMessage()
        for rec in caplog.records
    ), "canonical-read failure must surface a structured warning"


def test_evidence_sidecar_oserror_does_not_abort_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the sidecar write fails (read-only volume, full disk), the
    parser still returns the finding list to the worker — the sidecar is
    best-effort evidence, not a hard contract.
    """
    real_open = Path.open

    def _flaky(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.name == EVIDENCE_SIDECAR_NAME and "w" in mode:
            raise OSError("simulated read-only volume")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _flaky)

    with caplog.at_level(logging.WARNING):
        findings = parse_interactsh_jsonl(
            stdout=_to_jsonl([_record()]),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="interactsh_client",
        )

    assert len(findings) == 1, "sidecar write failure must NOT swallow the finding list"
    assert any(
        "evidence_sidecar_write_failed" in rec.getMessage() for rec in caplog.records
    ), "sidecar write failure must surface a structured warning"


def test_truncate_text_handles_empty_string(tmp_path: Path) -> None:
    """Defensive: empty ``raw-request`` / ``raw-response`` skip the
    truncation path cleanly; the sidecar simply omits the keys.
    """
    record = _record(raw_request="", raw_response="")
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1

    raw = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record_out = json.loads(raw.strip())
    assert "raw_request" not in record_out
    assert "raw_response" not in record_out


def test_unparseable_timezone_falls_back_to_literal(tmp_path: Path) -> None:
    """An RFC-3339-ish timestamp with a malformed timezone (e.g. ``+25:99``)
    cannot round-trip through ``datetime.fromisoformat`` and falls back
    to the literal string for the minute-bucket — dedup still works.
    """
    record_a = _record(timestamp="2026-04-19T12:34:56+25:99")
    record_b = _record(timestamp="2026-04-19T12:34:56+25:99")
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl([record_a, record_b]),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1, "identical malformed timestamps must still dedup"


# ---------------------------------------------------------------------------
# CVSS scoring (ARG-016/017 reviewer H1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("protocol", "expected_score"),
    [
        ("http", 7.5),
        ("https", 7.5),
        ("smb", 7.5),
        ("smtp", 7.0),
        ("smtps", 7.0),
        ("ldap", 7.0),
        ("dns", 6.5),
        ("ftp", 6.0),
        ("responder", 6.0),
    ],
)
def test_parse_interactsh_protocol_to_cvss_score(
    tmp_path: Path,
    protocol: str,
    expected_score: float,
) -> None:
    """Each documented OAST protocol lifts ``cvss_v3_score`` per H1 map.

    OAST callbacks are end-to-end proof that a sandboxed payload reached
    the OAST plane — the per-protocol score must lift the finding above
    the parser-layer ``cvss_v3_score=0.0`` sentinel so the downstream
    :class:`Prioritizer` does not flatten it to
    :attr:`PriorityTier.P4_INFO`.
    """
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl(
            [
                _record(
                    protocol=protocol,
                    unique_id=f"u_{protocol}",
                    full_id=f"u_{protocol}.oast.argus.local",
                ),
            ]
        ),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == expected_score


def test_parse_interactsh_unknown_protocol_falls_back_to_default_cvss(
    tmp_path: Path,
) -> None:
    """A future / unknown protocol → conservative info-grade baseline (6.0)."""
    findings = parse_interactsh_jsonl(
        stdout=_to_jsonl(
            [
                _record(
                    protocol="quic",
                    unique_id="u_quic",
                    full_id="u_quic.oast.argus.local",
                ),
            ]
        ),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 6.0
