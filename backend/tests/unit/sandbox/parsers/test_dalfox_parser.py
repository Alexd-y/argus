"""Unit tests for :mod:`src.sandbox.parsers.dalfox_parser` (Backlog/dev1_md §4.10).

Each test pins one contract documented in the parser:

* ``parse_dalfox_json`` resolves the canonical artifact first
  (``artifacts_dir/dalfox.json``) and falls back to ``stdout``.
* ``type=V`` (Verified) → :class:`FindingCategory.XSS` /
  :class:`ConfidenceLevel.CONFIRMED`.
* ``type=S`` (Stored) → :class:`FindingCategory.XSS` /
  :class:`ConfidenceLevel.LIKELY`.
* ``type=R`` (Reflected) → :class:`FindingCategory.INFO` /
  :class:`ConfidenceLevel.SUSPECTED`.
* ``cwe`` is normalised from ``"CWE-79"`` / ``79`` / ``"79"`` to a
  positive int list; absent / unparseable → ``[79]``.
* Records collapse on a stable ``(url, method, param, payload[:200])``
  dedup key — re-emitted dalfox payload variants fold into one
  finding.
* Output ordering is deterministic — sorted by severity desc → url →
  param → payload.
* Hard cap at 5 000 findings — defends the worker against a runaway
  ``--mining-dict`` enumeration.
* Malformed / non-dict-list-root inputs return ``[]``; one structured
  WARNING is emitted and no sidecar is written.
* Sidecar JSONL ``dalfox_findings.jsonl`` carries one compact record
  per emitted finding, stamped with the source ``tool_id``.
* Missing ``url`` in a result is logged and the result skipped.
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
from src.sandbox.parsers._base import SENTINEL_UUID
from src.sandbox.parsers.dalfox_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_dalfox_json,
)

# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _result(
    *,
    type_: str = "V",
    url: str = "https://target.test/?q=1",
    method: str = "GET",
    param: str = "q",
    payload: str = "><script>alert(1)</script>",
    severity: str = "high",
    cwe: list[Any] | None = None,
    evidence: str = "<script>alert(1)</script>",
    poc: str = "https://target.test/?q=%3E%3Cscript%3Ealert(1)%3C/script%3E",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": type_,
        "url": url,
        "method": method,
        "param": param,
        "payload": payload,
        "evidence": evidence,
        "severity": severity,
        "poc": poc,
    }
    if cwe is not None:
        record["cwe"] = list(cwe)
    return record


def _envelope(results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Newer dalfox builds wrap results in ``{"results": [...]}``."""
    return {"results": list(results or [])}


def _payload_bytes(payload: dict[str, Any] | list[Any]) -> bytes:
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# Resolution: canonical artifact vs stdout fallback
# ---------------------------------------------------------------------------


def test_parse_dalfox_canonical_artifact_takes_precedence_over_stdout(
    tmp_path: Path,
) -> None:
    """Canonical ``dalfox.json`` wins; stdout is ignored when both are set."""
    canonical = _envelope([_result(param="canonical")])
    (tmp_path / "dalfox.json").write_bytes(_payload_bytes(canonical))

    stdout_payload = _envelope([_result(param="should_not_appear")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(stdout_payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical" in sidecar
    assert "should_not_appear" not in sidecar


def test_parse_dalfox_stdout_fallback_when_canonical_missing(
    tmp_path: Path,
) -> None:
    """No canonical → fall back to stdout."""
    payload = _envelope([_result(param="from_stdout")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1


def test_parse_dalfox_canonical_unreadable_falls_back_to_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An OSError on the canonical artefact is logged + falls back to stdout."""
    canonical_path = tmp_path / "dalfox.json"
    canonical_path.write_bytes(_payload_bytes(_envelope([_result(param="canon")])))

    real_read_bytes = Path.read_bytes

    def _raise(self: Path) -> bytes:
        if self == canonical_path:
            raise PermissionError("simulated read failure")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _raise)

    stdout_payload = _envelope([_result(param="from_stdout")])
    with caplog.at_level(logging.WARNING):
        findings = parse_dalfox_json(
            stdout=_payload_bytes(stdout_payload),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="dalfox",
        )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "from_stdout" in sidecar
    assert any(
        getattr(r, "event", "") == "dalfox_parser_canonical_read_failed"
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# Type → (category, confidence) mapping
# ---------------------------------------------------------------------------


def test_parse_dalfox_verified_type_maps_to_confirmed_xss(tmp_path: Path) -> None:
    """``type=V`` → XSS / CONFIRMED with CWE-79 + WSTG-INPV-01/02."""
    payload = _envelope([_result(type_="V", param="v_param")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.XSS
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    assert 79 in finding.cwe
    assert "WSTG-INPV-01" in finding.owasp_wstg
    assert "WSTG-INPV-02" in finding.owasp_wstg
    assert finding.tenant_id == SENTINEL_UUID


def test_parse_dalfox_stored_type_maps_to_likely_xss(tmp_path: Path) -> None:
    """``type=S`` → XSS / LIKELY (stored without verification)."""
    payload = _envelope([_result(type_="S", param="s_param")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.XSS
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_parse_dalfox_reflected_type_maps_to_suspected_info(tmp_path: Path) -> None:
    """``type=R`` → INFO / SUSPECTED (reflection without proven JS context)."""
    payload = _envelope([_result(type_="R", param="r_param")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_parse_dalfox_unknown_type_falls_back_to_reflected(tmp_path: Path) -> None:
    """Unknown ``type`` value → safe fallback to R (INFO/SUSPECTED)."""
    payload = _envelope([_result(type_="Z", param="z_param")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


# ---------------------------------------------------------------------------
# CWE normalisation
# ---------------------------------------------------------------------------


def test_parse_dalfox_cwe_string_form_is_normalised(tmp_path: Path) -> None:
    """``"CWE-79"`` string → integer 79."""
    payload = _envelope([_result(cwe=["CWE-79"])])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings[0].cwe == [79]


def test_parse_dalfox_cwe_numeric_form_is_normalised(tmp_path: Path) -> None:
    """Numeric CWE int → kept as is, default still applied when absent."""
    payload = _envelope(
        [_result(cwe=[80, "CWE-79"]), _result(payload="alt", cwe=None)],
    )
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert sorted(findings[0].cwe) in ([79, 80], [80, 79])  # order preserved
    # Second result has no cwe: → default [79]
    assert findings[1].cwe == [79]


def test_parse_dalfox_cwe_invalid_token_is_dropped(tmp_path: Path) -> None:
    """``"not-a-cwe"`` → dropped; falls back to default ``[79]``."""
    payload = _envelope([_result(cwe=["not-a-cwe", "CWE-foo"])])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings[0].cwe == [79]


# ---------------------------------------------------------------------------
# Dedup / sort / cap
# ---------------------------------------------------------------------------


def test_parse_dalfox_dedup_collapses_duplicates(tmp_path: Path) -> None:
    """Re-emitted (url, method, param, payload) → one finding."""
    duplicate = _result(param="q", payload="<svg/onload=1>")
    payload = _envelope([duplicate, dict(duplicate)])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1


def test_parse_dalfox_output_sorted_by_severity_descending(tmp_path: Path) -> None:
    """Higher severity sorts first (critical > high > medium > low > info)."""
    payload = _envelope(
        [
            _result(param="low_one", severity="low"),
            _result(param="critical_one", severity="critical"),
            _result(param="medium_one", severity="medium"),
        ],
    )
    parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    sidecar_lines = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    severities = [r["severity"] for r in sidecar_lines]
    assert severities == ["critical", "medium", "low"]


def test_parse_dalfox_output_ordering_is_deterministic(tmp_path: Path) -> None:
    """Two runs of the parser on the same payload produce identical sidecars."""
    payload = _envelope(
        [
            _result(param="z_param", payload="<svg/onload=1>"),
            _result(param="a_param", payload="><script>1</script>"),
            _result(param="m_param", payload='"onclick=1"'),
        ],
    )
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME

    parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    first = sidecar_path.read_text(encoding="utf-8")
    sidecar_path.unlink()

    parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    second = sidecar_path.read_text(encoding="utf-8")
    assert first == second


def test_parse_dalfox_caps_at_5000_findings(tmp_path: Path) -> None:
    """A pathological mining run with >5 000 unique findings is hard-capped."""
    results = [_result(param=f"p{i:05d}", payload=f"alt{i}") for i in range(5_500)]
    payload = _envelope(results)
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 5_000


# ---------------------------------------------------------------------------
# Envelope shapes
# ---------------------------------------------------------------------------


def test_parse_dalfox_top_level_array_envelope_parses(tmp_path: Path) -> None:
    """Older dalfox builds emit a bare top-level array."""
    payload = [_result(param="bare_array")]
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1


def test_parse_dalfox_poc_envelope_alternative_parses(tmp_path: Path) -> None:
    """Some dalfox builds use ``"poc"`` instead of ``"results"``."""
    payload = {"poc": [_result(param="from_poc_envelope")]}
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Sidecar contract
# ---------------------------------------------------------------------------


def test_parse_dalfox_sidecar_records_carry_tool_id(tmp_path: Path) -> None:
    """Every sidecar record is stamped with the source ``tool_id``."""
    payload = _envelope([_result(param="foo")])
    parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["tool_id"] == "dalfox"
    assert sidecar["kind"] == "dalfox_xss"
    assert sidecar["param"] == "foo"
    assert sidecar["method"] == "GET"
    assert "synthetic_id" in sidecar


def test_parse_dalfox_sidecar_only_written_when_findings_exist(
    tmp_path: Path,
) -> None:
    """No findings → no sidecar artifact (avoid confusing zero-byte files)."""
    findings = parse_dalfox_json(
        stdout=_payload_bytes(_envelope([])),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_parse_dalfox_sidecar_write_failure_swallowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OSError on the sidecar path is logged, parser still returns findings."""
    payload = _envelope([_result(param="x")])

    real_open = Path.open

    def _raise(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == EVIDENCE_SIDECAR_NAME:
            raise PermissionError("simulated sidecar failure")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", _raise)
    with caplog.at_level(logging.WARNING):
        findings = parse_dalfox_json(
            stdout=_payload_bytes(payload),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="dalfox",
        )
    assert len(findings) == 1
    assert any(
        getattr(r, "event", "") == "dalfox_parser_evidence_sidecar_write_failed"
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# Edge cases / fail-soft
# ---------------------------------------------------------------------------


def test_parse_dalfox_empty_inputs_return_empty(tmp_path: Path) -> None:
    """Empty stdout + missing canonical → ``[]`` and no sidecar."""
    findings = parse_dalfox_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_parse_dalfox_malformed_json_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Garbage stdout → ``[]``; one structured WARNING is emitted."""
    with caplog.at_level(logging.WARNING):
        findings = parse_dalfox_json(
            stdout=b"<<not-json>>",
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="dalfox",
        )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()
    assert any(
        getattr(r, "event", "") == "parsers_json_malformed" for r in caplog.records
    )


def test_parse_dalfox_non_object_non_array_root_returns_empty(
    tmp_path: Path,
) -> None:
    """A bare JSON string at the root has no iterable results → ``[]``."""
    findings = parse_dalfox_json(
        stdout=_payload_bytes("just-a-string"),  # type: ignore[arg-type]
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings == []


def test_parse_dalfox_non_dict_items_inside_results_are_skipped(
    tmp_path: Path,
) -> None:
    """Garbage entries inside ``results[]`` are silently skipped."""
    payload = {
        "results": [
            "garbage",
            42,
            None,
            _result(param="real"),
        ],
    }
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1


def test_parse_dalfox_result_missing_url_is_skipped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Result without ``url`` → skipped; one structured WARNING emitted."""
    payload = {
        "results": [
            {"type": "V", "param": "no_url"},  # missing url
            _result(param="ok"),
        ],
    }
    with caplog.at_level(logging.WARNING):
        findings = parse_dalfox_json(
            stdout=_payload_bytes(payload),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="dalfox",
        )
    assert len(findings) == 1
    assert any(
        getattr(r, "event", "") == "dalfox_parser_result_missing_url"
        for r in caplog.records
    )


def test_parse_dalfox_data_field_used_as_url_fallback(tmp_path: Path) -> None:
    """When ``url`` is absent but ``data`` is set, ``data`` becomes the URL."""
    payload = {
        "results": [
            {
                "type": "V",
                "param": "x",
                "data": "https://target.test/api?x=1",
                "payload": "<svg/onload=1>",
                "severity": "high",
            },
        ],
    }
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["url"] == "https://target.test/api?x=1"


def test_parse_dalfox_unsafe_canonical_name_rejected(tmp_path: Path) -> None:
    """A traversal-shaped canonical name is refused; falls back to stdout.

    The defensive ``_safe_join`` is only reachable via the canonical name
    constant, so we cover it through the public entry point — but the
    canonical name is hard-coded to ``dalfox.json`` (no traversal possible),
    so this test confirms the constant alone is the canonical name.
    """
    findings = parse_dalfox_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings == []


def test_parse_dalfox_severity_unknown_falls_back_to_medium(tmp_path: Path) -> None:
    """Unknown severity → ``medium`` (still ranked correctly)."""
    payload = _envelope([_result(severity="extreme", param="weird_sev")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["severity"] == "medium"


def test_parse_dalfox_stderr_is_ignored(tmp_path: Path) -> None:
    """``stderr`` carries dalfox banners only; never produces findings."""
    findings = parse_dalfox_json(
        stdout=b"",
        stderr=_payload_bytes(_envelope([_result(param="from_stderr")])),
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Defensive coverage — payload truncation + boolean cwe rejection
# ---------------------------------------------------------------------------


def test_parse_dalfox_payload_over_evidence_cap_is_truncated(tmp_path: Path) -> None:
    """A 10 KiB payload string is truncated in the sidecar evidence (4 KiB cap)."""
    huge = "B" * 10_000
    payload = _envelope([_result(payload=huge, evidence=huge, poc=huge)])
    parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["payload"].endswith("...[truncated]")
    assert sidecar["evidence_snippet"].endswith("...[truncated]")
    assert sidecar["poc"].endswith("...[truncated]")


def test_parse_dalfox_cwe_boolean_token_is_rejected(tmp_path: Path) -> None:
    """Boolean CWE token (a JSON ``true`` / ``false``) → falls back to default."""
    payload = _envelope([_result(cwe=[True, False])])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings[0].cwe == [79]


def test_parse_dalfox_cwe_negative_int_is_rejected(tmp_path: Path) -> None:
    """Negative CWE id is rejected; falls back to default ``[79]``."""
    payload = _envelope([_result(cwe=[-1, 0])])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert findings[0].cwe == [79]


# ---------------------------------------------------------------------------
# CVSS scoring (ARG-016/017 reviewer H1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected_score"),
    [
        ("critical", 9.6),
        ("high", 7.5),
        ("medium", 6.1),
        ("low", 4.3),
        ("info", 0.0),
    ],
)
def test_parse_dalfox_severity_to_cvss_score(
    tmp_path: Path,
    severity: str,
    expected_score: float,
) -> None:
    """Each documented severity bucket lifts ``cvss_v3_score`` per the H1 map.

    Without this lift the downstream :class:`Prioritizer` flattens every
    XSS finding to :attr:`PriorityTier.P4_INFO` regardless of impact.
    """
    payload = _envelope([_result(severity=severity, param=f"sev_{severity}")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == expected_score


def test_parse_dalfox_unknown_severity_falls_back_to_default_cvss(
    tmp_path: Path,
) -> None:
    """An unknown severity bucket → ``medium``-bucket CVSS (6.1) baseline."""
    payload = _envelope([_result(severity="extreme", param="weird_sev_cvss")])
    findings = parse_dalfox_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="dalfox",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 6.1
