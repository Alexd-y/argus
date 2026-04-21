"""Unit tests for :mod:`src.findings.normalizer`."""

from __future__ import annotations

import json
import logging
from uuid import uuid4

import pytest

from src.findings.normalizer import SUPPORTED_STRATEGIES, Normalizer, ParseStrategy
from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO


@pytest.fixture
def normalizer() -> Normalizer:
    return Normalizer()


@pytest.fixture
def context_kwargs() -> dict[str, object]:
    return {
        "tool_run_id": uuid4(),
        "tool_id": "test-tool",
        "tenant_id": uuid4(),
        "scan_id": uuid4(),
        "asset_id": uuid4(),
    }


# ---------------------------------------------------------------------------
# Sanity / input validation
# ---------------------------------------------------------------------------


def test_non_bytes_raises(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    with pytest.raises(TypeError):
        normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output="hello",  # type: ignore[arg-type]
            parse_strategy=ParseStrategy.JSON_OBJECT,
        )


def test_unknown_strategy_raises(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=b"",
            parse_strategy="bogus",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("strategy", sorted(SUPPORTED_STRATEGIES, key=str))
def test_empty_input_returns_empty_list(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    strategy: ParseStrategy,
) -> None:
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=b"",
        parse_strategy=strategy,
    )
    assert findings == []


@pytest.mark.parametrize(
    "strategy",
    sorted(set(ParseStrategy) - SUPPORTED_STRATEGIES, key=str),
)
def test_unimplemented_strategy_raises(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    strategy: ParseStrategy,
) -> None:
    with pytest.raises(ValueError):
        normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=b"{}",
            parse_strategy=strategy,
        )


# ---------------------------------------------------------------------------
# Nuclei JSONL strategy
# ---------------------------------------------------------------------------


def test_nuclei_jsonl_round_trip(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    payload = {
        "template-id": "sqli-test",
        "info": {
            "name": "SQL injection",
            "severity": "high",
            "tags": ["sqli", "injection"],
            "classification": {"cwe-id": ["CWE-89"]},
        },
        "matched-at": "https://example.com/api?id=1",
        "matcher-name": "id-error",
    }
    raw = json.dumps(payload).encode("utf-8") + b"\n"
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, FindingDTO)
    assert f.category is FindingCategory.SQLI
    assert 89 in f.cwe
    assert f.cvss_v3_score >= 7.0
    assert f.tenant_id == context_kwargs["tenant_id"]


def test_nuclei_severity_unknown_falls_to_info(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = json.dumps(
        {
            "template-id": "x",
            "info": {"severity": "weird"},
            "matched-at": "https://x.invalid/",
        }
    ).encode("utf-8")
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 0.0


def test_nuclei_dedup_same_payload(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    payload = {
        "template-id": "xss-reflected",
        "info": {"severity": "medium", "tags": ["xss"]},
        "matched-at": "https://example.com/?q=test",
    }
    raw = b"\n".join([json.dumps(payload).encode("utf-8")] * 3)
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.XSS


def test_nuclei_idempotent_root_cause(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    payload = {
        "template-id": "ssrf",
        "info": {"severity": "high", "tags": ["ssrf"]},
        "matched-at": "https://internal.example/",
        "matcher-name": "callback",
    }
    raw = json.dumps(payload).encode("utf-8")
    a = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    b = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert a[0].id == b[0].id


def test_nuclei_malformed_lines_skipped_with_warning(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw = b"this is not json\n" + json.dumps(
        {"template-id": "x", "info": {"severity": "info"}, "matched-at": "https://x/"}
    ).encode("utf-8")
    with caplog.at_level(logging.WARNING, logger="src.findings.normalizer"):
        findings = normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=raw,
            parse_strategy=ParseStrategy.NUCLEI_JSONL,
        )
    assert len(findings) == 1
    assert any(
        "normalizer.nuclei.malformed" in r.message
        or "normalizer_nuclei_malformed" in r.message
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# nmap XML strategy
# ---------------------------------------------------------------------------


_NMAP_SAMPLE = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_xml_round_trip(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=_NMAP_SAMPLE,
        parse_strategy=ParseStrategy.XML_NMAP,
    )
    titles = [f.cvss_v3_vector for f in findings]
    assert len(findings) == 2
    assert all(t == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" for t in titles)
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_nmap_xml_malformed_returns_empty(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="src.findings.normalizer"):
        findings = normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=b"<not-valid-xml",
            parse_strategy=ParseStrategy.XML_NMAP,
        )
    assert findings == []
    assert any(
        "normalizer.nmap_xml.malformed" in r.message
        or "normalizer_nmap_xml_malformed" in r.message
        for r in caplog.records
    )


def test_nmap_xml_oversize_input_skipped(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("src.findings.normalizer._MAX_XML_BYTES", 4)
    with caplog.at_level(logging.WARNING, logger="src.findings.normalizer"):
        findings = normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=b"<xml/>",
            parse_strategy=ParseStrategy.XML_NMAP,
        )
    assert findings == []


# ---------------------------------------------------------------------------
# JSON strategies (single doc + JSON_LINES + JSON_GENERIC)
# ---------------------------------------------------------------------------


def test_json_single_doc_with_findings_array(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = json.dumps(
        {
            "findings": [
                {
                    "category": "xss",
                    "title": "Reflected XSS",
                    "severity": "medium",
                    "url": "https://example.com/?q=hello",
                },
                {
                    "type": "sqli",
                    "name": "SQL Injection",
                    "severity": "high",
                    "url": "https://example.com/api?id=1",
                },
            ]
        }
    ).encode("utf-8")
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.JSON_OBJECT,
    )
    cats = sorted(f.category.value for f in findings)
    assert cats == ["sqli", "xss"]


def test_json_lines_round_trip(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    line_a = json.dumps({"category": "xss", "title": "a", "severity": "low"})
    line_b = json.dumps({"category": "rce", "title": "b", "severity": "critical"})
    raw = (line_a + "\n" + line_b).encode("utf-8")
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.JSON_LINES,
    )
    assert {f.category for f in findings} == {FindingCategory.XSS, FindingCategory.RCE}


def test_json_lines_empty_lines_skipped(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = (
        b"\n\n"
        + json.dumps({"category": "info", "title": "a"}).encode("utf-8")
        + b"\n   \n"
    )
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.JSON_LINES,
    )
    assert len(findings) == 1


def test_json_lines_malformed_logs_warning(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw = b"this is not json\n" + json.dumps({"category": "info", "title": "x"}).encode(
        "utf-8"
    )
    with caplog.at_level(logging.WARNING, logger="src.findings.normalizer"):
        findings = normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=raw,
            parse_strategy=ParseStrategy.JSON_LINES,
        )
    assert len(findings) == 1
    assert any(
        "normalizer.json_lines.malformed" in r.message
        or "normalizer_json_lines_malformed" in r.message
        for r in caplog.records
    )


def test_json_malformed_returns_empty(
    normalizer: Normalizer,
    context_kwargs: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="src.findings.normalizer"):
        findings = normalizer.normalize(
            **context_kwargs,  # type: ignore[arg-type]
            raw_output=b"not-json",
            parse_strategy=ParseStrategy.JSON_OBJECT,
        )
        assert findings == []


def test_json_generic_array_top_level(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = json.dumps(
        [
            {"category": "csrf", "title": "csrf-issue"},
            {"category": "cors", "title": "cors-issue"},
        ]
    ).encode("utf-8")
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.JSON_GENERIC,
    )
    assert {f.category for f in findings} == {
        FindingCategory.CSRF,
        FindingCategory.CORS,
    }


def test_json_generic_dict_with_keyword_in_title(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = json.dumps({"title": "Reflected XSS in /search", "severity": "low"}).encode(
        "utf-8"
    )
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.JSON_GENERIC,
    )
    assert findings and findings[0].category is FindingCategory.XSS


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def test_csv_round_trip(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = (
        b"category,title,severity,url,parameter\n"
        b"xss,Reflected XSS,medium,https://x.invalid/,q\n"
        b"sqli,Time SQLi,high,https://x.invalid/api?id=1,id\n"
    )
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.CSV,
    )
    assert len(findings) == 2
    cats = sorted(f.category.value for f in findings)
    assert cats == ["sqli", "xss"]


def test_csv_empty_input(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=b"category,title\n",
        parse_strategy=ParseStrategy.CSV,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Text fallback
# ---------------------------------------------------------------------------


def test_text_fallback_extracts_severity_and_url(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = b"[2024-01-01] HIGH: detected SQLi at https://x.invalid/api?id=1 (CWE-89, CVE-2024-9999)\n"
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.TEXT_LINES,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.category is FindingCategory.INFO
    assert 89 in f.cwe


def test_text_fallback_skips_lines_without_signal(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = b"random log line\nanother\n"
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.TEXT_LINES,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_output_is_sorted_deterministically(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    raw = b"\n".join(
        [
            json.dumps(
                {
                    "template-id": f"t-{i}",
                    "info": {"severity": "low", "tags": ["xss"]},
                    "matched-at": f"https://x.invalid/{i}",
                }
            ).encode("utf-8")
            for i in range(5)
        ]
    )
    a = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    b = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
    )
    assert [f.id for f in a] == [f.id for f in b]


def test_dedup_across_3_identical_findings(
    normalizer: Normalizer, context_kwargs: dict[str, object]
) -> None:
    payload = {
        "category": "rce",
        "title": "Same finding repeated",
        "severity": "critical",
        "url": "https://example.com/cgi-bin/test",
    }
    raw = b"\n".join([json.dumps(payload).encode("utf-8")] * 3)
    findings = normalizer.normalize(
        **context_kwargs,  # type: ignore[arg-type]
        raw_output=raw,
        parse_strategy=ParseStrategy.JSON_LINES,
    )
    assert len(findings) == 1
