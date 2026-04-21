"""Unit tests for :mod:`src.sandbox.parsers.httpx_parser` (Backlog/dev1_md §4.4).

Each test exercises one explicit contract documented in the parser module:

* Records without a ``url`` field are skipped (logged once).
* ``(url, tech_tuple)`` is the dedup key — duplicate rows collapse.
* The output ordering is deterministic.
* Malformed JSONL lines are skipped (the JSONL helper logs at WARNING).
* The evidence sidecar is written to ``artifacts_dir / "httpx_findings.jsonl"``
  with one compact JSON record per emitted finding.
* The dispatch-friendly adapter returns the same payload as the public
  parser and ignores the ``ParserContext`` argument.
* Empty / whitespace stdout returns no findings (and no sidecar file).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
    ParserContext,
)
from src.sandbox.parsers.httpx_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_httpx_for_dispatch,
    parse_httpx_jsonl,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jsonl(*records: dict[str, object]) -> bytes:
    """Encode ``records`` as a JSONL bytes blob."""
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records)).encode("utf-8")


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, Any]]:
    """Return parsed evidence JSONL contents (empty list if file is missing)."""
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    if not sidecar.is_file():
        return []
    return [
        cast(dict[str, Any], json.loads(line))
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Happy-path coverage
# ---------------------------------------------------------------------------


def test_single_record_produces_one_finding(tmp_path: Path) -> None:
    """A minimal httpx record with a URL emits one well-formed FindingDTO."""
    stdout = _jsonl(
        {"url": "https://example.com", "status_code": 200, "title": "Example"}
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, FindingDTO)
    assert finding.category is FindingCategory.INFO
    assert finding.cwe == [200]
    assert finding.owasp_wstg == ["WSTG-INFO-02", "WSTG-INFO-08"]
    # Sentinels — to be replaced downstream by the Normalizer.
    assert finding.id == SENTINEL_UUID
    assert finding.tenant_id == SENTINEL_UUID
    assert finding.scan_id == SENTINEL_UUID
    assert finding.asset_id == SENTINEL_UUID
    assert finding.tool_run_id == SENTINEL_UUID
    assert finding.cvss_v3_vector == SENTINEL_CVSS_VECTOR
    assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
    assert finding.confidence is ConfidenceLevel.SUSPECTED
    assert finding.status is FindingStatus.NEW
    assert finding.ssvc_decision is SSVCDecision.TRACK


def test_records_without_url_are_skipped(tmp_path: Path) -> None:
    """httpx records missing ``url`` (or with empty/whitespace) are dropped."""
    stdout = _jsonl(
        {"status_code": 200, "title": "no url"},
        {"url": "", "status_code": 200},
        {"url": "   ", "status_code": 200},
        {"url": "https://kept.example", "status_code": 200},
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)

    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    assert sidecar[0]["url"] == "https://kept.example"


def test_dedup_collapses_repeated_url_tech_pair(tmp_path: Path) -> None:
    """The same ``(url, sorted-tech)`` pair must collapse to a single finding."""
    stdout = _jsonl(
        {"url": "https://a.example", "tech": ["Nginx", "Cloudflare"]},
        {"url": "https://a.example", "tech": ["Cloudflare", "Nginx"]},
        {"url": "https://a.example", "tech": ["Nginx", "Cloudflare"]},
        {"url": "https://b.example", "tech": ["Apache"]},
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 2
    urls: list[str] = sorted({str(rec["url"]) for rec in sidecar})
    assert urls == ["https://a.example", "https://b.example"]


def test_dedup_treats_distinct_tech_as_distinct_findings(tmp_path: Path) -> None:
    """Same URL, different tech stack → two findings (rare but legitimate)."""
    stdout = _jsonl(
        {"url": "https://a.example", "tech": ["Nginx"]},
        {"url": "https://a.example", "tech": ["Apache"]},
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 2
    tech_sets: list[tuple[str, ...]] = sorted(
        tuple(str(t) for t in rec.get("tech", [])) for rec in sidecar
    )
    assert tech_sets == [("Apache",), ("Nginx",)]


def test_evidence_sidecar_contains_expected_fields(tmp_path: Path) -> None:
    """The sidecar JSONL captures URL, status, tech, title, and TLS digest."""
    stdout = _jsonl(
        {
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example",
            "webserver": "nginx/1.21.6",
            "content_type": "text/html",
            "host": "93.184.216.34",
            "favicon": "0xdeadbeef",
            "jarm": "29d29d29d29d29d",
            "tech": ["Nginx", "Cloudflare"],
            "tls": {
                "subject_cn": "example.com",
                "issuer_cn": "DigiCert",
                "tls_version": "tls13",
                "fingerprint_hash": {"sha256": "deadbeef" * 4},
            },
            # Verbose noise that MUST NOT leak into the evidence.
            "raw_request": "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: secret=1\r\n",
            "headers": {"Set-Cookie": "session=secret"},
        }
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 1
    assert len(sidecar) == 1

    record = sidecar[0]
    assert record["url"] == "https://example.com"
    assert record["status_code"] == 200
    assert record["title"] == "Example"
    assert record["tech"] == ["Cloudflare", "Nginx"]  # sorted, deduped
    assert record["webserver"] == "nginx/1.21.6"
    assert record["content_type"] == "text/html"
    assert record["host"] == "93.184.216.34"
    assert record["favicon"] == "0xdeadbeef"
    assert record["jarm"] == "29d29d29d29d29d"
    assert record["tls"] == {
        "subject_cn": "example.com",
        "issuer_cn": "DigiCert",
        "tls_version": "tls13",
        "fingerprint_hash": {"sha256": "deadbeef" * 4},
    }
    # Defence-in-depth: noisy fields stay out of the evidence projection.
    assert "raw_request" not in record
    assert "headers" not in record


def test_empty_stdout_returns_no_findings_and_no_sidecar(tmp_path: Path) -> None:
    """No input → no output, no sidecar file written."""
    findings = parse_httpx_jsonl(b"", b"", tmp_path)
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_whitespace_only_stdout_returns_no_findings(tmp_path: Path) -> None:
    """Trailing newlines / blank lines are safely tolerated."""
    findings = parse_httpx_jsonl(b"\n\n   \n", b"", tmp_path)
    assert findings == []


def test_malformed_json_lines_are_skipped(tmp_path: Path) -> None:
    """A bad JSON line in the middle must not poison surrounding records."""
    stdout = (
        _jsonl({"url": "https://good-1.example", "status_code": 200})
        + b"\n"
        + b"this is not valid json\n"
        + _jsonl({"url": "https://good-2.example", "status_code": 200})
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 2
    urls: list[str] = sorted(str(rec["url"]) for rec in sidecar)
    assert urls == ["https://good-1.example", "https://good-2.example"]


def test_tech_field_accepts_alternative_shapes(tmp_path: Path) -> None:
    """``tech`` may arrive as list / string / dict; all normalise the same way."""
    stdout = _jsonl(
        {"url": "https://a.example", "tech": ["Nginx", "Nginx", "  Apache "]},
        {"url": "https://b.example", "tech": "Nginx, Apache , Apache"},
        {"url": "https://c.example", "tech": {"Nginx": True, "Apache": False}},
        {"url": "https://d.example", "tech": None},
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 4
    by_url = {rec["url"]: rec for rec in sidecar}
    assert by_url["https://a.example"]["tech"] == ["Apache", "Nginx"]
    assert by_url["https://b.example"]["tech"] == ["Apache", "Nginx"]
    assert by_url["https://c.example"]["tech"] == ["Apache", "Nginx"]
    # Empty tech tuple → key absent from sidecar (the parser drops empties).
    assert "tech" not in by_url["https://d.example"]


def test_dispatch_adapter_matches_public_parser(tmp_path: Path) -> None:
    """``parse_httpx_for_dispatch`` is a transparent wrapper for dispatch."""
    stdout = _jsonl(
        {"url": "https://a.example", "tech": ["Nginx"]},
        {"url": "https://b.example", "tech": ["Apache"]},
    )
    direct = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar_direct = _read_sidecar(tmp_path)

    # Re-run via the dispatch adapter into a fresh artifact dir so the two
    # sidecar writes do not race.
    other = tmp_path / "via-dispatch"
    other.mkdir()
    via_dispatch = parse_httpx_for_dispatch(
        stdout,
        b"",
        other,
        ParserContext(tool_id="httpx", artifacts_dir=other),
    )
    sidecar_via_dispatch = _read_sidecar(other)

    assert [f.category for f in direct] == [f.category for f in via_dispatch]
    assert len(direct) == len(via_dispatch) == 2
    assert sidecar_direct == sidecar_via_dispatch


@pytest.mark.parametrize("raw_status", [200, 301, 401, 404, 500, 503])
def test_status_codes_are_propagated_to_evidence(
    tmp_path: Path, raw_status: int
) -> None:
    """Every standard HTTP status round-trips into the evidence record."""
    stdout = _jsonl(
        {"url": f"https://s.example/{raw_status}", "status_code": raw_status}
    )

    parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(sidecar) == 1
    assert sidecar[0]["status_code"] == raw_status


def test_sidecar_write_failure_is_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OSError during sidecar write must not propagate to the caller.

    Simulates a read-only artifacts dir by monkey-patching ``Path.open`` to
    raise on the sidecar file specifically. The parser must still return
    its FindingDTO list.
    """
    stdout = _jsonl({"url": "https://ok.example", "status_code": 200})

    real_open = Path.open

    def _raising_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == EVIDENCE_SIDECAR_NAME:
            raise PermissionError("simulated read-only mount")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _raising_open, raising=True)

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)

    assert len(findings) == 1
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


# ---------------------------------------------------------------------------
# ARG-011 follow-up coverage — extra edge cases requested by the test plan.
# Appended (do not interleave with the worker's tests above so a future
# rebase / blame stays readable).
# ---------------------------------------------------------------------------


def test_utf8_bom_prefix_does_not_crash_parser(tmp_path: Path) -> None:
    """A UTF-8 BOM at the start of stdout must not abort the whole parse.

    Python's ``json.loads`` rejects a leading ``\\ufeff`` (the BOM has no
    place inside a JSON document), so the BOM-prefixed first record is
    dropped per the documented fail-soft contract for malformed JSONL
    lines. Subsequent records still produce findings — the parser must
    keep going. This guards against a regression where a single BOM at
    the head of a piped stream would silently zero-out the whole tool
    run.
    """
    bom = "\ufeff".encode("utf-8")
    stdout = (
        bom
        + _jsonl({"url": "https://first.example", "status_code": 200})
        + b"\n"
        + _jsonl({"url": "https://second.example", "status_code": 200})
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 1
    assert sidecar[0]["url"] == "https://second.example"


def test_unicode_in_title_is_preserved_in_evidence(tmp_path: Path) -> None:
    """Non-ASCII titles round-trip through the evidence projection unchanged.

    httpx is fully UTF-8; the parser must not lose Cyrillic / CJK / emoji
    characters in the ``title`` field when writing the sidecar JSONL.
    """
    title = "Главная страница — Привет, мир!"
    stdout = _jsonl({"url": "https://ru.example", "status_code": 200, "title": title})

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 1
    assert sidecar[0]["title"] == title


def test_tech_single_item_string_coerces_to_one_element_list(
    tmp_path: Path,
) -> None:
    """A single tech name as a bare string (no comma) → one-element list."""
    stdout = _jsonl({"url": "https://a.example", "tech": "Nginx"})

    parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(sidecar) == 1
    assert sidecar[0]["tech"] == ["Nginx"]


def test_tech_empty_list_omits_field_from_evidence(tmp_path: Path) -> None:
    """An explicit empty ``tech: []`` collapses to no ``tech`` key in evidence.

    The evidence projection drops empty collections to keep payloads small
    and to mirror the ``tech: None`` behaviour already covered above.
    """
    stdout = _jsonl({"url": "https://a.example", "tech": []})

    parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(sidecar) == 1
    assert "tech" not in sidecar[0]


def test_large_input_is_deduplicated_and_completes_quickly(
    tmp_path: Path,
) -> None:
    """10 000 records with 100 unique ``(url, tech)`` pairs → 100 findings.

    Smoke-tests the parser's loop performance and dedup-set behaviour on a
    realistic-ish payload without enabling a benchmark plug-in. The 5-second
    bound is generous enough to survive a slow CI runner but tight enough
    to catch an accidental ``O(n^2)`` regression (e.g. dedup via list).
    """
    import time

    records: list[dict[str, object]] = [
        {"url": f"https://h{i % 100}.example", "tech": [f"Tech{i % 100}"]}
        for i in range(10_000)
    ]
    stdout = _jsonl(*records)

    start = time.perf_counter()
    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    elapsed = time.perf_counter() - start

    assert len(findings) == 100, f"expected 100 dedupped findings, got {len(findings)}"
    assert elapsed < 5.0, f"parser too slow on 10k records: {elapsed:.2f}s"


def test_tls_block_with_nested_issuer_and_subject_is_kept(tmp_path: Path) -> None:
    """Nested ``issuer`` / ``subject`` dicts inside ``tls`` are flattened safely.

    httpx occasionally serialises the whole certificate identity as a sub
    dict instead of flat ``subject_cn`` / ``issuer_cn`` strings. The
    projector must keep the scalar leaves of those sub dicts and drop the
    rest (chains, raw extensions) to avoid bloating the evidence sidecar.
    """
    stdout = _jsonl(
        {
            "url": "https://tls.example",
            "tls": {
                "subject_cn": "tls.example",
                "issuer_cn": "Let's Encrypt",
                "subject_dn": {"cn": "tls.example", "o": "Example Inc"},
                "issuer_dn": {"cn": "Let's Encrypt", "o": "ISRG"},
                "tls_version": "tls13",
                "chain": ["should_be_dropped"],
            },
        }
    )

    parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(sidecar) == 1
    tls = sidecar[0]["tls"]
    assert tls["subject_cn"] == "tls.example"
    assert tls["issuer_cn"] == "Let's Encrypt"
    assert tls["tls_version"] == "tls13"
    assert tls["subject_dn"] == {"cn": "tls.example", "o": "Example Inc"}
    assert tls["issuer_dn"] == {"cn": "Let's Encrypt", "o": "ISRG"}
    assert "chain" not in tls


def test_status_code_as_string_is_dropped_gracefully(tmp_path: Path) -> None:
    """A stringified ``status_code`` (``"200"``) is not silently coerced.

    The projector accepts only ``int`` for ``status_code`` (``bool``
    excluded since it subclasses int). When httpx — or a wrapper — sends
    the wrong shape, the field is omitted from evidence rather than
    propagating a typo into downstream metrics. The finding itself still
    emits because the URL is present.
    """
    stdout = _jsonl(
        {"url": "https://typo.example", "status_code": "200", "title": "Typo"}
    )

    findings = parse_httpx_jsonl(stdout, b"", tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 1
    assert "status_code" not in sidecar[0]
    assert sidecar[0]["title"] == "Typo"


def test_stderr_is_ignored_only_stdout_drives_findings(tmp_path: Path) -> None:
    """JSONL parsing keys solely off stdout; stderr noise is discarded.

    ``parse_httpx_jsonl`` accepts ``stderr`` for adapter-signature symmetry
    but explicitly deletes it. A scary-looking warnings dump on stderr
    must not influence the finding count or the sidecar contents.
    """
    stdout = _jsonl({"url": "https://ok.example", "status_code": 200})
    stderr = (
        b"WARN: TLS handshake retry on https://ok.example\n"
        b"ERROR: probe limit reached for https://ok.example\n"
    )

    findings = parse_httpx_jsonl(stdout, stderr, tmp_path)
    sidecar = _read_sidecar(tmp_path)

    assert len(findings) == 1
    assert sidecar[0]["url"] == "https://ok.example"
