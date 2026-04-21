"""Unit tests for :mod:`src.sandbox.parsers.whatweb_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per ``(host, plugin, version)`` tuple.
* Skipped plugins (``Title``, ``IP``, ``HTTPServer``…) do not surface.
* Versioned plugins emit ``CONFIRMED``; unversioned emit ``LIKELY``.
* URL credentials in ``target`` redacted before sidecar.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.whatweb_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_whatweb,
)


def _payload(records: list[dict]) -> bytes:
    return json.dumps(records).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_whatweb(b"", b"", tmp_path, "whatweb") == []


def test_versioned_plugin_emits_confirmed(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "target": "http://example.com",
                "http_status": 200,
                "plugins": {"Apache": {"version": ["2.4.41"]}},
            }
        ]
    )
    findings = parse_whatweb(payload, b"", tmp_path, "whatweb")
    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_unversioned_plugin_emits_likely(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "target": "http://example.com",
                "plugins": {"Apache": {}},
            }
        ]
    )
    findings = parse_whatweb(payload, b"", tmp_path, "whatweb")
    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_skipped_plugins_ignored(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "target": "http://example.com",
                "plugins": {
                    "Title": {"string": ["Welcome"]},
                    "IP": {"string": ["1.2.3.4"]},
                    "HTTPServer": {"string": ["nginx"]},
                },
            }
        ]
    )
    assert parse_whatweb(payload, b"", tmp_path, "whatweb") == []


def test_dedup_on_host_plugin_version(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "target": "http://example.com",
                "plugins": {"Apache": {"version": ["2.4"]}},
            },
            {
                "target": "http://example.com",
                "plugins": {"Apache": {"version": ["2.4"]}},
            },
        ]
    )
    assert len(parse_whatweb(payload, b"", tmp_path, "whatweb")) == 1


def test_url_credentials_redacted(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "target": "http://user:hunter2@example.com/",
                "plugins": {"PHP": {"version": ["7.4"]}},
            }
        ]
    )
    parse_whatweb(payload, b"", tmp_path, "whatweb")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "hunter2" not in sidecar


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = _payload(
        [{"target": "http://canonical.example", "plugins": {"X": {"version": ["1"]}}}]
    )
    (tmp_path / "whatweb.json").write_bytes(canonical)
    decoy = _payload(
        [{"target": "http://decoy.example", "plugins": {"Y": {"version": ["1"]}}}]
    )
    parse_whatweb(decoy, b"", tmp_path, "whatweb")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example" in sidecar
    assert "decoy.example" not in sidecar


def test_categories_field_supports_dict_input(tmp_path: Path) -> None:
    payload = json.dumps(
        {"target": "http://example.com", "plugins": {"Apache": {"version": ["2.4"]}}}
    ).encode()
    findings = parse_whatweb(payload, b"", tmp_path, "whatweb")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
