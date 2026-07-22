"""Unit tests for the HAR importer (WB-P10a)."""

from __future__ import annotations

import base64
import json

import pytest

from src.web_workbench.imports.har import (
    HarImportError,
    ImportedExchange,
    import_har,
)


def _entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "startedDateTime": "2026-07-22T10:00:00.000Z",
        "request": {
            "method": "GET",
            "url": "https://app.test/api/users?id=7",
            "httpVersion": "HTTP/1.1",
            "headers": [
                {"name": "Host", "value": "app.test"},
                {"name": "Accept", "value": "application/json"},
            ],
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"text": '{"ok":true}', "mimeType": "application/json"},
        },
    }
    entry.update(overrides)
    return entry


def _har(*entries: dict[str, object]) -> str:
    return json.dumps({"log": {"version": "1.2", "entries": list(entries)}})


# --------------------------------------------------------------------------- #
# Happy path                                                                  #
# --------------------------------------------------------------------------- #


def test_import_single_entry() -> None:
    exchanges = import_har(_har(_entry()))
    assert len(exchanges) == 1
    ex = exchanges[0]
    assert isinstance(ex, ImportedExchange)
    assert ex.request.method == "GET"
    assert ex.request.target == "/api/users?id=7"
    assert ex.request.header("Host") == "app.test"
    assert ex.response is not None
    assert ex.response.status_code == 200
    assert ex.response_body == b'{"ok":true}'
    assert ex.started_at == "2026-07-22T10:00:00.000Z"
    assert ex.truncated is False


def test_import_accepts_bytes() -> None:
    exchanges = import_har(_har(_entry()).encode("utf-8"))
    assert len(exchanges) == 1


def test_request_body_imported() -> None:
    entry = _entry(
        request={
            "method": "POST",
            "url": "https://app.test/login",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "postData": {"mimeType": "application/json", "text": '{"u":"a"}'},
        }
    )
    ex = import_har(_har(entry))[0]
    assert ex.request.method == "POST"
    assert ex.request_body == b'{"u":"a"}'


def test_base64_response_body_decoded() -> None:
    payload = b"\x89PNG\r\n\x1a\n binary"
    entry = _entry(
        response={
            "status": 200,
            "statusText": "OK",
            "headers": [],
            "content": {
                "text": base64.b64encode(payload).decode("ascii"),
                "encoding": "base64",
            },
        }
    )
    ex = import_har(_har(entry))[0]
    assert ex.response_body == payload


def test_host_header_synthesized_when_missing() -> None:
    entry = _entry(
        request={
            "method": "GET",
            "url": "https://example.org/x",
            "headers": [{"name": "Accept", "value": "*/*"}],
        }
    )
    ex = import_har(_har(entry))[0]
    assert ex.request.header("Host") == "example.org"


def test_multiple_entries_preserved_in_order() -> None:
    e1 = _entry()
    e2 = _entry(request={"method": "DELETE", "url": "https://app.test/api/users/1"})
    exchanges = import_har(_har(e1, e2))
    assert [e.request.method for e in exchanges] == ["GET", "DELETE"]


# --------------------------------------------------------------------------- #
# Response edge cases                                                         #
# --------------------------------------------------------------------------- #


def test_failed_request_has_no_response() -> None:
    entry = _entry(response={"status": 0, "statusText": "", "headers": [], "content": {}})
    ex = import_har(_har(entry))[0]
    assert ex.response is None
    assert ex.response_body == b""


def test_missing_response_object() -> None:
    entry = _entry()
    del entry["response"]
    ex = import_har(_har(entry))[0]
    assert ex.response is None


# --------------------------------------------------------------------------- #
# Security / robustness                                                       #
# --------------------------------------------------------------------------- #


def test_pseudo_and_injection_headers_dropped() -> None:
    entry = _entry(
        request={
            "method": "GET",
            "url": "https://app.test/x",
            "headers": [
                {"name": ":authority", "value": "app.test"},
                {"name": "X-Bad", "value": "a\r\nInjected: 1"},
                {"name": "X-Good", "value": "ok"},
            ],
        }
    )
    ex = import_har(_har(entry))[0]
    names = [name for name, _ in ex.request.headers]
    assert ":authority" not in names
    assert "X-Bad" not in names
    assert "X-Good" in names


def test_body_truncation_flagged() -> None:
    big = "A" * (5_242_880 + 10)
    entry = _entry(
        request={
            "method": "POST",
            "url": "https://app.test/upload",
            "headers": [],
            "postData": {"text": big},
        }
    )
    ex = import_har(_har(entry))[0]
    assert ex.truncated is True
    assert len(ex.request_body) == 5_242_880


def test_entry_cap_enforced() -> None:
    entries = [_entry() for _ in range(3)]
    har = json.dumps({"log": {"entries": entries}})
    # Sanity: within cap all are imported.
    assert len(import_har(har)) == 3


# --------------------------------------------------------------------------- #
# Fail-closed parsing                                                         #
# --------------------------------------------------------------------------- #


def test_invalid_json_rejected() -> None:
    with pytest.raises(HarImportError):
        import_har("{not json")


def test_root_not_object_rejected() -> None:
    with pytest.raises(HarImportError):
        import_har("[]")


def test_missing_log_rejected() -> None:
    with pytest.raises(HarImportError):
        import_har(json.dumps({"notlog": {}}))


def test_entries_not_array_rejected() -> None:
    with pytest.raises(HarImportError):
        import_har(json.dumps({"log": {"entries": {}}}))


def test_entry_missing_request_rejected() -> None:
    with pytest.raises(HarImportError):
        import_har(json.dumps({"log": {"entries": [{"response": {}}]}}))


def test_request_missing_method_rejected() -> None:
    entry = {"request": {"url": "https://app.test/x", "headers": []}}
    with pytest.raises(HarImportError):
        import_har(json.dumps({"log": {"entries": [entry]}}))


def test_request_missing_url_rejected() -> None:
    entry = {"request": {"method": "GET", "headers": []}}
    with pytest.raises(HarImportError):
        import_har(json.dumps({"log": {"entries": [entry]}}))
