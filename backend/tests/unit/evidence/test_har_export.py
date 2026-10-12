"""Wave 2a / stage 4 — HAR exporter round-trip + redaction."""

from __future__ import annotations

import json

from src.evidence.har_export import exchange_from_http_evidence, export_har
from src.web_workbench.imports.har import import_har

_SOURCE_HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {
                "startedDateTime": "2026-01-01T00:00:00.000Z",
                "request": {
                    "method": "GET",
                    "url": "https://t.example/a?x=1&y=2",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Host", "value": "t.example"},
                        {"name": "Accept", "value": "*/*"},
                    ],
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": "Content-Type", "value": "text/plain"}],
                    "content": {"text": "aGVsbG8=", "encoding": "base64"},
                },
            },
            {
                "startedDateTime": "2026-01-01T00:00:01.000Z",
                "request": {
                    "method": "POST",
                    "url": "https://t.example/login",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": "Host", "value": "t.example"},
                        {"name": "Authorization", "value": "Bearer SECRET.tok-123"},
                    ],
                    "postData": {"text": "user=admin&password=hunter2"},
                },
                "response": {
                    "status": 401,
                    "statusText": "Unauthorized",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "content": {"text": ""},
                },
            },
        ],
    }
}


def test_export_import_round_trip_is_lossless() -> None:
    exchanges = import_har(json.dumps(_SOURCE_HAR))
    har = export_har(exchanges, redact=False)
    assert import_har(har) == exchanges


def test_export_produces_har_1_2_shape() -> None:
    exchanges = import_har(json.dumps(_SOURCE_HAR))
    doc = json.loads(export_har(exchanges, redact=False))
    assert doc["log"]["version"] == "1.2"
    assert "creator" in doc["log"]
    assert len(doc["log"]["entries"]) == 2
    entry = doc["log"]["entries"][0]
    assert {"startedDateTime", "request", "response", "time", "timings"} <= set(entry)
    assert {"method", "url", "httpVersion", "headers", "queryString"} <= set(entry["request"])


def test_export_redacts_sensitive_header_and_body() -> None:
    exchanges = import_har(json.dumps(_SOURCE_HAR))
    har = export_har(exchanges, redact=True)
    assert "Bearer SECRET.tok-123" not in har
    assert "SECRET.tok-123" not in har  # Authorization value scrubbed
    assert "hunter2" not in har  # password in postData scrubbed
    # Non-sensitive data survives.
    assert "t.example" in har
    # Still valid + re-importable after redaction.
    assert len(import_har(har)) == 2


def test_exchange_from_http_evidence() -> None:
    class _Ev:
        request_method = "GET"
        request_url = "https://t.example/p?q=1"
        request_headers = {"Accept": "*/*"}
        request_body = ""
        response_status = 200
        response_headers = {"Content-Type": "text/html"}
        response_body_snippet = "<html/>"
        timestamp = "2026-01-01T00:00:00.000Z"

    ex = exchange_from_http_evidence(_Ev())
    assert ex.url == "https://t.example/p?q=1"
    assert ex.request.method == "GET"
    assert ex.response is not None and ex.response.status_code == 200
    # Round-trips through export + import.
    assert import_har(export_har([ex], redact=False))[0].url == ex.url
