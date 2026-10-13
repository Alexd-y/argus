"""Wave 2a / stage 4 — HAR exporter round-trip + redaction."""

from __future__ import annotations

import base64
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


def _big_exchange(body_len: int):
    class _Ev:
        request_method = "GET"
        request_url = "https://t.example/big"
        request_headers = {"Accept": "*/*"}
        request_body = ""
        response_status = 200
        response_headers = {"Content-Type": "text/plain"}
        response_body_snippet = "A" * body_len
        timestamp = "2026-01-01T00:00:00.000Z"

    return exchange_from_http_evidence(_Ev())


def test_export_caps_body_with_explicit_marker() -> None:
    ex = _big_exchange(10_000)
    doc = json.loads(export_har([ex], redact=False, max_body_bytes=100))
    content = doc["log"]["entries"][0]["response"]["content"]
    # size stays honest (original), stored text is cut, and the cut is marked.
    assert content["size"] == 10_000
    assert len(base64.b64decode(content["text"])) == 100
    assert "truncated" in content["comment"] and "10000" in content["comment"]


def test_export_does_not_truncate_under_cap() -> None:
    # A body under the cap round-trips losslessly (no marker, no loss).
    exchanges = import_har(json.dumps(_SOURCE_HAR))
    doc = json.loads(export_har(exchanges, redact=False, max_body_bytes=1024))
    for entry in doc["log"]["entries"]:
        assert "comment" not in entry["response"]["content"]
    assert import_har(export_har(exchanges, redact=False, max_body_bytes=1024)) == exchanges


def test_export_caps_entry_count_with_marker() -> None:
    exchanges = [_big_exchange(8) for _ in range(5)]
    doc = json.loads(export_har(exchanges, redact=False, max_entries=2))
    assert len(doc["log"]["entries"]) == 2
    assert "truncated" in doc["log"]["creator"]["comment"]
    assert "2 of 5" in doc["log"]["creator"]["comment"]


def test_http_evidence_to_har_produces_importable_har() -> None:
    from src.evidence.har_export import http_evidence_to_har

    class _Ev:
        request_method = "POST"
        request_url = "https://t.example/login?x=1"
        request_headers = {"Authorization": "Bearer SECRET-tok", "Accept": "*/*"}
        request_body = "user=admin&password=hunter2"
        response_status = 401
        response_headers = {"Content-Type": "text/plain"}
        response_body_snippet = "denied"
        timestamp = "2026-01-01T00:00:00.000Z"

    raw = http_evidence_to_har([_Ev()], redact=True)
    assert isinstance(raw, bytes)
    # Redacted: the planted bearer token and password are gone.
    assert b"SECRET-tok" not in raw
    assert b"hunter2" not in raw
    # Still a valid, importable HAR carrying the exchange.
    exchanges = import_har(raw.decode("utf-8"))
    assert len(exchanges) == 1 and exchanges[0].url == "https://t.example/login?x=1"


def test_export_redacts_query_string_secrets() -> None:
    from src.evidence.har_export import http_evidence_to_har

    class _Ev:
        request_method = "GET"
        request_url = "https://t.example/cb?code=SECRETCODE&token=SECRETTOK&q=visible"
        request_headers = {"Accept": "*/*"}
        request_body = ""
        response_status = 200
        response_headers = {"Content-Type": "text/html"}
        response_body_snippet = "ok"
        timestamp = "2026-01-01T00:00:00.000Z"

    raw = http_evidence_to_har([_Ev()], redact=True)
    text = raw.decode("utf-8")
    # Secret-bearing query values scrubbed from BOTH url and queryString.
    assert "SECRETCODE" not in text
    assert "SECRETTOK" not in text
    # Non-sensitive query value + param names survive.
    assert "visible" in text
    doc = json.loads(text)
    url = doc["log"]["entries"][0]["request"]["url"]
    assert "code=[REDACTED]" in url and "token=[REDACTED]" in url and "q=visible" in url


def test_http_evidence_to_har_skips_urlless() -> None:
    from src.evidence.har_export import http_evidence_to_har

    class _NoUrl:
        request_method = "GET"
        request_url = ""
        request_headers = {}
        request_body = ""
        response_status = None
        response_headers = {}
        response_body_snippet = ""
        timestamp = ""

    raw = http_evidence_to_har([_NoUrl()], redact=True)
    assert len(import_har(raw.decode("utf-8"))) == 0
