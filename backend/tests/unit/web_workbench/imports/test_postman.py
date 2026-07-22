"""Unit tests for the Postman Collection v2.1 importer (WB-P10c)."""

from __future__ import annotations

import json

import pytest

from src.web_workbench.imports.har import ImportedExchange
from src.web_workbench.imports.postman import PostmanImportError, import_postman


def _collection(*items: dict[str, object], **overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "info": {
            "name": "c",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": list(items),
    }
    doc.update(overrides)
    return doc


def _req_item(name: str, request: dict[str, object]) -> dict[str, object]:
    return {"name": name, "request": request}


# --------------------------------------------------------------------------- #
# URL forms                                                                   #
# --------------------------------------------------------------------------- #


def test_import_string_url() -> None:
    doc = _collection(_req_item("get", {"method": "GET", "url": "https://api.test/users?limit=10"}))
    exchanges = import_postman(json.dumps(doc))
    assert len(exchanges) == 1
    ex = exchanges[0]
    assert isinstance(ex, ImportedExchange)
    assert ex.request.method == "GET"
    assert ex.request.target == "/users?limit=10"
    assert ex.request.header("Host") == "api.test"
    assert ex.response is None


def test_import_url_object_raw() -> None:
    doc = _collection(
        _req_item(
            "get",
            {"method": "GET", "url": {"raw": "https://api.test/items/1", "host": ["api", "test"]}},
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.target == "/items/1"
    assert ex.request.header("Host") == "api.test"


def test_import_url_object_components() -> None:
    doc = _collection(
        _req_item(
            "get",
            {
                "method": "GET",
                "url": {
                    "protocol": "https",
                    "host": ["api", "test"],
                    "path": ["v2", "ping"],
                    "query": [
                        {"key": "q", "value": "x"},
                        {"key": "off", "value": "y", "disabled": True},
                    ],
                },
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.target == "/v2/ping?q=x"


def test_yaml_collection_supported() -> None:
    yaml_doc = (
        "info:\n  name: c\n  schema: v2.1.0\n"
        "item:\n"
        "  - name: ping\n"
        "    request:\n"
        "      method: GET\n"
        "      url: https://api.test/ping\n"
    )
    ex = import_postman(yaml_doc)[0]
    assert ex.request.target == "/ping"


# --------------------------------------------------------------------------- #
# Variables                                                                   #
# --------------------------------------------------------------------------- #


def test_collection_variable_resolved() -> None:
    doc = _collection(
        _req_item("get", {"method": "GET", "url": "{{base_url}}/health"}),
        variable=[{"key": "base_url", "value": "https://api.test"}],
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.header("Host") == "api.test"
    assert ex.request.target == "/health"


def test_variable_override_wins() -> None:
    doc = _collection(
        _req_item("get", {"method": "GET", "url": "{{base_url}}/health"}),
        variable=[{"key": "base_url", "value": "https://collection.test"}],
    )
    ex = import_postman(json.dumps(doc), variables={"base_url": "https://override.test"})[0]
    assert ex.request.header("Host") == "override.test"


def test_path_variable_colon_form_resolved() -> None:
    doc = _collection(
        _req_item(
            "get",
            {
                "method": "GET",
                "url": {
                    "raw": "https://api.test/users/:id",
                    "variable": [{"key": "id", "value": "42"}],
                },
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.target == "/users/42"


# --------------------------------------------------------------------------- #
# Headers & bodies                                                            #
# --------------------------------------------------------------------------- #


def test_headers_imported_and_disabled_skipped() -> None:
    doc = _collection(
        _req_item(
            "get",
            {
                "method": "GET",
                "url": "https://api.test/x",
                "header": [
                    {"key": "X-Api", "value": "abc"},
                    {"key": "X-Off", "value": "no", "disabled": True},
                ],
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.header("X-Api") == "abc"
    assert ex.request.header("X-Off") is None


def test_header_injection_dropped() -> None:
    doc = _collection(
        _req_item(
            "get",
            {
                "method": "GET",
                "url": "https://api.test/x",
                "header": [{"key": "X-Bad", "value": "a\r\nInjected: 1"}],
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.header("X-Bad") is None


def test_raw_json_body_sets_content_type() -> None:
    doc = _collection(
        _req_item(
            "post",
            {
                "method": "POST",
                "url": "https://api.test/login",
                "body": {
                    "mode": "raw",
                    "raw": '{"u":"a"}',
                    "options": {"raw": {"language": "json"}},
                },
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request_body == b'{"u":"a"}'
    assert ex.request.header("Content-Type") == "application/json"


def test_urlencoded_body() -> None:
    doc = _collection(
        _req_item(
            "post",
            {
                "method": "POST",
                "url": "https://api.test/form",
                "body": {
                    "mode": "urlencoded",
                    "urlencoded": [{"key": "a", "value": "1"}, {"key": "b", "value": "2"}],
                },
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request_body == b"a=1&b=2"
    assert ex.request.header("Content-Type") == "application/x-www-form-urlencoded"


def test_formdata_body_multipart() -> None:
    doc = _collection(
        _req_item(
            "post",
            {
                "method": "POST",
                "url": "https://api.test/upload",
                "body": {"mode": "formdata", "formdata": [{"key": "field", "value": "val"}]},
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    ct = ex.request.header("Content-Type") or ""
    assert ct.startswith("multipart/form-data; boundary=")
    assert b'name="field"' in ex.request_body
    assert b"val" in ex.request_body


def test_explicit_content_type_not_overwritten() -> None:
    doc = _collection(
        _req_item(
            "post",
            {
                "method": "POST",
                "url": "https://api.test/x",
                "header": [{"key": "Content-Type", "value": "application/vnd.custom+json"}],
                "body": {"mode": "raw", "raw": "{}", "options": {"raw": {"language": "json"}}},
            },
        )
    )
    ex = import_postman(json.dumps(doc))[0]
    assert ex.request.header("Content-Type") == "application/vnd.custom+json"


# --------------------------------------------------------------------------- #
# Folders / nesting                                                           #
# --------------------------------------------------------------------------- #


def test_nested_folders_walked() -> None:
    doc = _collection(
        {
            "name": "folder",
            "item": [
                _req_item("a", {"method": "GET", "url": "https://api.test/a"}),
                {
                    "name": "sub",
                    "item": [_req_item("b", {"method": "POST", "url": "https://api.test/b"})],
                },
            ],
        },
        _req_item("c", {"method": "GET", "url": "https://api.test/c"}),
    )
    exchanges = import_postman(json.dumps(doc))
    targets = sorted(e.request.target for e in exchanges)
    assert targets == ["/a", "/b", "/c"]


# --------------------------------------------------------------------------- #
# Fail-closed                                                                 #
# --------------------------------------------------------------------------- #


def test_invalid_json_rejected() -> None:
    with pytest.raises(PostmanImportError):
        import_postman("{not json")


def test_root_not_mapping_rejected() -> None:
    with pytest.raises(PostmanImportError):
        import_postman("[]")


def test_missing_info_rejected() -> None:
    with pytest.raises(PostmanImportError):
        import_postman(json.dumps({"item": []}))


def test_missing_item_rejected() -> None:
    with pytest.raises(PostmanImportError):
        import_postman(json.dumps({"info": {"name": "c"}}))


def test_bad_method_rejected() -> None:
    doc = _collection(_req_item("x", {"method": "FOO", "url": "https://api.test/x"}))
    with pytest.raises(PostmanImportError):
        import_postman(json.dumps(doc))


def test_url_without_host_rejected() -> None:
    doc = _collection(_req_item("x", {"method": "GET", "url": "{{unresolved}}/x"}))
    with pytest.raises(PostmanImportError):
        import_postman(json.dumps(doc))
