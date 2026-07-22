"""Unit tests for the OpenAPI / Swagger importer (WB-P10b)."""

from __future__ import annotations

import json

import pytest

from src.web_workbench.imports.har import ImportedExchange
from src.web_workbench.imports.openapi import OpenApiImportError, import_openapi


def _openapi3(**overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "openapi": "3.0.3",
        "servers": [{"url": "https://api.test/v1"}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        },
                        {
                            "name": "verbose",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "boolean"},
                        },
                    ]
                }
            }
        },
    }
    doc.update(overrides)
    return doc


# --------------------------------------------------------------------------- #
# OpenAPI 3.x                                                                 #
# --------------------------------------------------------------------------- #


def test_import_basic_operation() -> None:
    exchanges = import_openapi(json.dumps(_openapi3()))
    assert len(exchanges) == 1
    ex = exchanges[0]
    assert isinstance(ex, ImportedExchange)
    assert ex.request.method == "GET"
    assert ex.request.target == "/v1/users/1?verbose=true"
    assert ex.request.header("Host") == "api.test"
    assert ex.response is None


def test_yaml_spec_supported() -> None:
    yaml_spec = (
        "openapi: 3.0.0\n"
        "servers:\n  - url: https://api.test\n"
        "paths:\n"
        "  /ping:\n"
        "    get: {}\n"
    )
    exchanges = import_openapi(yaml_spec)
    assert len(exchanges) == 1
    assert exchanges[0].request.target == "/ping"


def test_multiple_methods_per_path() -> None:
    spec = _openapi3(paths={"/items": {"get": {}, "post": {}, "delete": {}}})
    methods = {e.request.method for e in import_openapi(json.dumps(spec))}
    assert methods == {"GET", "POST", "DELETE"}


def test_header_param_included() -> None:
    spec = _openapi3(
        paths={
            "/x": {
                "get": {
                    "parameters": [
                        {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}}
                    ]
                }
            }
        }
    )
    ex = import_openapi(json.dumps(spec))[0]
    assert ex.request.header("X-Tenant") == "example"


def test_enum_sample_used_for_path_param() -> None:
    spec = _openapi3(
        paths={
            "/status/{s}": {
                "get": {
                    "parameters": [
                        {
                            "name": "s",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string", "enum": ["active", "inactive"]},
                        }
                    ]
                }
            }
        }
    )
    ex = import_openapi(json.dumps(spec))[0]
    assert ex.request.target.endswith("/status/active")


def test_request_body_example_used() -> None:
    spec = _openapi3(
        paths={
            "/login": {
                "post": {
                    "requestBody": {"content": {"application/json": {"example": {"user": "alice"}}}}
                }
            }
        }
    )
    ex = import_openapi(json.dumps(spec))[0]
    assert json.loads(ex.request_body) == {"user": "alice"}
    assert ex.request.header("Content-Type") == "application/json"


def test_request_body_defaults_to_empty_object() -> None:
    spec = _openapi3(
        paths={
            "/login": {
                "post": {
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}
                }
            }
        }
    )
    ex = import_openapi(json.dumps(spec))[0]
    assert ex.request_body == b"{}"


def test_optional_query_param_omitted() -> None:
    spec = _openapi3(
        paths={
            "/search": {
                "get": {
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                        }
                    ]
                }
            }
        }
    )
    ex = import_openapi(json.dumps(spec))[0]
    assert "?" not in ex.request.target


def test_path_level_parameters_applied() -> None:
    spec = _openapi3(
        paths={
            "/orgs/{org}": {
                "parameters": [
                    {"name": "org", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "get": {},
            }
        }
    )
    ex = import_openapi(json.dumps(spec))[0]
    assert ex.request.target == "/v1/orgs/example"


# --------------------------------------------------------------------------- #
# Swagger 2.0                                                                 #
# --------------------------------------------------------------------------- #


def test_swagger2_host_basepath() -> None:
    spec = {
        "swagger": "2.0",
        "host": "legacy.test",
        "basePath": "/api",
        "schemes": ["https"],
        "paths": {"/ping": {"get": {}}},
    }
    ex = import_openapi(json.dumps(spec))[0]
    assert ex.request.header("Host") == "legacy.test"
    assert ex.request.target == "/api/ping"


# --------------------------------------------------------------------------- #
# base_url resolution                                                         #
# --------------------------------------------------------------------------- #


def test_base_url_override() -> None:
    spec = {"openapi": "3.0.0", "servers": [{"url": "/relative"}], "paths": {"/x": {"get": {}}}}
    ex = import_openapi(json.dumps(spec), base_url="https://override.test/base")[0]
    assert ex.request.header("Host") == "override.test"
    assert ex.request.target == "/base/x"


def test_relative_server_without_base_url_rejected() -> None:
    spec = {"openapi": "3.0.0", "servers": [{"url": "/relative"}], "paths": {"/x": {"get": {}}}}
    with pytest.raises(OpenApiImportError):
        import_openapi(json.dumps(spec))


# --------------------------------------------------------------------------- #
# Fail-closed parsing                                                         #
# --------------------------------------------------------------------------- #


def test_invalid_document_rejected() -> None:
    with pytest.raises(OpenApiImportError):
        import_openapi("[]")


def test_missing_version_rejected() -> None:
    with pytest.raises(OpenApiImportError):
        import_openapi(json.dumps({"paths": {"/x": {"get": {}}}}))


def test_missing_paths_rejected() -> None:
    with pytest.raises(OpenApiImportError):
        import_openapi(json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://a.test"}]}))


def test_non_operation_keys_ignored() -> None:
    spec = _openapi3(paths={"/x": {"summary": "not an operation", "get": {}}})
    exchanges = import_openapi(json.dumps(spec))
    assert len(exchanges) == 1
    assert exchanges[0].request.method == "GET"
