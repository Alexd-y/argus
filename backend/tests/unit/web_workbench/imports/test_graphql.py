"""Unit tests for the GraphQL introspection importer (WB-P10d)."""

from __future__ import annotations

import json

import pytest

from src.web_workbench.imports.graphql import (
    GraphQLImportError,
    import_graphql_introspection,
)
from src.web_workbench.imports.har import ImportedExchange

ENDPOINT = "https://api.test/graphql"


def _nn(inner: dict[str, object]) -> dict[str, object]:
    return {"kind": "NON_NULL", "ofType": inner}


def _list(inner: dict[str, object]) -> dict[str, object]:
    return {"kind": "LIST", "ofType": inner}


def _scalar(name: str) -> dict[str, object]:
    return {"kind": "SCALAR", "name": name}


def _obj(name: str) -> dict[str, object]:
    return {"kind": "OBJECT", "name": name}


def _schema(
    *, query_fields: list[dict], mutation_fields: list[dict] | None, extra_types: list[dict]
) -> str:
    types: list[dict] = [
        {"kind": "OBJECT", "name": "Query", "fields": query_fields},
        *extra_types,
    ]
    schema: dict[str, object] = {"queryType": {"name": "Query"}, "types": types}
    if mutation_fields is not None:
        types.append({"kind": "OBJECT", "name": "Mutation", "fields": mutation_fields})
        schema["mutationType"] = {"name": "Mutation"}
    return json.dumps({"data": {"__schema": schema}})


_USER_TYPE = {
    "kind": "OBJECT",
    "name": "User",
    "fields": [
        {"name": "id", "args": [], "type": _nn(_scalar("ID"))},
        {"name": "name", "args": [], "type": _scalar("String")},
        {"name": "role", "args": [], "type": {"kind": "ENUM", "name": "Role"}},
        {"name": "friends", "args": [], "type": _list(_obj("User"))},
    ],
}
_ROLE_ENUM = {
    "kind": "ENUM",
    "name": "Role",
    "enumValues": [{"name": "ADMIN"}, {"name": "USER"}],
}


def _query(ex: ImportedExchange) -> str:
    return json.loads(ex.request_body)["query"]


# --------------------------------------------------------------------------- #
# Happy path                                                                  #
# --------------------------------------------------------------------------- #


def test_basic_query_and_mutation() -> None:
    raw = _schema(
        query_fields=[
            {
                "name": "user",
                "args": [{"name": "id", "type": _nn(_scalar("ID"))}],
                "type": _obj("User"),
            },
            {"name": "version", "args": [], "type": _scalar("String")},
        ],
        mutation_fields=[
            {
                "name": "createUser",
                "args": [{"name": "name", "type": _nn(_scalar("String"))}],
                "type": _obj("User"),
            },
        ],
        extra_types=[_USER_TYPE, _ROLE_ENUM],
    )
    exchanges = import_graphql_introspection(raw, endpoint_url=ENDPOINT)
    assert len(exchanges) == 3
    for ex in exchanges:
        assert isinstance(ex, ImportedExchange)
        assert ex.request.method == "POST"
        assert ex.request.target == "/graphql"
        assert ex.request.header("Host") == "api.test"
        assert ex.request.header("Content-Type") == "application/json"
        assert ex.response is None

    queries = [_query(ex) for ex in exchanges]
    assert 'query user(id: "1") { id name role }' in queries
    assert "query version" in queries
    assert 'mutation createUser(name: "example") { id name role }' in queries


def test_scalar_root_field_has_no_selection() -> None:
    raw = _schema(
        query_fields=[{"name": "ping", "args": [], "type": _scalar("String")}],
        mutation_fields=None,
        extra_types=[],
    )
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    assert _query(ex) == "query ping"


def test_cyclic_selection_guarded() -> None:
    raw = _schema(
        query_fields=[{"name": "me", "args": [], "type": _obj("User")}],
        mutation_fields=None,
        extra_types=[_USER_TYPE, _ROLE_ENUM],
    )
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    # `friends` is another User (already visited) → dropped, no infinite recursion.
    assert _query(ex) == "query me { id name role }"


def test_enum_argument_literal_unquoted() -> None:
    raw = _schema(
        query_fields=[
            {
                "name": "usersByRole",
                "args": [{"name": "role", "type": _nn({"kind": "ENUM", "name": "Role"})}],
                "type": _list(_obj("User")),
            }
        ],
        mutation_fields=None,
        extra_types=[_USER_TYPE, _ROLE_ENUM],
    )
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    assert _query(ex).startswith("query usersByRole(role: ADMIN)")


def test_scalar_arg_literals() -> None:
    raw = _schema(
        query_fields=[
            {
                "name": "calc",
                "args": [
                    {"name": "i", "type": _nn(_scalar("Int"))},
                    {"name": "f", "type": _nn(_scalar("Float"))},
                    {"name": "b", "type": _nn(_scalar("Boolean"))},
                ],
                "type": _scalar("String"),
            }
        ],
        mutation_fields=None,
        extra_types=[],
    )
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    assert _query(ex) == "query calc(i: 1, f: 1.0, b: true)"


def test_optional_args_omitted() -> None:
    raw = _schema(
        query_fields=[
            {
                "name": "list",
                "args": [{"name": "limit", "type": _scalar("Int")}],
                "type": _scalar("String"),
            }
        ],
        mutation_fields=None,
        extra_types=[],
    )
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    assert _query(ex) == "query list"


def test_required_non_scalar_arg_skips_operation() -> None:
    raw = _schema(
        query_fields=[
            {
                "name": "search",
                "args": [
                    {"name": "filter", "type": _nn({"kind": "INPUT_OBJECT", "name": "Filter"})}
                ],
                "type": _scalar("String"),
            },
            {"name": "ok", "args": [], "type": _scalar("String")},
        ],
        mutation_fields=None,
        extra_types=[{"kind": "INPUT_OBJECT", "name": "Filter", "inputFields": []}],
    )
    queries = [_query(ex) for ex in import_graphql_introspection(raw, endpoint_url=ENDPOINT)]
    assert queries == ["query ok"]


def test_object_without_leaves_falls_back_to_typename() -> None:
    guarded_type = {
        "kind": "OBJECT",
        "name": "Vault",
        "fields": [
            {
                "name": "secret",
                "args": [{"name": "key", "type": _nn(_scalar("String"))}],
                "type": _scalar("String"),
            }
        ],
    }
    raw = _schema(
        query_fields=[{"name": "vault", "args": [], "type": _obj("Vault")}],
        mutation_fields=None,
        extra_types=[guarded_type],
    )
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    assert _query(ex) == "query vault { __typename }"


def test_top_level_schema_without_data_wrapper() -> None:
    inner = _schema(
        query_fields=[{"name": "ping", "args": [], "type": _scalar("String")}],
        mutation_fields=None,
        extra_types=[],
    )
    schema = json.loads(inner)["data"]["__schema"]
    raw = json.dumps({"__schema": schema})
    ex = import_graphql_introspection(raw, endpoint_url=ENDPOINT)[0]
    assert _query(ex) == "query ping"


def test_endpoint_host_only_normalised() -> None:
    raw = _schema(
        query_fields=[{"name": "ping", "args": [], "type": _scalar("String")}],
        mutation_fields=None,
        extra_types=[],
    )
    ex = import_graphql_introspection(raw, endpoint_url="api.test/gql")[0]
    assert ex.request.header("Host") == "api.test"
    assert ex.request.target == "/gql"


# --------------------------------------------------------------------------- #
# Fail-closed                                                                 #
# --------------------------------------------------------------------------- #


def test_empty_endpoint_rejected() -> None:
    with pytest.raises(GraphQLImportError):
        import_graphql_introspection("{}", endpoint_url="")


def test_endpoint_without_host_rejected() -> None:
    raw = _schema(
        query_fields=[{"name": "ping", "args": [], "type": _scalar("String")}],
        mutation_fields=None,
        extra_types=[],
    )
    with pytest.raises(GraphQLImportError):
        import_graphql_introspection(raw, endpoint_url="https:///onlypath")


def test_invalid_json_rejected() -> None:
    with pytest.raises(GraphQLImportError):
        import_graphql_introspection("{not json", endpoint_url=ENDPOINT)


def test_missing_schema_rejected() -> None:
    with pytest.raises(GraphQLImportError):
        import_graphql_introspection(json.dumps({"data": {}}), endpoint_url=ENDPOINT)


def test_types_not_array_rejected() -> None:
    with pytest.raises(GraphQLImportError):
        import_graphql_introspection(
            json.dumps({"__schema": {"queryType": {"name": "Query"}, "types": {}}}),
            endpoint_url=ENDPOINT,
        )


def test_no_importable_fields_rejected() -> None:
    raw = _schema(query_fields=[], mutation_fields=None, extra_types=[])
    with pytest.raises(GraphQLImportError):
        import_graphql_introspection(raw, endpoint_url=ENDPOINT)
