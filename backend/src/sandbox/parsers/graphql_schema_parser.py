"""Parser for clairvoyance GraphQL schema recovery (Backlog/dev1_md §4.14).

``clairvoyance -o /out/clairvoyance.json {url}/graphql`` reconstructs a
GraphQL schema — even when introspection is disabled — by abusing the
field-suggestion oracle.  The output is a standard GraphQL introspection
document::

    {
      "data": {
        "__schema": {
          "queryType": {"name": "Query"},
          "mutationType": {"name": "Mutation"},
          "subscriptionType": null,
          "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [...]},
            {"name": "User",  "kind": "OBJECT", "fields": [...]},
            ...
          ]
        }
      }
    }

Translation rule (conservative)
-------------------------------
A recovered schema is an information-exposure finding: the API surface
(types, queries, mutations) is disclosed to an unauthenticated client
(CWE-200, WSTG-INFO-08 / WSTG-CONF-04).  The parser emits exactly one
:class:`FindingCategory.INFO` finding summarising the recovered schema
shape (type / query-field / mutation-field counts, whether mutations
are exposed, a capped list of type names).  No secret material is
present in a schema document, but the evidence is still bounded and
sorted for deterministic snapshots.

Only the standard introspection shape is recognised; any other JSON
(including the empty ``{}`` object) yields ``[]`` — the parser never
fabricates a finding from an unrecognised document.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import make_finding_dto
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "graphql_schema_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "clairvoyance.json"
_MAX_TYPE_NAMES: Final[int] = 30


def parse_clairvoyance(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate a recovered GraphQL introspection schema into one finding."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    schema = _extract_schema(payload)
    if schema is None:
        return []

    types = schema.get("types")
    if not isinstance(types, list):
        types = []

    user_types = sorted(
        {
            name
            for entry in types
            if isinstance(entry, dict)
            and isinstance((name := entry.get("name")), str)
            and name
            and not name.startswith("__")
        }
    )
    if not user_types:
        # A schema with only introspection meta-types is not a meaningful
        # recovery — do not emit a finding.
        return []

    query_type = _type_name(schema.get("queryType"))
    mutation_type = _type_name(schema.get("mutationType"))
    subscription_type = _type_name(schema.get("subscriptionType"))

    query_fields = _field_count(types, query_type)
    mutation_fields = _field_count(types, mutation_type)

    finding = make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-08", "WSTG-CONF-04"],
    )
    evidence: dict[str, Any] = {
        "tool_id": tool_id,
        "recovered_type_count": len(user_types),
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
        "query_field_count": query_fields,
        "mutation_field_count": mutation_fields,
        "mutations_exposed": bool(mutation_type),
        "type_names": user_types[:_MAX_TYPE_NAMES],
    }
    cleaned = {k: v for k, v in evidence.items() if v not in (None, "", [], {})}
    persist_jsonl_sidecar(
        artifacts_dir,
        sidecar_name=EVIDENCE_SIDECAR_NAME,
        evidence_records=[json.dumps(cleaned, sort_keys=True, ensure_ascii=False)],
        tool_id=tool_id,
    )
    return [finding]


def _extract_schema(payload: Any) -> dict[str, Any] | None:
    """Return the ``__schema`` dict from either envelope shape."""
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
        return data["__schema"]
    if isinstance(payload.get("__schema"), dict):
        return payload["__schema"]
    return None


def _type_name(node: Any) -> str | None:
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str) and name:
            return name
    return None


def _field_count(types: list[Any], type_name: str | None) -> int:
    if not type_name:
        return 0
    for entry in types:
        if not isinstance(entry, dict) or entry.get("name") != type_name:
            continue
        fields = entry.get("fields")
        if isinstance(fields, list):
            return len(fields)
        return 0
    return 0


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_clairvoyance",
]
