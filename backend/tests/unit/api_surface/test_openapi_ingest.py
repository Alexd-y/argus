"""OpenAPI ingest mode-aware tests."""

from __future__ import annotations

import pytest

from src.api_surface.openapi_ingest import OpenApiIngestError, ingest_openapi
from src.execution_mode.mode import ExecutionMode


_MINIMAL_OAS3 = """
openapi: 3.0.0
info:
  title: Demo
  version: "1.0"
servers:
  - url: https://api.lab.argus
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - name: q
          in: query
          schema:
            type: string
      responses:
        "200":
          description: ok
"""


def test_ingest_openapi3_endpoints():
    doc = ingest_openapi(
        _MINIMAL_OAS3,
        tenant_id="t1",
        asset_id="a1",
        mode=ExecutionMode.PRODUCTION,
    )
    assert len(doc.endpoints) == 1
    assert doc.endpoints[0].method.upper() == "GET"
    assert doc.endpoints[0].normalized_path == "/items"


def test_production_blocks_external_ref():
    bad = """
openapi: 3.0.0
info: {title: x, version: "1"}
servers:
  - url: https://api.lab.argus
paths:
  /x:
    get:
      responses:
        "200":
          $ref: "https://evil.example/schemas.json#/Ok"
"""
    with pytest.raises(OpenApiIngestError):
        ingest_openapi(
            bad,
            tenant_id="t1",
            asset_id="a1",
            mode=ExecutionMode.PRODUCTION,
        )
