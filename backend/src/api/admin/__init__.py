"""ARGUS admin HTTP surface — namespace package for C7 admin routers + schemas.

Module layout
-------------
* :mod:`src.api.admin.schemas` — Pydantic request / response models for
  admin-facing endpoints. Schemas live here (separated from the routers)
  so the same envelope can be consumed by other tooling (CLI, OpenAPI
  client codegen, dashboard typings) without importing FastAPI.
* :mod:`src.api.admin.mfa` — MFA enrollment / verify / disable / status
  endpoints (C7-T03). Mounted by :mod:`backend.main` under
  ``/api/v1/auth/admin/mfa``.

The legacy admin endpoints (tenants, providers, audit) still live under
``src.api.routers.admin*`` and are reachable via ``/api/v1/admin/*``.
This sub-package is intentionally narrow: it carries only the new
auth-adjacent surface introduced by Cycle 7 so the dependency footprint
stays small (no SQLAlchemy ORM imports at module-import time).
"""

from __future__ import annotations

__all__: list[str] = []
