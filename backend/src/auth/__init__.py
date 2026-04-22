"""Admin auth primitives — bcrypt accounts + cookie sessions (ISS-T20-003 Phase 1).

This package owns the data-plane primitives for the new cookie-based admin
session flow that replaces the forgeable ``argus.admin.role`` cookie:

* :mod:`src.auth.admin_users` — bcrypt password verification + idempotent
  bootstrap from ``ADMIN_BOOTSTRAP_SUBJECT`` / ``ADMIN_BOOTSTRAP_PASSWORD_HASH``.
* :mod:`src.auth.admin_sessions` — CSPRNG session ids, sliding-window TTL,
  ``hmac.compare_digest`` lookup, IP / UA fingerprints.

The HTTP surface (``POST /auth/admin/login`` etc.) lives in
``src.api.routers.admin_auth``; the dual-mode dependency guarding
``/admin/*`` lives in ``src.api.routers.admin``.
"""
