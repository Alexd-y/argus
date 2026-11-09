"""Pure helpers that derive authenticated-testing flags from scan options.

No credential VALUES are ever read or returned here — only booleans, the method
label, and role NAMES — so nothing secret can reach the report context. An
operator enables authenticated scanning via ``authenticated_scan_profile``
(login_url + username/password) or the legacy ``authenticated`` flag; this surfaces
that truthfully even when the explicit ``auth_*`` keys are absent.
"""

from __future__ import annotations

from typing import Any

ANON_ROLE = "anonymous (unauthenticated)"
ANON_NOTE = (
    "Authorization was exercised only from an anonymous (unauthenticated) session: "
    "no credentials were supplied for this scan, so role-segregated access control "
    "was not tested. Provide authenticated scan credentials (scan option "
    "auth_credentials) to populate per-role authorization results."
)


def derive_auth_scan_flags(scan_opts: dict[str, Any]) -> dict[str, Any]:
    """Return ``{enabled, creds_provided, method, roles}`` — booleans/labels only."""
    profile = scan_opts.get("authenticated_scan_profile")
    profile = profile if isinstance(profile, dict) else {}
    creds_present = bool(
        profile.get("username") or profile.get("email") or profile.get("username_present")
    ) and bool(profile.get("password") or profile.get("password_present"))
    enabled = (
        bool(scan_opts.get("auth_testing_enabled", False))
        or bool(profile.get("enabled"))
        or bool(scan_opts.get("authenticated"))
    )
    method = str(scan_opts.get("auth_method", "")).strip()
    if not method and profile.get("login_url"):
        method = "form-login"
    roles_src = scan_opts.get("roles_tested") or profile.get("roles") or []
    roles = (
        [str(r)[:128] for r in roles_src if str(r).strip()][:16]
        if isinstance(roles_src, list)
        else []
    )
    return {
        "enabled": enabled,
        "creds_provided": bool(scan_opts.get("auth_credentials_provided", False)) or creds_present,
        "method": method[:128],
        "roles": roles,
    }


def default_matrix_role(authenticated: bool, method: str) -> str:
    """The role the scanner actually operated as — a definitive value, never "unknown"."""
    return (method or "authenticated")[:128] if authenticated else ANON_ROLE
