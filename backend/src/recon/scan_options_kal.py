"""Extract KAL-related scan flags from persisted options (nested ``kal`` or legacy flat keys)."""

from __future__ import annotations

from typing import Any


def scan_kal_flags(options: dict[str, Any] | None) -> dict[str, bool]:
    """password_audit_opt_in, recon_dns_enumeration_opt_in, va_network_capture_opt_in."""
    empty = {
        "password_audit_opt_in": False,
        "recon_dns_enumeration_opt_in": False,
        "va_network_capture_opt_in": False,
    }
    if not options or not isinstance(options, dict):
        return dict(empty)
    kal = options.get("kal")
    if isinstance(kal, dict):
        return {
            "password_audit_opt_in": bool(kal.get("password_audit_opt_in")),
            "recon_dns_enumeration_opt_in": bool(kal.get("recon_dns_enumeration_opt_in")),
            "va_network_capture_opt_in": bool(kal.get("va_network_capture_opt_in")),
        }
    return {
        "password_audit_opt_in": bool(options.get("password_audit_opt_in")),
        "recon_dns_enumeration_opt_in": bool(options.get("recon_dns_enumeration_opt_in")),
        "va_network_capture_opt_in": bool(options.get("va_network_capture_opt_in")),
    }
