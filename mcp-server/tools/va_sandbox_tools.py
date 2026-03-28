"""VA sandbox enqueue allowlist — keep in sync with backend ``VA_ACTIVE_SCAN_ALLOWED_TOOLS`` / enqueue API."""

from __future__ import annotations

import json
from typing import Any

# Subset allowed for POST /api/v1/internal/va-tools/enqueue (VA-005)
VA_SANDBOX_ENQUEUE_TOOLS = frozenset(
    {
        "dalfox",
        "xsstrike",
        "ffuf",
        "sqlmap",
        "nuclei",
        "whatweb",
        "nikto",
        "testssl",
    }
)


def normalize_va_tool_name(raw: str) -> str | None:
    t = str(raw or "").strip().lower()
    return t if t in VA_SANDBOX_ENQUEUE_TOOLS else None


def parse_optional_args_json(args_json: str) -> tuple[list[str] | None, str | None]:
    """Returns (args, error_message). None args = use server defaults; empty list invalid."""
    s = (args_json or "").strip()
    if not s:
        return None, None
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        return None, "invalid_args_json"
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        return None, "args_json_must_be_string_array"
    return data, None


def build_enqueue_payload(
    tool: str,
    tenant_id: str,
    scan_id: str,
    target: str,
    args_json: str,
) -> tuple[dict[str, Any] | None, str | None]:
    nt = normalize_va_tool_name(tool)
    if not nt:
        return None, "tool_not_allowlisted"
    args, err = parse_optional_args_json(args_json)
    if err:
        return None, err
    return {
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "target": target,
        "tool": nt,
        "args": args,
    }, None
