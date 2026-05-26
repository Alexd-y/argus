"""Bugcrowd API client for scope ingestion."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

BUGCROWD_API_BASE = "https://api.bugcrowd.com"


async def list_programs(api_token: str | None = None) -> list[dict[str, Any]]:
    """List accessible Bugcrowd programs.

    Requires Bugcrowd API token in ``BUGCROWD_API_TOKEN`` env var.
    """
    import os

    token = api_token or os.environ.get("BUGCROWD_API_TOKEN", "").strip()
    if not token:
        logger.info("bugcrowd_list_skipped_missing_credentials")
        return []

    programs: list[dict[str, Any]] = []
    url = f"{BUGCROWD_API_BASE}/programs"

    async with httpx.AsyncClient(
        headers={
            "Authorization": f"Token {token}",
            "Accept": "application/vnd.bugcrowd+json",
        },
        timeout=15.0,
    ) as client:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    programs.append({
                        "slug": item.get("id", ""),
                        "name": attrs.get("name", ""),
                        "status": attrs.get("status", ""),
                    })
        except Exception as exc:
            logger.warning("bugcrowd_api_error", extra={"error": str(exc)})

    return programs


async def import_scope(
    program_slug: str,
    api_token: str | None = None,
) -> dict[str, Any]:
    """Import scope from a Bugcrowd program by slug."""
    import os

    token = api_token or os.environ.get("BUGCROWD_API_TOKEN", "").strip()
    if not token:
        return {"error": "Missing Bugcrowd API token"}

    url = f"{BUGCROWD_API_BASE}/programs/{program_slug}"

    async with httpx.AsyncClient(
        headers={
            "Authorization": f"Token {token}",
            "Accept": "application/vnd.bugcrowd+json",
        },
        timeout=15.0,
    ) as client:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                attrs = data.get("attributes", {})
                scope_items = attrs.get("scope", [])
                in_scope = [
                    s.get("target", "") for s in scope_items
                    if s.get("eligible_for_bounty")
                ]
                out_scope = [
                    s.get("target", "") for s in scope_items
                    if not s.get("eligible_for_bounty")
                ]
                return {
                    "program_name": attrs.get("name", program_slug),
                    "platform": "bugcrowd",
                    "in_scope": list(set(filter(None, in_scope))),
                    "out_of_scope": list(set(filter(None, out_scope))),
                }
        except Exception as exc:
            logger.warning("bugcrowd_import_error", extra={"error": str(exc)})
            return {"error": str(exc)}

    return {"error": f"Failed to import scope for {program_slug}"}