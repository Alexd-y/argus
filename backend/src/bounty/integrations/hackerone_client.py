"""HackerOne API client for scope ingestion."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

HACKERONE_API_BASE = "https://api.hackerone.com/v1"


async def list_programs(
    api_token: str | None = None,
    username: str | None = None,
) -> list[dict[str, Any]]:
    """List accessible HackerOne programs.

    Requires API credentials (username + API token) stored in
    ``HACKERONE_API_USERNAME`` and ``HACKERONE_API_TOKEN`` env vars
    or passed explicitly.

    Returns a list of program dicts with handle, name, and scope.
    """
    import os

    uname = username or os.environ.get("HACKERONE_API_USERNAME", "").strip()
    token = api_token or os.environ.get("HACKERONE_API_TOKEN", "").strip()

    if not uname or not token:
        logger.info("hackerone_list_skipped_missing_credentials")
        return []

    programs: list[dict[str, Any]] = []
    url = f"{HACKERONE_API_BASE}/programs?page[number]=1&page[size]=100"

    async with httpx.AsyncClient(
        auth=(uname, token),
        headers={"Accept": "application/json"},
        timeout=15.0,
    ) as client:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    programs.append({
                        "handle": attrs.get("handle", ""),
                        "name": attrs.get("name", ""),
                        "submission_state": attrs.get("submission_state", ""),
                        "triaged_count": attrs.get("triaged_count", 0),
                    })
        except Exception as exc:
            logger.warning("hackerone_api_error", extra={"error": str(exc)})

    return programs


async def import_scope(
    program_handle: str,
    api_token: str | None = None,
    username: str | None = None,
) -> dict[str, Any]:
    """Import scope from a HackerOne program by handle."""
    import os

    uname = username or os.environ.get("HACKERONE_API_USERNAME", "").strip()
    token = api_token or os.environ.get("HACKERONE_API_TOKEN", "").strip()

    if not uname or not token:
        return {"error": "Missing HackerOne API credentials"}

    url = f"{HACKERONE_API_BASE}/programs/{program_handle}"

    async with httpx.AsyncClient(
        auth=(uname, token),
        headers={"Accept": "application/json"},
        timeout=15.0,
    ) as client:
        try:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                attrs = data.get("attributes", {})
                structured_scope = attrs.get("structured_scope", {})
                in_scope = [
                    s.get("asset_identifier", "")
                    for s in structured_scope.get("included", [])
                    if s.get("eligible_for_bounty")
                ]
                out_scope = [
                    s.get("asset_identifier", "")
                    for s in structured_scope.get("included", [])
                    if not s.get("eligible_for_bounty")
                ]
                return {
                    "program_name": attrs.get("name", program_handle),
                    "platform": "hackerone",
                    "in_scope": list(set(filter(None, in_scope))),
                    "out_of_scope": list(set(filter(None, out_scope))),
                }
        except Exception as exc:
            logger.warning("hackerone_import_error", extra={"error": str(exc)})
            return {"error": str(exc)}

    return {"error": f"Failed to import scope for {program_handle}"}