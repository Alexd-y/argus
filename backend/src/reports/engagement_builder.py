"""Engagement metadata builder (Part II, Phase L — prompt §17).

Assembles the "Engagement Parameters" section (testing windows, source IPs, user
agents, canaries, OAST domains, test accounts, run profile, execution mode, tool
catalog version, RoE restrictions, incidents, time source) so the client can
correlate the test with their own monitoring — the section that separates a
professional report from an automated one.

Pure module: consumes a plain ``scan_meta`` dict (tolerant of missing keys) and
returns an :class:`EngagementMetadata`. Passwords are never included — only account
aliases and roles.
"""

from __future__ import annotations

from typing import Any

from src.reports.report_document import EngagementMetadata


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _redact_accounts(value: Any) -> list[str]:
    """Return ``alias (role)`` entries; never a password/secret."""
    out: list[str] = []
    if isinstance(value, (list, tuple)):
        for entry in value:
            if isinstance(entry, dict):
                alias = str(entry.get("alias") or entry.get("username") or "account").strip()
                role = str(entry.get("role") or "").strip()
                out.append(f"{alias} ({role})" if role else alias)
            else:
                out.append(str(entry).strip())
    return [x for x in out if x]


def build_engagement_metadata(scan_meta: dict[str, Any] | None) -> EngagementMetadata:
    """Build engagement metadata from ``scan_meta`` (tolerant of absent keys)."""
    meta = scan_meta or {}
    eng = meta.get("engagement") if isinstance(meta.get("engagement"), dict) else {}

    def _pick(key: str) -> Any:
        return eng.get(key, meta.get(key))

    return EngagementMetadata(
        testing_windows=_as_list(_pick("testing_windows") or _pick("testing_window")),
        source_ips=_as_list(_pick("source_ips") or _pick("worker_ips")),
        user_agents=_as_list(_pick("user_agents") or _pick("user_agent")),
        canaries=_as_list(_pick("canaries") or _pick("canary_markers")),
        oast_domains=_as_list(_pick("oast_domains") or _pick("oast")),
        test_accounts=_redact_accounts(_pick("test_accounts")),
        run_profile=(str(_pick("run_profile")) if _pick("run_profile") else None)
        or (str(meta.get("scan_profile")) if meta.get("scan_profile") else None),
        execution_mode=str(_pick("execution_mode")) if _pick("execution_mode") else None,
        tool_catalog_version=(
            str(_pick("tool_catalog_version")) if _pick("tool_catalog_version") else None
        ),
        roe_restrictions=_as_list(_pick("roe_restrictions") or _pick("roe")),
        incidents=_as_list(_pick("incidents")),
        time_source=str(_pick("time_source")) if _pick("time_source") else None,
    )


def engagement_is_empty(engagement: EngagementMetadata) -> bool:
    """Whether the engagement carries no meaningful data (all fields empty)."""
    return not any(
        (
            engagement.testing_windows,
            engagement.source_ips,
            engagement.user_agents,
            engagement.canaries,
            engagement.oast_domains,
            engagement.test_accounts,
            engagement.run_profile,
            engagement.execution_mode,
            engagement.tool_catalog_version,
            engagement.roe_restrictions,
            engagement.incidents,
            engagement.time_source,
        )
    )


__all__ = ["build_engagement_metadata", "engagement_is_empty"]
