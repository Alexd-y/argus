"""Sandbox tool result cache — Redis optional; no-op when Redis is down.

Cache key (legacy / ad-hoc): ``argus:sandbox:exec:`` + SHA-256 hex of canonical JSON
``{command, use_sandbox, timeout_sec}`` — shared across callers until TTL.

When ``scan_id`` is passed to ``cache_key_for_execute``, the key becomes
``argus:sandbox:exec:{scan_id}:{same_digest}`` so a new scan UUID naturally misses
cache from prior runs; ``invalidate_scan_cache(scan_id)`` matches ``argus:*:{scan_id}:*``.

``invalidate_target_cache`` does not apply to sandbox exec keys (target is not part of the key).
TTL: per-tool defaults (seconds); ttl==0 disables cache for that tool.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from src.core.config import settings

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS: int = 86400  # 24 hours — global max TTL for cached scan results

# TTL (seconds) by tool name; 0 = never cache
_TOOL_TTL_SEC: dict[str, int] = {
    "nmap": 3600,
    "nuclei": 1800,
    "nikto": 1800,
    "gobuster": 900,
    "sqlmap": 600,
    "dig": 86400,
    "whois": 86400,
    "host": 86400,
    "curl": 300,
    "gitleaks": 600,
    "trivy": 3600,
    "semgrep": 1800,
    "trufflehog": 1800,
    "prowler": 1800,
    "scout": 1800,
    "checkov": 1800,
    "terrascan": 1800,
    "searchsploit": 7200,
}

_DEFAULT_TTL_SEC = 300
_CACHE_PREFIX = "argus:sandbox:exec:"
# Public alias for routers / admin cache API
SANDBOX_EXEC_CACHE_PREFIX: str = _CACHE_PREFIX

# Runtime overrides from PUT /cache/tool-ttls (not persisted across restarts).
_tool_ttl_overrides: dict[str, int] = {}


def ttl_for_tool(tool_name: str | None) -> int:
    if not tool_name:
        return _DEFAULT_TTL_SEC
    tl = tool_name.lower()
    if tl in _tool_ttl_overrides:
        return int(_tool_ttl_overrides[tl])
    return int(_TOOL_TTL_SEC.get(tl, _DEFAULT_TTL_SEC))


def get_default_ttl_sec() -> int:
    return _DEFAULT_TTL_SEC


def get_base_tool_ttl_map() -> dict[str, int]:
    return dict(_TOOL_TTL_SEC)


def get_all_tool_ttls() -> dict[str, int]:
    merged = dict(_TOOL_TTL_SEC)
    merged.update(_tool_ttl_overrides)
    return merged


def set_tool_ttl_runtime(tool: str, ttl_sec: int) -> tuple[int, int]:
    """Return (old_effective_ttl, new_ttl)."""
    t = tool.strip().lower()
    old = ttl_for_tool(t) if t else _DEFAULT_TTL_SEC
    if t:
        _tool_ttl_overrides[t] = int(ttl_sec)
    return old, int(ttl_sec)


def cache_key_for_execute(
    command: str,
    use_sandbox: bool,
    timeout_sec: int | None,
    scan_id: str | None = None,
) -> str:
    """Redis key for cached stdout/stderr of a successful allowlisted exec.

    Empty ``scan_id`` preserves cross-request cache sharing (e.g. manual /sandbox/execute).
    Non-empty ``scan_id`` scopes entries to that scan so re-scans with a new id are not
    served stale tool output from Redis.
    """
    payload = json.dumps(
        {
            "command": command.strip(),
            "use_sandbox": use_sandbox,
            "timeout_sec": timeout_sec,
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    sid = (scan_id or "").strip()
    if sid:
        return f"{_CACHE_PREFIX}{sid}:{digest}"
    return f"{_CACHE_PREFIX}{digest}"


class ToolResultCache:
    """Redis-backed get/set; degraded mode when Redis unavailable."""

    def __init__(self) -> None:
        self._redis: Any = None
        try:
            import redis

            r = redis.Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
            )
            r.ping()
            self._redis = r
        except Exception:
            logger.warning(
                "tool_cache_redis_unavailable",
                extra={"event": "argus.tool_cache.redis_unavailable"},
            )
            self._redis = None

    @property
    def enabled(self) -> bool:
        return self._redis is not None

    def get(self, key: str) -> dict[str, Any] | None:
        if not self._redis:
            return None
        try:
            raw = self._redis.get(key)
            if not raw:
                return None
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except Exception:
            logger.warning(
                "tool_cache_get_failed",
                extra={"event": "argus.tool_cache.get_failed"},
            )
            return None

    def set(self, key: str, value: dict[str, Any], ttl_sec: int) -> None:
        if not self._redis or ttl_sec <= 0:
            return
        effective_ttl = min(ttl_sec, CACHE_TTL_SECONDS)
        try:
            self._redis.setex(key, effective_ttl, json.dumps(value, ensure_ascii=True))
        except Exception:
            logger.warning(
                "tool_cache_set_failed",
                extra={"event": "argus.tool_cache.set_failed"},
            )


_singleton: ToolResultCache | None = None


def get_tool_cache() -> ToolResultCache:
    global _singleton
    if _singleton is None:
        _singleton = ToolResultCache()
    return _singleton


def invalidate_scan_cache(scan_id: str) -> int:
    """Delete Redis keys matching ``argus:*:{scan_id}:*`` (e.g. scoped sandbox exec cache)."""
    cache = get_tool_cache()
    if not cache._redis:
        logger.warning(
            "cache_invalidation_skipped_redis_unavailable",
            extra={"event": "argus.tool_cache.invalidate_scan_skip", "scan_id": scan_id},
        )
        return 0
    try:
        pattern = f"argus:*:{scan_id}:*"
        deleted = 0
        cursor = 0
        while True:
            cursor, keys = cache._redis.scan(cursor=cursor, match=pattern, count=200)
            if keys:
                deleted += cache._redis.delete(*keys)
            if cursor == 0:
                break
        if deleted:
            logger.info(
                "cache_invalidation_scan",
                extra={
                    "event": "argus.tool_cache.invalidate_scan",
                    "scan_id": scan_id,
                    "deleted": deleted,
                },
            )
        return deleted
    except Exception:
        logger.warning(
            "cache_invalidation_scan_failed",
            extra={"event": "argus.tool_cache.invalidate_scan_failed", "scan_id": scan_id},
        )
        return 0


def invalidate_target_cache(target: str) -> int:
    """Best-effort delete for keys matching ``argus:*:*{target}*`` (glob).

    Sandbox exec entries use ``argus:sandbox:exec:…`` without embedding the target string,
    so this helper does not clear tool result cache for typical execute keys; use
    scan-scoped keys (``cache_key_for_execute(..., scan_id=…)``) or TTL expiry instead.
    """
    cache = get_tool_cache()
    if not cache._redis:
        logger.warning(
            "cache_invalidation_skipped_redis_unavailable",
            extra={"event": "argus.tool_cache.invalidate_target_skip", "target": target[:128]},
        )
        return 0
    try:
        pattern = f"argus:*:*{target}*"
        deleted = 0
        cursor = 0
        while True:
            cursor, keys = cache._redis.scan(cursor=cursor, match=pattern, count=200)
            if keys:
                deleted += cache._redis.delete(*keys)
            if cursor == 0:
                break
        if deleted:
            logger.info(
                "cache_invalidation_target",
                extra={
                    "event": "argus.tool_cache.invalidate_target",
                    "target": target[:128],
                    "deleted": deleted,
                },
            )
        return deleted
    except Exception:
        logger.warning(
            "cache_invalidation_target_failed",
            extra={
                "event": "argus.tool_cache.invalidate_target_failed",
                "target": target[:128],
            },
        )
        return 0
