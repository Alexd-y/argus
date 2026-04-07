"""Admin-protected cache management — SCAN-based key listing, allowlisted flush."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, select

from src.api.routers.admin import require_admin
from src.cache.scan_knowledge_base import get_knowledge_base
from src.cache.tool_cache import (
    SANDBOX_EXEC_CACHE_PREFIX,
    cache_key_for_execute,
    get_all_tool_ttls,
    get_default_ttl_sec,
    set_tool_ttl_runtime,
)
from src.core.config import settings
from src.core.redis_client import get_redis
from src.db.models import ToolRun
from src.db.session import async_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cache", tags=["cache"])

_ARGUS = "argus:"


class CacheFlushBody(BaseModel):
    patterns: list[str] = Field(..., min_length=1)
    confirm: bool = False


class ToolTtlPutBody(BaseModel):
    tool: str = Field(..., min_length=1, max_length=128)
    ttl_sec: int = Field(..., ge=0, le=604800)


def _require_argus_pattern(p: str) -> str:
    s = p.strip()
    if not s.startswith(_ARGUS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pattern must start with argus:",
        )
    return s


def _require_argus_key(k: str) -> str:
    s = k.strip()
    if not s.startswith(_ARGUS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key must start with argus:",
        )
    return s


def _gather_cache_stats_sync() -> dict[str, Any]:
    r = get_redis()
    if not r:
        return {
            "connected": False,
            "hit_rate": 0.0,
            "hits": 0,
            "misses": 0,
            "total_keys": 0,
            "memory_used_bytes": 0,
            "memory_human": "",
            "uptime_seconds": 0,
            "tool_breakdown": {},
        }
    try:
        mem = r.info("memory")
        st = r.info("stats")
        srv = r.info("server")
    except Exception:
        logger.warning("cache_stats_info_failed", extra={"event": "argus.cache.stats_info_failed"})
        return {
            "connected": False,
            "hit_rate": 0.0,
            "hits": 0,
            "misses": 0,
            "total_keys": 0,
            "memory_used_bytes": 0,
            "memory_human": "",
            "uptime_seconds": 0,
            "tool_breakdown": {},
        }

    hits = int(st.get("keyspace_hits", 0) or 0)
    misses = int(st.get("keyspace_misses", 0) or 0)
    denom = hits + misses
    hit_rate = float(hits) / float(denom) if denom else 0.0

    total = 0
    sandbox_keys = 0
    kb_keys = 0
    ttl_sum_sandbox = 0
    ttl_sum_kb = 0
    try:
        for key in r.scan_iter(match=f"{_ARGUS}*", count=256):
            total += 1
            if key.startswith(SANDBOX_EXEC_CACHE_PREFIX):
                sandbox_keys += 1
                with contextlib.suppress(Exception):
                    ttl_sum_sandbox += int(r.ttl(key))
            elif key.startswith("argus:kb:"):
                kb_keys += 1
                with contextlib.suppress(Exception):
                    ttl_sum_kb += int(r.ttl(key))
    except Exception:
        logger.warning("cache_stats_scan_failed", extra={"event": "argus.cache.stats_scan_failed"})

    tool_breakdown: dict[str, Any] = {}
    if sandbox_keys:
        tool_breakdown["sandbox_exec"] = {
            "keys": sandbox_keys,
            "avg_ttl_sec": int(ttl_sum_sandbox / sandbox_keys) if sandbox_keys else 0,
        }
    if kb_keys:
        tool_breakdown["kb"] = {
            "keys": kb_keys,
            "avg_ttl_sec": int(ttl_sum_kb / kb_keys) if kb_keys else 0,
        }

    used = int(mem.get("used_memory", 0) or 0)
    human = str(mem.get("used_memory_human", "") or "")

    return {
        "connected": True,
        "hit_rate": round(hit_rate, 6),
        "hits": hits,
        "misses": misses,
        "total_keys": total,
        "memory_used_bytes": used,
        "memory_human": human,
        "uptime_seconds": int(srv.get("uptime_in_seconds", 0) or 0),
        "tool_breakdown": tool_breakdown,
    }


@router.get("/stats")
async def cache_stats(_: None = Depends(require_admin)) -> dict[str, Any]:
    return await asyncio.to_thread(_gather_cache_stats_sync)


@router.delete("")
async def cache_flush(
    body: CacheFlushBody,
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="confirm must be true",
        )
    r = get_redis()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis unavailable",
        )
    patterns = [_require_argus_pattern(p) for p in body.patterns]
    deleted_count = 0

    def _flush() -> int:
        n = 0
        for pat in patterns:
            keys_batch = list(r.scan_iter(match=pat, count=200))
            for key in keys_batch:
                try:
                    n += int(r.delete(key))
                except Exception:
                    continue
        return n

    deleted_count = await asyncio.to_thread(_flush)
    return {"deleted_count": deleted_count, "patterns_matched": patterns}


@router.get("/keys")
async def cache_keys(
    _: None = Depends(require_admin),
    pattern: str = Query(..., description="Glob-style pattern, must start with argus:"),
    limit: int = Query(100, ge=1, le=10_000),
    cursor: str = Query("0"),
) -> dict[str, Any]:
    pat = _require_argus_pattern(pattern)
    r = get_redis()
    if not r:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable")

    def _scan() -> dict[str, Any]:
        try:
            cur = int(cursor)
        except ValueError:
            cur = 0
        cur, keys = r.scan(cur, match=pat, count=min(500, max(limit, 1)))
        keys = list(keys)[:limit]
        next_c = str(cur) if cur != 0 else None
        return {"keys": keys, "count": len(keys), "next_cursor": next_c, "pattern": pat}

    return await asyncio.to_thread(_scan)


@router.get("/key/{key:path}")
async def cache_get_key(
    key: str,
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    k = _require_argus_key(key)
    r = get_redis()
    if not r:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable")

    def _get() -> dict[str, Any]:
        t = r.type(k)
        ttl = int(r.ttl(k))
        raw = r.get(k)
        if raw is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
        size_b = len(raw.encode("utf-8")) if isinstance(raw, str) else len(raw)
        val: Any
        try:
            val = json.loads(raw)
        except Exception:
            val = raw
        return {
            "key": k,
            "value": val,
            "ttl_remaining_sec": ttl,
            "size_bytes": size_b,
            "type": str(t),
        }

    return await asyncio.to_thread(_get)


@router.delete("/key/{key:path}")
async def cache_delete_key(
    key: str,
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    k = _require_argus_key(key)
    r = get_redis()
    if not r:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable")

    def _del() -> bool:
        return bool(r.delete(k))

    deleted = await asyncio.to_thread(_del)
    return {"key": k, "deleted": deleted}


@router.get("/tool-ttls")
async def cache_tool_ttls_get(_: None = Depends(require_admin)) -> dict[str, Any]:
    return {"ttls": get_all_tool_ttls(), "default_ttl": get_default_ttl_sec()}


@router.put("/tool-ttls")
async def cache_tool_ttls_put(
    body: ToolTtlPutBody,
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    old, new = set_tool_ttl_runtime(body.tool, body.ttl_sec)
    return {"tool": body.tool.strip().lower(), "old_ttl": old, "new_ttl": new}


@router.get("/health")
async def cache_health(_: None = Depends(require_admin)) -> dict[str, Any]:
    r = get_redis()

    def _health() -> dict[str, Any]:
        if not r:
            return {
                "connected": False,
                "latency_ms": 0.0,
                "version": "",
                "used_memory_human": "",
                "maxmemory_human": "",
                "eviction_policy": "",
            }
        t0 = time.perf_counter()
        try:
            r.ping()
            lat = (time.perf_counter() - t0) * 1000.0
            mem = r.info("memory")
            return {
                "connected": True,
                "latency_ms": round(lat, 3),
                "version": str(r.info("server").get("redis_version", "")),
                "used_memory_human": str(mem.get("used_memory_human", "")),
                "maxmemory_human": str(mem.get("maxmemory_human", "")),
                "eviction_policy": str(mem.get("maxmemory_policy", "")),
            }
        except Exception:
            return {
                "connected": False,
                "latency_ms": 0.0,
                "version": "",
                "used_memory_human": "",
                "maxmemory_human": "",
                "eviction_policy": "",
            }

    return await asyncio.to_thread(_health)


@router.post("/warm")
async def cache_warm(_: None = Depends(require_admin)) -> dict[str, Any]:
    t0 = time.perf_counter()

    def _warm() -> dict[str, Any]:
        kb = get_knowledge_base()
        kb.warm_cache()
        st = kb.stats()
        warmed = int(st.get("key_count", 0) or 0)
        return {
            "warmed_keys": warmed,
            "duration_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "source": "scan_knowledge_base",
        }

    return await asyncio.to_thread(_warm)


@router.get("/scan/{scan_id}")
async def cache_scan_scope(
    scan_id: str,
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    r = get_redis()
    if not r:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable")

    async with async_session_factory() as session:
        tr = await session.execute(
            select(ToolRun).where(cast(ToolRun.scan_id, String) == scan_id)
        )
        rows = list(tr.scalars().all())

    cached_results: list[dict[str, Any]] = []

    def _lookup_row(row: ToolRun) -> dict[str, Any]:
        params = row.input_params if isinstance(row.input_params, dict) else {}
        cmd = params.get("command")
        if not cmd or not isinstance(cmd, str):
            return {
                "tool": row.tool_name,
                "key": None,
                "ttl_remaining": 0,
                "size_bytes": 0,
                "cached": False,
            }
        use_sb = bool(params.get("use_sandbox", False))
        to = params.get("timeout_sec")
        if to is None:
            to = int(settings.recon_tools_timeout or 300)
        try:
            to_int = int(to)
        except (TypeError, ValueError):
            to_int = int(settings.recon_tools_timeout or 300)
        sid = str(row.scan_id) if row.scan_id is not None else ""
        key = cache_key_for_execute(cmd, use_sb, to_int, scan_id=sid.strip() or None)
        try:
            raw = r.get(key)
        except Exception:
            raw = None
        ttl = 0
        size_b = 0
        if raw is not None:
            try:
                ttl = int(r.ttl(key))
            except Exception:
                ttl = -1
            size_b = len(raw.encode("utf-8")) if isinstance(raw, str) else len(raw)
        return {
            "tool": row.tool_name,
            "key": key,
            "ttl_remaining": ttl,
            "size_bytes": size_b,
            "cached": raw is not None,
        }

    for row in rows:
        cached_results.append(await asyncio.to_thread(_lookup_row, row))

    return {"scan_id": scan_id, "cached_results": cached_results}

