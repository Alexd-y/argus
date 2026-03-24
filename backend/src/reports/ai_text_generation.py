"""RPT-004 — AI report section text generation with Redis cache and sync LLM wrapper."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any

from src.core.config import settings
from src.core.llm_config import get_llm_client, has_any_llm_key
from src.orchestration.prompt_registry import (
    REPORT_AI_SECTION_KEYS,
    get_report_ai_section_prompt,
)

logger = logging.getLogger(__name__)

_CACHE_KEY_PREFIX = "argus:ai_text:"


def canonical_payload_hash(input_payload: dict[str, Any]) -> str:
    """Deterministic SHA-256 over canonical JSON (sorted keys, compact separators)."""
    body = json.dumps(input_payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def build_ai_text_cache_key(
    tenant_id: str,
    scan_id: str,
    tier: str,
    section_key: str,
    payload_hash: str,
    prompt_version: str,
) -> str:
    """Redis cache key: SHA-256 over canonical JSON of components (colon-safe, no collisions)."""
    components = {
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "tier": tier,
        "section_key": section_key,
        "payload_hash": payload_hash,
        "prompt_version": prompt_version,
    }
    body = json.dumps(components, sort_keys=True).encode("utf-8")
    return _CACHE_KEY_PREFIX + hashlib.sha256(body).hexdigest()


def _log_ai_text_event(
    *,
    cache_hit: bool,
    section_key: str,
    tier: str,
    tenant_id: str,
    scan_id: str,
    payload_sha256: str,
    prompt_version: str,
    status: str,
) -> None:
    logger.info(
        "argus.ai_text_generation",
        extra={
            "event": "argus.ai_text_generation",
            "cache_hit": cache_hit,
            "section_key": section_key,
            "tier": tier,
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "payload_sha256": payload_sha256,
            "prompt_version": prompt_version,
            "status": status,
        },
    )


def run_ai_text_generation(
    tenant_id: str,
    scan_id: str,
    tier: str,
    section_key: str,
    input_payload: dict[str, Any],
    *,
    redis_client: Any | None = None,
    llm_callable: Callable[[str, dict], str] | None = None,
    cache_ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """
    Resolve report section text from cache or sync LLM call.
    ``llm_callable`` and ``redis_client`` are injectable for tests.
    """
    if section_key not in REPORT_AI_SECTION_KEYS:
        _log_ai_text_event(
            cache_hit=False,
            section_key=section_key,
            tier=tier,
            tenant_id=tenant_id,
            scan_id=scan_id,
            payload_sha256="",
            prompt_version="",
            status="invalid_section",
        )
        return {
            "status": "failed",
            "error": "invalid_section",
            "section_key": section_key,
            "cache_hit": False,
        }

    system_prompt, user_prompt, prompt_version = get_report_ai_section_prompt(
        section_key, input_payload
    )
    payload_hash = canonical_payload_hash(input_payload)
    cache_key = build_ai_text_cache_key(
        tenant_id, scan_id, tier, section_key, payload_hash, prompt_version
    )
    ttl = cache_ttl_seconds if cache_ttl_seconds is not None else settings.ai_text_cache_ttl_seconds

    r = redis_client
    if r is not None:
        try:
            cached_raw = r.get(cache_key)
            if cached_raw:
                try:
                    parsed = json.loads(cached_raw)
                    text = parsed.get("text", "")
                    if isinstance(text, str) and text:
                        _log_ai_text_event(
                            cache_hit=True,
                            section_key=section_key,
                            tier=tier,
                            tenant_id=tenant_id,
                            scan_id=scan_id,
                            payload_sha256=payload_hash,
                            prompt_version=prompt_version,
                            status="ok",
                        )
                        return {
                            "status": "ok",
                            "text": text,
                            "cache_hit": True,
                            "section_key": section_key,
                            "prompt_version": prompt_version,
                            "payload_sha256": payload_hash,
                        }
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception as e:
            logger.warning(
                "Redis cache read failed for AI text generation",
                extra={
                    "event": "argus.ai_text_redis_cache_get_error",
                    "error_type": type(e).__name__,
                },
            )

    call_llm = llm_callable
    if call_llm is None:
        if not has_any_llm_key():
            _log_ai_text_event(
                cache_hit=False,
                section_key=section_key,
                tier=tier,
                tenant_id=tenant_id,
                scan_id=scan_id,
                payload_sha256=payload_hash,
                prompt_version=prompt_version,
                status="llm_unavailable",
            )
            return {
                "status": "failed",
                "error": "llm_unavailable",
                "section_key": section_key,
                "cache_hit": False,
                "prompt_version": prompt_version,
                "payload_sha256": payload_hash,
            }
        try:
            call_llm = get_llm_client()
        except Exception:
            _log_ai_text_event(
                cache_hit=False,
                section_key=section_key,
                tier=tier,
                tenant_id=tenant_id,
                scan_id=scan_id,
                payload_sha256=payload_hash,
                prompt_version=prompt_version,
                status="llm_unavailable",
            )
            return {
                "status": "failed",
                "error": "llm_unavailable",
                "section_key": section_key,
                "cache_hit": False,
                "prompt_version": prompt_version,
                "payload_sha256": payload_hash,
            }

    combined_prompt = f"{system_prompt}\n\n{user_prompt}"
    try:
        generated = (call_llm(combined_prompt, {"task": section_key, "tier": tier}) or "").strip()
    except Exception:
        _log_ai_text_event(
            cache_hit=False,
            section_key=section_key,
            tier=tier,
            tenant_id=tenant_id,
            scan_id=scan_id,
            payload_sha256=payload_hash,
            prompt_version=prompt_version,
            status="llm_error",
        )
        return {
            "status": "failed",
            "error": "generation_failed",
            "section_key": section_key,
            "cache_hit": False,
            "prompt_version": prompt_version,
            "payload_sha256": payload_hash,
        }

    if r is not None and generated and ttl > 0:
        try:
            r.set(cache_key, json.dumps({"text": generated}), ex=ttl)
        except Exception as e:
            logger.warning(
                "Redis cache write failed for AI text generation",
                extra={
                    "event": "argus.ai_text_redis_cache_set_error",
                    "error_type": type(e).__name__,
                },
            )

    _log_ai_text_event(
        cache_hit=False,
        section_key=section_key,
        tier=tier,
        tenant_id=tenant_id,
        scan_id=scan_id,
        payload_sha256=payload_hash,
        prompt_version=prompt_version,
        status="ok",
    )
    return {
        "status": "ok",
        "text": generated,
        "cache_hit": False,
        "section_key": section_key,
        "prompt_version": prompt_version,
        "payload_sha256": payload_hash,
    }
