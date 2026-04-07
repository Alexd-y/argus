"""RPT-004 — AI report section text generation with Redis cache and sync LLM wrapper."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable
from typing import Any

from src.core.config import settings
from src.core.llm_config import get_llm_client, has_any_llm_key
from src.orchestration.prompt_registry import (
    REPORT_AI_SECTION_KEYS,
    get_report_ai_section_prompt,
)
from src.reports.report_data_validation import (
    grounded_executive_summary_fallback_text,
    validate_executive_ai_text_against_payload,
)

logger = logging.getLogger(__name__)

_CACHE_KEY_PREFIX = "argus:ai_text:"

# Template / Jinja-safe placeholders when LLM is unavailable (match REPORT_AI_SECTION_KEYS consumers).
REPORT_AI_SKIPPED_NO_LLM = "AI generation skipped: no LLM provider available"
REPORT_AI_SKIPPED_GENERATION_FAILED = "AI generation skipped: could not generate content"


class AITextDeduplicator:
    """Remove duplicate content across AI-generated report sections using n-gram similarity.

    Deterministic, no AI/embedding dependencies. Operates on character-level n-grams
    and Jaccard similarity. Duplicate sentences in later sections are replaced with
    cross-references to the earlier section that contains the original.
    """

    SIMILARITY_THRESHOLD = 0.70
    MIN_SENTENCE_WORDS = 5

    _SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\u0410-\u042f\u0401])")

    def deduplicate_sections(self, sections: dict[str, str]) -> dict[str, str]:
        """Remove duplicate sentences across sections, keeping first occurrence.

        Returns a new dict with the same keys. Sections with duplicated sentences
        get those sentences replaced by a cross-reference to the originating section.
        """
        if len(sections) < 2:
            return dict(sections)

        ordered_keys = list(sections.keys())
        section_sentences: dict[str, list[str]] = {
            key: self._extract_sentences(text) for key, text in sections.items()
        }

        dup_map: dict[str, dict[int, str]] = {k: {} for k in ordered_keys}

        for i, key_a in enumerate(ordered_keys):
            sents_a = section_sentences[key_a]
            for j in range(i + 1, len(ordered_keys)):
                key_b = ordered_keys[j]
                sents_b = section_sentences[key_b]
                for idx_b, sent_b in enumerate(sents_b):
                    if idx_b in dup_map[key_b]:
                        continue
                    if len(sent_b.split()) < self.MIN_SENTENCE_WORDS:
                        continue
                    for sent_a in sents_a:
                        if len(sent_a.split()) < self.MIN_SENTENCE_WORDS:
                            continue
                        if self._ngram_similarity(sent_a, sent_b) > self.SIMILARITY_THRESHOLD:
                            dup_map[key_b][idx_b] = key_a
                            break

        result: dict[str, str] = {}
        for key in ordered_keys:
            duplicates = dup_map[key]
            if not duplicates:
                result[key] = sections[key]
                continue

            sents = section_sentences[key]
            cleaned: list[str] = []
            cross_ref_targets: set[str] = set()
            for idx, sent in enumerate(sents):
                origin = duplicates.get(idx)
                if origin is not None:
                    cross_ref_targets.add(origin)
                else:
                    cleaned.append(sent)

            if cross_ref_targets:
                refs = " ".join(
                    self._generate_cross_reference(t) for t in sorted(cross_ref_targets)
                )
                cleaned.append(refs)

            result[key] = " ".join(cleaned)

            removed = len(duplicates)
            logger.info(
                "ai_text_deduplication",
                extra={
                    "event": "ai_text_deduplication",
                    "section_key": key,
                    "sentences_removed": removed,
                    "cross_ref_targets": sorted(cross_ref_targets),
                },
            )

        return result

    def _extract_sentences(self, text: str) -> list[str]:
        """Split text into sentences using punctuation + uppercase heuristic."""
        if not text or not text.strip():
            return []
        normalized = " ".join(text.split())
        sentences = self._SENTENCE_SPLIT_RE.split(normalized)
        return [s.strip() for s in sentences if s.strip()]

    def _ngram_similarity(self, s1: str, s2: str, n: int = 3) -> float:
        """Calculate character n-gram Jaccard similarity between two strings."""
        if not s1 or not s2:
            return 0.0
        s1_lower = s1.lower()
        s2_lower = s2.lower()
        if len(s1_lower) < n or len(s2_lower) < n:
            return 1.0 if s1_lower == s2_lower else 0.0
        ngrams1 = {s1_lower[i : i + n] for i in range(len(s1_lower) - n + 1)}
        ngrams2 = {s2_lower[i : i + n] for i in range(len(s2_lower) - n + 1)}
        if not ngrams1 or not ngrams2:
            return 0.0
        intersection = ngrams1 & ngrams2
        union = ngrams1 | ngrams2
        return len(intersection) / len(union)

    @staticmethod
    def _generate_cross_reference(section_name: str) -> str:
        """Generate a human-readable cross-reference string for the given section."""
        readable = section_name.replace("_", " ").title()
        return f"(See \u00ab{readable}\u00bb section for additional details.)"


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
    """Redis cache key: SHA-256 over canonical JSON of components (colon-safe, no collisions).

    ``scan_id`` is part of the hashed payload, so each new scan gets distinct AI text cache
    entries without explicit invalidation on re-scan.
    """
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
    other_sections_summary: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Resolve report section text from cache or sync LLM call.
    ``llm_callable`` and ``redis_client`` are injectable for tests.

    ``other_sections_summary`` (ARGUS-008): maps section_key → short summary of already-generated
    sections. Forwarded to ``get_report_ai_section_prompt`` to build the deduplication preamble.

    RPT-004 / OWASP-004 / VHL-003: ``input_payload`` is passed through unchanged into
    ``get_report_ai_section_prompt`` (serialized as ``context_json``). All section keys receive the
    same dict from ``ReportGenerator.build_ai_input_payload`` — including ``owasp_compliance_table``,
    ``owasp_category_reference_ru``, and ``owasp_summary`` when present. Valhalla-tier runs also embed
    compact ``valhalla_context`` and optional aggregate ``hibp_pwned_password_summary`` (no secrets).
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
        section_key, input_payload, other_sections_summary=other_sections_summary
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
                "status": "skipped_no_llm",
                "error": "llm_unavailable",
                "text": REPORT_AI_SKIPPED_NO_LLM,
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
                "status": "skipped_no_llm",
                "error": "llm_unavailable",
                "text": REPORT_AI_SKIPPED_NO_LLM,
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
            "text": REPORT_AI_SKIPPED_GENERATION_FAILED,
            "section_key": section_key,
            "cache_hit": False,
            "prompt_version": prompt_version,
            "payload_sha256": payload_hash,
        }

    if not generated:
        _log_ai_text_event(
            cache_hit=False,
            section_key=section_key,
            tier=tier,
            tenant_id=tenant_id,
            scan_id=scan_id,
            payload_sha256=payload_hash,
            prompt_version=prompt_version,
            status="llm_empty_response",
        )
        return {
            "status": "failed",
            "error": "generation_failed",
            "text": REPORT_AI_SKIPPED_GENERATION_FAILED,
            "section_key": section_key,
            "cache_hit": False,
            "prompt_version": prompt_version,
            "payload_sha256": payload_hash,
        }

    fact_ok, fact_codes = validate_executive_ai_text_against_payload(
        section_key, input_payload, generated
    )
    if not fact_ok:
        logger.warning(
            json.dumps(
                {
                    "event": "executive_ai_text_fact_mismatch",
                    "section_key": section_key,
                    "tier": tier,
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "reason_codes": fact_codes,
                },
                ensure_ascii=False,
            )
        )
        if settings.ai_text_executive_fact_check_replace:
            generated = grounded_executive_summary_fallback_text(input_payload)

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
