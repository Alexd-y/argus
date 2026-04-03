"""
ScanKnowledgeBase — Redis-backed knowledge mapping for intelligent scan planning.

Maps OWASP categories and CWE IDs to skills, tools, and scan strategies.
TTL 30 days. Falls back to in-memory dict when Redis unavailable.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from typing import Final

from src.core.redis_client import get_redis

logger = logging.getLogger(__name__)

KB_TTL_SEC: Final[int] = 2_592_000  # 30 days

KB_KEY_PREFIX: Final[str] = "argus:kb:"
INVALIDATE_UNLINK_CHUNK: Final[int] = 500

STATS_KEYS_PREFIX: Final[str] = "argus:kb:stats:"
STATS_HITS_KEY: Final[str] = "argus:kb:stats:hits"
STATS_MISSES_KEY: Final[str] = "argus:kb:stats:misses"


def _owasp_key(owasp_id: str) -> str:
    return f"argus:kb:owasp:{owasp_id}"


def _cwe_key(cwe_id: str) -> str:
    return f"argus:kb:cwe:{cwe_id}"


def _tools_key(owasp_id: str) -> str:
    return f"argus:kb:tools:owasp:{owasp_id}"


def _normalize_owasp(raw: str) -> str | None:
    s = raw.strip().upper()
    m = re.search(r"A(0[1-9]|10)\b", s)
    if m:
        return f"A{m.group(1)}"
    return None


def _normalize_cwe(raw: str) -> str | None:
    s = raw.strip().upper()
    m = re.search(r"(?:CWE-)?(\d+)", s)
    if not m:
        return None
    num = m.group(1)
    return f"CWE-{num}"


_kb_instance: ScanKnowledgeBase | None = None


class ScanKnowledgeBase:
    """OWASP/CWE → skills/tools with Redis or in-memory cache."""

    def __init__(self) -> None:
        self._redis = get_redis()
        self._memory: dict[str, str] = {}
        self._mem_hits = 0
        self._mem_misses = 0
        self._owasp_skills = self._build_owasp_skill_map()
        self._cwe_skills = self._build_cwe_skill_map()
        self._owasp_tools = self._build_owasp_tools_map()

    @staticmethod
    def _build_owasp_skill_map() -> dict[str, list[str]]:
        return {
            "A01": ["idor", "authentication_jwt", "business_logic"],
            "A02": ["information_disclosure"],
            "A03": [],
            "A04": ["authentication_jwt"],
            "A05": ["sql_injection", "xss", "rce", "path_traversal"],
            "A06": ["business_logic", "race_conditions"],
            "A07": ["authentication_jwt", "csrf"],
            "A08": ["mass_assignment", "file_upload"],
            "A09": ["information_disclosure"],
            "A10": ["ssrf", "xxe"],
        }

    @staticmethod
    def _build_cwe_skill_map() -> dict[str, list[str]]:
        return {
            "CWE-79": ["xss"],
            "CWE-89": ["sql_injection"],
            "CWE-22": ["path_traversal"],
            "CWE-352": ["csrf"],
            "CWE-918": ["ssrf"],
            "CWE-611": ["xxe"],
            "CWE-502": ["mass_assignment"],
            "CWE-434": ["file_upload"],
            "CWE-287": ["authentication_jwt"],
            "CWE-639": ["idor"],
            "CWE-362": ["race_conditions"],
            "CWE-601": ["open_redirect"],
            "CWE-78": ["rce"],
            "CWE-94": ["rce"],
            "CWE-77": ["rce"],
            "CWE-863": ["idor", "business_logic"],
            "CWE-284": ["idor", "authentication_jwt"],
            "CWE-798": ["authentication_jwt"],
            "CWE-306": ["authentication_jwt"],
            "CWE-862": ["idor"],
            "CWE-200": ["information_disclosure"],
            "CWE-209": ["information_disclosure"],
            "CWE-532": ["information_disclosure"],
            "CWE-312": ["authentication_jwt", "information_disclosure"],
            "CWE-327": ["authentication_jwt"],
            "CWE-328": ["authentication_jwt"],
            "CWE-330": ["authentication_jwt"],
            "CWE-347": ["authentication_jwt"],
            "CWE-384": ["authentication_jwt"],
            "CWE-613": ["authentication_jwt"],
            "CWE-521": ["authentication_jwt"],
            "CWE-307": ["authentication_jwt"],
            "CWE-640": ["authentication_jwt"],
            "CWE-1321": ["mass_assignment"],
            "CWE-915": ["mass_assignment"],
            "CWE-285": ["idor"],
            "CWE-943": ["sql_injection"],
            "CWE-564": ["sql_injection"],
            "CWE-113": ["ssrf"],
            "CWE-116": ["xss"],
            "CWE-346": ["csrf"],
            "CWE-1275": ["csrf"],
            "CWE-538": ["information_disclosure"],
            "CWE-548": ["information_disclosure"],
            "CWE-1004": ["authentication_jwt"],
            "CWE-614": ["authentication_jwt"],
            "CWE-942": ["information_disclosure"],
            "CWE-829": ["rce", "file_upload"],
            "CWE-426": ["rce"],
            "CWE-427": ["rce"],
        }

    @staticmethod
    def _build_owasp_tools_map() -> dict[str, list[str]]:
        return {
            "A01": ["ffuf", "nuclei", "burp-intruder"],
            "A02": ["nikto", "nuclei", "trivy", "testssl"],
            "A03": ["trivy", "gitleaks", "semgrep"],
            "A04": ["testssl", "openssl", "nuclei"],
            "A05": ["sqlmap", "dalfox", "nuclei", "semgrep", "ffuf"],
            "A06": ["ffuf", "nuclei", "custom-python-asyncio"],
            "A07": ["hydra", "jwt_tool", "ffuf", "nuclei"],
            "A08": ["nuclei", "semgrep", "trufflehog"],
            "A09": ["nuclei", "nikto"],
            "A10": ["nuclei", "ffuf"],
        }

    def _redis_get(self, key: str) -> str | None:
        if not self._redis:
            return None
        try:
            return self._redis.get(key)
        except Exception as exc:
            logger.warning(
                "kb_redis_get_failed",
                extra={"event": "kb_redis_get_failed", "error_type": type(exc).__name__},
            )
            return None

    def _redis_setex_json(self, key: str, value: list[str]) -> bool:
        if not self._redis:
            return False
        try:
            self._redis.setex(key, KB_TTL_SEC, json.dumps(value))
            return True
        except Exception as exc:
            logger.warning(
                "kb_redis_set_failed",
                extra={"event": "kb_redis_set_failed", "error_type": type(exc).__name__},
            )
            return False

    def _memory_get(self, key: str) -> str | None:
        return self._memory.get(key)

    def _memory_set(self, key: str, value: list[str]) -> None:
        self._memory[key] = json.dumps(value)

    def _bump_hit(self) -> None:
        if self._redis:
            try:
                self._redis.incr(STATS_HITS_KEY, 1)
                return
            except Exception as exc:
                logger.warning(
                    "kb_stats_hit_failed",
                    extra={"event": "kb_stats_hit_failed", "error_type": type(exc).__name__},
                )
        self._mem_hits += 1

    def _bump_miss(self) -> None:
        if self._redis:
            try:
                self._redis.incr(STATS_MISSES_KEY, 1)
                return
            except Exception as exc:
                logger.warning(
                    "kb_stats_miss_failed",
                    extra={"event": "kb_stats_miss_failed", "error_type": type(exc).__name__},
                )
        self._mem_misses += 1

    def _load_list(self, key: str, static: list[str]) -> list[str]:
        raw: str | None = None
        if self._redis:
            raw = self._redis_get(key)
        if raw is None:
            raw = self._memory_get(key)

        if raw is not None:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
                    self._bump_hit()
                    return list(parsed)
            except json.JSONDecodeError:
                pass

        self._bump_miss()
        if self._redis:
            self._redis_setex_json(key, static)
        self._memory_set(key, static)
        return list(static)

    def get_skills_for_owasp(self, owasp_id: str) -> list[str]:
        norm = _normalize_owasp(owasp_id)
        if not norm:
            upper = owasp_id.strip().upper()
            if upper in self._owasp_skills:
                norm = upper
        if not norm or norm not in self._owasp_skills:
            return []
        key = _owasp_key(norm)
        return self._load_list(key, self._owasp_skills[norm])

    def get_skills_for_cwe(self, cwe_id: str) -> list[str]:
        norm = _normalize_cwe(cwe_id)
        if not norm:
            norm = cwe_id.strip().upper()
        if norm not in self._cwe_skills and (m := re.search(r"(\d+)", norm)):
            norm = f"CWE-{m.group(1)}"
        if norm not in self._cwe_skills:
            return []
        key = _cwe_key(norm)
        return self._load_list(key, self._cwe_skills[norm])

    def get_tools_for_owasp(self, owasp_id: str) -> list[str]:
        norm = _normalize_owasp(owasp_id)
        if not norm:
            upper = owasp_id.strip().upper()
            if upper in self._owasp_tools:
                norm = upper
        if not norm or norm not in self._owasp_tools:
            return []
        key = _tools_key(norm)
        return self._load_list(key, self._owasp_tools[norm])

    def get_scan_strategy(
        self,
        owasp_ids: list[str],
        cwe_ids: list[str],
    ) -> dict[str, object]:
        skills_ordered: list[str] = []
        tools_ordered: list[str] = []
        seen_s: set[str] = set()
        seen_t: set[str] = set()

        owasp_norm: list[str] = []
        for oid in owasp_ids:
            n = _normalize_owasp(oid)
            if n and n in self._owasp_skills:
                owasp_norm.append(n)
        owasp_norm = sorted(set(owasp_norm), key=lambda x: int(x[1:]))

        cwe_norm: list[str] = []
        for cid in cwe_ids:
            n = _normalize_cwe(cid)
            if n and n in self._cwe_skills:
                cwe_norm.append(n)
        cwe_norm = sorted(set(cwe_norm), key=lambda x: int(x.split("-", 1)[1]))

        for n in owasp_norm:
            for s in self.get_skills_for_owasp(n):
                if s not in seen_s:
                    seen_s.add(s)
                    skills_ordered.append(s)
            for t in self.get_tools_for_owasp(n):
                if t not in seen_t:
                    seen_t.add(t)
                    tools_ordered.append(t)

        for n in cwe_norm:
            for s in self.get_skills_for_cwe(n):
                if s not in seen_s:
                    seen_s.add(s)
                    skills_ordered.append(s)

        ordered_priority = sorted(owasp_norm, key=lambda x: int(x[1:])) + cwe_norm

        return {
            "skills": skills_ordered,
            "tools": tools_ordered,
            "priority": ordered_priority,
            "owasp_ids": owasp_norm,
            "cwe_ids": cwe_norm,
        }

    def warm_cache(self) -> None:
        try:
            if self._redis:
                pipe = self._redis.pipeline()
                for oid, skills in self._owasp_skills.items():
                    pipe.setex(_owasp_key(oid), KB_TTL_SEC, json.dumps(skills))
                for cid, skills in self._cwe_skills.items():
                    pipe.setex(_cwe_key(cid), KB_TTL_SEC, json.dumps(skills))
                for oid, tools in self._owasp_tools.items():
                    pipe.setex(_tools_key(oid), KB_TTL_SEC, json.dumps(tools))
                pipe.execute()
            for oid, skills in self._owasp_skills.items():
                self._memory_set(_owasp_key(oid), skills)
            for cid, skills in self._cwe_skills.items():
                self._memory_set(_cwe_key(cid), skills)
            for oid, tools in self._owasp_tools.items():
                self._memory_set(_tools_key(oid), tools)
            logger.info(
                "kb_warm_cache_ok",
                extra={
                    "event": "kb_warm_cache_ok",
                    "owasp_keys": len(self._owasp_skills),
                    "cwe_keys": len(self._cwe_skills),
                    "redis": bool(self._redis),
                },
            )
        except Exception as exc:
            logger.warning(
                "kb_warm_cache_failed",
                extra={"event": "kb_warm_cache_failed", "error_type": type(exc).__name__},
            )

    def invalidate(self, pattern: str) -> int:
        raw = (pattern or "").strip()
        if raw in ("", "*"):
            raise ValueError(
                "ScanKnowledgeBase.invalidate: pattern must not be empty or '*' alone",
            )
        norm = raw if raw.startswith(KB_KEY_PREFIX) else f"{KB_KEY_PREFIX}{raw.lstrip(':')}"
        pattern_targets_stats = "stats" in norm.lower()

        deleted = 0
        if self._redis:
            try:
                to_del: list[str] = []
                for key in self._redis.scan_iter(match=norm, count=256):
                    if isinstance(key, bytes):
                        key = key.decode("utf-8", errors="replace")
                    ks = str(key)
                    if not ks.startswith(KB_KEY_PREFIX):
                        continue
                    if not pattern_targets_stats and ks.startswith(STATS_KEYS_PREFIX):
                        continue
                    to_del.append(ks)
                for i in range(0, len(to_del), INVALIDATE_UNLINK_CHUNK):
                    chunk = to_del[i : i + INVALIDATE_UNLINK_CHUNK]
                    deleted += int(self._redis.unlink(*chunk))
                return deleted
            except Exception as exc:
                logger.warning(
                    "kb_invalidate_redis_failed",
                    extra={"event": "kb_invalidate_redis_failed", "error_type": type(exc).__name__},
                )
        for k in list(self._memory):
            ks = str(k)
            if not ks.startswith(KB_KEY_PREFIX):
                continue
            if not pattern_targets_stats and ks.startswith(STATS_KEYS_PREFIX):
                continue
            if fnmatch.fnmatchcase(k, norm) or fnmatch.fnmatch(k, norm):
                del self._memory[k]
                deleted += 1
        return deleted

    def stats(self) -> dict[str, object]:
        hits = self._mem_hits
        misses = self._mem_misses
        key_count = 0
        memory_estimate = 0

        if self._redis:
            try:
                rh = self._redis.get(STATS_HITS_KEY)
                rm = self._redis.get(STATS_MISSES_KEY)
                if rh is not None:
                    hits += int(rh)
                if rm is not None:
                    misses += int(rm)
            except Exception as exc:
                logger.warning(
                    "kb_stats_read_failed",
                    extra={"event": "kb_stats_read_failed", "error_type": type(exc).__name__},
                )
            try:
                for key in self._redis.scan_iter(match="argus:kb:*", count=256):
                    key_count += 1
                    try:
                        v = self._redis.get(key)
                        if v is not None:
                            memory_estimate += len(key.encode("utf-8")) + len(v.encode("utf-8"))
                    except Exception:
                        continue
            except Exception as exc:
                logger.warning(
                    "kb_stats_scan_failed",
                    extra={"event": "kb_stats_scan_failed", "error_type": type(exc).__name__},
                )
        else:
            key_count = len(self._memory)
            for k, v in self._memory.items():
                memory_estimate += len(k.encode("utf-8")) + len(v.encode("utf-8"))

        return {
            "hits": hits,
            "misses": misses,
            "key_count": key_count,
            "memory_usage_estimate_bytes": memory_estimate,
            "backend": "redis" if self._redis else "memory",
        }


def get_knowledge_base() -> ScanKnowledgeBase:
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = ScanKnowledgeBase()
    return _kb_instance
