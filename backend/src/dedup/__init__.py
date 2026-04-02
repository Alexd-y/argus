"""LLM-based vulnerability deduplication (Strix-style XML response parsing)."""

from src.dedup.llm_dedup import DedupResult, check_duplicate, check_duplicates_batch

__all__ = ["DedupResult", "check_duplicate", "check_duplicates_batch"]
