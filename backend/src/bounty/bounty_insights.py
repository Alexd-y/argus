"""LLM-powered bug bounty hunter insights.

Uses ARGUS LLM facade (WhiteRabbitNeo for security-sensitive analysis,
cloud fallback for general formatting) to generate creative attack vectors
and non-obvious testing approaches from scope data.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def generate_bounty_insights(
    scope_json: str,
    llm_facade: Any | None = None,
) -> str:
    """Generate LLM insights from bounty scope.

    Uses WhiteRabbitNeo (local LLM) for security-sensitive analysis.
    Falls back to empty string if no LLM is available.
    """
    if llm_facade is None:
        return ""

    prompt = (
        "You are an expert bug bounty hunter and penetration tester.\n\n"
        "Analyze this bug bounty program scope and provide:\n"
        "1. Top 3 highest-value attack vectors to focus on first\n"
        "2. Any unusual or interesting scope items worth deep investigation\n"
        "3. Common mistakes hunters make on this type of program\n"
        "4. One creative/non-obvious test approach specific to this scope\n\n"
        f"Bug Bounty Program:\n{scope_json}\n\n"
        "Be concise, practical, and specific to the actual scope items provided."
    )

    try:
        from src.llm.facade import call_llm_unified
        from src.llm.task_router import LLMTask

        result = await call_llm_unified(
            prompt=prompt,
            task=LLMTask.THREAT_MODELING,
            max_tokens=1000,
        )
        return str(result) if result else ""
    except Exception as exc:
        logger.warning("bounty_insights_llm_failed", extra={"error": str(exc)})
        return ""


def generate_bounty_insights_sync(
    scope_json: str,
    llm_facade: Any | None = None,
) -> str:
    """Synchronous wrapper for generate_bounty_insights.

    Useful when running outside async context (CLI mode).
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        return ""
    except RuntimeError:
        return asyncio.run(generate_bounty_insights(scope_json, llm_facade))
