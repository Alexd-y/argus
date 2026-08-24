"""AI endpoint pattern detection and prompt-injection fuzzing adapter.

Detects AI/LLM endpoints from RECON results and tests them with prompt
injection payloads. Produces ``FindingCategory.PROMPT_INJECTION`` findings
that flow into VULN_ANALYSIS for deep testing.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from src.recon.quick_fuzz.detection_sigs import DETECTION_SIGNATURES
from src.recon.quick_fuzz.payload_registry import BUILTIN_PAYLOADS

logger = logging.getLogger(__name__)

AI_ENDPOINT_PATTERNS: tuple[str, ...] = (
    "/api/chat",
    "/api/completion",
    "/api/completions",
    "/api/generate",
    "/api/v1/chat",
    "/api/v1/completions",
    "/v1/chat/completions",
    "/api/ask",
    "/api/query",
    "/api/search",
    "/graphql",
    "/api/embeddings",
    "/api/inference",
    "/api/translate",
    "/api/summarize",
    "/chat",
    "/completions",
    "/infer",
)

AI_RESPONSE_INDICATORS: tuple[str, ...] = (
    "as a language model",
    "i am an ai",
    "i cannot",
    "i'm not able",
    "my instructions are",
    "system prompt",
    "i don't have access",
    "i'm designed to",
    "as an ai assistant",
)

AI_CONTENT_TYPE: tuple[str, ...] = (
    "application/json",
)


def detect_ai_endpoints(
    urls: list[str],
    recon_responses: dict[str, Any] | None = None,
) -> list[str]:
    """Filter URLs that match known AI endpoint patterns."""
    candidates: list[str] = []

    for url in urls:
        path = url.lower()
        for pattern in AI_ENDPOINT_PATTERNS:
            if pattern in path:
                candidates.append(url)
                break

    if recon_responses:
        for url, resp_data in recon_responses.items():
            body = str(resp_data.get("body", "") or "").lower()
            if any(ind in body for ind in ("openai", "anthropic", "llm", "gpt", "claude", "gemini")):
                if url not in candidates:
                    candidates.append(url)

    return candidates


async def fuzz_ai_endpoints(
    target: str,
    ai_urls: list[str] | None = None,
    recon_urls: list[str] | None = None,
    delay: float = 0.5,
    console: Any | None = None,
) -> list[dict[str, Any]]:

    payloads = BUILTIN_PAYLOADS.get("prompt_injection", [])
    sigs = DETECTION_SIGNATURES.get("prompt_injection", [])
    findings: list[dict[str, Any]] = []

    urls_to_test = list(ai_urls or [])
    if not urls_to_test and recon_urls:
        urls_to_test = detect_ai_endpoints(recon_urls)

    if not urls_to_test:
        if console:
            console.print("[dim]No AI endpoints detected for prompt injection testing[/dim]")
        return findings

    if console:
        console.print(f"[bold]Testing {len(urls_to_test)} AI endpoint(s) for prompt injection[/bold]")

    async with httpx.AsyncClient(
        headers={"User-Agent": "ARGUS-QuickFuzz/1.0"},
        follow_redirects=True,
    ) as client:
        for url in urls_to_test:
            for payload in payloads:
                body_data = {
                    "messages": [{"role": "user", "content": payload}],
                    "model": "test",
                }
                try:
                    r = await client.post(
                        url, json=body_data, timeout=10.0,
                        headers={"Content-Type": "application/json"},
                    )
                    resp_lower = r.text.lower()

                    triggered = any(s.lower() in resp_lower for s in sigs)

                    if triggered:
                        findings.append({
                            "module": "quick_fuzz",
                            "category": "prompt_injection",
                            "owasp_id": "A05",
                            "owasp_name": "Injection",
                            "severity": "medium",
                            "title": f"Prompt Injection — AI endpoint {url[:50]}",
                            "description": (
                                "The AI endpoint responded to a prompt injection payload "
                                "with content that suggests the system prompt or internal "
                                "instructions were revealed or overridden."
                            ),
                            "evidence": (
                                f"URL: {url}\n"
                                f"Payload: {payload[:200]}\n"
                                f"Response snippet: {r.text[:300]}"
                            ),
                            "fix": "Implement input sanitization on AI prompts, use guardrails, "
                                   "and never include system instructions in user-accessible context.",
                            "url": url,
                            "payload_attempted": [payload],
                            "payload_successful": [payload],
                            "taint_path": ["user_input -> AI_endpoint -> response_includes_system_prompt"],
                        })
                        if console:
                            console.print(
                                f"  [bold red]⚠ PROMPT INJECTION[/bold red] at {url[:60]}"
                            )
                        break

                    await asyncio.sleep(delay)
                except httpx.HTTPError:
                    continue

    return findings
