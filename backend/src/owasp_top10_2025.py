"""OWASP Top 10:2025 category codes for ``findings.owasp_category``.

Stored values are short ids ``A01``…``A10`` (no year suffix, no slug). Titles below
match OWASP Top 10:2025; see https://owasp.org/Top10/ for authoritative wording.

- A01 — Broken Access Control
- A02 — Security Misconfiguration
- A03 — Software Supply Chain Failures
- A04 — Cryptographic Failures
- A05 — Injection
- A06 — Insecure Design
- A07 — Authentication Failures
- A08 — Software or Data Integrity Failures
- A09 — Security Logging & Alerting Failures
- A10 — Mishandling of Exceptional Conditions
"""

from typing import Literal, cast

OWASP_TOP10_2025_CATEGORY_IDS: tuple[str, ...] = (
    "A01",
    "A02",
    "A03",
    "A04",
    "A05",
    "A06",
    "A07",
    "A08",
    "A09",
    "A10",
)

# Short titles for reports / UI (OWASP Top 10:2025)
OWASP_TOP10_2025_CATEGORY_TITLES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

OwaspTop102025CategoryId = Literal[
    "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"
]

OWASP_A05_AI_INDICATORS: tuple[str, ...] = (
    "prompt injection",
    "system prompt leakage",
    "llm output manipulation",
    "rag poisoning",
    "ai model misuse",
    "llm endpoint unprotected",
    "ai api key exposed",
    "model config exposed",
    "ai cost amplification",
)

OWASP_A05_AI_TEST_STEPS: tuple[str, ...] = (
    "Test AI/LLM endpoints for prompt injection with override payloads",
    "Test for system prompt leakage via direct queries",
    "Test for RAG poisoning via malicious document uploads",
    "Test for LLM output XSS via reflected AI-generated content",
    "Check AI endpoint authentication and rate limiting",
    "Verify AI API keys are not exposed in client-side code",
    "Test for cost amplification via repeated LLM inference requests",
)

OWASP_AI_SPECIFIC_GAP_DESCRIPTIONS: dict[str, list[str]] = {
    "A01": [
        "LLM endpoints exposed without authentication",
        "Vector DB / embedding endpoints unprotected",
        "Admin AI model config routes accessible to regular users",
    ],
    "A02": [
        "AI API keys hardcoded or committed to repository",
        "Ollama/LM Studio exposed on 0.0.0.0 without auth",
        "Model config/temperature exposed via API endpoint",
    ],
    "A05": [
        "Prompt injection — user input in LLM prompts without sanitization",
        "System prompt leakage via crafted input",
        "RAG poisoning via malicious document retrieval",
        "LLM output rendered as HTML without escaping",
    ],
    "A06": [
        "No rate limiting on AI inference endpoints (cost amplification)",
        "No max token limits per user/session",
        "AI outputs not reviewed before high-stakes actions",
    ],
    "A07": [
        "API keys for AI services shared across tenants",
        "JWT with none algorithm accepted at AI endpoints",
        "AI chatbot sessions not isolated between users",
    ],
    "A08": [
        "Model weights loaded without checksum verification",
        "pickle.loads used to deserialize AI model artifacts",
    ],
    "A09": [
        "AI prompt/response not logged for abuse detection",
        "No monitoring on AI API cost spikes",
    ],
}


def findings_owasp_category_check_sql() -> str:
    """PostgreSQL CHECK expression for nullable ``findings.owasp_category``."""
    inside = ", ".join(f"'{x}'" for x in OWASP_TOP10_2025_CATEGORY_IDS)
    return f"owasp_category IS NULL OR owasp_category IN ({inside})"


def parse_owasp_category(value: str | None) -> OwaspTop102025CategoryId | None:
    """Map DB string to API literal; unknown values become ``None`` (defensive)."""
    if value is None:
        return None
    if value in OWASP_TOP10_2025_CATEGORY_IDS:
        return cast(OwaspTop102025CategoryId, value)
    return None
