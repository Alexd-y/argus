"""SEC-001 — Regression gate: no high-entropy provider secrets in infra/.env.example."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_ENV_EXAMPLE: Final[Path] = _REPO_ROOT / "infra" / ".env.example"

# Lines that clearly use intentional placeholders skip stricter checks.
_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "REPLACE_ME",
    "CHANGE_ME",
    "change-me",
    "your-google-api-key",
    "<jwt",
)

_FORBIDDEN: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"sk-or-v1-[0-9a-f]{20,}", re.IGNORECASE), "OpenRouter-like hex tail"),
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"), "OpenAI project key-like tail"),
    (re.compile(r"pplx-[0-9A-Za-z]{20,}"), "Perplexity-like tail"),
    (re.compile(r"(?i)deepseek_api_key=sk-[0-9a-f]{30,}\s*$"), "DeepSeek-like hex secret"),
    (re.compile(r"(?i)kimi_api_key=sk-(?!REPLACE_ME)[A-Za-z0-9]{20,}\s*$"), "Kimi-like sk- secret"),
    (re.compile(r"(?i)shodan_api_key=[A-Za-z0-9]{20,}\s*$"), "Shodan-like alphanumeric secret"),
)


def _line_uses_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(m.lower() in lowered for m in _PLACEHOLDER_MARKERS)


def test_env_example_has_no_high_entropy_provider_secrets() -> None:
    assert _ENV_EXAMPLE.is_file(), f"Missing {_ENV_EXAMPLE}"

    text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    failures: list[str] = []

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        if _line_uses_placeholder(stripped):
            continue
        for pattern, label in _FORBIDDEN:
            if pattern.search(stripped):
                failures.append(f"L{lineno}: matches {label}")
                break

    assert not failures, "infra/.env.example contains suspicious provider material:\n" + "\n".join(
        failures
    )
