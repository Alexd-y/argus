"""Ad-hoc WRB → local OpenAI-compatible LLM connectivity check.

Proves the ARGUS WhiteRabbitNeo adapter can drive a local model (laptop Ollama)
before wiring the full e2e stack. Env is set BEFORE import so the module-level
WRB_DEFAULT_MODEL / registry pick up the override.

Run from backend/ with the venv:
    WHITERABBITNEO_URL=http://localhost:11434/v1 WHITERABBITNEO_MODEL=phi4-mini:latest \
        python scripts/wrb_connectivity_check.py
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("WHITERABBITNEO_URL", "http://localhost:11434/v1")
os.environ.setdefault("WHITERABBITNEO_MODEL", "phi4-mini:latest")

from src.llm.whiterabbitneo_adapter import (  # noqa: E402
    WRB_DEFAULT_MODEL,
    get_whiterabbitneo_adapter,
)


async def main() -> int:
    print(f"WRB_DEFAULT_MODEL = {WRB_DEFAULT_MODEL}")
    adapter = get_whiterabbitneo_adapter()
    print(f"is_configured = {adapter.is_configured}  base_url = {adapter.base_url}")
    if not adapter.is_configured:
        print("FAIL: adapter not configured (WHITERABBITNEO_URL empty)")
        return 1

    prompt = (
        "You are a pentest recon planner. Output ONLY compact JSON, no prose. "
        'Schema: {"actions":[{"tool":"<name>","reason":"<why>"}]}. '
        "Give exactly 2 passive recon actions for target http://juice-shop:3000."
    )
    resp = await adapter.call(prompt, max_tokens=256, temperature=0.0)
    text = (resp or "").strip()
    print(f"RESP ({len(text)} chars): {text[:600]}")
    ok = bool(text) and ("{" in text and "tool" in text.lower())
    print("RESULT:", "OK — WRB adapter drove the local LLM" if ok else "WEAK/EMPTY response")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
