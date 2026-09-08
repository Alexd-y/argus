"""Robust JSON extraction from LLM responses.

Local models (WhiteRabbitNeo) frequently wrap JSON in prose, fence it in
```json blocks, or emit a leading ``Thought:`` preamble. A naive
``text[first "{" : last "}"]`` slice fails on any of these, and truncated
output (max_tokens cut-off) yields unbalanced braces. This module centralises a
tolerant extractor so every phase (critic, threat modeling, vuln analysis)
parses the same way instead of each re-implementing a brittle heuristic.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object from an LLM response, or ``None``.

    Strategy (each step is a fallback for the previous):

    1. Direct ``json.loads`` of the whole (stripped) text.
    2. First fenced ```json ... ``` block.
    3. Balanced-brace scan from the first ``{`` (tolerates trailing prose and
       ignores braces inside JSON string literals).

    Returns ``None`` when no valid object can be recovered; callers decide how
    to degrade gracefully. Only ``dict`` results are returned (a bare JSON
    array or scalar is treated as "no object").
    """
    if not text or not text.strip():
        return None
    stripped = text.strip()

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fence = _FENCE_RE.search(stripped)
    if fence:
        try:
            parsed = json.loads(fence.group(1).strip())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    recovered = _balanced_object(stripped)
    if recovered is not None:
        try:
            parsed = json.loads(recovered)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return None


def _balanced_object(text: str) -> str | None:
    """Return the substring of the first brace-balanced object, or ``None``.

    Tracks string literals and escapes so that ``{`` / ``}`` characters inside
    JSON strings do not skew the depth counter.
    """
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


__all__ = ["extract_json_object"]
