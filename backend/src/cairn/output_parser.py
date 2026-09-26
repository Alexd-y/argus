"""Extract a JSON object from a chatty LLM/agent response.

Reuses the shared ARGUS extractor (``src.llm.json_extract.extract_json_object``)
and extends it with the upstream Cairn tolerance
(``_external/Cairn/cairn/src/cairn/dispatcher/output_parser.py``): scan every
fenced ```json block and attempt ``JSONDecoder.raw_decode`` from each ``{``
position, so a valid object embedded after invalid preamble is still recovered.

Unlike the shared util (which returns ``None``), this raises ``ValueError`` when
no object is found, because the Cairn contract validators expect a dict.
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.llm.json_extract import extract_json_object as _shared_extract

_FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    """Return the first JSON object in ``text`` or raise ``ValueError``."""
    shared = _shared_extract(text)
    if shared is not None:
        return shared

    decoder = json.JSONDecoder()
    seen: set[str] = set()
    for candidate in _candidate_segments(text):
        segment = candidate.strip()
        if not segment or segment in seen:
            continue
        seen.add(segment)
        try:
            parsed = json.loads(segment)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(parsed, dict):
                return parsed
        for start in (i for i, char in enumerate(segment) if char == "{"):
            try:
                parsed, _end = decoder.raw_decode(segment[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed

    raise ValueError("no JSON object found in output")


def _candidate_segments(text: str) -> list[str]:
    segments = [text.strip()]
    segments.extend(match.group(1).strip() for match in _FENCED_BLOCK_RE.finditer(text))
    return segments


__all__ = ["extract_json_object"]
