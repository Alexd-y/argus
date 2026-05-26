"""Scope ingester — parse bug bounty scope from JSON, raw text, or platform APIs."""

from __future__ import annotations

import json
import re
from typing import Any

from src.bounty.schemas import BountyScope, ScopeIngestRequest


def ingest_scope(request: ScopeIngestRequest) -> BountyScope:
    """Ingest scope from a ScopeIngestRequest.

    Tries in order: JSON scope → raw text parse → empty scope.
    """
    if request.scope_json:
        return _parse_json_scope(request.scope_json)
    if request.raw_text:
        return _parse_raw_text(request.raw_text)
    return BountyScope(platform=request.platform or "")


def _parse_json_scope(data: dict[str, Any]) -> BountyScope:
    """Parse a structured JSON scope dict."""
    scope = BountyScope()
    scope.program_name = str(data.get("program_name", "") or data.get("name", ""))
    scope.platform = str(data.get("platform", ""))
    scope.reward_range = str(data.get("reward_range", "") or data.get("bounty_range", ""))
    scope.in_scope = list(data.get("in_scope", []))
    scope.out_of_scope = list(data.get("out_of_scope", []))
    scope.vulnerability_types = list(data.get("vulnerability_types", []))
    scope.excluded_vuln_types = list(data.get("excluded_vuln_types", []))
    scope.special_rules = list(data.get("special_rules", []))
    scope.notes = str(data.get("notes", ""))
    return scope


def _parse_raw_text(text: str) -> BountyScope:
    """Parse a raw pasted bug bounty scope text block."""
    scope = BountyScope()
    lines = [l.strip() for l in text.strip().split("\n") if l.strip()]

    in_section: str | None = None
    for line in lines:
        lower = line.lower()

        if any(w in lower for w in ("in scope", "in-scope", "targets:")):
            in_section = "in_scope"
            continue
        elif any(w in lower for w in ("out of scope", "out-of-scope", "exclusions")):
            in_section = "out_of_scope"
            continue
        elif any(w in lower for w in ("vulnerability types", "accepted vulns", "bounty types")):
            in_section = "vulnerability_types"
            continue
        elif any(w in lower for w in ("rules", "restrictions", "notes")):
            in_section = "special_rules"
            continue

        if re.search(r"https?://|www\.|^\*\.", line) and in_section in (None, "in_scope"):
            scope.in_scope.append(line.lstrip("-*• "))
        elif in_section and in_section in ("in_scope", "out_of_scope", "vulnerability_types", "special_rules"):
            items = getattr(scope, in_section, None)
            if isinstance(items, list):
                items.append(line.lstrip("-*• "))

    return scope