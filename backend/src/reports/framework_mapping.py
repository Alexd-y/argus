"""Compliance framework mapping for findings (Block 4.2).

Config-driven, pure mapper from a finding's CWE / vuln_type to ISO 27001
(Annex A) and SOC 2 (Trust Services Criteria) controls, loaded from
``config/framework_mappings.yaml``. Unlike the audit-evidence mapper in
``src.governance.compliance``, this is synchronous and per-finding, producing a
compact ``compliance`` annotation the report/UI renders next to CWE/OWASP.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_MAPPINGS_PATH = Path(__file__).resolve().parents[2] / "config" / "framework_mappings.yaml"
_CWE_NUM_RE = re.compile(r"(\d{1,6})")


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    try:
        return yaml.safe_load(_MAPPINGS_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - config error
        logger.warning("framework_mappings_load_failed", extra={"error": str(exc)})
        return {}


def _cwe_number(finding: dict[str, Any]) -> str | None:
    raw = finding.get("cwe") or finding.get("cwe_id")
    if raw is None:
        return None
    match = _CWE_NUM_RE.search(str(raw))
    return match.group(1) if match else None


def _controls_for(entry: dict[str, Any], catalog: dict[str, Any]) -> list[dict[str, str]]:
    """Expand a ``{framework: [control_id, ...]}`` entry into control dicts."""
    out: list[dict[str, str]] = []
    for framework, control_ids in entry.items():
        fw_catalog = catalog.get(framework, {}) if isinstance(catalog, dict) else {}
        for control_id in control_ids or []:
            out.append(
                {
                    "framework": str(framework),
                    "control_id": str(control_id),
                    "control_name": str(fw_catalog.get(control_id, "")),
                }
            )
    return out


def map_finding_frameworks(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Return ISO 27001 / SOC 2 controls a finding maps to.

    Resolution order: CWE mapping → vuln_type mapping → default. Returns a list
    of ``{framework, control_id, control_name}`` dicts (possibly empty if the
    config is missing).
    """
    if not isinstance(finding, dict):
        return []
    config = _load()
    if not config:
        return []
    catalog = config.get("controls", {})

    cwe = _cwe_number(finding)
    cwe_map = config.get("cwe", {}) or {}
    if cwe and cwe in cwe_map:
        return _controls_for(cwe_map[cwe], catalog)

    vuln_type = str(finding.get("vuln_type") or "").strip().lower()
    vt_map = config.get("vuln_type", {}) or {}
    if vuln_type and vuln_type in vt_map:
        return _controls_for(vt_map[vuln_type], catalog)

    default = config.get("default", {}) or {}
    return _controls_for(default, catalog)


__all__ = ["map_finding_frameworks"]
