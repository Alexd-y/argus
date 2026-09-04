"""Baseline control scoring: coverage vs pass_rate (Block 3).

The historical "Pass Rate" conflated *how many tools ran* with *security
posture*, so a scan that silently skipped whole check classes could still look
green ("0 findings = OK"). This module introduces an explicit **baseline** — a
mandatory checklist (``config/baseline.yaml``) — and derives two distinct
metrics from the scan's findings + recon output:

* ``coverage``  = executed / total  — how much of the baseline was actually run.
* ``pass_rate`` = passed  / total   — how much of the baseline passed.

A control that never ran is ``not_assessed`` (a coverage gap), never an implicit
pass. ``executed_overrides`` lets the reporting phase assert that a check ran
even when it produced no findings (a passing control leaves no finding behind).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_BASELINE_PATH = Path(__file__).resolve().parents[2] / "config" / "baseline.yaml"

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Tokens that identify an HTTP security-header finding (matched in the finding
# blob). Broad enough to catch per-header findings that omit the word "security".
_SECURITY_HEADER_NEEDLES = (
    "security header",
    "security http",
    "hsts",
    "strict-transport",
    "content-security-policy",
    "content security policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "clickjacking",
)


@lru_cache(maxsize=1)
def load_baseline_controls() -> tuple[dict[str, Any], ...]:
    """Load the baseline control definitions from ``config/baseline.yaml``."""
    try:
        raw = yaml.safe_load(_BASELINE_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - config error
        logger.warning("baseline_config_load_failed", extra={"error": str(exc)})
        return ()
    controls = raw.get("controls") or []
    return tuple(c for c in controls if isinstance(c, dict) and c.get("id"))


def _sev(finding: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 0)


def _blob(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(k, "")).lower()
        for k in ("title", "vuln_type", "source_tool", "description")
    )


def _matches(findings: list[dict[str, Any]], *needles: str) -> list[dict[str, Any]]:
    return [f for f in findings if isinstance(f, dict) and any(n in _blob(f) for n in needles)]


def _control_status(
    control_id: str,
    findings: list[dict[str, Any]],
    recon: dict[str, Any],
    executed_overrides: set[str],
) -> tuple[bool, bool]:
    """Return ``(executed, passed)`` for a single control.

    A control "passed" only when it executed and no disqualifying finding is
    present. When a check produced no finding, ``executed`` relies on recon
    signals or an explicit override (a silent pass must still count as covered).
    """
    ports = recon.get("ports") or []
    subdomains = recon.get("subdomains") or []
    forced = control_id in executed_overrides

    if control_id == "tls":
        tls_findings = _matches(findings, "tls", "ssl", "certificate", "cipher")
        executed = forced or bool(tls_findings) or 443 in ports
        # A TLS weakness (medium+) or explicit "weak/outdated" wording fails it.
        weak = any(
            _sev(f) >= _SEVERITY_ORDER["medium"]
            or "weak" in _blob(f)
            or "outdated" in _blob(f)
            for f in tls_findings
        )
        return executed, executed and not weak

    if control_id == "open_ports":
        # "Passed" means the port scan ran successfully; a host with zero open
        # ports is good posture, not a failure. Coverage tracks that it ran.
        executed = forced or bool(ports)
        return executed, executed

    if control_id == "dns":
        dns_findings = _matches(findings, "dns", "zone transfer", "axfr", "caa", "dnssec")
        executed = forced or bool(dns_findings) or bool(subdomains)
        # A high-severity DNS issue (e.g. open AXFR) fails the control.
        fails = any(_sev(f) >= _SEVERITY_ORDER["high"] for f in dns_findings)
        return executed, executed and not fails

    if control_id == "mail_headers":
        mail_findings = _matches(findings, "spf", "dmarc", "dkim")
        executed = forced or bool(mail_findings)
        return executed, executed and not mail_findings

    if control_id == "security_headers":
        header_findings = _matches(findings, *_SECURITY_HEADER_NEEDLES)
        executed = forced or bool(header_findings)
        return executed, executed and not header_findings

    # Unknown control: only counts if explicitly asserted executed.
    return forced, False


def evaluate_baseline(
    findings: list[dict[str, Any]] | None,
    recon: dict[str, Any] | None = None,
    *,
    executed_overrides: set[str] | None = None,
) -> dict[str, Any]:
    """Evaluate baseline controls and return coverage + pass_rate + per-control.

    Returns a dict::

        {
          "total": int,
          "executed": int,
          "passed": int,
          "coverage": float,     # executed / total (0..1)
          "pass_rate": float,    # passed / total   (0..1)
          "controls": [{id,title,category,executed,passed,status}, ...],
        }

    ``status`` is one of ``pass`` / ``fail`` / ``not_assessed``.
    """
    controls = load_baseline_controls()
    findings = findings or []
    recon = recon or {}
    overrides = executed_overrides or set()

    rows: list[dict[str, Any]] = []
    executed_count = 0
    passed_count = 0
    for control in controls:
        cid = str(control["id"])
        executed, passed = _control_status(cid, findings, recon, overrides)
        if executed:
            executed_count += 1
        if executed and passed:
            passed_count += 1
        status = "pass" if (executed and passed) else ("fail" if executed else "not_assessed")
        rows.append(
            {
                "id": cid,
                "title": control.get("title", cid),
                "category": control.get("category", ""),
                "executed": executed,
                "passed": executed and passed,
                "status": status,
            }
        )

    total = len(controls)
    coverage = round(executed_count / total, 4) if total else 0.0
    pass_rate = round(passed_count / total, 4) if total else 0.0
    return {
        "total": total,
        "executed": executed_count,
        "passed": passed_count,
        "coverage": coverage,
        "pass_rate": pass_rate,
        "controls": rows,
    }


__all__ = ["evaluate_baseline", "load_baseline_controls"]
