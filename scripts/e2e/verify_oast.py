"""
ARG-047 Phase 07 — verify OAST callbacks for the e2e capstone scan.

Background
----------
The OAST correlator (``backend/src/oast/correlator.py``) is **in-memory** and
does NOT publish callbacks to a Redis stream — historic guidance to poll
``oast:callbacks`` does not match the current implementation. The honest way
to verify OAST behaviour from outside the process is to:

  1. List findings for the scan via ``GET /api/v1/scans/<scan_id>/findings``.
  2. For each finding, fetch the detail row and inspect ``evidence_type`` /
     ``evidence_refs`` for OAST evidence (``oast_callback`` per
     ``EvidenceKind`` in ``backend/src/pipeline/contracts/finding_dto.py``).
  3. Treat OAST evidence as *opportunistic*: OWASP Juice Shop is heavy on
     web vulnerabilities (XSS, SQLi, broken-auth) where OAST is rarely the
     primary signal — Backlog/dev1_md §19.4 explicitly classes OAST as a
     soft requirement for the Juice Shop run. The script therefore returns
     ``status='no_oast_in_scope'`` (still exit 0) when no callbacks are
     observed, distinguishing it from a hard failure.

Hard-fail conditions (exit 1):
  * Cannot reach the findings endpoint (transport-level failure).
  * The findings response shape is unexpected (schema drift).

Output: structured JSON document mirroring the wrapper's phase-record contract.

Usage::

  python scripts/e2e/verify_oast.py \\
      --backend-url http://localhost:8000 \\
      --token e2e-api-key-not-for-production \\
      --scan-id <uuid> \\
      --output verify_oast.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

# Evidence type tokens that count as OAST signal (matches EvidenceKind enum).
OAST_EVIDENCE_TYPES: frozenset[str] = frozenset({"oast_callback", "oast", "out_of_band"})
OAST_HINT_TOKENS: tuple[str, ...] = (
    "interactsh",
    "oast",
    "out-of-band",
    "blind-",
    "ssrf",
    "log4shell",
    "xxe",
)
TIMEOUT_HTTP_SECONDS = 15.0


@dataclass
class Result:
    status: str = "passed"  # passed | no_oast_in_scope | failed
    findings_total: int = 0
    findings_with_oast_evidence: int = 0
    findings_with_oast_hint: int = 0
    sample_oast_finding_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    note: str = ""
    timestamp_utc: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def _http_get(url: str, token: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "argus-e2e-verifier/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_HTTP_SECONDS) as resp:  # noqa: S310 — controlled URL
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else None


def _has_oast_evidence(finding: dict[str, Any]) -> bool:
    ev_type = (finding.get("evidence_type") or "").strip().lower()
    if ev_type in OAST_EVIDENCE_TYPES:
        return True
    refs = finding.get("evidence_refs") or []
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, str) and any(token in ref.lower() for token in OAST_EVIDENCE_TYPES):
                return True
    return False


def _has_oast_hint(finding: dict[str, Any]) -> bool:
    """Best-effort signal: any descriptive text mentioning OAST-style detectors."""
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    return any(tok in title or tok in desc for tok in OAST_HINT_TOKENS)


def verify(args: argparse.Namespace) -> Result:
    res = Result()
    started = time.perf_counter()

    try:
        findings = _http_get(
            f"{args.backend_url}/api/v1/scans/{args.scan_id}/findings",
            args.token,
        )
    except urllib.error.HTTPError as exc:
        res.status = "failed"
        res.errors.append(f"findings endpoint returned HTTP {exc.code}")
        res.elapsed_seconds = round(time.perf_counter() - started, 3)
        return res
    except urllib.error.URLError as exc:
        res.status = "failed"
        res.errors.append(f"findings endpoint unreachable: {type(exc).__name__}")
        res.elapsed_seconds = round(time.perf_counter() - started, 3)
        return res

    if not isinstance(findings, list):
        res.status = "failed"
        res.errors.append(
            f"findings response shape unexpected: {type(findings).__name__}"
        )
        res.elapsed_seconds = round(time.perf_counter() - started, 3)
        return res

    res.findings_total = len(findings)

    sample: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if _has_oast_evidence(finding):
            res.findings_with_oast_evidence += 1
            fid = str(finding.get("id") or "")
            if fid and len(sample) < 5:
                sample.append(fid)
        elif _has_oast_hint(finding):
            res.findings_with_oast_hint += 1

    res.sample_oast_finding_ids = sample

    if res.findings_with_oast_evidence:
        res.status = "passed"
        res.note = (
            f"{res.findings_with_oast_evidence} finding(s) carry OAST callback evidence"
        )
    elif res.findings_with_oast_hint:
        res.status = "no_oast_in_scope"
        res.note = (
            f"{res.findings_with_oast_hint} finding(s) mention OAST-style detectors but "
            "no callback evidence captured — Juice Shop is web-vuln heavy"
        )
    else:
        res.status = "no_oast_in_scope"
        res.note = (
            "No OAST evidence in scan output. Juice Shop rarely triggers OAST; "
            "this is acceptable per Backlog/dev1_md §19.4."
        )

    res.elapsed_seconds = round(time.perf_counter() - started, 3)
    return res


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backend-url", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--scan-id", required=True)
    p.add_argument("--output", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    try:
        result = verify(args)
    except Exception as exc:  # noqa: BLE001
        result = Result(status="failed", errors=[f"unexpected error: {type(exc).__name__}"])
    out_payload = asdict(result)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(out_payload, fh, indent=2, sort_keys=True)
    print(json.dumps(out_payload, sort_keys=True))
    # Exit 0 unless we explicitly failed; ``no_oast_in_scope`` is acceptable.
    return 0 if result.status in ("passed", "no_oast_in_scope") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
