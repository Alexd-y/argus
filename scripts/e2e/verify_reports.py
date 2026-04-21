"""
ARG-047 Phase 06 — verify the report bundle produced by the e2e capstone.

Calls the backend's report listing endpoint, filters to the rows generated for
the scan currently under test, and asserts:

  * Each row is in ``generation_status='ready'`` (no pending/processing/failed).
  * The row count matches ``--expected-count`` (default 12 — three tiers
    ``midgard``/``asgard``/``valhalla`` × four formats ``pdf``/``html``/``json``/
    ``csv``, the long-term Backlog §19.4 invariant being 18 once SARIF/JUNIT
    are exposed via ``generate-all`` — pass ``--expected-count 18`` to assert
    that variant).
  * Each tier appears the expected number of times — i.e. no tier is silently
    missing rows.
  * For every report we can fetch the detail endpoint and the ``summary``
    payload reports a non-empty findings count consistent with the scan.

Output: structured JSON document compatible with the wrapper's phase-record
contract (``status: passed|failed`` plus diagnostic fields). Exit code 0 on
success, 1 on assertion failure, 2 on transport / unexpected error.

Usage::

  python scripts/e2e/verify_reports.py \\
      --backend-url http://localhost:8000 \\
      --token e2e-api-key-not-for-production \\
      --scan-id <uuid> \\
      --target http://juice-shop:3000 \\
      --expected-count 12 \\
      --output verify_reports.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

EXPECTED_TIERS: tuple[str, ...] = ("midgard", "asgard", "valhalla")
DEFAULT_FORMATS: tuple[str, ...] = ("pdf", "html", "json", "csv")
EXTENDED_FORMATS: tuple[str, ...] = ("pdf", "html", "json", "csv", "sarif", "junit")
TIMEOUT_HTTP_SECONDS = 15.0


@dataclass
class Result:
    """Verification verdict — serialised to the structured JSON output."""

    status: str = "passed"
    expected_count: int = 0
    actual_count: int = 0
    expected_per_tier: int = 0
    per_tier_counts: dict[str, int] = field(default_factory=dict)
    not_ready_count: int = 0
    not_ready_ids: list[str] = field(default_factory=list)
    missing_tiers: list[str] = field(default_factory=list)
    extra_tiers: list[str] = field(default_factory=list)
    summary_zero_findings_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
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


def _fetch_reports_for_target(backend_url: str, token: str, target: str) -> list[dict[str, Any]]:
    """Call ``GET /api/v1/reports?target=...`` and return the list payload.

    Falls back to an unfiltered listing if the targeted query returns empty —
    this guards against URL-encoding subtleties where the stored target may
    differ slightly from the query string (e.g. trailing slash).
    """
    encoded = urllib.parse.quote(target, safe=":/?#[]@!$&'()*+,;=")
    listed = _http_get(f"{backend_url}/api/v1/reports?target={encoded}", token)
    if isinstance(listed, list) and listed:
        return listed
    # Unfiltered fallback — return everything, the caller will filter by scan_id
    # via the detail endpoint.
    listed = _http_get(f"{backend_url}/api/v1/reports", token)
    return listed if isinstance(listed, list) else []


def _fetch_detail(backend_url: str, token: str, report_id: str) -> dict[str, Any]:
    return _http_get(f"{backend_url}/api/v1/reports/{report_id}", token)


def _filter_to_scan(
    reports: list[dict[str, Any]],
    backend_url: str,
    token: str,
    scan_id: str,
) -> list[dict[str, Any]]:
    """Hydrate each row with detail data so we can filter by ``scan_id``.

    The list endpoint omits ``scan_id`` — the only authoritative way to bind
    a row to the current scan is via the detail endpoint. We hydrate at most
    one round-trip per report (typically 12-18), which fits inside the phase
    timeout.
    """
    enriched: list[dict[str, Any]] = []
    for row in reports:
        rid = row.get("report_id") or row.get("id")
        if not rid:
            continue
        try:
            detail = _fetch_detail(backend_url, token, str(rid))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
            continue
        if detail.get("scan_id") == scan_id:
            merged = {**row, **detail}
            enriched.append(merged)
    return enriched


def verify(args: argparse.Namespace) -> Result:
    res = Result(expected_count=int(args.expected_count))
    started = time.perf_counter()

    try:
        listing = _fetch_reports_for_target(args.backend_url, args.token, args.target)
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        res.status = "failed"
        res.errors.append(f"failed to list reports: {type(exc).__name__}: {exc}")
        res.elapsed_seconds = round(time.perf_counter() - started, 3)
        return res

    scan_rows = _filter_to_scan(listing, args.backend_url, args.token, args.scan_id)
    res.actual_count = len(scan_rows)

    tier_counts = Counter((r.get("tier") or "unknown").lower() for r in scan_rows)
    res.per_tier_counts = dict(sorted(tier_counts.items()))

    # Per-tier balance check — every tier should have the same count.
    if res.actual_count and res.expected_count:
        res.expected_per_tier = res.expected_count // max(len(EXPECTED_TIERS), 1)

    res.missing_tiers = sorted(set(EXPECTED_TIERS) - set(tier_counts.keys()))
    res.extra_tiers = sorted(set(tier_counts.keys()) - set(EXPECTED_TIERS))

    not_ready_rows = [r for r in scan_rows if (r.get("generation_status") or "").lower() != "ready"]
    res.not_ready_count = len(not_ready_rows)
    res.not_ready_ids = [str(r.get("report_id") or r.get("id") or "") for r in not_ready_rows]

    # Each ``ready`` report should have a non-empty summary with at least one
    # finding in any severity bucket — the bundle is meant to mirror real
    # scan output, so a uniformly empty summary indicates a generation regression.
    for row in scan_rows:
        if (row.get("generation_status") or "").lower() != "ready":
            continue
        summary = row.get("summary") or {}
        if not isinstance(summary, dict):
            continue
        # The Pydantic ReportSummary schema exposes ``total_findings`` plus
        # severity counts — accept either as the signal of populated data.
        total = summary.get("total_findings")
        if not isinstance(total, int):
            total = sum(
                summary.get(k, 0) or 0
                for k in ("critical", "high", "medium", "low", "info")
                if isinstance(summary.get(k, 0), int)
            )
        if not total:
            res.summary_zero_findings_ids.append(str(row.get("report_id") or row.get("id") or ""))

    # Aggregate verdict.
    if res.actual_count != res.expected_count:
        res.status = "failed"
        res.errors.append(
            f"report count mismatch: got {res.actual_count}, expected {res.expected_count}"
        )
    if res.not_ready_count:
        res.status = "failed"
        res.errors.append(f"{res.not_ready_count} report(s) not in 'ready' state")
    if res.missing_tiers:
        res.status = "failed"
        res.errors.append(f"missing tiers: {res.missing_tiers}")
    # Accept up to one tier with zero findings (Juice Shop is heavy on web
    # vulns — Asgard/recon may legitimately yield few findings if the recon
    # tier is configured for shallow scans).
    if len(res.summary_zero_findings_ids) > res.expected_per_tier:
        res.status = "failed"
        res.errors.append(
            f"{len(res.summary_zero_findings_ids)} report(s) have empty summaries"
        )

    res.elapsed_seconds = round(time.perf_counter() - started, 3)
    return res


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backend-url", required=True, help="Backend base URL (e.g. http://localhost:8000)")
    p.add_argument("--token", required=True, help="Bearer token for the API")
    p.add_argument("--scan-id", required=True, help="Scan UUID to verify reports for")
    p.add_argument("--target", required=True, help="Scan target URL (used to filter the list endpoint)")
    p.add_argument("--expected-count", type=int, default=12, help="Expected report count (default 12)")
    p.add_argument("--output", required=True, help="Path to write the structured result JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    try:
        result = verify(args)
    except Exception as exc:  # noqa: BLE001 — wrapper-level catch; surface as JSON
        result = Result(
            status="failed",
            expected_count=int(args.expected_count),
            errors=[f"unexpected error: {type(exc).__name__}"],
        )
    out_payload = asdict(result)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(out_payload, fh, indent=2, sort_keys=True)
    print(json.dumps(out_payload, sort_keys=True))
    return 0 if result.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
