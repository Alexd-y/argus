"""
ARG-047 Phase 09 — verify Prometheus has scraped the live ARGUS metrics.

Asserts that the Prometheus instance shipped with ``infra/docker-compose.e2e.yml``
has scraped the backend (and worker, transitively via shared multiprocess
registry) and that the headline counters incremented during the scan run:

  * ``argus_http_requests_total > 0`` — proves the API was exercised.
  * ``argus_findings_emitted_total > 0`` — proves the worker reached at
    least one finding-emit call.
  * ``argus_sandbox_runs_total > 0`` — proves the active-scan dispatcher
    fired at least one sandboxed tool execution.

Additionally walks ``GET /api/v1/label/__name__/values`` to assert the full
nine-family metric set declared by ``backend/src/core/observability.py`` is
present (allow up to ``ALLOWED_MISSING`` to absorb metric families that have
no recorded events, e.g. ``argus_celery_task_failures_total`` on a clean run).

Output: structured JSON document mirroring the wrapper's phase-record contract.

Usage::

  python scripts/e2e/verify_prometheus.py \\
      --prometheus-url http://localhost:9090 \\
      --output verify_prometheus.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

# Headline counters — each MUST have at least one positive sample after a
# successful e2e scan. These are the "smoke" metrics from observability.py.
HEADLINE_METRICS: tuple[str, ...] = (
    "argus_http_requests_total",
    "argus_findings_emitted_total",
    "argus_sandbox_runs_total",
)

# All nine metric families registered by ``backend/src/core/observability.py``.
EXPECTED_METRIC_FAMILIES: tuple[str, ...] = (
    "argus_http_requests_total",
    "argus_http_request_duration_seconds",
    "argus_celery_task_duration_seconds",
    "argus_celery_task_failures_total",
    "argus_sandbox_runs_total",
    "argus_sandbox_run_duration_seconds",
    "argus_findings_emitted_total",
    "argus_llm_tokens_total",
    "argus_mcp_calls_total",
)

# Counters that have no observations on a clean Juice Shop run are tolerated
# (errors-only counters and LLM tokens may legitimately stay at zero when no
# AI provider is configured for the e2e lane).
ALLOWED_MISSING: frozenset[str] = frozenset(
    {
        "argus_celery_task_failures_total",
        "argus_llm_tokens_total",
        "argus_mcp_calls_total",
    }
)

TIMEOUT_HTTP_SECONDS = 15.0
SCRAPE_SETTLE_SECONDS = 3.0  # let the last scrape land before querying


@dataclass
class Result:
    status: str = "passed"
    headline_metric_values: dict[str, float] = field(default_factory=dict)
    missing_metric_families: list[str] = field(default_factory=list)
    unexpected_zero_counters: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    timestamp_utc: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def _http_get(url: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "argus-e2e-verifier/1.0"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_HTTP_SECONDS) as resp:  # noqa: S310 — controlled URL
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else None


def _query_instant(prom_url: str, expr: str) -> float | None:
    """Return the first numeric sample for an instant query, or ``None``."""
    encoded = urllib.parse.quote(expr, safe="")
    url = f"{prom_url}/api/v1/query?query={encoded}"
    try:
        payload = _http_get(url)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("status") != "success":
        return None
    data = payload.get("data") or {}
    result = data.get("result") or []
    if not result:
        return None
    first = result[0]
    value = first.get("value")
    if not isinstance(value, list) or len(value) < 2:
        return None
    try:
        return float(value[1])
    except (TypeError, ValueError):
        return None


def _label_values(prom_url: str, label: str = "__name__") -> set[str]:
    url = f"{prom_url}/api/v1/label/{label}/values"
    try:
        payload = _http_get(url)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return set()
    if not isinstance(payload, dict) or payload.get("status") != "success":
        return set()
    data = payload.get("data") or []
    return {str(v) for v in data if isinstance(v, str)}


def verify(args: argparse.Namespace) -> Result:
    res = Result()
    started = time.perf_counter()

    # Give Prometheus one extra scrape window to land the latest values.
    time.sleep(SCRAPE_SETTLE_SECONDS)

    # 1. Headline counters — sum across all label permutations.
    for metric in HEADLINE_METRICS:
        value = _query_instant(args.prometheus_url, f"sum({metric})")
        if value is None:
            value = _query_instant(args.prometheus_url, metric)
        res.headline_metric_values[metric] = float(value or 0.0)
        if value is None or value <= 0.0:
            res.unexpected_zero_counters.append(metric)

    if res.unexpected_zero_counters:
        res.status = "failed"
        res.errors.append(
            f"headline counters have zero/missing samples: {res.unexpected_zero_counters}"
        )

    # 2. Metric family inventory.
    available = _label_values(args.prometheus_url)
    if not available:
        res.status = "failed"
        res.errors.append("Prometheus label endpoint returned no metric names")
        res.elapsed_seconds = round(time.perf_counter() - started, 3)
        return res

    missing = []
    for family in EXPECTED_METRIC_FAMILIES:
        # Counters expose both ``name_total`` and ``name_created`` series — match
        # any prefix with the family name.
        if not any(name == family or name.startswith(family + ".") for name in available):
            if family not in ALLOWED_MISSING:
                missing.append(family)
    res.missing_metric_families = missing
    if missing:
        res.status = "failed"
        res.errors.append(f"missing required metric families: {missing}")

    res.elapsed_seconds = round(time.perf_counter() - started, 3)
    return res


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prometheus-url", required=True, help="Prometheus base URL (e.g. http://localhost:9090)")
    p.add_argument("--output", required=True, help="Path to write the structured result JSON")
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
    return 0 if result.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
