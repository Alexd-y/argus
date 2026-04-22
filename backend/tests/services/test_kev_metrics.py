"""C7-T06 Wave 5 — KEV-aware HPA metric-surface contract tests.

Pinned scope
------------
The KEV-aware HPA (``infra/helm/argus/templates/hpa-celery-worker-kev.yaml``)
scales the ARGUS Celery scan-worker pool on TWO Prometheus *external metrics*
exposed by the cluster's Prometheus Adapter:

  1. ``argus_kev_findings_emit_rate_5m`` — derived by the Adapter from
     ``argus_findings_emitted_total{kev_listed="true"}`` (the source counter
     emitted by ``backend/src/core/observability.py::record_finding_emitted``).
     Adapter rule:
         sum(rate(<<.Series>>{<<.LabelMatchers>>}[5m]))

  2. ``argus_celery_queue_depth`` (selector ``queue="argus.scans"``) — a Gauge
     emitted by ``backend/src/celery/metrics_updater.py::refresh_queue_depths``
     against whatever registry ``observability.get_registry()`` exposes.

Plan-spec discrepancies, intentionally surfaced here so reviewers don't waste
cycles cross-checking metric names that never landed in code:

  * The plan refers to ``argus_kev_active_findings_total`` and
    ``argus_kev_hpa_target_replicas``. NEITHER name exists in the backend
    metric registry (Cycle 6 / Batch 6 implementation locked the names listed
    above).
  * The "active findings" semantic does not exist as a backend metric — KEV
    findings are recorded as a **monotonic Counter** by the normaliser, not a
    point-in-time Gauge. "Active KEV count" can be derived in PromQL as
    ``sum(argus_findings_emitted_total{kev_listed="true"}) -
        sum(argus_findings_remediated_total{kev_listed="true"})`` BUT no
    ``_remediated_`` counter exists yet either.
  * "HPA target replicas" is computed by the Adapter + HPA controller, not by
    the backend. The closest backend-side surface is the source counter rate;
    the post-Adapter desired-replicas value is observable via the cluster
    metric ``kube_horizontalpodautoscaler_status_desired_replicas`` (which is
    what the C7-T06 PrometheusRule alerts on directly).

This suite therefore validates the ACTUAL contracts the production HPA
depends on — not the speculative metric names from the plan.

Coverage (8 cases):
  1. ``record_finding_emitted(kev_listed=True)`` increments the
     ``argus_findings_emitted_total{kev_listed="true"}`` series.
  2. ``record_finding_emitted(kev_listed=False)`` does NOT touch the
     ``kev_listed="true"`` slice the HPA scales on.
  3. The counter labels match the documented contract — exactly
     ``{tier, severity, kev_listed}``, no high-cardinality leak.
  4. Unknown / out-of-whitelist label values collapse to ``_other`` so the
     KEV slice cannot be polluted by an attacker-controlled finding row.
  5. CVE-id-style high-cardinality strings cannot reach the metric label
     surface via the recorder (defence in depth — the recorder API has
     no ``cve_id`` parameter, asserting that the surface stays sealed).
  6. The Adapter rule's ``metricsQuery`` (sum-rate over 5m) matches the
     spec the HPA template was authored against — drift between
     ``values.yaml`` and ``hpa-celery-worker-kev.yaml`` would silently
     break HPA scaling, this test gates that.
  7. The Adapter rule's ``seriesQuery`` for the KEV emit-rate filters on
     ``kev_listed="true"`` (so non-KEV findings don't inflate the
     scaling signal).
  8. The Grafana dashboard JSON gate is documented but skipped — no
     ``infra/helm/argus/grafana/*.json`` exists yet (a future ticket
     should land the operator-built dashboard JSON; until then this
     test is xfail-marked so the absence remains visible in CI).

Determinism: no network, no real Celery, no Redis. Helm rendering uses the
``helm template`` CLI when available; tests requiring it skip gracefully on
machines without Helm so the suite stays runnable in any local dev env.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Layer 1 — env defaults BEFORE any ``src.*`` import.
# Mirrors the patterns in tests/celery/test_queue_depth_metrics_updater.py and
# tests/unit/conftest.py so the settings module loads without a live DB.
# ---------------------------------------------------------------------------

import os

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Layer 2 — module-under-test imports.
# ---------------------------------------------------------------------------

import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Final  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402
from prometheus_client import CollectorRegistry  # noqa: E402

from src.core import observability as obs  # noqa: E402
from src.core.observability import (  # noqa: E402
    METRIC_CATALOGUE,
    OTHER_LABEL_VALUE,
    record_finding_emitted,
    reset_metrics_registry,
)


# ---------------------------------------------------------------------------
# Constants — single source of truth for the contract surface.
# ---------------------------------------------------------------------------

#: Source counter the Prometheus Adapter rate-derives the HPA's external
#: metric from. Renaming this requires a coordinated change in
#: ``backend/src/core/observability.py``, ``infra/helm/argus/values.yaml``
#: (`prometheusAdapter.rules.kevEmitRate.seriesQuery`), and the C7-T06
#: PrometheusRule (`templates/prometheusrule-kev-hpa.yaml`).
SOURCE_COUNTER: Final[str] = "argus_findings_emitted_total"

#: The KEV-only label slice the Adapter rule selects on. Anything else is
#: invisible to the HPA's scaling decision.
KEV_LABEL_KEY: Final[str] = "kev_listed"
KEV_LABEL_VALUE: Final[str] = "true"

#: Documented contract — the source counter MUST carry exactly these labels.
#: Adding a label here without updating the Adapter ``seriesQuery`` would
#: silently fan out the HPA's input series into multiple distinct external
#: metrics (cardinality bug + scaling regression).
EXPECTED_COUNTER_LABELS: Final[frozenset[str]] = frozenset(
    {"tier", "severity", "kev_listed"},
)

#: Repository root — used by Helm-rendering tests to locate the chart.
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
HELM_CHART_DIR: Final[Path] = REPO_ROOT / "infra" / "helm" / "argus"
GRAFANA_DASHBOARDS_DIR: Final[Path] = HELM_CHART_DIR / "grafana"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry() -> CollectorRegistry:
    """Each test runs against a private CollectorRegistry.

    Mirrors ``tests/unit/core/test_observability.py`` — the metric registry
    is rebuilt from scratch so series state never leaks between cases
    (Prometheus globals are otherwise persistent across the process).
    """
    reg = CollectorRegistry()
    reset_metrics_registry(registry=reg)
    return reg


def _samples(
    reg: CollectorRegistry,
    metric_name: str,
) -> list[tuple[dict[str, str], float]]:
    """Return ``[(labels, value), ...]`` for the named counter.

    Counters are exposed by ``prometheus_client`` with a ``_total`` suffix on
    the actual sample name; the helper accepts both forms so callers can pass
    the catalogue name directly.
    """
    out: list[tuple[dict[str, str], float]] = []
    suffixes = ("", "_total")
    for family in reg.collect():
        for sample in family.samples:
            if any(sample.name == metric_name + s for s in suffixes):
                out.append((dict(sample.labels), float(sample.value)))
    return out


def _kev_slice_total(reg: CollectorRegistry) -> float:
    """Sum every sample on the ``kev_listed="true"`` slice.

    This is the exact aggregate the Prometheus Adapter would compute via
    ``sum(rate(argus_findings_emitted_total{kev_listed="true"}[5m]))``, minus
    the rate-window normalisation (which is not testable in-process — it
    happens server-side at scrape time).
    """
    return sum(
        value
        for labels, value in _samples(reg, SOURCE_COUNTER)
        if labels.get(KEV_LABEL_KEY) == KEV_LABEL_VALUE
    )


# ---------------------------------------------------------------------------
# Case 1 — kev=True increments the HPA's input series.
# ---------------------------------------------------------------------------


def test_record_kev_finding_increments_kev_slice(
    _isolated_registry: CollectorRegistry,
) -> None:
    """``record_finding_emitted(kev_listed=True)`` lands on the slice the
    Adapter selects for the HPA — every call increments the counter by 1."""
    assert _kev_slice_total(_isolated_registry) == 0.0

    for _ in range(7):
        record_finding_emitted(tier="midgard", severity="critical", kev_listed=True)

    assert _kev_slice_total(_isolated_registry) == 7.0


# ---------------------------------------------------------------------------
# Case 2 — kev=False MUST NOT contaminate the kev slice.
# ---------------------------------------------------------------------------


def test_record_non_kev_finding_does_not_touch_kev_slice(
    _isolated_registry: CollectorRegistry,
) -> None:
    """The Adapter rule filters on ``kev_listed="true"``. A non-KEV finding
    must leave the HPA's input series at zero — otherwise normal scan
    activity would mistakenly drive scale-up."""
    record_finding_emitted(tier="midgard", severity="high", kev_listed=False)
    record_finding_emitted(tier="asgard", severity="medium", kev_listed=False)

    assert _kev_slice_total(_isolated_registry) == 0.0

    # Adding one KEV finding must show up cleanly against the zero baseline.
    record_finding_emitted(tier="midgard", severity="critical", kev_listed=True)
    assert _kev_slice_total(_isolated_registry) == 1.0


# ---------------------------------------------------------------------------
# Case 3 — counter labels match the documented contract exactly.
# ---------------------------------------------------------------------------


def test_source_counter_label_set_is_pinned_to_contract() -> None:
    """The catalogue (``METRIC_CATALOGUE``) is the single source of truth for
    the metric surface. Drift between the catalogue and this test surfaces a
    reviewer-actionable signal: any label addition needs Adapter + Helm value
    + PrometheusRule co-update or scaling silently breaks."""
    spec = next(
        (s for s in METRIC_CATALOGUE if s.name == SOURCE_COUNTER),
        None,
    )
    assert spec is not None, (
        f"{SOURCE_COUNTER!r} missing from METRIC_CATALOGUE — the HPA's source "
        "counter has been removed; revisit the chart and Adapter rules."
    )
    assert frozenset(spec.labels) == EXPECTED_COUNTER_LABELS, (
        f"Label drift: catalogue={set(spec.labels)!r}, "
        f"contract={set(EXPECTED_COUNTER_LABELS)!r}. "
        "Update Adapter `seriesQuery` and PrometheusRule expressions in lock-step."
    )


# ---------------------------------------------------------------------------
# Case 4 — out-of-whitelist values collapse to `_other`.
# ---------------------------------------------------------------------------


def test_unknown_kev_listed_value_is_coerced_to_other(
    _isolated_registry: CollectorRegistry,
) -> None:
    """``record_finding_emitted`` coerces ``kev_listed`` to ``"true"|"false"``
    via the recorder body, but the underlying ``_LabelGuard.normalize`` is the
    backstop. If a caller bypasses the recorder, an unknown value becomes the
    ``_other`` sentinel — the HPA slice (``kev_listed="true"``) stays clean."""
    obs._safe_emit_counter(  # type: ignore[attr-defined]  (intentional internal API
        SOURCE_COUNTER,                               # access — defence-in-depth check)
        {"tier": "midgard", "severity": "critical", "kev_listed": "yes-please"},
    )

    samples = _samples(_isolated_registry, SOURCE_COUNTER)
    assert samples, "expected at least one sample after the bypass call"
    kev_values = {labels.get(KEV_LABEL_KEY) for labels, _ in samples}
    assert KEV_LABEL_VALUE not in kev_values, (
        "Unwhitelisted kev_listed value MUST NOT land on the HPA-watched slice"
    )
    assert OTHER_LABEL_VALUE in kev_values


# ---------------------------------------------------------------------------
# Case 5 — recorder API has no high-cardinality parameters.
# ---------------------------------------------------------------------------


def test_recorder_api_has_no_high_cardinality_parameters() -> None:
    """The HPA's source counter MUST NOT carry attacker-controlled high-
    cardinality labels (CVE id, target host, finding id). This is enforced
    structurally — the recorder ``record_finding_emitted`` only accepts the
    three contract labels, so bypassing the catalogue requires going through
    the unsanctioned ``_safe_emit_counter`` path (which is then guarded by
    the whitelist + cardinality cap, see Case 4 + the cardinality unit
    suite). This test pins the public-API parameter set as the structural
    invariant — review of any signature change to ``record_finding_emitted``
    triggers a deliberate failure here."""
    import inspect

    sig = inspect.signature(record_finding_emitted)
    params = set(sig.parameters)
    forbidden = {"cve_id", "target", "host", "finding_id", "url", "ip"}

    assert params == {"tier", "severity", "kev_listed"}, (
        f"Public recorder signature changed: {sorted(params)!r}. If you added "
        f"a label, audit cardinality + update Adapter rules + bump the unit "
        f"suite contract."
    )
    assert not (params & forbidden), (
        f"High-cardinality leak: {sorted(params & forbidden)!r} reachable "
        "via the public recorder — block via type signature, not at runtime."
    )


# ---------------------------------------------------------------------------
# Case 6 — Adapter `metricsQuery` for KEV emit-rate matches the contract.
# ---------------------------------------------------------------------------


def _helm_available() -> bool:
    """True iff the ``helm`` CLI is on PATH and resolves a version successfully."""
    helm = shutil.which("helm")
    if helm is None:
        return False
    try:
        subprocess.run(
            [helm, "version", "--short"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return True


def _render_adapter_configmap() -> dict[str, object] | None:
    """Render ``templates/prometheus-adapter-rules.yaml`` and return the parsed
    ConfigMap document. Returns ``None`` when Helm is unavailable so callers
    can skip cleanly on non-CI machines."""
    if not _helm_available():
        return None

    helm = shutil.which("helm")
    assert helm is not None  # narrowed by _helm_available()
    proc = subprocess.run(
        [
            helm,
            "template",
            "argus",
            str(HELM_CHART_DIR),
            "--show-only",
            "templates/prometheus-adapter-rules.yaml",
            "--set",
            "prometheusAdapter.enabled=true",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        # Render failure is a HARD test failure — the chart is supposed to
        # render with the documented value-set. Surface stderr so a CI log is
        # immediately actionable.
        pytest.fail(
            "helm template failed for prometheus-adapter-rules.yaml:\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return yaml.safe_load(proc.stdout)


def test_adapter_kev_metric_query_matches_documented_5m_rate_formula() -> None:
    """The Adapter rule's ``metricsQuery`` for the KEV emit-rate MUST be the
    canonical 5-minute rate. Drift means the HPA either reacts on the wrong
    window (too jumpy / too sluggish) or breaks entirely — both regressions
    that have a measurable SLO impact."""
    rendered = _render_adapter_configmap()
    if rendered is None:
        pytest.skip("helm CLI not available on this machine — render-time gate")

    data = rendered.get("data", {}) if isinstance(rendered, dict) else {}
    config_yaml_text = data.get("config.yaml") if isinstance(data, dict) else None
    assert isinstance(config_yaml_text, str), (
        "Adapter ConfigMap missing inline config.yaml (chart drift)"
    )
    config = yaml.safe_load(config_yaml_text)
    rules = config.get("externalRules") if isinstance(config, dict) else None
    assert isinstance(rules, list) and rules, "no externalRules rendered"

    kev_rule = next(
        (
            r
            for r in rules
            if isinstance(r, dict)
            and r.get("name", {}).get("as") == "argus_kev_findings_emit_rate_5m"
        ),
        None,
    )
    assert kev_rule is not None, "KEV emit-rate Adapter rule not rendered"

    metrics_query = kev_rule.get("metricsQuery")
    assert isinstance(metrics_query, str), "metricsQuery is not a string"
    # Tight contract: rate over a 5m window, summed (the Adapter's only
    # supported aggregation surface for an HPA averageValue input).
    assert "rate(" in metrics_query
    assert "[5m]" in metrics_query
    assert metrics_query.lstrip().startswith("sum("), (
        f"metricsQuery must aggregate via sum(): got {metrics_query!r}"
    )


# ---------------------------------------------------------------------------
# Case 7 — Adapter `seriesQuery` filters on the KEV slice.
# ---------------------------------------------------------------------------


def test_adapter_kev_series_query_filters_on_kev_listed_true() -> None:
    """The ``seriesQuery`` MUST pin ``kev_listed="true"`` — without that
    selector, the rate would include non-KEV findings and the HPA would
    scale on regular scan activity (a major false-positive surface)."""
    rendered = _render_adapter_configmap()
    if rendered is None:
        pytest.skip("helm CLI not available on this machine — render-time gate")

    data = rendered.get("data", {}) if isinstance(rendered, dict) else {}
    config_yaml_text = data.get("config.yaml") if isinstance(data, dict) else None
    assert isinstance(config_yaml_text, str)
    config = yaml.safe_load(config_yaml_text)
    rules = config.get("externalRules") if isinstance(config, dict) else None
    assert isinstance(rules, list) and rules

    kev_rule = next(
        (
            r
            for r in rules
            if isinstance(r, dict)
            and r.get("name", {}).get("as") == "argus_kev_findings_emit_rate_5m"
        ),
        None,
    )
    assert kev_rule is not None

    series_query = kev_rule.get("seriesQuery")
    assert isinstance(series_query, str)
    assert SOURCE_COUNTER in series_query
    assert 'kev_listed="true"' in series_query, (
        f"seriesQuery must pin kev_listed=\"true\": got {series_query!r}"
    )


# ---------------------------------------------------------------------------
# Case 8 — Grafana dashboard JSON validation (xfail until dashboards ship).
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason=(
        "C7-T06 follow-up — operator-built Grafana dashboards have not landed "
        "in infra/helm/argus/grafana/. Runbook §6.3 documents the expected "
        "panel set; a future ticket should ship the dashboard JSON and flip "
        "this gate from xfail to passing."
    ),
    strict=False,
)
def test_grafana_dashboards_reference_kev_metric_surface() -> None:
    """Validate every Grafana dashboard JSON parses AND references the KEV
    metric surface (source counter and / or the Adapter-derived rate metric).

    Strict-False xfail: the moment ANY dashboard JSON lands, this turns into
    a real assertion. If the JSON is valid + references the metrics, pytest
    reports XPASS — the operator can then flip ``strict=True`` to make CI
    enforce the dashboards stay valid forever."""
    if not GRAFANA_DASHBOARDS_DIR.exists():
        pytest.fail(
            "Expected Grafana dashboards under "
            f"{GRAFANA_DASHBOARDS_DIR.relative_to(REPO_ROOT)} — none found. "
            "See docs/operations/kev-hpa-runbook.md §6.3 for the panel spec."
        )

    dashboards = sorted(GRAFANA_DASHBOARDS_DIR.rglob("*.json"))
    assert dashboards, (
        "Grafana dashboard directory exists but is empty — ship at least one "
        "dashboard or remove the directory."
    )

    referenced_metrics = {SOURCE_COUNTER, "argus_kev_findings_emit_rate_5m"}
    matched: set[str] = set()

    for dashboard_path in dashboards:
        # Parse first — invalid JSON is a hard failure (caught by the
        # outer xfail until dashboards ship).
        try:
            content = json.loads(dashboard_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            pytest.fail(f"Invalid Grafana JSON: {dashboard_path}: {exc}")

        flattened = json.dumps(content)
        for metric in referenced_metrics:
            if metric in flattened:
                matched.add(metric)

    missing = referenced_metrics - matched
    assert not missing, (
        f"Grafana dashboards do not reference required metrics: {sorted(missing)}"
    )
