"""B6-T04 (T50 + T51) — KEV-aware HPA kind-cluster integration test.

Validates the full external-metric path:

    pushgateway  →  Prometheus  →  Prometheus Adapter  →
        external.metrics.k8s.io/v1beta1  →  HPA  →  Deployment scale

The CI workflow ``.github/workflows/kev-hpa-kind.yml`` provisions:

* a ``kind`` cluster (Kubernetes ≥1.31),
* the ``prometheus-community/prometheus`` chart (single Pod, scrapes
  pushgateway every 5s),
* the ``prometheus-community/prometheus-pushgateway`` chart (entry point
  for the synthetic KEV burst this test pushes),
* the ``prometheus-community/prometheus-adapter`` chart configured with
  the same external-rules our chart's
  ``templates/prometheus-adapter-rules.yaml`` ConfigMap encodes
  (``argus_kev_findings_emit_rate_5m`` + ``argus_celery_queue_depth``),
* a placeholder ``argus-celery`` Deployment (``registry.k8s.io/pause``
  image — keeps the cluster lean; the HPA only ever inspects
  ``spec.replicas``, never the running pods),
* the ``argus`` chart rendered with ``prometheusAdapter.enabled=true``
  and ``autoscaling.kevAware.enabled=true`` so
  ``templates/hpa-celery-worker-kev.yaml`` lands as
  ``argus-celery-kev``.

Test flow:

1. **Sanity** — assert the HPA is present, healthy, and reports
   ``status.currentReplicas == minReplicas`` (2).
2. **Burst** — push a sustained KEV-finding rate to the pushgateway and
   poll the HPA up to 60s, asserting ``status.desiredReplicas`` rises to
   ``≥4`` (per acceptance criterion (d) in the plan).
3. **Decay** — drop the metric to zero, wait the configured
   ``stabilizationWindowSeconds + 30s`` buffer, and assert the HPA
   collapses back to ``minReplicas`` (2).

The test never raises a stack trace at the user; every failure path
emits a captured ``kubectl describe hpa`` block + the latest
``status.conditions`` so the CI artifact upload contains forensics.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Final

import pytest

from .conftest import skip_if_no_kind

pytestmark = skip_if_no_kind

# ---------------------------------------------------------------------------
# Constants — overridable via environment so the CI workflow can pin them
# to the exact namespaces / service names it provisions.
# ---------------------------------------------------------------------------

NAMESPACE: Final[str] = os.environ.get("ARGUS_KIND_NAMESPACE", "argus-test")
HPA_NAME: Final[str] = os.environ.get(
    "ARGUS_KIND_HPA_NAME", "argus-celery-kev"
)
PUSHGATEWAY_SERVICE: Final[str] = os.environ.get(
    "ARGUS_KIND_PUSHGATEWAY_SERVICE", "prometheus-pushgateway.monitoring"
)
PUSHGATEWAY_PORT: Final[int] = int(
    os.environ.get("ARGUS_KIND_PUSHGATEWAY_PORT", "9091")
)

MIN_REPLICAS: Final[int] = 2
SCALE_UP_TARGET_REPLICAS: Final[int] = 4

# Tuned to match `templates/hpa-celery-worker-kev.yaml` behavior.scaleDown.
# Test-side override via env keeps the CI lane snappy if needed.
STABILIZATION_WINDOW_SECONDS: Final[int] = int(
    os.environ.get("ARGUS_KIND_STABILIZATION_WINDOW_SECONDS", "300")
)

# Deadlines (seconds). Generous on scale-up because the adapter scrape
# window + Prometheus rate evaluation adds latency on top of the HPA
# control-loop tick.
SCALE_UP_DEADLINE_SECONDS: Final[int] = int(
    os.environ.get("ARGUS_KIND_SCALE_UP_DEADLINE_SECONDS", "60")
)
POLL_INTERVAL_SECONDS: Final[float] = float(
    os.environ.get("ARGUS_KIND_POLL_INTERVAL_SECONDS", "3.0")
)

# Synthetic burst — 50 KEV findings injected at the pushgateway, then held.
# The adapter's PromQL rule is `sum(rate(argus_findings_emitted_total[5m]))`
# so we need a sample > the 5m window's denominator threshold to clear the
# `kevEmitRateTarget=1` HPA bound (50 / 300s ≈ 0.17/s — still below 1/s,
# so we set a deliberately high counter value to exceed the per-replica
# target as the rate is computed against the previous scrape).
KEV_BURST_COUNTER_VALUE: Final[int] = int(
    os.environ.get("ARGUS_KIND_KEV_BURST_COUNTER", "50000")
)
KEV_DECAY_COUNTER_VALUE: Final[int] = 0


# ---------------------------------------------------------------------------
# Subprocess helpers — every shell-out is centralised here so a single
# `KubectlError` surface drives the user-visible failure message.
# ---------------------------------------------------------------------------


class KubectlError(RuntimeError):
    """Raised when a kubectl command fails. Carries the captured logs."""


def _run(
    cmd: list[str],
    *,
    timeout: int = 30,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run *cmd* and return the completed process; raise KubectlError on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            input=input_text,
        )
    except FileNotFoundError as exc:
        raise KubectlError(
            f"binary not found on PATH: {cmd[0]} (set up by helm/kind-action in CI)"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise KubectlError(
            f"command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc

    if check and result.returncode != 0:
        raise KubectlError(
            f"command failed (rc={result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _kubectl_json(*args: str, namespace: str | None = NAMESPACE) -> dict:
    """Run ``kubectl <args> -o json`` and return the parsed JSON body."""
    cmd: list[str] = ["kubectl"]
    if namespace is not None:
        cmd += ["-n", namespace]
    cmd += [*args, "-o", "json"]
    result = _run(cmd)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise KubectlError(
            f"non-JSON stdout from kubectl: {result.stdout!r}"
        ) from exc


def _hpa_status() -> dict:
    """Return the parsed `.status` block of the KEV-aware HPA."""
    return _kubectl_json("get", "hpa", HPA_NAME).get("status", {})


def _hpa_desired_replicas() -> int:
    """Return ``status.desiredReplicas`` (or 0 when not yet populated)."""
    status = _hpa_status()
    return int(status.get("desiredReplicas", 0))


def _hpa_current_replicas() -> int:
    """Return ``status.currentReplicas`` (or 0 when not yet populated)."""
    status = _hpa_status()
    return int(status.get("currentReplicas", 0))


def _capture_diagnostics(reason: str) -> str:
    """Return a multi-line forensic dump pinned to the failure point.

    Used to enrich assertion messages so the CI artifact upload step has
    something concrete to attach. Never raises — diagnostic gathering must
    not mask the actual test failure.
    """
    chunks: list[str] = [f"=== diagnostics: {reason} ==="]
    for tail in (
        ["describe", "hpa", HPA_NAME],
        ["get", "hpa", HPA_NAME, "-o", "yaml"],
        ["get", "deploy", "argus-celery", "-o", "yaml"],
        ["get", "events", "--sort-by=.lastTimestamp"],
    ):
        try:
            res = _run(["kubectl", "-n", NAMESPACE, *tail], check=False, timeout=20)
            chunks.append(f"--- kubectl {' '.join(tail)} ---\n{res.stdout}\n{res.stderr}")
        except KubectlError as exc:
            chunks.append(f"--- kubectl {' '.join(tail)} failed: {exc} ---")
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Pushgateway interaction — uses an in-cluster ephemeral pod so we do not
# need a port-forward (port-forward in a pytest process is fragile across
# Linux/Windows runners).
# ---------------------------------------------------------------------------


_PUSH_POD_NAME: Final[str] = "kev-pushgateway-injector"


def _push_metric(value: int) -> None:
    """Push ``argus_findings_emitted_total{kev_listed="true"}`` = *value*.

    Uses ``kubectl run --rm`` against a curl image so the test process
    does not need network access to the pushgateway — kubectl streams the
    HTTP POST through the cluster's pod network.
    """
    pushgateway_url = (
        f"http://{PUSHGATEWAY_SERVICE}.svc.cluster.local:{PUSHGATEWAY_PORT}"
        f"/metrics/job/kev_burst_test"
    )
    payload = (
        "# TYPE argus_findings_emitted_total counter\n"
        f'argus_findings_emitted_total{{tier="midgard",severity="critical",'
        f'kev_listed="true",namespace="{NAMESPACE}"}} {value}\n'
    )
    _run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "run",
            _PUSH_POD_NAME,
            "--rm",
            "--restart=Never",
            "--image=curlimages/curl:8.11.0",
            "--quiet",
            "--",
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
            "-X",
            "POST",
            "--data-binary",
            payload,
            pushgateway_url,
        ],
        timeout=60,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_hpa_present_and_healthy() -> None:
    """Sanity gate — the chart-rendered HPA must be live before we start."""
    try:
        body = _kubectl_json("get", "hpa", HPA_NAME)
    except KubectlError as exc:
        pytest.fail(f"KEV-aware HPA {HPA_NAME!r} not found in namespace {NAMESPACE!r}: {exc}")

    spec = body.get("spec", {})
    assert int(spec.get("minReplicas", 0)) == MIN_REPLICAS, (
        f"HPA spec.minReplicas = {spec.get('minReplicas')!r}, expected {MIN_REPLICAS}"
    )
    assert int(spec.get("maxReplicas", 0)) >= SCALE_UP_TARGET_REPLICAS, (
        "HPA spec.maxReplicas must allow the scale-up assertion's target "
        f"({SCALE_UP_TARGET_REPLICAS}); got {spec.get('maxReplicas')!r}"
    )
    metrics = spec.get("metrics") or []
    metric_names = {
        m.get("external", {}).get("metric", {}).get("name")
        for m in metrics
        if m.get("type") == "External"
    }
    assert "argus_kev_findings_emit_rate_5m" in metric_names, (
        f"HPA missing argus_kev_findings_emit_rate_5m external metric; got {metric_names}"
    )
    assert "argus_celery_queue_depth" in metric_names, (
        f"HPA missing argus_celery_queue_depth external metric; got {metric_names}"
    )


def test_kev_burst_triggers_scale_up() -> None:
    """Push a KEV burst and assert the HPA scales above ``MIN_REPLICAS``."""
    initial = _hpa_current_replicas() or MIN_REPLICAS
    assert initial <= MIN_REPLICAS + 1, (
        f"Test pre-condition: currentReplicas should start near {MIN_REPLICAS}; got {initial}\n"
        + _capture_diagnostics("pre-burst replica drift")
    )

    _push_metric(KEV_BURST_COUNTER_VALUE)
    deadline = time.monotonic() + SCALE_UP_DEADLINE_SECONDS
    last_seen = initial
    while time.monotonic() < deadline:
        try:
            last_seen = _hpa_desired_replicas()
        except KubectlError:
            last_seen = 0
        if last_seen >= SCALE_UP_TARGET_REPLICAS:
            return
        # Re-push periodically so pushgateway's TTL'd sample stays fresh
        # if Prometheus has already scraped + dropped the previous value.
        _push_metric(KEV_BURST_COUNTER_VALUE)
        time.sleep(POLL_INTERVAL_SECONDS)

    diagnostics = _capture_diagnostics(
        f"scale-up deadline reached; last desiredReplicas={last_seen}"
    )
    pytest.fail(
        f"KEV burst failed to trigger HPA scale-up to >={SCALE_UP_TARGET_REPLICAS} "
        f"within {SCALE_UP_DEADLINE_SECONDS}s (last_seen={last_seen}, initial={initial})\n"
        + diagnostics
    )


def test_kev_decay_returns_to_min_replicas() -> None:
    """After draining the burst, the HPA must collapse back to ``MIN_REPLICAS``.

    Order matters — this test depends on the burst test having pushed the
    HPA above ``MIN_REPLICAS``. We rely on pytest's in-file ordering
    (top-down) which is the documented default, so no explicit dependency
    declaration is needed.
    """
    _push_metric(KEV_DECAY_COUNTER_VALUE)
    deadline_buffer_seconds: Final[int] = 30
    decay_deadline = time.monotonic() + STABILIZATION_WINDOW_SECONDS + deadline_buffer_seconds

    last_seen = _hpa_desired_replicas()
    while time.monotonic() < decay_deadline:
        try:
            last_seen = _hpa_desired_replicas()
        except KubectlError:
            last_seen = -1
        if 0 < last_seen <= MIN_REPLICAS:
            return
        time.sleep(POLL_INTERVAL_SECONDS * 2)

    diagnostics = _capture_diagnostics(
        f"scale-down deadline reached; last desiredReplicas={last_seen}"
    )
    pytest.fail(
        f"HPA failed to scale back to {MIN_REPLICAS} after KEV decay within "
        f"stabilizationWindow ({STABILIZATION_WINDOW_SECONDS}s) + "
        f"{deadline_buffer_seconds}s buffer (last_seen={last_seen})\n"
        + diagnostics
    )


# ---------------------------------------------------------------------------
# Module shutdown — best-effort cleanup so re-runs in the same cluster
# are idempotent. Cleanup never fails the suite.
# ---------------------------------------------------------------------------


def teardown_module(module: object) -> None:  # noqa: ARG001 — pytest hook signature
    """Drop the pushgateway job-bucket so the next run starts from zero."""
    if not shutil.which("kubectl"):
        return
    pushgateway_url = (
        f"http://{PUSHGATEWAY_SERVICE}.svc.cluster.local:{PUSHGATEWAY_PORT}"
        f"/metrics/job/kev_burst_test"
    )
    try:
        _run(
            [
                "kubectl",
                "-n",
                NAMESPACE,
                "run",
                f"{_PUSH_POD_NAME}-cleanup",
                "--rm",
                "--restart=Never",
                "--image=curlimages/curl:8.11.0",
                "--quiet",
                "--",
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-X",
                "DELETE",
                pushgateway_url,
            ],
            timeout=30,
            check=False,
        )
    except KubectlError:
        # Cleanup must never raise; the cluster is torn down by CI anyway.
        return
