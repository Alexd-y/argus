"""End-to-end integration test: signed catalog → builder → ConfigMap → Job.

Wires the four ARG-005 layers together against the real production catalog:

1. :class:`PayloadRegistry` loads ``backend/config/payloads/`` (signed).
2. :class:`PayloadBuilder` materialises a :class:`PayloadBundle`.
3. :class:`PayloadDeliveryConfigMap.from_bundle` builds a v1 ConfigMap manifest.
4. :func:`attach_payload_bundle_to_job` mounts that ConfigMap on a fake Job.

Asserts the security guarantee: NO raw payload byte ever appears in the
Job manifest — only the ConfigMap reference and the bundle's manifest hash.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import pytest

from src.payloads.builder import (
    PayloadBuildRequest,
    PayloadBuilder,
)
from src.payloads.integration import (
    PayloadDeliveryConfigMap,
    attach_payload_bundle_to_job,
)
from src.payloads.registry import PayloadRegistry


_NAMESPACE: Final[str] = "argus-sandbox"


@pytest.fixture(scope="module")
def loaded_registry() -> PayloadRegistry:
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "payloads"
    registry = PayloadRegistry(payloads_dir=catalog)
    registry.load()
    return registry


@pytest.fixture()
def builder(loaded_registry: PayloadRegistry) -> PayloadBuilder:
    return PayloadBuilder(loaded_registry)


def _baseline_job_manifest(name: str = "argus-validator-1") -> dict[str, Any]:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": _NAMESPACE,
            "labels": {"app.kubernetes.io/name": "argus-validator"},
        },
        "spec": {
            "template": {
                "metadata": {
                    "labels": {"app.kubernetes.io/name": "argus-validator"},
                },
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "validator",
                            "image": "argus/validator:1.0.0",
                            "env": [
                                {"name": "ARGUS_TARGET", "value": "https://example"}
                            ],
                            "volumeMounts": [{"name": "out", "mountPath": "/out"}],
                        }
                    ],
                    "volumes": [
                        {"name": "out", "emptyDir": {}},
                    ],
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# End-to-end happy path on the real catalog
# ---------------------------------------------------------------------------


def test_real_catalog_sqli_to_job_manifest(builder: PayloadBuilder) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="sqli",
            correlation_key="scan-int-1|hyp-1",
            parameters={
                "param": "id",
                "canary": "argus-canary-001",
            },
        )
    )
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace=_NAMESPACE)
    cm_manifest = cm.to_manifest()
    job = attach_payload_bundle_to_job(_baseline_job_manifest(), cm)

    # ConfigMap-level checks.
    assert cm_manifest["kind"] == "ConfigMap"
    assert cm_manifest["immutable"] is True
    assert cm_manifest["metadata"]["labels"]["argus.io/payload-family"] == "sqli"
    assert "bundle.json" in cm_manifest["data"]

    # Job-level checks: volume + mount + env vars.
    pod_spec = job["spec"]["template"]["spec"]
    assert any(v["name"] == "argus-payloads" for v in pod_spec["volumes"])
    container = pod_spec["containers"][0]
    env_map = {e["name"]: e["value"] for e in container["env"]}
    assert env_map["ARGUS_PAYLOAD_BUNDLE"] == "/in/payloads/bundle.json"
    assert env_map["ARGUS_PAYLOAD_FAMILY"] == "sqli"
    assert env_map["ARGUS_PAYLOAD_MANIFEST_HASH"] == bundle.manifest_hash


def test_real_catalog_high_risk_family_requires_approval(
    builder: PayloadBuilder,
) -> None:
    """The four high-risk families MUST trip the approval gate."""
    from src.payloads.builder import PayloadApprovalRequiredError

    with pytest.raises(PayloadApprovalRequiredError):
        builder.build(
            PayloadBuildRequest(
                family_id="rce",
                correlation_key="scan-int-2",
                parameters={
                    "param": "id",
                    "canary": "argus-canary-002",
                    "oast_host": "oast.example.com",
                },
            )
        )


def test_real_catalog_high_risk_family_with_approval_succeeds(
    builder: PayloadBuilder,
) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="rce",
            correlation_key="scan-int-3",
            parameters={
                "param": "id",
                "canary": "argus-canary-003",
                "oast_host": "oast.example.com",
            },
            approval_id="op-12345",
        )
    )
    assert bundle.requires_approval is True
    assert bundle.approval_id == "op-12345"
    assert len(bundle.payloads) >= 3


# ---------------------------------------------------------------------------
# Security invariants on the real-catalog Job manifest
# ---------------------------------------------------------------------------


def test_no_raw_payload_bytes_in_job_manifest(builder: PayloadBuilder) -> None:
    """Critical security check: the assembled Job manifest never embeds a raw payload."""
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="xss",
            correlation_key="scan-int-4",
            parameters={
                "param": "name",
                "canary": "argus-canary-004",
                "oast_host": "oast.example.com",
            },
        )
    )
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace=_NAMESPACE)
    job = attach_payload_bundle_to_job(_baseline_job_manifest(), cm)
    job_serialised = json.dumps(job, sort_keys=True)

    # CRITICAL: no rendered payload string may appear anywhere in the Job manifest.
    for rendered in bundle.payloads:
        if len(rendered.payload) >= 4:  # very-short payloads (e.g. "*") are noisy
            assert rendered.payload not in job_serialised, (
                f"raw payload {rendered.id!r} leaked into Job manifest"
            )
    # The Job MUST instead carry the manifest hash (pointer-only delivery).
    assert bundle.manifest_hash in job_serialised


def test_configmap_name_is_dns_compatible(builder: PayloadBuilder) -> None:
    """Family ids contain underscores; ConfigMap names must not."""
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="auth_bypass",
            correlation_key="scan-int-5",
            parameters={
                "param": "id",
                "canary": "argus-canary-005",
                "oast_host": "oast.example.com",
            },
        )
    )
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace=_NAMESPACE)
    assert "_" not in cm.name
    assert cm.name.startswith("argus-payloads-auth-bypass-")


def test_bundle_is_deterministic_for_same_correlation_key(
    builder: PayloadBuilder,
) -> None:
    base = PayloadBuildRequest(
        family_id="ssrf",
        correlation_key="scan-int-6|hyp-deterministic",
        parameters={
            "param": "url",
            "canary": "argus-canary-006",
            "oast_host": "oast.example.com",
        },
    )
    a = builder.build(base)
    b = builder.build(base)
    assert a.manifest_hash == b.manifest_hash
    assert [p.payload for p in a.payloads] == [p.payload for p in b.payloads]


def test_attach_payload_bundle_does_not_mutate_input_in_real_pipeline(
    builder: PayloadBuilder,
) -> None:
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="path_traversal",
            correlation_key="scan-int-7",
            parameters={
                "param": "file",
                "canary": "argus-canary-007",
            },
        )
    )
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace=_NAMESPACE)
    original = _baseline_job_manifest()
    snapshot = json.dumps(original, sort_keys=True)
    out = attach_payload_bundle_to_job(original, cm)
    assert json.dumps(original, sort_keys=True) == snapshot
    assert out is not original
