"""Unit tests for :mod:`src.payloads.integration` (ARG-005, Backlog/dev1_md §6, §7).

Verifies the contract documented at the top of
:mod:`src.payloads.integration`:

* ``PayloadDeliveryConfigMap.from_bundle`` produces a deterministic,
  DNS-1123-compatible ConfigMap name.
* ``to_manifest`` emits a v1 ConfigMap with the canonical bundle JSON,
  ``immutable: True``, and the ``argus.io/payload-family`` labels.
* ``attach_payload_bundle_to_job`` deepcopies the input, adds the
  ConfigMap volume + mount + env vars, and never embeds raw payload
  bytes in the Job manifest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.payloads.builder import (
    PayloadBuildRequest,
    PayloadBuilder,
    PayloadBundle,
)
from src.payloads.integration import (
    PayloadDeliveryConfigMap,
    PayloadIntegrationError,
    attach_payload_bundle_to_job,
    collect_payload_artifacts,
)
from src.payloads.registry import PayloadRegistry


@pytest.fixture()
def loaded_registry(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> PayloadRegistry:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    return registry


@pytest.fixture()
def bundle(loaded_registry: PayloadRegistry) -> PayloadBundle:
    builder = PayloadBuilder(loaded_registry)
    return builder.build(
        PayloadBuildRequest(
            family_id="demo_sqli",
            correlation_key="scan-1|hyp-1",
            parameters={"param": "id", "canary": "abc123"},
        )
    )


def _baseline_job_manifest() -> dict[str, Any]:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "argus-validator-1",
            "namespace": "argus-sandbox",
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
                                {"name": "ARGUS_TARGET", "value": "https://example"},
                            ],
                            "volumeMounts": [
                                {"name": "out", "mountPath": "/out"},
                            ],
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
# ConfigMap renderer
# ---------------------------------------------------------------------------


def test_from_bundle_derives_dns1123_name(bundle: PayloadBundle) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    # Must NOT contain underscores.
    assert "_" not in cm.name
    assert cm.name.startswith("argus-payloads-demo-sqli-")
    assert cm.name.endswith(bundle.manifest_hash[:12])


def test_from_bundle_requires_namespace(bundle: PayloadBundle) -> None:
    with pytest.raises(PayloadIntegrationError):
        PayloadDeliveryConfigMap.from_bundle(bundle, namespace="")


def test_from_bundle_requires_name_prefix(bundle: PayloadBundle) -> None:
    with pytest.raises(PayloadIntegrationError):
        PayloadDeliveryConfigMap.from_bundle(
            bundle, namespace="argus-sandbox", name_prefix=""
        )


def test_to_manifest_emits_v1_configmap(bundle: PayloadBundle) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    manifest = cm.to_manifest()
    assert manifest["apiVersion"] == "v1"
    assert manifest["kind"] == "ConfigMap"
    assert manifest["immutable"] is True
    assert manifest["metadata"]["namespace"] == "argus-sandbox"
    labels = manifest["metadata"]["labels"]
    assert labels["argus.io/payload-family"] == "demo_sqli"
    assert labels["argus.io/manifest-hash"] == bundle.manifest_hash[:12]
    annotations = manifest["metadata"]["annotations"]
    assert annotations["argus.io/manifest-hash-full"] == bundle.manifest_hash
    assert annotations["argus.io/encoding-pipeline"] == bundle.encoding_pipeline


def test_to_manifest_data_is_canonical_bundle_json(bundle: PayloadBundle) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    manifest = cm.to_manifest()
    bundle_json = manifest["data"]["bundle.json"]
    parsed = json.loads(bundle_json)
    assert parsed["family_id"] == "demo_sqli"
    assert parsed["manifest_hash"] == bundle.manifest_hash
    assert len(parsed["payloads"]) == len(bundle.payloads)


# ---------------------------------------------------------------------------
# Job manifest mutator
# ---------------------------------------------------------------------------


def test_attach_payload_bundle_does_not_mutate_input(bundle: PayloadBundle) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    original = _baseline_job_manifest()
    snapshot = json.dumps(original, sort_keys=True)
    out = attach_payload_bundle_to_job(original, cm)
    # Input must be untouched.
    assert json.dumps(original, sort_keys=True) == snapshot
    # Output must be a different dict.
    assert out is not original


def test_attach_payload_bundle_adds_volume_and_mount(bundle: PayloadBundle) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    out = attach_payload_bundle_to_job(_baseline_job_manifest(), cm)
    pod_spec = out["spec"]["template"]["spec"]
    volume_names = [v["name"] for v in pod_spec["volumes"]]
    assert "argus-payloads" in volume_names
    payload_vol = next(v for v in pod_spec["volumes"] if v["name"] == "argus-payloads")
    assert payload_vol["configMap"]["name"] == cm.name
    assert payload_vol["configMap"]["defaultMode"] == 0o444  # read-only

    container = pod_spec["containers"][0]
    mount_names = [m["name"] for m in container["volumeMounts"]]
    assert "argus-payloads" in mount_names
    payload_mount = next(
        m for m in container["volumeMounts"] if m["name"] == "argus-payloads"
    )
    assert payload_mount["mountPath"] == "/in/payloads"
    assert payload_mount["readOnly"] is True


def test_attach_payload_bundle_sets_env_vars(bundle: PayloadBundle) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    out = attach_payload_bundle_to_job(_baseline_job_manifest(), cm)
    container = out["spec"]["template"]["spec"]["containers"][0]
    env_map = {e["name"]: e["value"] for e in container["env"]}
    assert env_map["ARGUS_PAYLOAD_BUNDLE"] == "/in/payloads/bundle.json"
    assert env_map["ARGUS_PAYLOAD_FAMILY"] == "demo_sqli"
    assert env_map["ARGUS_PAYLOAD_MANIFEST_HASH"] == bundle.manifest_hash


def test_attach_payload_bundle_no_raw_payload_bytes_anywhere(
    bundle: PayloadBundle,
) -> None:
    """Critical security guarantee: raw payload bytes never enter the Job manifest."""
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    out = attach_payload_bundle_to_job(_baseline_job_manifest(), cm)
    serialised = json.dumps(out, sort_keys=True)
    for rendered in bundle.payloads:
        assert rendered.payload not in serialised, (
            f"raw payload {rendered.id!r} leaked into Job manifest"
        )


def test_attach_payload_bundle_writes_pod_and_job_labels(
    bundle: PayloadBundle,
) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    out = attach_payload_bundle_to_job(_baseline_job_manifest(), cm)
    job_labels = out["metadata"]["labels"]
    pod_labels = out["spec"]["template"]["metadata"]["labels"]
    # family_id is normalised — underscores become dashes.
    assert job_labels["argus.io/payload-family"] == "demo-sqli"
    assert pod_labels["argus.io/payload-family"] == "demo-sqli"
    assert job_labels["argus.io/payload-manifest-hash"] == bundle.manifest_hash[:12]
    assert pod_labels["argus.io/payload-manifest-hash"] == bundle.manifest_hash[:12]


def test_attach_payload_bundle_rejects_missing_pod_spec(
    bundle: PayloadBundle,
) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    bad: dict[str, Any] = {"apiVersion": "batch/v1", "kind": "Job", "spec": {}}
    with pytest.raises(PayloadIntegrationError):
        attach_payload_bundle_to_job(bad, cm)


def test_attach_payload_bundle_rejects_no_containers(
    bundle: PayloadBundle,
) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    bad: dict[str, Any] = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "spec": {"template": {"spec": {"containers": []}}},
    }
    with pytest.raises(PayloadIntegrationError):
        attach_payload_bundle_to_job(bad, cm)


def test_attach_payload_bundle_rejects_volume_collision(
    bundle: PayloadBundle,
) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    manifest = _baseline_job_manifest()
    manifest["spec"]["template"]["spec"]["volumes"].append(
        {"name": "argus-payloads", "emptyDir": {}}
    )
    with pytest.raises(PayloadIntegrationError, match="already present"):
        attach_payload_bundle_to_job(manifest, cm)


def test_attach_payload_bundle_rejects_non_dict_input(
    bundle: PayloadBundle,
) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    with pytest.raises(PayloadIntegrationError):
        attach_payload_bundle_to_job([], cm)  # type: ignore[arg-type]


def test_attach_payload_bundle_rejects_non_configmap(
    bundle: PayloadBundle,
) -> None:
    with pytest.raises(PayloadIntegrationError):
        attach_payload_bundle_to_job(_baseline_job_manifest(), object())  # type: ignore[arg-type]


def test_collect_payload_artifacts_returns_indented_json(
    bundle: PayloadBundle,
) -> None:
    cm = PayloadDeliveryConfigMap.from_bundle(bundle, namespace="argus-sandbox")
    artifacts = collect_payload_artifacts(bundle, cm)
    assert set(artifacts) == {cm.name}
    parsed = json.loads(artifacts[cm.name])
    assert parsed["family_id"] == "demo_sqli"
