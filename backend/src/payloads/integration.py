"""Sandbox integration for ARGUS payload bundles (Backlog/dev1_md §6, §7).

Bridges the :class:`~src.payloads.builder.PayloadBundle` produced by the
builder and the Kubernetes Job manifest produced by
:class:`~src.sandbox.k8s_adapter.KubernetesSandboxAdapter`.

Two responsibilities, deliberately small:

* :class:`PayloadDeliveryConfigMap` — pure renderer that turns a bundle
  into a versioned ConfigMap manifest. The ConfigMap contains exactly one
  data file: ``bundle.json`` carrying the canonical payload list. Tools
  read the bundle from ``/in/payloads/bundle.json`` inside the sandbox.

* :func:`attach_payload_bundle_to_job` — pure post-processor that mutates
  a *fresh* copy of the Job manifest dict to:
  - mount the ConfigMap at ``/in/payloads`` (read-only, immutable);
  - inject ``ARGUS_PAYLOAD_BUNDLE`` env vars pointing at the bundle path
    + manifest hash;
  - add a ``argus.io/payload-family`` label / annotation so dashboards
    and audit pipelines can correlate the run with the family.

The function never embeds raw payloads in env / args / annotations — only
pointers to the ConfigMap and the bundle's manifest hash. This is the
guarantee "no raw payloads in Job manifests" verified by the integration
test under ``backend/tests/integration/payloads/``.

This module does NOT touch the cluster — it returns dicts. The caller
(orchestrator / cluster runner) is responsible for ``kubectl apply``.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.payloads.builder import PayloadBundle


_PAYLOAD_MOUNT_PATH: Final[str] = "/in/payloads"
_PAYLOAD_BUNDLE_FILENAME: Final[str] = "bundle.json"
_PAYLOAD_VOLUME_NAME: Final[str] = "argus-payloads"
_CONFIGMAP_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?$"
)
_LABEL_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9._-]{0,63}$")


class PayloadIntegrationError(ValueError):
    """Raised when bundle-to-manifest integration is invoked with bad input."""


# ---------------------------------------------------------------------------
# ConfigMap renderer
# ---------------------------------------------------------------------------


class PayloadDeliveryConfigMap(BaseModel):
    """Versioned ConfigMap descriptor for a :class:`PayloadBundle`.

    The ConfigMap name is derived from ``family_id`` + ``manifest_hash[:12]``
    so concurrent runs of the same family with different bundles never
    collide in a shared namespace. It is marked **immutable** so a
    misconfigured controller cannot silently swap the payload bytes
    underneath a running Job.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=253)
    namespace: StrictStr = Field(min_length=1, max_length=63)
    bundle: PayloadBundle

    @classmethod
    def from_bundle(
        cls,
        bundle: PayloadBundle,
        *,
        namespace: str,
        name_prefix: str = "argus-payloads",
    ) -> "PayloadDeliveryConfigMap":
        """Build the ConfigMap descriptor for ``bundle`` in ``namespace``.

        ``name_prefix`` defaults to ``argus-payloads``; the final name is
        ``<prefix>-<family_id>-<manifest_hash[:12]>`` truncated to 253
        chars. Family ids are snake_case (``[a-z_][a-z0-9_]{2,32}``) but
        Kubernetes object names disallow underscores, so they are mapped
        to dashes here.
        """
        if not namespace:
            raise PayloadIntegrationError("namespace must be a non-empty string")
        if not name_prefix:
            raise PayloadIntegrationError("name_prefix must be a non-empty string")
        family_dns = bundle.family_id.replace("_", "-")
        suffix = bundle.manifest_hash[:12]
        candidate = f"{name_prefix}-{family_dns}-{suffix}"[:253]
        if not _CONFIGMAP_NAME_RE.fullmatch(candidate):
            raise PayloadIntegrationError(
                f"derived ConfigMap name {candidate!r} is not DNS-1123 compatible"
            )
        return cls(name=candidate, namespace=namespace, bundle=bundle)

    def to_manifest(self) -> dict[str, Any]:
        """Render the ConfigMap as a v1 Kubernetes manifest dict.

        ``data`` carries one key (``bundle.json``); the value is the
        canonical, sort_keys-stable JSON serialisation of the bundle.
        ``immutable: True`` forbids in-place mutation by any operator,
        matching the security guarantees we make to the validator.
        """
        bundle_payload = json.dumps(
            self.bundle.to_serialisable(),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/name": "argus-sandbox",
                    "app.kubernetes.io/component": "payload-bundle",
                    "argus.io/payload-family": self.bundle.family_id,
                    "argus.io/manifest-hash": self.bundle.manifest_hash[:12],
                },
                "annotations": {
                    "argus.io/manifest-hash-full": self.bundle.manifest_hash,
                    "argus.io/correlation-key": _truncate_annotation(
                        self.bundle.correlation_key
                    ),
                    "argus.io/encoding-pipeline": self.bundle.encoding_pipeline,
                    "argus.io/oast-required": str(self.bundle.oast_required).lower(),
                },
            },
            "data": {_PAYLOAD_BUNDLE_FILENAME: bundle_payload},
            "immutable": True,
        }


# ---------------------------------------------------------------------------
# Job manifest mutator
# ---------------------------------------------------------------------------


def attach_payload_bundle_to_job(
    job_manifest: dict[str, Any],
    configmap: PayloadDeliveryConfigMap,
) -> dict[str, Any]:
    """Return a *new* Job manifest that mounts ``configmap`` at ``/in/payloads``.

    The original ``job_manifest`` is not mutated. The returned manifest
    differs only in:

    * ``spec.template.spec.volumes`` gains a new ``configMap`` volume.
    * Every container under ``spec.template.spec.containers`` gains a
      read-only ``volumeMount`` at ``/in/payloads`` and two extra env
      vars pointing at the bundle path + manifest hash.
    * ``metadata.labels`` and ``spec.template.metadata.labels`` gain
      ``argus.io/payload-family`` and ``argus.io/payload-manifest-hash``.

    Raises :class:`PayloadIntegrationError` for malformed inputs (missing
    spec.template.spec, conflicting volume names, wrong types).
    """
    if not isinstance(job_manifest, dict):
        raise PayloadIntegrationError("job_manifest must be a dict")
    if not isinstance(configmap, PayloadDeliveryConfigMap):
        raise PayloadIntegrationError("configmap must be a PayloadDeliveryConfigMap")

    out: dict[str, Any] = copy.deepcopy(job_manifest)
    spec = _require_dict(out, "spec")
    template = _require_dict(spec, "template")
    pod_spec = _require_dict(template, "spec")
    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or not containers:
        raise PayloadIntegrationError(
            "job_manifest.spec.template.spec.containers must be a non-empty list"
        )

    volumes_raw = pod_spec.get("volumes", [])
    if not isinstance(volumes_raw, list):
        raise PayloadIntegrationError(
            "job_manifest.spec.template.spec.volumes must be a list (or absent)"
        )
    volumes: list[dict[str, Any]] = list(volumes_raw)
    for vol in volumes:
        if isinstance(vol, dict) and vol.get("name") == _PAYLOAD_VOLUME_NAME:
            raise PayloadIntegrationError(
                f"volume name {_PAYLOAD_VOLUME_NAME!r} is already present"
            )
    volumes.append(
        {
            "name": _PAYLOAD_VOLUME_NAME,
            "configMap": {
                "name": configmap.name,
                "defaultMode": 0o444,
                "items": [
                    {
                        "key": _PAYLOAD_BUNDLE_FILENAME,
                        "path": _PAYLOAD_BUNDLE_FILENAME,
                    }
                ],
            },
        }
    )
    pod_spec["volumes"] = volumes

    for container in containers:
        if not isinstance(container, dict):
            raise PayloadIntegrationError(
                "job_manifest.spec.template.spec.containers entries must be dicts"
            )
        mounts_raw = container.get("volumeMounts", [])
        if not isinstance(mounts_raw, list):
            raise PayloadIntegrationError(
                "container.volumeMounts must be a list (or absent)"
            )
        mounts = list(mounts_raw)
        for mount in mounts:
            if isinstance(mount, dict) and mount.get("name") == _PAYLOAD_VOLUME_NAME:
                raise PayloadIntegrationError(
                    f"volumeMount {_PAYLOAD_VOLUME_NAME!r} already exists on container"
                )
        mounts.append(
            {
                "name": _PAYLOAD_VOLUME_NAME,
                "mountPath": _PAYLOAD_MOUNT_PATH,
                "readOnly": True,
            }
        )
        container["volumeMounts"] = mounts

        env_raw = container.get("env", [])
        if not isinstance(env_raw, list):
            raise PayloadIntegrationError("container.env must be a list (or absent)")
        env = list(env_raw)
        env.extend(
            [
                {
                    "name": "ARGUS_PAYLOAD_BUNDLE",
                    "value": f"{_PAYLOAD_MOUNT_PATH}/{_PAYLOAD_BUNDLE_FILENAME}",
                },
                {
                    "name": "ARGUS_PAYLOAD_FAMILY",
                    "value": configmap.bundle.family_id,
                },
                {
                    "name": "ARGUS_PAYLOAD_MANIFEST_HASH",
                    "value": configmap.bundle.manifest_hash,
                },
            ]
        )
        container["env"] = env

    metadata = out.get("metadata")
    if isinstance(metadata, dict):
        labels = metadata.setdefault("labels", {})
        if isinstance(labels, dict):
            labels["argus.io/payload-family"] = _safe_label(configmap.bundle.family_id)
            labels["argus.io/payload-manifest-hash"] = configmap.bundle.manifest_hash[
                :12
            ]
    pod_meta = template.get("metadata")
    if isinstance(pod_meta, dict):
        pod_labels = pod_meta.setdefault("labels", {})
        if isinstance(pod_labels, dict):
            pod_labels["argus.io/payload-family"] = _safe_label(
                configmap.bundle.family_id
            )
            pod_labels["argus.io/payload-manifest-hash"] = (
                configmap.bundle.manifest_hash[:12]
            )

    return out


def collect_payload_artifacts(
    bundle: PayloadBundle,
    configmap: PayloadDeliveryConfigMap,
) -> dict[str, str]:
    """Return a map of ``configmap_name -> bundle.json contents`` for export.

    Useful for dry-run artifact inspection: callers can pickle the rendered
    manifests next to ``bundle.json`` so the operator sees both layers
    side-by-side.
    """
    return {
        configmap.name: json.dumps(
            bundle.to_serialisable(),
            sort_keys=True,
            ensure_ascii=False,
            indent=2,
        )
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise PayloadIntegrationError(
            f"job_manifest is missing required dict at {key!r}"
        )
    return value


def _safe_label(value: str) -> str:
    """Return a value safe for a Kubernetes label (DNS-1123 friendly)."""
    candidate = value.replace("_", "-")[:63]
    if not _LABEL_VALUE_RE.fullmatch(candidate):
        return "invalid"
    return candidate


def _truncate_annotation(value: str, *, limit: int = 256) -> str:
    """Annotations have a 256 KiB total budget; we keep individual values short."""
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


__all__ = [
    "PayloadDeliveryConfigMap",
    "PayloadIntegrationError",
    "attach_payload_bundle_to_job",
    "collect_payload_artifacts",
]
