"""Public surface of the ARGUS payload subsystem (Backlog/dev1_md §6, §7).

This package owns:

* ``PayloadFamily``, ``PayloadEntry``, ``MutationRule``, ``EncodingPipeline``
  — strict Pydantic descriptors for the signed YAML catalog.
* ``PayloadRegistry`` — fail-closed loader that mirrors
  :class:`src.sandbox.tool_registry.ToolRegistry` for payload families.
* ``PayloadBuilder`` + ``PayloadBundle`` / ``RenderedPayload`` — the
  deterministic materialiser that turns a signed family + parameter map
  into a payload bundle ready for sandbox delivery.
* Pure encoder / mutation helpers (no I/O, no shell, no subprocess).
* ``PayloadDeliveryConfigMap`` and ``attach_payload_bundle_to_job`` —
  the bridge to the Kubernetes sandbox layer; payloads are delivered via
  an immutable ConfigMap mounted at ``/in/payloads`` and never embedded
  in Job env / args.

Importing from sub-modules is also fine; this re-export exists so the rest
of the codebase can write ``from src.payloads import PayloadBuilder`` like
it does for ``src.sandbox``.
"""

from __future__ import annotations

from src.payloads.builder import (
    PayloadApprovalRequiredError,
    PayloadBuildError,
    PayloadBuildRequest,
    PayloadBuilder,
    PayloadBundle,
    RenderedPayload,
)
from src.payloads.encoders import (
    ENCODER_NAMES,
    UnknownEncoderError,
    apply_pipeline,
)
from src.payloads.integration import (
    PayloadDeliveryConfigMap,
    PayloadIntegrationError,
    attach_payload_bundle_to_job,
    collect_payload_artifacts,
)
from src.payloads.mutations import (
    MUTATION_NAMES,
    MutationContext,
    MutationResult,
    MutationRuleSpec,
    UnknownMutationError,
    apply_mutations,
)
from src.payloads.registry import (
    EncodingPipeline,
    MutationRule,
    PayloadEntry,
    PayloadFamily,
    PayloadFamilyNotFoundError,
    PayloadRegistry,
    PayloadRegistrySummary,
    PayloadSignatureError,
    RegistryLoadError,
)

__all__ = [
    "ENCODER_NAMES",
    "MUTATION_NAMES",
    "EncodingPipeline",
    "MutationContext",
    "MutationResult",
    "MutationRule",
    "MutationRuleSpec",
    "PayloadApprovalRequiredError",
    "PayloadBuildError",
    "PayloadBuildRequest",
    "PayloadBuilder",
    "PayloadBundle",
    "PayloadDeliveryConfigMap",
    "PayloadEntry",
    "PayloadFamily",
    "PayloadFamilyNotFoundError",
    "PayloadIntegrationError",
    "PayloadRegistry",
    "PayloadRegistrySummary",
    "PayloadSignatureError",
    "RegistryLoadError",
    "RenderedPayload",
    "UnknownEncoderError",
    "UnknownMutationError",
    "apply_mutations",
    "apply_pipeline",
    "attach_payload_bundle_to_job",
    "collect_payload_artifacts",
]
