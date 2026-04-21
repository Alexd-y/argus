"""Payload bundle builder for ARGUS validators (Backlog/dev1_md §6, §7).

The :class:`PayloadBuilder` is the **only** path between an LLM-emitted
:class:`~src.orchestrator.schemas.loader.ValidationPlanV1` and a concrete
list of payload strings handed to a sandboxed validator. It enforces:

* The targeted ``registry_family`` exists and is signed
  (delegated to :class:`~src.payloads.registry.PayloadRegistry`).
* If the family has ``requires_approval=True``, the build call must
  carry an ``approval_id`` token (validator caller's responsibility);
  otherwise :class:`PayloadApprovalRequiredError` is raised.
* All template placeholders are present in the supplied parameter map.
  Missing placeholders raise :class:`PayloadBuildError`.
* Every payload is materialised through the family's declared mutation
  list and the *first* declared encoding pipeline (the LLM picks the
  pipeline by name in :attr:`PayloadBuildRequest.encoding_pipeline`).
* The output is deterministic given a stable correlation key — the same
  ``(scan_id, family_id, encoding_pipeline)`` triple always yields the
  same :class:`PayloadBundle`. This is what lets the validator replay an
  exact bundle on rebuild and guarantees evidence-by-hash.

The bundle is *opaque* to the rest of the system — it is delivered to
sandboxed tools via a ConfigMap (see :mod:`src.payloads.integration`),
never embedded in Job env / args.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
)

from src.payloads.encoders import apply_pipeline
from src.payloads.mutations import MutationContext, apply_mutations
from src.payloads.registry import (
    EncodingPipeline,
    PayloadFamily,
    PayloadFamilyNotFoundError,
    PayloadRegistry,
)
from src.policy.preflight import PreflightDeniedError


if TYPE_CHECKING:
    # Concrete types used only for static analysis. The runtime constructor
    # accepts any object exposing the ``check`` method of the preflight
    # checker (duck-typed) so payload tests can run without instantiating
    # the full policy plane.
    from src.pipeline.contracts.tool_job import TargetSpec
    from src.policy.policy_engine import PolicyContext
    from src.policy.preflight import PreflightChecker, PreflightDecision


_TEMPLATE_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_DEFAULT_MAX_PAYLOADS: Final[int] = 64
_PAYLOAD_MAX_LEN: Final[int] = 8192


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PayloadBuildError(ValueError):
    """Raised when a build request is malformed or references an unknown family."""


class PayloadApprovalRequiredError(PayloadBuildError):
    """Raised when an approval-gated family is built without an approval token."""

    def __init__(self, family_id: str) -> None:
        super().__init__(
            f"family_id={family_id!r} requires explicit approval; "
            "supply approval_id in the build request"
        )
        self.family_id = family_id


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class RenderedPayload(BaseModel):
    """One concrete payload string + provenance.

    The validator persists ``id`` on the resulting finding so the dispatcher
    can later trace back to the seed entry. ``index`` is the ordinal
    within the bundle, useful for stable logging.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=64)
    index: StrictInt = Field(ge=0, le=10_000)
    payload: StrictStr = Field(min_length=1, max_length=_PAYLOAD_MAX_LEN)
    template_id: StrictStr = Field(min_length=1, max_length=64)
    encoding_pipeline: StrictStr = Field(min_length=1, max_length=64)


class PayloadBundle(BaseModel):
    """Fully materialised, deterministic bundle of payloads for one family.

    The bundle's ``manifest_hash`` is the SHA-256 of the canonical JSON
    representation of the rendered payload list — it lets the orchestrator
    diff bundles across runs and binds evidence to the exact bytes used.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    family_id: StrictStr = Field(min_length=3, max_length=32)
    encoding_pipeline: StrictStr = Field(min_length=1, max_length=64)
    correlation_key: StrictStr = Field(min_length=1, max_length=256)
    requires_approval: StrictBool = False
    approval_id: StrictStr | None = Field(default=None, max_length=128)
    oast_required: StrictBool = False
    payloads: list[RenderedPayload] = Field(min_length=1, max_length=10_000)
    manifest_hash: StrictStr = Field(min_length=64, max_length=64)

    def to_serialisable(self) -> dict[str, object]:
        """Return a JSON-safe dict suitable for ConfigMap delivery.

        Pydantic ``model_dump`` plus normalisation to native types only
        (no ``UUID``/``datetime`` here); the orchestrator embeds this
        verbatim in the sandbox ConfigMap.
        """
        return {
            "family_id": self.family_id,
            "encoding_pipeline": self.encoding_pipeline,
            "correlation_key": self.correlation_key,
            "requires_approval": self.requires_approval,
            "approval_id": self.approval_id,
            "oast_required": self.oast_required,
            "manifest_hash": self.manifest_hash,
            "payloads": [p.model_dump() for p in self.payloads],
        }


class PayloadBuildRequest(BaseModel):
    """Input contract for :meth:`PayloadBuilder.build`.

    The ``correlation_key`` is the only knob driving determinism — the
    orchestrator builds it from ``scan_id`` + ``finding_hypothesis_id``
    so the same hypothesis re-uses the same bundle bytes across retries.
    ``parameters`` is the placeholder context substituted into each
    seed template.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    family_id: StrictStr = Field(min_length=3, max_length=32)
    correlation_key: StrictStr = Field(min_length=1, max_length=256)
    encoding_pipeline: StrictStr | None = Field(default=None, max_length=64)
    approval_id: StrictStr | None = Field(default=None, max_length=128)
    parameters: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    max_payloads: StrictInt = Field(default=_DEFAULT_MAX_PAYLOADS, ge=1, le=1024)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class PayloadBuilder:
    """Materialise signed payload-family seeds into a deterministic bundle.

    The builder is stateless apart from its registry + optional preflight
    checker reference; safe to share as a singleton.

    When ``preflight_checker`` is supplied, every :meth:`build` call MUST
    receive a ``preflight_context`` and ``target_spec`` so the four
    guardrails (scope, ownership, policy, approval) can run before any
    payload bytes are materialised. Denials surface as
    :class:`PreflightDeniedError`.
    """

    def __init__(
        self,
        registry: PayloadRegistry,
        *,
        preflight_checker: "PreflightChecker | None" = None,
    ) -> None:
        self._registry = registry
        self._preflight_checker = preflight_checker

    def build(
        self,
        request: PayloadBuildRequest,
        *,
        preflight_context: "PolicyContext | None" = None,
        target_spec: "TargetSpec | None" = None,
    ) -> PayloadBundle:
        """Build the payload bundle for ``request``.

        Parameters
        ----------
        request
            Validated :class:`PayloadBuildRequest`.
        preflight_context
            Required when the builder was constructed with a
            ``preflight_checker``; carries tenant / phase / risk
            information needed by the policy engine.
        target_spec
            Required when the builder was constructed with a
            ``preflight_checker``; the target the resulting payload bundle
            will eventually be fired at.

        Raises
        ------
        PayloadBuildError
            For unknown family IDs, unknown encoding pipelines, missing
            placeholders, empty results, or missing preflight inputs.
        PayloadApprovalRequiredError
            When the family requires approval and no ``approval_id`` is set.
        PreflightDeniedError
            When the configured preflight checker denies the build.
        """
        if self._preflight_checker is not None:
            self._run_preflight(
                request=request,
                preflight_context=preflight_context,
                target_spec=target_spec,
            )

        family = self._fetch_family(request.family_id)

        if family.requires_approval and not request.approval_id:
            raise PayloadApprovalRequiredError(family.family_id)
        if not family.requires_approval and request.approval_id is not None:
            raise PayloadBuildError(
                f"family_id={family.family_id!r} does not require approval; "
                "approval_id must be omitted"
            )

        pipeline = self._resolve_pipeline(family, request.encoding_pipeline)

        rendered: list[RenderedPayload] = []
        seed_base = self._derive_seed(request.correlation_key, family.family_id)
        max_payloads = min(request.max_payloads, len(family.payloads))

        for index, entry in enumerate(family.payloads[:max_payloads]):
            substituted = self._substitute(entry.template, request.parameters)
            ctx = MutationContext(
                seed=seed_base ^ index,
                family_id=family.family_id,
                payload_index=index,
            )
            mutation_result = apply_mutations(substituted, family.mutations, ctx)
            encoded = apply_pipeline(mutation_result.payload, list(pipeline.stages))
            if not encoded:
                raise PayloadBuildError(
                    f"empty render for entry id={entry.id!r} in family {family.family_id!r}"
                )
            if len(encoded) > _PAYLOAD_MAX_LEN:
                raise PayloadBuildError(
                    f"rendered payload exceeds {_PAYLOAD_MAX_LEN} chars "
                    f"(entry id={entry.id!r}, family={family.family_id!r})"
                )
            rendered.append(
                RenderedPayload(
                    id=entry.id,
                    index=index,
                    payload=encoded,
                    template_id=entry.id,
                    encoding_pipeline=pipeline.name,
                )
            )

        if not rendered:
            raise PayloadBuildError(
                f"family {family.family_id!r} produced an empty bundle"
            )

        manifest_hash = self._compute_manifest_hash(rendered, pipeline.name)
        return PayloadBundle(
            family_id=family.family_id,
            encoding_pipeline=pipeline.name,
            correlation_key=request.correlation_key,
            requires_approval=family.requires_approval,
            approval_id=request.approval_id,
            oast_required=family.oast_required,
            payloads=rendered,
            manifest_hash=manifest_hash,
        )

    # -- helpers -------------------------------------------------------------

    def _fetch_family(self, family_id: str) -> PayloadFamily:
        try:
            return self._registry.get_family(family_id)
        except PayloadFamilyNotFoundError as exc:
            raise PayloadBuildError(f"unknown payload family_id {family_id!r}") from exc

    def _run_preflight(
        self,
        *,
        request: PayloadBuildRequest,
        preflight_context: "PolicyContext | None",
        target_spec: "TargetSpec | None",
    ) -> "PreflightDecision":
        """Invoke the preflight checker and surface denials as exceptions."""
        if preflight_context is None or target_spec is None:
            raise PayloadBuildError(
                "preflight_checker requires both preflight_context and target_spec"
            )
        assert self._preflight_checker is not None
        decision = self._preflight_checker.check(
            target_spec=target_spec,
            port=None,
            policy_context=preflight_context,
        )
        if not decision.allowed:
            assert decision.failure_summary is not None
            raise PreflightDeniedError(decision.failure_summary, decision=decision)
        return decision

    @staticmethod
    def _resolve_pipeline(
        family: PayloadFamily, requested: str | None
    ) -> "_PipelineSnapshot":
        if not family.encodings:
            return _PipelineSnapshot(name="identity", stages=())
        by_name = {p.name: p for p in family.encodings}
        if requested is None:
            chosen: EncodingPipeline = family.encodings[0]
        else:
            candidate = by_name.get(requested)
            if candidate is None:
                raise PayloadBuildError(
                    f"unknown encoding pipeline {requested!r} for family "
                    f"{family.family_id!r}; available={sorted(by_name)}"
                )
            chosen = candidate
        return _PipelineSnapshot(name=chosen.name, stages=tuple(chosen.stages))

    @staticmethod
    def _substitute(template: str, parameters: Mapping[str, str]) -> str:
        def _replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in parameters:
                raise PayloadBuildError(
                    f"missing parameter {name!r} for payload template"
                )
            value = parameters[name]
            if not isinstance(value, str):
                raise PayloadBuildError(
                    f"parameter {name!r} must be a string, got {type(value).__name__}"
                )
            return value

        return _TEMPLATE_PLACEHOLDER_RE.sub(_replace, template)

    @staticmethod
    def _derive_seed(correlation_key: str, family_id: str) -> int:
        material = f"{correlation_key}|{family_id}".encode("utf-8")
        digest = hashlib.sha256(material).digest()
        return int.from_bytes(digest[:8], byteorder="big", signed=False)

    @staticmethod
    def _compute_manifest_hash(
        rendered: list[RenderedPayload], pipeline_name: str
    ) -> str:
        canonical = json.dumps(
            {
                "pipeline": pipeline_name,
                "payloads": [
                    {
                        "id": item.id,
                        "index": item.index,
                        "payload": item.payload,
                        "template_id": item.template_id,
                        "encoding_pipeline": item.encoding_pipeline,
                    }
                    for item in rendered
                ],
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Internal value objects
# ---------------------------------------------------------------------------


class _PipelineSnapshot:
    """Tiny private holder of the resolved pipeline (name + ordered stages)."""

    __slots__ = ("name", "stages")

    def __init__(self, name: str, stages: tuple[str, ...]) -> None:
        self.name = name
        self.stages = stages


__all__ = [
    "PayloadApprovalRequiredError",
    "PayloadBuildError",
    "PayloadBuildRequest",
    "PayloadBuilder",
    "PayloadBundle",
    "RenderedPayload",
]
