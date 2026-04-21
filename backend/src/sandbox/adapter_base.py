"""Single contract for every tool invocation across the ARGUS catalog.

This module defines the public surface that every concrete tool adapter (and
the sandbox driver) speaks against. It is the architectural narrow waist
described in ``Backlog/dev1_md`` §3:

* :class:`ToolAdapter` — the duck-typed ``Protocol`` exposing the contract
  attributes (``tool_id``, ``category``, ``phase``, ``risk_level``, …) plus
  the three behavioural hooks (:meth:`build_command`, :meth:`parse_output`,
  :meth:`collect_evidence`).
* :class:`ToolDescriptor` — the strict Pydantic model that the signed YAML
  catalog is parsed into. Mirrors the Protocol attributes 1-to-1 so a
  descriptor + a default :class:`ShellToolAdapter` is enough to produce a
  working adapter for any plain shell tool.
* :class:`ShellToolAdapter` — concrete (non-abstract) base class that builds
  argv lists via :func:`src.sandbox.templating.render_argv`, returns an empty
  parsed list by default, and yields the sidecar artifact paths from
  :class:`ToolDescriptor.evidence_artifacts` on demand.
* :class:`NetworkPolicyRef` and :class:`ResourceLimits` — frozen value
  objects consumed by the (forthcoming) k8s sandbox driver.
* :class:`ToolCategory`, :class:`ParseStrategy` — enums fixed at the
  catalog-design level.

Errors:
* :class:`AdapterRegistrationError` — raised by the registry when an adapter
  cannot be wired up (bad descriptor, duplicate ``tool_id``, …).
* :class:`AdapterExecutionError` — raised by adapters when the sandbox
  invocation fails in a way that should fail the whole tool run.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.pipeline.contracts.finding_dto import EvidenceDTO, FindingDTO
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, ToolJob
from src.sandbox.templating import render_argv, validate_template


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ToolCategory(StrEnum):
    """High-level grouping for the ARGUS tool catalog (Backlog/dev1_md §4)."""

    RECON = "recon"
    WEB_VA = "web_va"
    CLOUD = "cloud"
    IAC = "iac"
    NETWORK = "network"
    AUTH = "auth"
    BINARY = "binary"
    BROWSER = "browser"
    OAST = "oast"
    MISC = "misc"


class ParseStrategy(StrEnum):
    """Output-parser dispatch strategy declared by a :class:`ToolDescriptor`.

    Concrete parsers live in :mod:`src.sandbox.parsers` (introduced in ARG-003).
    The default :class:`ShellToolAdapter.parse_output` returns ``[]`` and
    emits a structured warning for any non-:attr:`BINARY_BLOB` strategy until
    the parsers package is wired in.
    """

    JSON_LINES = "json_lines"
    JSON_OBJECT = "json_object"
    JSON_GENERIC = "json_generic"
    NUCLEI_JSONL = "nuclei_jsonl"
    XML_NMAP = "xml_nmap"
    XML_GENERIC = "xml_generic"
    TEXT_LINES = "text_lines"
    CSV = "csv"
    BINARY_BLOB = "binary_blob"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AdapterRegistrationError(Exception):
    """Raised when a tool adapter cannot be wired up at registry-load time."""


class AdapterExecutionError(Exception):
    """Raised by an adapter when a sandbox invocation fails fatally."""


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


class NetworkPolicyRef(BaseModel):
    """Reference to a NetworkPolicy template + per-tool overrides.

    The k8s sandbox driver picks the named policy template (e.g. ``recon``,
    ``web_va``, ``cloud``) and may extend the egress allow-list with the
    per-tool ``egress_allowlist`` (CIDRs / FQDNs) and DNS resolver list.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64)
    egress_allowlist: list[StrictStr] = Field(default_factory=list, max_length=64)
    dns_resolvers: list[StrictStr] = Field(default_factory=list, max_length=8)


class ResourceLimits(BaseModel):
    """K8s-style resource limits for an ephemeral sandbox Job.

    ``cpu_limit`` follows k8s notation (``500m``, ``2``); ``memory_limit``
    follows the binary-prefix convention (``256Mi``, ``2Gi``). The
    ``pids_limit`` defaults to 256 — generous enough for fork-heavy tools
    such as ``masscan`` while still capping forkbomb damage.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu_limit: StrictStr = Field(min_length=1, max_length=16)
    memory_limit: StrictStr = Field(min_length=2, max_length=16)
    default_timeout_s: StrictInt = Field(ge=1, le=86_400)
    pids_limit: StrictInt = Field(default=256, ge=1, le=65_536)


# ---------------------------------------------------------------------------
# Tool descriptor (Pydantic model — parsed from YAML)
# ---------------------------------------------------------------------------


_TOOL_ID_PATTERN = r"^[a-z][a-z0-9_]{1,63}$"
_SECCOMP_PATTERN = r"^[A-Za-z0-9_./\-]{1,128}$"
# Semantic Versioning 2.0.0 (https://semver.org/) — MAJOR.MINOR.PATCH with
# optional pre-release / build metadata. Catalog ratchet C14 in
# ``tests/test_tool_catalog_coverage.py`` mirrors this exact regex.
_SEMVER_PATTERN = r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.]+)?(?:\+[\w.]+)?$"


class ToolDescriptor(BaseModel):
    """Strict Pydantic model for a signed ``backend/config/tools/*.yaml`` entry.

    Mirrors the :class:`ToolAdapter` Protocol attributes verbatim; everything
    a sandbox driver needs to launch the tool ephemerally lives here. The
    extra fields ``image``, ``command_template``, ``parse_strategy``,
    ``evidence_artifacts``, ``cwe_hints``, and ``owasp_wstg`` are not on the
    runtime Protocol but are required for catalog-driven dispatch (Backlog
    §3 + ARG-003 cycle plan example schema).

    ARG-040 (Cycle 4 capstone) introduced :attr:`version` — a Semantic
    Versioning 2.0.0 string captured in every signed YAML. The default
    ``"1.0.0"`` keeps load-time backwards compatibility for any YAML that
    pre-dates the backfill; the catalog-coverage gate C14
    (``test_tool_yaml_has_version_field``) enforces presence at the raw
    YAML layer so a new descriptor cannot land without an explicit version.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: StrictStr = Field(min_length=2, max_length=64, pattern=_TOOL_ID_PATTERN)
    version: StrictStr = Field(
        default="1.0.0",
        min_length=5,
        max_length=64,
        pattern=_SEMVER_PATTERN,
    )
    category: ToolCategory
    phase: ScanPhase
    risk_level: RiskLevel
    requires_approval: StrictBool = False
    network_policy: NetworkPolicyRef
    seccomp_profile: StrictStr = Field(
        min_length=1, max_length=128, pattern=_SECCOMP_PATTERN
    )
    default_timeout_s: StrictInt = Field(ge=1, le=86_400)
    cpu_limit: StrictStr = Field(min_length=1, max_length=16)
    memory_limit: StrictStr = Field(min_length=2, max_length=16)
    pids_limit: StrictInt = Field(default=256, ge=1, le=65_536)
    image: StrictStr = Field(min_length=3, max_length=256)
    command_template: list[StrictStr] = Field(min_length=1, max_length=128)
    parse_strategy: ParseStrategy
    evidence_artifacts: list[StrictStr] = Field(default_factory=list, max_length=32)
    cwe_hints: list[StrictInt] = Field(default_factory=list, max_length=32)
    owasp_wstg: list[StrictStr] = Field(default_factory=list, max_length=32)
    # Free-form human-readable summary; rendered into docs/tool-catalog.md and the
    # admin UI. Capped at 500 chars so a misconfigured YAML cannot hide a giant
    # blob of unrelated content. Defaults to "" so descriptors authored before
    # ARG-003 stay backward compatible.
    description: StrictStr = Field(default="", max_length=500)

    def resource_limits(self) -> ResourceLimits:
        """Return a :class:`ResourceLimits` view over the descriptor."""
        return ResourceLimits(
            cpu_limit=self.cpu_limit,
            memory_limit=self.memory_limit,
            default_timeout_s=self.default_timeout_s,
            pids_limit=self.pids_limit,
        )


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ToolAdapter(Protocol):
    """Single contract every concrete tool adapter implements (Backlog §3).

    The attributes mirror :class:`ToolDescriptor` so the registry can index
    adapters without re-loading the YAML at every dispatch. They are exposed
    as read-only properties on purpose — an adapter's identity must not
    drift after construction. Behavioural methods are pure: they take a
    :class:`ToolJob` (or its derived workdir) and return typed DTOs — they
    never spawn subprocesses themselves; that is the sandbox driver's
    responsibility.
    """

    @property
    def tool_id(self) -> str: ...

    @property
    def category(self) -> ToolCategory: ...

    @property
    def phase(self) -> ScanPhase: ...

    @property
    def risk_level(self) -> RiskLevel: ...

    @property
    def requires_approval(self) -> bool: ...

    @property
    def network_policy(self) -> NetworkPolicyRef: ...

    @property
    def seccomp_profile(self) -> str: ...

    @property
    def default_timeout_s(self) -> int: ...

    @property
    def cpu_limit(self) -> str: ...

    @property
    def memory_limit(self) -> str: ...

    def build_command(self, job: ToolJob) -> list[str]:
        """Render the descriptor's ``command_template`` against ``job.parameters``.

        Return value is an argv ``list[str]`` ready for
        ``subprocess.run(argv, shell=False)``. Every adapter MUST go through
        :func:`src.sandbox.templating.render_argv` (or :func:`render`) so the
        shell-injection allow-list is enforced uniformly.
        """
        ...

    def parse_output(
        self,
        raw_stdout: bytes,
        raw_stderr: bytes,
        artifacts_dir: Path,
    ) -> list[FindingDTO]:
        """Convert raw tool output and side-effect files into :class:`FindingDTO` records."""
        ...

    def collect_evidence(self, job: ToolJob, workdir: Path) -> list[EvidenceDTO]:
        """Walk ``workdir`` and yield :class:`EvidenceDTO` records for upload."""
        ...


# ---------------------------------------------------------------------------
# Concrete base class
# ---------------------------------------------------------------------------


class ShellToolAdapter:
    """Concrete (non-abstract) base adapter for plain shell-based tools.

    A ``ShellToolAdapter`` is fully functional out of the box: it builds the
    command via the safe templating layer and returns no findings / no
    evidence by default. Subclasses override :meth:`parse_output` (and
    optionally :meth:`collect_evidence`) when a tool produces a structured
    artifact that maps onto :class:`FindingDTO` / :class:`EvidenceDTO`.

    All Protocol attributes are populated from the bound :class:`ToolDescriptor`,
    so type-checking against :class:`ToolAdapter` is satisfied without any
    extra wiring on the subclass side.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        self._descriptor = descriptor
        # Pre-validate the template once at construction time to fail fast
        # on misconfigured YAMLs (defence-in-depth — ToolRegistry already
        # invokes validate_template on every load).
        validate_template(descriptor.command_template)

    # -- Protocol attribute mirrors --------------------------------------------------

    @property
    def descriptor(self) -> ToolDescriptor:
        """Return the underlying :class:`ToolDescriptor` (for tests / introspection)."""
        return self._descriptor

    @property
    def tool_id(self) -> str:
        return self._descriptor.tool_id

    @property
    def category(self) -> ToolCategory:
        return self._descriptor.category

    @property
    def phase(self) -> ScanPhase:
        return self._descriptor.phase

    @property
    def risk_level(self) -> RiskLevel:
        return self._descriptor.risk_level

    @property
    def requires_approval(self) -> bool:
        return self._descriptor.requires_approval

    @property
    def network_policy(self) -> NetworkPolicyRef:
        return self._descriptor.network_policy

    @property
    def seccomp_profile(self) -> str:
        return self._descriptor.seccomp_profile

    @property
    def default_timeout_s(self) -> int:
        return self._descriptor.default_timeout_s

    @property
    def cpu_limit(self) -> str:
        return self._descriptor.cpu_limit

    @property
    def memory_limit(self) -> str:
        return self._descriptor.memory_limit

    # -- Behavioural methods --------------------------------------------------

    def build_command(self, job: ToolJob) -> list[str]:
        """Materialise the descriptor's command_template against ``job.parameters``.

        Refuses to build a command when ``job.tool_id`` does not match the
        bound descriptor — this catches mis-routed jobs at the adapter layer.
        """
        if job.tool_id != self._descriptor.tool_id:
            raise AdapterExecutionError(
                f"job.tool_id={job.tool_id!r} does not match adapter "
                f"{self._descriptor.tool_id!r}"
            )
        return render_argv(list(self._descriptor.command_template), job.parameters)

    def parse_output(
        self,
        raw_stdout: bytes,
        raw_stderr: bytes,
        artifacts_dir: Path,
    ) -> list[FindingDTO]:
        """Dispatch to the registered parser for this tool's parse strategy.

        ``ParseStrategy.BINARY_BLOB`` short-circuits to ``[]`` because the
        evidence is consumed downstream by the binary-evidence pipeline,
        not by the FindingDTO normaliser.

        Every other strategy delegates to
        :func:`src.sandbox.parsers.dispatch_parse`. The dispatcher is
        fail-soft: an unknown strategy, an unmapped ``tool_id``, or a
        handler exception logs a structured warning and returns ``[]`` so
        a single misbehaving parser cannot take down the worker.

        ``dispatch_parse`` is imported locally to side-step the
        ``adapter_base`` ↔ ``parsers`` import cycle: parsers depend on
        :class:`ParseStrategy` defined here, while this method needs the
        dispatch table they build.
        """
        if self._descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
            return []

        from src.sandbox.parsers import dispatch_parse

        return dispatch_parse(
            self._descriptor.parse_strategy,
            raw_stdout,
            raw_stderr,
            artifacts_dir,
            self._descriptor.tool_id,
        )

    def collect_evidence(self, job: ToolJob, workdir: Path) -> list[EvidenceDTO]:
        """Default: returns ``[]`` — the evidence pipeline (ARG-009) wires this up.

        Subclasses that produce side-effect artifacts (e.g. nmap XML) override
        this to emit :class:`EvidenceDTO` rows pointing at the uploaded S3
        objects. The default is a no-op so a basic shell tool is still
        runnable end-to-end without the evidence pipeline.
        """
        del job, workdir
        return []
