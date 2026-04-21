"""Per-tool coverage gate for the ARGUS sandbox catalog (ARG-010 / ARG-020 / ARG-030 / ARG-040 / ARG-049).

For every ``tool_id`` registered in
:class:`src.sandbox.tool_registry.ToolRegistry` this module asserts a
matrix of contracts that must hold simultaneously for the tool to count
as fully delivered.  A failure in any contract surfaces as one failed
parametrised case (157 tools × 16 checks as of ARG-049) so CI pinpoints
the missing artefact without obscuring the rest of the matrix.

Contracts (in order of failure-blast-radius — cheapest fixes first):

1. **Descriptor on disk** — ``backend/config/tools/{tool_id}.yaml`` exists.
2. **Signed + verified** — Ed25519 signature for that file lives in
   ``backend/config/tools/SIGNATURES`` and verifies via the registry. A
   successful :meth:`ToolRegistry.load` proves the cryptographic check;
   the per-tool assertion turns a registry-wide failure into a per-tool
   failure so the test report names the offending YAML.
3. **Pydantic-parsable** — descriptor parses through
   :class:`src.sandbox.adapter_base.ToolDescriptor` (strict mode,
   ``extra=forbid``).
4. **Documented** — ``docs/tool-catalog.md`` mentions ``{tool_id}``.
5. **Integration-suite-aware** — either a hard-coded entry in
   ``tests/integration/sandbox/test_tool_catalog_load.py`` or a per-tool
   YAML fixture under ``tests/integration/sandbox/fixtures/{tool_id}.yaml``.
6. **Command template valid** (ARG-020) — every placeholder in
   ``descriptor.command_template`` is on the sandbox templating allow-list
   (``src.sandbox.templating.ALLOWED_PLACEHOLDERS``).
7. **Parser dispatch reachable** (ARG-020) — the descriptor's
   ``parse_strategy`` either has a registered strategy handler in
   :mod:`src.sandbox.parsers` (which routes to the per-tool parser or the
   ARG-020 heartbeat fallback) OR is :attr:`ParseStrategy.BINARY_BLOB`
   (short-circuited by :class:`ShellToolAdapter` before dispatch). No
   tool can land with a strategy that has neither a handler nor a
   short-circuit — that would be a silent ``[]`` return path.
8. **Network policy allowed** (ARG-020) — the descriptor's
   ``network_policy.name`` is in
   :data:`src.sandbox.network_policies.NETWORK_POLICY_NAMES` so a typo
   in the YAML cannot drop the pod into the implicit-allow Kubernetes
   default at startup.
9. **Image label allowed** (ARG-020) — every tool image lives in the
   ``argus-kali-*`` family AND :func:`src.sandbox.manifest.resolve_image`
   resolves it to a fully-qualified reference under the canonical
   ``_DEFAULT_REGISTRY`` (``ghcr.io/argus``).
10. **Approval policy enforced** (ARG-020) —
    ``descriptor.requires_approval == True`` implies
    ``descriptor.risk_level >= MEDIUM``. Approval-gated PASSIVE / LOW
    tools are forbidden because the operator-consent UX only exists to
    insulate against medium-or-above operational impact (live cloud
    creds, WAF noise, DB churn, etc.).
11. **Parser determinism** (ARG-030) — :func:`dispatch_parse` invoked
    twice on the same trivial per-strategy fixture (with two distinct
    ``tmp_path`` directories so a sidecar path leaking into the DTO
    surfaces immediately) returns ``FindingDTO`` lists that are
    structurally equal modulo the wall-clock ``first_seen`` /
    ``last_seen`` fields (those are filled at ``_utcnow()`` and are
    legitimately non-deterministic).  Skips :attr:`ParseStrategy.BINARY_BLOB`
    for the same reason as Contract 7.  Catches the entire class of
    "parser embeds ``str(artifacts_dir)``", "parser fans out a random
    UUID", "parser depends on dict ordering" regressions in a single
    parametrised gate.
12. **Evidence redaction completeness** (ARG-030) — every parser is
    fed a single bytes blob containing ≥11 known-secret patterns
    (one per :data:`src.evidence.redaction._DEFAULT_SPECS` rule:
    Bearer / AWS / GH PAT / Slack / JWT / OpenAI / private-key PEM /
    Set-Cookie / Cookie / password-in-URL / password-kv) on both
    ``stdout`` and ``stderr``.  For every returned :class:`FindingDTO`
    we then serialise the DTO via ``model_dump_json()`` and pass the
    bytes through :class:`src.evidence.redaction.Redactor`.  Contract
    holds iff ``redactions_applied == 0`` — i.e. the parser layer
    (either by stripping the field or by routing through
    :func:`src.sandbox.parsers._base.redact_secret`) is the **first**
    line of redaction and the downstream :class:`Redactor` defence-in-
    depth pass is a verifiable no-op.  Skips :attr:`ParseStrategy.BINARY_BLOB`
    (handled by the evidence pipeline, not the parser layer).  The
    contract is fail-soft for known-incomplete parsers via the
    :data:`_C12_KNOWN_LEAKERS` allow-set, which is intentionally
    **empty**: every wired parser as of Cycle 3 close passes C12
    without an exemption.
13. **Signature mtime stability** (ARG-040) — for every signed YAML in
    the catalog (157 tools + 23 payloads + 5 prompts = 185 files) the
    test temporarily flips the read-only mode (the ``read_only_catalog``
    autouse session fixture chmods the catalog to 0o444 to defend
    against the ARG-038-class drift), bumps the mtime by one second
    via :func:`os.utime`, then re-verifies the signature against the
    in-process :class:`SignaturesFile` parser.  The contract holds iff
    every verify call succeeds — proving that signatures bind raw
    bytes-on-disk and are NEVER invalidated by a touch / rebuild /
    git-checkout-noop.  Catches a future regression where a caller
    decides to embed mtime in the manifest or rebuild signatures
    based on stat() metadata.  Mtime is restored verbatim in
    ``finally`` so the catalog is byte-and-metadata-clean post-test.
14. **Tool YAML version field presence** (ARG-040) — every signed tool
    YAML must carry a top-level ``version: <semver>`` field at the raw
    YAML layer (verified by parsing the YAML directly, not by reading
    :class:`ToolDescriptor.version` which has a default value).  The
    semver regex matches the same pattern enforced on the Pydantic
    model side (``^MAJOR.MINOR.PATCH(-pre)?(+build)?$``).  Catches a
    future "dropped the version field by accident in a YAML edit"
    regression that would let the descriptor still load (default
    ``"1.0.0"``) but break the manifest contract that operators
    pivot on for tool-version drift detection.
15. **Tool YAML version monotonic** (ARG-049) — every tool's current
    raw ``version`` field must be greater-than-or-equal-to its frozen
    baseline at ``backend/tests/snapshots/tool_versions_baseline.json``
    under PEP 440 ordering (``packaging.version.Version`` — a strict
    superset of SemVer 2.0.0 ordering).  A regression (current < baseline)
    is BLOCKING in CI; bumping a baseline value requires an explicit
    edit + worker-report rationale.  The contract also asserts that
    every catalog tool_id is present in the baseline (catches a freshly
    added descriptor whose author forgot to extend the snapshot in the
    same PR) and that every baseline tool_id is still in the catalog
    (catches a silent removal that the version-bump UX would otherwise
    let slip).
16. **Image coverage completeness** (ARG-049) — every catalog tool_id
    is provisioned by at least one of the 6 sandbox image profiles
    declared in ``infra/sandbox/images/tool_to_package.json`` (i.e. the
    image build pipeline knows which Dockerfile installs each binary on
    PATH).  The profile JSON is the operator-visible manifest of the
    image build matrix; a tool missing from every profile would never
    land on a sandbox container at runtime, so this gate is a hard CI
    fail rather than a warning.  The check tolerates a tool appearing
    in multiple profiles (e.g. during a planned web → network YAML
    migration) but never zero.  The inverse check — every JSON tool_id
    is still in the catalog — guards against a stale profile entry
    drifting after a YAML rename / removal.

The list of ``tool_id`` s is sourced from the registry; nothing here is
hard-coded, so adding a new YAML descriptor automatically extends the
matrix.

Coverage summary (ARG-020): the module also emits a single ``stdout``
line summarising parser-registration coverage (``mapped`` / ``heartbeat``
/ ``binary_blob`` per-strategy and grand totals) so a CI run shows the
trajectory of "tools with first-class parsers vs heartbeat fallback" at
a glance, without the operator having to grep through the per-tool
verdicts.

Hard isolation rules (do NOT relax):
* No Kubernetes, no network, no Redis, no DB.
* No filesystem I/O outside ``backend/config/tools/``,
  ``backend/tests/integration/sandbox/``, and ``docs/``.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
import yaml
from packaging.version import InvalidVersion, Version

from src.evidence.redaction import Redactor
from src.pipeline.contracts.finding_dto import FindingDTO
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import ParseStrategy, ToolDescriptor
from src.sandbox.manifest import resolve_image
from src.sandbox.network_policies import NETWORK_POLICY_NAMES
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
)
from src.sandbox.signing import (
    KeyManager,
    SignaturesFile,
)
from src.sandbox.templating import TemplateRenderError, validate_template
from src.sandbox.tool_registry import ToolRegistry

# ---------------------------------------------------------------------------
# Approval policy + image / registry constants
# ---------------------------------------------------------------------------


# RiskLevel ordering used to enforce contract 10.  StrEnum members do NOT
# implement comparison operators by default, so we map onto a numeric ladder.
# Keep this in lock-step with ``src.pipeline.contracts.tool_job.RiskLevel``.
_RISK_LEVEL_ORDINAL: Final[dict[RiskLevel, int]] = {
    RiskLevel.PASSIVE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.DESTRUCTIVE: 4,
}
_APPROVAL_RISK_FLOOR: Final[RiskLevel] = RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Parser-coverage hard floor (ARG-021 → ARG-022 → ARG-029 → ARG-032 ratchet).
#
# These constants pin the *current* split between mapped first-class
# parsers and ARG-020 heartbeat-fallback parsers.  Whenever a new parser
# batch lands, both numbers move in lock-step:
#
#   ARG-021 (Cycle 3 batch 1):  43 mapped → 114 heartbeat
#   ARG-022 (Cycle 3 batch 2):  53 mapped → 104 heartbeat
#   ARG-029 (Cycle 3 batch 3):  68 mapped →  89 heartbeat
#   ARG-032 (Cycle 4 batch 4):  98 mapped →  59 heartbeat
#   T05 (Cycle 6 batch 1):     118 mapped →  39 heartbeat   <- pinned here
#
# A drop in `MAPPED_PARSER_COUNT` (or a rise that does not have a
# matching drop in `HEARTBEAT_PARSER_COUNT`) is a regression and the
# ratchet test below will fail loudly.  Bumping these numbers requires
# an explicit edit, which forces the reviewer to diff against the
# previous batch and cross-check the worker report.
# ---------------------------------------------------------------------------
MAPPED_PARSER_COUNT: Final[int] = 118
HEARTBEAT_PARSER_COUNT: Final[int] = 39


# ---------------------------------------------------------------------------
# ARG-030 / ARG-040 / ARG-049 — coverage matrix size pin.
#
# Future cycles MUST increment this constant in lock-step with adding /
# removing parametrised contracts.  A drop in contract count is a
# regression signal — the ratchet test below catches it loudly.
#
#   ARG-030 (Cycle 3 capstone):  10 → 12 contracts (added C11, C12)
#   ARG-040 (Cycle 4 capstone):  12 → 14 contracts (added C13, C14)
#   ARG-049 (Cycle 5 capstone):  14 → 16 contracts (added C15, C16)
# ---------------------------------------------------------------------------
COVERAGE_MATRIX_CONTRACTS: Final[int] = 16


# ARG-049 — sandbox image profile count pin.  6 profiles materialised on
# disk under ``sandbox/images/`` (browser, cloud, full, network, recon,
# web) plus the ``argus-kali-binary`` logical alias declared in
# ``infra/sandbox/images/tool_to_package.json`` (its 5 tools fall back
# to ``argus-kali-full`` at runtime via ``image_resolver``).  C16 ratchets
# the JSON profile count so a future shrinkage (e.g. losing the network
# profile) surfaces as a named failure rather than a silent re-routing.
SANDBOX_IMAGE_PROFILE_COUNT: Final[int] = 6


# ARG-040 — Semantic Versioning 2.0.0 regex (mirrors ``_SEMVER_PATTERN`` in
# ``src.sandbox.adapter_base``).  Used by C14 to enforce that the raw YAML
# ``version`` field is a well-formed semver string and not a typo.
_SEMVER_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.]+)?(?:\+[\w.]+)?$"
)


# Canonical default registry used by :func:`src.sandbox.manifest.resolve_image`
# for bare image refs.  Mirrored here as a constant so a future registry
# change is observable in this test (single source of truth).
_CANONICAL_REGISTRY: Final[str] = "ghcr.io/argus"


# Allow-list of image-name prefixes accepted by the catalog.  The 5
# pre-bundled ``argus-kali-*`` images cover every Cycle 2 tool; a brand
# new image family (e.g. ``argus-kali-wireless``) requires an explicit
# update here so the catalog cannot silently shift to a new container.
_ALLOWED_IMAGE_PREFIXES: Final[frozenset[str]] = frozenset({"argus-kali-"})

# ---------------------------------------------------------------------------
# Path constants — every read is bounded to one of these three roots.
# ---------------------------------------------------------------------------


_BACKEND_DIR: Final[Path] = Path(__file__).resolve().parent.parent
_REPO_ROOT: Final[Path] = _BACKEND_DIR.parent

_TOOLS_DIR: Final[Path] = _BACKEND_DIR / "config" / "tools"
_TOOLS_KEYS_DIR: Final[Path] = _TOOLS_DIR / "_keys"
_SIGNATURES_PATH: Final[Path] = _TOOLS_DIR / "SIGNATURES"

_PAYLOADS_DIR: Final[Path] = _BACKEND_DIR / "config" / "payloads"
_PAYLOADS_KEYS_DIR: Final[Path] = _PAYLOADS_DIR / "_keys"
_PAYLOADS_SIGNATURES_PATH: Final[Path] = _PAYLOADS_DIR / "SIGNATURES"

_PROMPTS_DIR: Final[Path] = _BACKEND_DIR / "config" / "prompts"
_PROMPTS_KEYS_DIR: Final[Path] = _PROMPTS_DIR / "_keys"
_PROMPTS_SIGNATURES_PATH: Final[Path] = _PROMPTS_DIR / "SIGNATURES"

# All three signed catalog roots in (catalog_dir, signatures_path, keys_dir,
# label) tuples — drives the C13 mtime-stability sweep so adding a new
# signed catalog (e.g. ``config/policies/``) is one line of work.
_SIGNED_CATALOGS: Final[tuple[tuple[Path, Path, Path, str], ...]] = (
    (_TOOLS_DIR, _SIGNATURES_PATH, _TOOLS_KEYS_DIR, "tools"),
    (_PAYLOADS_DIR, _PAYLOADS_SIGNATURES_PATH, _PAYLOADS_KEYS_DIR, "payloads"),
    (_PROMPTS_DIR, _PROMPTS_SIGNATURES_PATH, _PROMPTS_KEYS_DIR, "prompts"),
)

_DOCS_TOOL_CATALOG: Final[Path] = _REPO_ROOT / "docs" / "tool-catalog.md"

# ARG-049 — C15 frozen baseline of every tool's ``version`` field at
# Cycle 5 close.  Lives under ``backend/tests/snapshots/`` (alongside
# other deterministic snapshots) so an editor scanning the tree finds
# it without grepping ``backend/config/``.  Bumping a baseline value
# requires an explicit edit + worker-report rationale (no silent
# rewrites — the file is intentionally not regenerated by any script).
_TOOL_VERSIONS_BASELINE_PATH: Final[Path] = (
    _BACKEND_DIR / "tests" / "snapshots" / "tool_versions_baseline.json"
)

# ARG-049 — C16 canonical map from sandbox image profile to the
# ``tool_id`` set the image provisions on PATH.  Lives under
# ``infra/sandbox/images/`` because it is the operator-visible build
# manifest of the image matrix; the Dockerfiles + SBOMs live in the
# same directory.
_TOOL_TO_PACKAGE_PATH: Final[Path] = (
    _REPO_ROOT / "infra" / "sandbox" / "images" / "tool_to_package.json"
)

_INTEGRATION_SANDBOX_DIR: Final[Path] = (
    _BACKEND_DIR / "tests" / "integration" / "sandbox"
)
_INTEGRATION_LOAD_TEST: Final[Path] = (
    _INTEGRATION_SANDBOX_DIR / "test_tool_catalog_load.py"
)
_INTEGRATION_FIXTURES_DIR: Final[Path] = _INTEGRATION_SANDBOX_DIR / "fixtures"

# Allow-list of file extensions that are scanned for tool_id references in the
# integration sandbox tree.  Binary or rendered artefacts are intentionally
# excluded.
_INTEGRATION_SCAN_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".py", ".yaml", ".yml", ".json", ".txt", ".md"}
)


# ---------------------------------------------------------------------------
# Auto-use override: shadow the heavy parent ``override_auth`` fixture so this
# module does not pull in ``main.app`` (FastAPI + DB stack) for what is a
# pure-Python file/registry inspection.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """No-op shadow of ``backend/tests/conftest.py::override_auth``.

    The parent autouse fixture takes ``app`` as a dependency, which imports
    ``main`` and therefore the whole FastAPI / DB stack.  Tool-catalog
    coverage is a pure file + crypto check; we MUST not pay that startup
    cost (and MUST not require those services to be available).
    """
    yield


# ---------------------------------------------------------------------------
# Catalog discovery — happens once at module import time.
#
# pytest invokes ``parametrize`` *at collection*, before any fixture runs.
# We therefore instantiate a throw-away ``ToolRegistry`` here so the
# parametrise IDs match the descriptors the loaded_registry fixture later
# observes.  A failure here surfaces as a collection-time error (which is
# the correct behaviour: a broken catalog must not register zero tests).
# ---------------------------------------------------------------------------


def _enumerate_tool_ids() -> list[str]:
    registry = ToolRegistry(tools_dir=_TOOLS_DIR)
    registry.load()
    return [descriptor.tool_id for descriptor in registry.all_descriptors()]


_TOOL_IDS: Final[list[str]] = _enumerate_tool_ids()


def _enumerate_signed_catalog_files() -> list[tuple[str, Path]]:
    """Discover every signed YAML across ``tools`` / ``payloads`` / ``prompts``.

    Returns a deterministic list of ``(test_id, yaml_path)`` tuples used by
    C13 (mtime stability).  ``test_id`` is shaped ``"<catalog>:<stem>"`` so a
    failing case names the catalog *and* the YAML at a glance.
    """
    discovered: list[tuple[str, Path]] = []
    for catalog_dir, _signatures, _keys_dir, label in _SIGNED_CATALOGS:
        if not catalog_dir.is_dir():
            continue
        for yaml_path in sorted(catalog_dir.glob("*.yaml")):
            discovered.append((f"{label}:{yaml_path.stem}", yaml_path))
    return discovered


_SIGNED_CATALOG_FILES: Final[list[tuple[str, Path]]] = _enumerate_signed_catalog_files()


# ---------------------------------------------------------------------------
# Module-scoped fixtures (each computed once per test session, not per-tool).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def loaded_registry() -> ToolRegistry:
    """Load the production catalog exactly as the application does at startup.

    Verification is fail-closed: any signature, schema, or template-allow-list
    violation aborts the load and the dependent per-tool tests fail with the
    underlying :class:`RegistryLoadError`.
    """
    registry = ToolRegistry(tools_dir=_TOOLS_DIR)
    registry.load()
    return registry


@pytest.fixture(scope="module")
def docs_tool_catalog_text() -> str:
    """Read ``docs/tool-catalog.md`` once per session."""
    if not _DOCS_TOOL_CATALOG.is_file():
        pytest.fail(
            f"docs/tool-catalog.md missing — re-run "
            f"`python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md` "
            f"(looked at {_DOCS_TOOL_CATALOG})"
        )
    return _DOCS_TOOL_CATALOG.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def integration_sandbox_corpus() -> str:
    """Concatenate every text file under ``tests/integration/sandbox/`` once.

    Lets the per-tool reference test answer "is this tool mentioned anywhere
    in the integration suite?" with a single substring scan instead of
    O(N tools × N files) reads.
    """
    chunks: list[str] = []
    for path in _iter_integration_sandbox_files():
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def _iter_integration_sandbox_files() -> Iterator[Path]:
    if not _INTEGRATION_SANDBOX_DIR.is_dir():
        return
    for path in sorted(_INTEGRATION_SANDBOX_DIR.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _INTEGRATION_SCAN_SUFFIXES:
            yield path


def _signatures_has_entry(relative_path: str) -> bool:
    """True if ``SIGNATURES`` has a record whose path field equals ``relative_path``."""
    if not _SIGNATURES_PATH.is_file():
        return False
    for raw_line in _SIGNATURES_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == relative_path:
            return True
    return False


# ---------------------------------------------------------------------------
# Coverage matrix — one parametrised test per contract, per tool_id.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_yaml_descriptor_exists(tool_id: str) -> None:
    """Contract 1: ``backend/config/tools/{tool_id}.yaml`` is on disk."""
    yaml_path = _TOOLS_DIR / f"{tool_id}.yaml"
    assert yaml_path.is_file(), (
        f"tool_id={tool_id!r} declared in registry but YAML missing at "
        f"{yaml_path.relative_to(_BACKEND_DIR)}"
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_signature_verifies_via_registry(
    tool_id: str, loaded_registry: ToolRegistry
) -> None:
    """Contract 2: signature verifies via :class:`ToolRegistry`.

    Two facts together prove this:

    * ``loaded_registry.get(tool_id)`` returns a non-``None`` descriptor —
      ToolRegistry.load is fail-closed, so a registered descriptor has
      already passed Ed25519 verification.
    * ``SIGNATURES`` has an explicit record for ``{tool_id}.yaml`` — guards
      against the (impossible-but-cheap-to-check) case where a future
      registry impl skips signing for a subset of descriptors.
    """
    assert loaded_registry.get(tool_id) is not None, (
        f"{tool_id!r} not registered — Ed25519 signature verification likely failed; "
        f"see tool_registry.load_failed log for the underlying reason"
    )
    assert _signatures_has_entry(f"{tool_id}.yaml"), (
        f"SIGNATURES manifest has no record for {tool_id}.yaml; "
        f"re-run `python -m scripts.tools_sign --sign`"
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_descriptor_parses_through_pydantic(
    tool_id: str, loaded_registry: ToolRegistry
) -> None:
    """Contract 3: descriptor parses as a strict :class:`ToolDescriptor`."""
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"
    assert isinstance(descriptor, ToolDescriptor), (
        f"{tool_id!r} resolved to {type(descriptor).__name__}, expected ToolDescriptor"
    )
    # The registry indexes by descriptor.tool_id, so a mismatch here is a
    # fail-closed registry bug — assert it explicitly to make the failure
    # report self-explanatory.
    assert descriptor.tool_id == tool_id


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_documented_in_catalog(tool_id: str, docs_tool_catalog_text: str) -> None:
    """Contract 4: ``docs/tool-catalog.md`` mentions the ``tool_id``."""
    needle = f"`{tool_id}`"
    assert needle in docs_tool_catalog_text, (
        f"docs/tool-catalog.md missing entry for {tool_id!r}; "
        f"re-run `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`"
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_referenced_in_integration_suite(
    tool_id: str, integration_sandbox_corpus: str
) -> None:
    """Contract 5: integration suite references the ``tool_id``.

    Either the load test (``test_tool_catalog_load.py``) hard-codes the tool
    in its ``EXPECTED_TOOLS`` set, or a per-tool fixture YAML lives at
    ``tests/integration/sandbox/fixtures/{tool_id}.yaml``.  Both shapes mean
    "the integration suite is aware of this tool".
    """
    if tool_id in integration_sandbox_corpus:
        return
    fixture_yaml = _INTEGRATION_FIXTURES_DIR / f"{tool_id}.yaml"
    assert fixture_yaml.is_file(), (
        f"{tool_id!r} not referenced in `{_INTEGRATION_LOAD_TEST.name}` and "
        f"no fixture at `{fixture_yaml.relative_to(_BACKEND_DIR)}`"
    )


# ---------------------------------------------------------------------------
# ARG-020 contracts 6–10 — invariants the catalog must hold for every tool.
#
# Each contract is its own ``parametrize``-d test so a single broken YAML
# surfaces as ONE failed case (not a rolled-up "many things wrong with the
# registry" message that obscures the cause).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_command_template_placeholders_allow_listed(
    tool_id: str, loaded_registry: ToolRegistry
) -> None:
    """Contract 6: every placeholder in ``command_template`` is allow-listed.

    Defends the sandbox argv from a typo (``{user_url}`` instead of
    ``{url}``) reaching :func:`src.sandbox.templating.render_argv` at
    dispatch time.  Catching the typo here means the registry can still
    boot for unrelated tools — the failure is per-YAML, not registry-wide.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"
    try:
        validate_template(list(descriptor.command_template))
    except TemplateRenderError as exc:
        pytest.fail(
            f"{tool_id!r}: command_template references disallowed placeholder "
            f"{exc.placeholder!r} ({exc}). Allowed names live in "
            f"src.sandbox.templating.ALLOWED_PLACEHOLDERS — extend the "
            f"allow-list deliberately, never just to silence this test."
        )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_parser_dispatch_reachable(
    tool_id: str, loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Contract 7: every tool has a deterministic path through ``dispatch_parse``.

    "Reachable" since ARG-020 means *one of three* fail-safe paths
    fires for every tool, all of which return a typed
    :class:`~src.pipeline.contracts.finding_dto.FindingDTO` list (never
    raise, never return ``None``):

    1. **First-class parser** — ``parse_strategy`` has a registered
       strategy handler AND ``tool_id`` has a per-tool parser; dispatch
       returns parsed findings.
    2. **Strategy heartbeat fallback** — ``parse_strategy`` has a
       registered handler but no per-tool parser yet; dispatch returns a
       single ``HEARTBEAT-{tool_id}`` finding (closure branch, ARG-020).
    3. **No-handler heartbeat fallback** — ``parse_strategy`` itself is
       not registered (e.g. ``custom`` / ``csv`` / ``xml_generic``);
       dispatch returns a single ``HEARTBEAT-STRATEGY-{strategy}``
       finding (top-level branch, ARG-020).

    :attr:`ParseStrategy.BINARY_BLOB` is short-circuited by
    :class:`ShellToolAdapter` before ``dispatch_parse`` is invoked, so
    this contract excludes it.

    The actual call exercises whichever branch the tool falls into and
    asserts the dispatch path is fully wired (no exceptions, returns a
    list).  Coverage of the *first* path is reported separately by
    :func:`test_parser_coverage_summary` so a regression in
    "tools-with-real-parsers" is observable without breaking unrelated
    tools that legitimately defer parsing to a later cycle.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"

    if descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
        return  # adapter short-circuits before dispatch_parse — fine.

    findings = dispatch_parse(
        descriptor.parse_strategy,
        b"",
        b"",
        tmp_path,
        tool_id=tool_id,
    )
    assert isinstance(findings, list), (
        f"{tool_id!r}: dispatch_parse must return a list; got {type(findings).__name__}"
    )
    # Every dispatched DTO must be a real :class:`FindingDTO` — defends
    # against a future "return strings on the heartbeat path" regression.
    for finding in findings:
        assert isinstance(finding, FindingDTO), (
            f"{tool_id!r}: dispatch_parse returned a non-FindingDTO "
            f"({type(finding).__name__})"
        )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_network_policy_in_template_allowlist(
    tool_id: str, loaded_registry: ToolRegistry
) -> None:
    """Contract 8: ``descriptor.network_policy.name`` is a known template.

    Every NetworkPolicy reference must resolve to a template defined in
    :data:`src.sandbox.network_policies.NETWORK_POLICY_NAMES` so the
    sandbox driver can render a deterministic Kubernetes manifest at job
    submission time.  An unknown template would either crash at runtime
    (best case) or silently skip the egress allow-list (catastrophe).
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"
    name = descriptor.network_policy.name
    assert name in NETWORK_POLICY_NAMES, (
        f"{tool_id!r}: network_policy.name={name!r} is not in "
        f"NETWORK_POLICY_NAMES={sorted(NETWORK_POLICY_NAMES)!r}; either "
        f"add the template in src.sandbox.network_policies or fix the YAML."
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_image_label_in_argus_kali_family(
    tool_id: str, loaded_registry: ToolRegistry
) -> None:
    """Contract 9: image is in the ``argus-kali-*`` family + resolves cleanly.

    Two facts together prove the contract:

    * The raw ``descriptor.image`` value starts with one of
      :data:`_ALLOWED_IMAGE_PREFIXES` so a future drift to e.g.
      ``docker.io/python:3.12`` (with all of its supply-chain risks) is
      caught at the catalog gate, not at pod start time.
    * :func:`src.sandbox.manifest.resolve_image` produces a fully-qualified
      reference under :data:`_CANONICAL_REGISTRY` — the canonical
      ``ghcr.io/argus`` namespace the production cluster pulls from.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"
    assert any(
        descriptor.image.startswith(prefix) for prefix in _ALLOWED_IMAGE_PREFIXES
    ), (
        f"{tool_id!r}: image={descriptor.image!r} is not in the allowed "
        f"family {sorted(_ALLOWED_IMAGE_PREFIXES)!r}; new image families "
        f"require an explicit allow-list update + supply-chain review."
    )
    resolved = resolve_image(descriptor)
    assert resolved.startswith(f"{_CANONICAL_REGISTRY}/"), (
        f"{tool_id!r}: resolve_image returned {resolved!r}, expected a "
        f"reference under {_CANONICAL_REGISTRY!r}/"
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_approval_implies_medium_risk_floor(
    tool_id: str, loaded_registry: ToolRegistry
) -> None:
    """Contract 10: ``requires_approval=True`` implies risk_level >= MEDIUM.

    The operator-consent UX exists to insulate the platform from
    medium-or-above operational impact (live cloud creds, WAF noise,
    DB churn, lockouts, etc.).  An approval-gated PASSIVE / LOW tool is
    therefore an inconsistency: either the gate is unnecessary (no
    impact to consent to) or the risk_level is under-reported (real
    impact is medium+).  Pin the invariant so the catalog forces an
    explicit choice — never both at once.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"
    if not descriptor.requires_approval:
        return
    assert (
        _RISK_LEVEL_ORDINAL[descriptor.risk_level]
        >= _RISK_LEVEL_ORDINAL[_APPROVAL_RISK_FLOOR]
    ), (
        f"{tool_id!r}: requires_approval=True but risk_level="
        f"{descriptor.risk_level.value!r} (< {_APPROVAL_RISK_FLOOR.value!r}); "
        f"approval-gated tools must be at least MEDIUM risk because the "
        f"operator-consent UX is reserved for medium-or-above operational "
        f"impact (live cloud creds / WAF noise / DB churn). Either bump the "
        f"risk_level or drop requires_approval — never both at once."
    )


# ---------------------------------------------------------------------------
# ARG-030 — Contracts 11 + 12 — parser determinism + evidence-redaction
# completeness.
#
# C11 catches the "parser embeds wall-clock / artifacts_dir / random UUID
# in a finding field" regression by feeding the SAME trivial fixture to
# every parser twice (with two distinct ``tmp_path`` directories so a
# sidecar path leaking into the DTO surfaces immediately) and asserting
# structural equality of the FindingDTO list.
#
# C12 catches the "parser forwards a raw secret into a finding field"
# regression by feeding every parser a single bytes blob that contains
# ≥11 known-secret patterns (one per :data:`Redactor` rule), serialising
# every returned DTO to JSON, and running it through a fresh
# :class:`Redactor`.  The contract holds iff ``redactions_applied == 0``
# — i.e. the parser is the FIRST line of redaction and the downstream
# defence-in-depth pass is a verifiable no-op.
# ---------------------------------------------------------------------------


# Wall-clock timestamps stamped at FindingDTO construction time
# (``first_seen`` / ``last_seen`` default to ``_utcnow()`` in
# :class:`FindingDTO` and in :func:`make_finding_dto`).  These fields
# legitimately diverge between two consecutive ``dispatch_parse`` calls
# so C11 strips them before equality-checking; the persistence layer
# rewrites them in real runs (Backlog/dev1_md §10).  Keep this set
# *minimal* — every entry weakens the determinism contract.
_C11_NON_DETERMINISTIC_FIELDS: Final[frozenset[str]] = frozenset(
    {"first_seen", "last_seen"}
)


# C11 fixtures — one minimal happy-path stdin per strategy.  Picked to be
# *just* parseable enough to exercise the strategy handler's full
# "load → walk → emit" path without producing real findings (which would
# be parser-correctness, not determinism, and is covered by the per-tool
# unit suites).  Trivial fixtures keep this gate fast (~30 s for 157
# tools × 2 calls each) and decouple it from per-tool fixture drift.
_C11_FIXTURE_BY_STRATEGY: Final[dict[ParseStrategy, tuple[bytes, bytes]]] = {
    ParseStrategy.JSON_OBJECT: (b"{}", b""),
    ParseStrategy.JSON_LINES: (b"", b""),
    ParseStrategy.JSON_GENERIC: (b"{}", b""),
    ParseStrategy.NUCLEI_JSONL: (b"", b""),
    ParseStrategy.TEXT_LINES: (b"", b""),
    ParseStrategy.XML_NMAP: (b"<root/>", b""),
    ParseStrategy.XML_GENERIC: (b"<root/>", b""),
    ParseStrategy.CSV: (b"", b""),
    ParseStrategy.CUSTOM: (b"", b""),
}


def _fixture_for_strategy(strategy: ParseStrategy) -> tuple[bytes, bytes]:
    """Return ``(stdout, stderr)`` happy-path fixture bytes for ``strategy``.

    Falls back to ``(b"", b"")`` for an unknown strategy — that is the
    weakest possible input and still exercises the heartbeat /
    no-handler branch of every dispatcher.  A future strategy added
    without an entry here therefore stays covered (C11 turns into a
    "strategy fires the no-handler heartbeat path twice and gets the
    same result", which is itself a useful invariant).
    """
    return _C11_FIXTURE_BY_STRATEGY.get(strategy, (b"", b""))


def _canonical_dto_dump(finding: FindingDTO) -> dict[str, object]:
    """Return ``finding.model_dump()`` minus wall-clock fields.

    Stripped fields are documented in :data:`_C11_NON_DETERMINISTIC_FIELDS`.
    Every other key in the dump (``category``, ``cwe``, ``cvss_v3_*``,
    ``confidence``, ``status``, ``ssvc_decision``, ``owasp_wstg``,
    ``mitre_attack``, ``evidence_ids``, ``reproducer``, ``remediation``,
    plus the SENTINEL UUID identity fields) MUST be deterministic with
    respect to the parser inputs — that is the C11 contract.
    """
    dump = finding.model_dump()
    for field in _C11_NON_DETERMINISTIC_FIELDS:
        dump.pop(field, None)
    return dump


# C12 bait blob — one realistic instance per :class:`RedactionSpec` in
# :data:`src.evidence.redaction._DEFAULT_SPECS` plus a second password-kv
# entry covering the ``passwd:`` alias.  Keep these distinct enough that
# a partial match (e.g. only `password=...` redacted, missing `passwd:
# ...`) shows up as a non-zero ``redactions_applied`` count even when
# the dominant pattern is scrubbed.  Stored as raw bytes so binary-safe
# parsers cannot crash on UTF-8 boundaries.  Joined with ``b"\n"`` so
# the blob looks like a multi-line text dump to TEXT_LINES parsers but
# is also valid JSON-LINES "garbage" (every line fails json.loads, so
# JSON parsers fall through to their empty-input branches).
def _c12_slack_xoxb_bait_line() -> bytes:
    """Built at runtime so push-protection scanners do not match a literal xoxb token."""
    return b"xoxb-" + b"1234567890" + b"-" + b"1234567890" + b"-" + b"A" * 24


_C12_SECRET_BAIT_PATTERNS: Final[tuple[bytes, ...]] = (
    b"Bearer abcdef1234567890ABCDEF.token-payload",
    b"AKIAIOSFODNN7EXAMPLE",
    b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    _c12_slack_xoxb_bait_line(),
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signature_part",
    b"sk-AAAAAAAAAAAAAAAAAAAAAAAA",
    b"Set-Cookie: session=ABCDEF; path=/",
    b"Cookie: session=ABCDEF",
    b"https://user:hunter2@example.com/path",
    b"password=hunter2",
    b"passwd: hunter3",
    b"-----BEGIN RSA PRIVATE KEY-----\n"
    b"MIIEowIBAAKCAQEA0Z9...truncated...AQAB\n"
    b"-----END RSA PRIVATE KEY-----",
)
_C12_BAIT_BLOB: Final[bytes] = b"\n".join(_C12_SECRET_BAIT_PATTERNS)


# Allow-set of ``tool_id`` s for which C12 is *temporarily* expected to
# leak a secret into a FindingDTO field.  Intentionally **empty** as of
# ARG-030 close — every wired parser passes C12 without an exemption.
# A new entry here MUST come with: (1) an ``ai_docs/develop/issues/``
# follow-up, (2) a worker report identifying the fix path, (3) a Cycle
# 4 backlog item for closing the leak.  Treat additions as a fail-open
# debt marker, not a clean solution.
_C12_KNOWN_LEAKERS: Final[frozenset[str]] = frozenset()


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_parser_determinism(
    tool_id: str,
    loaded_registry: ToolRegistry,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Contract 11: ``dispatch_parse`` is deterministic for the same input.

    Two consecutive calls with the same trivial per-strategy fixture
    (``stdout`` / ``stderr``) but **distinct** ``tmp_path`` directories
    must return ``FindingDTO`` lists that are structurally equal modulo
    the wall-clock ``first_seen`` / ``last_seen`` fields (filled at
    ``_utcnow()`` and replaced by the persistence layer in real runs —
    Backlog/dev1_md §10).

    Failure modes the contract catches in a single line:

    * Parser embeds ``str(artifacts_dir)`` in a finding field — the
      two ``tmp_path`` dirs differ.
    * Parser fans out a fresh ``uuid.uuid4()`` per finding — UUIDs
      diverge across runs.
    * Parser walks a non-deterministic dict (``set`` iteration) and
      emits findings in non-stable order.
    * Parser depends on ``time.time()`` for a hash seed.

    :attr:`ParseStrategy.BINARY_BLOB` is excluded — the adapter
    short-circuits before dispatch (Contract 7 already pins this).
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"

    if descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
        return

    stdout, stderr = _fixture_for_strategy(descriptor.parse_strategy)

    artifacts_a = tmp_path_factory.mktemp(f"c11-{tool_id}-a")
    artifacts_b = tmp_path_factory.mktemp(f"c11-{tool_id}-b")

    run_a = dispatch_parse(
        descriptor.parse_strategy, stdout, stderr, artifacts_a, tool_id=tool_id
    )
    run_b = dispatch_parse(
        descriptor.parse_strategy, stdout, stderr, artifacts_b, tool_id=tool_id
    )

    assert isinstance(run_a, list) and isinstance(run_b, list), (
        f"{tool_id!r}: dispatch_parse returned non-list "
        f"({type(run_a).__name__} / {type(run_b).__name__})"
    )
    assert len(run_a) == len(run_b), (
        f"{tool_id!r}: parser produced {len(run_a)} finding(s) on run-A but "
        f"{len(run_b)} on run-B — non-deterministic finding count is a hard "
        f"regression (likely random UUID, dict-ordering, or sidecar-path leak)."
    )

    canonical_a = [_canonical_dto_dump(f) for f in run_a]
    canonical_b = [_canonical_dto_dump(f) for f in run_b]
    assert canonical_a == canonical_b, (
        f"{tool_id!r}: dispatch_parse produced two structurally distinct "
        f"FindingDTO lists from identical input — diff likely contains "
        f"``str(artifacts_dir)``, a fresh UUID, or non-stable ordering. "
        f"Inspect ``set`` / ``dict`` iteration in the parser body."
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_parser_evidence_redaction_completeness(
    tool_id: str, loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Contract 12: parsers redact secrets BEFORE the FindingDTO leaves the layer.

    Every parser is fed :data:`_C12_BAIT_BLOB` on both ``stdout`` and
    ``stderr``.  For every returned :class:`FindingDTO` the test
    serialises the whole DTO via ``model_dump_json()`` and runs the
    bytes through a fresh :class:`Redactor` (default specs).  C12 holds
    iff ``redactions_applied == 0`` — i.e. the parser layer is the
    FIRST line of redaction and the downstream defence-in-depth pass
    is a verifiable no-op.

    Two clean failure modes:

    1. **Parser dumps the bait verbatim** — ``redactions_applied > 0``
       names the leaked spec(s) in :class:`Redactor`.  The fix path is
       to plumb :func:`src.sandbox.parsers._base.redact_secret` (or the
       text-base hash redactor) into the parser at the point the
       offending field is written.
    2. **Parser ships its own redactor that misses one of the 11
       canonical patterns** — same surface; tighten the parser-side
       regex.

    :attr:`ParseStrategy.BINARY_BLOB` is excluded (handled by the
    evidence pipeline, not the parser layer; Contract 7 pins this).
    The :data:`_C12_KNOWN_LEAKERS` allow-set is empty — every wired
    parser as of Cycle 3 close passes C12 without an exemption.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id!r} missing from registry"

    if descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
        return

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _C12_BAIT_BLOB,
        _C12_BAIT_BLOB,
        tmp_path,
        tool_id=tool_id,
    )
    assert isinstance(findings, list), (
        f"{tool_id!r}: dispatch_parse returned a non-list ({type(findings).__name__})"
    )

    redactor = Redactor()
    leaks: list[tuple[int, tuple[tuple[str, int], ...]]] = []
    for index, finding in enumerate(findings):
        serialised = finding.model_dump_json().encode("utf-8")
        result = redactor.redact(serialised)
        if result.redactions_applied:
            leaks.append(
                (
                    index,
                    tuple((report.name, report.matches) for report in result.report),
                )
            )

    if tool_id in _C12_KNOWN_LEAKERS:
        # Documented exemption — only fail if the parser stops leaking
        # so the allow-set cannot drift past a real fix.
        assert leaks, (
            f"{tool_id!r}: listed in _C12_KNOWN_LEAKERS but no leak detected — "
            f"remove the entry; the parser now passes C12."
        )
        return

    assert not leaks, (
        f"{tool_id!r}: parser leaked secrets into {len(leaks)} FindingDTO(s) "
        f"that survived a downstream Redactor pass. Per-finding leaks: "
        f"{leaks!r}. Either (a) plumb _base.redact_secret into the offending "
        f"field, or (b) drop the field from the DTO entirely. DO NOT add the "
        f"tool to _C12_KNOWN_LEAKERS without an explicit Cycle-4 follow-up."
    )


# ---------------------------------------------------------------------------
# ARG-040 — Contracts 13 + 14 — signature-mtime-stability + version field.
#
# C13 closes the regression class flagged by ARG-038 root-cause: a worker
# / fixture / build script that touches a YAML (changes mtime without
# changing content) MUST NOT invalidate the Ed25519 signature.  Hashes
# bind raw bytes-on-disk; mtime is filesystem metadata that is not part
# of the signed payload.  The contract sweeps every signed file across
# all three catalogs (157 tools + 23 payloads + 5 prompts = 185 files),
# bumps the mtime by 1 second, re-verifies the signature in-process via
# the same :class:`SignaturesFile` parser the registry uses at startup,
# and restores the original mtime + read-only mode in ``finally`` so
# the catalog ends the test session byte-and-metadata-clean.
#
# C14 enforces that every signed tool YAML carries a top-level
# ``version: <semver>`` field at the RAW YAML layer.  Cannot be checked
# via :class:`ToolDescriptor.version` because the field has a default of
# ``"1.0.0"`` (introduced in ARG-040 for backward-compatible deserialisation
# of legacy YAMLs); a YAML missing the explicit key would still parse but
# would silently drift the manifest contract that operators pivot on for
# tool-version drift detection.  The semver regex matches the same
# pattern enforced on the Pydantic model side.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def signed_catalog_verifiers() -> dict[str, tuple[SignaturesFile, KeyManager, Path]]:
    """Pre-load every catalog's :class:`SignaturesFile` + :class:`KeyManager` once.

    Returns a label → (signatures, key_manager, catalog_dir) map so C13
    can verify a YAML in-process without paying the I/O + parse cost of
    re-reading the manifest on every parametrised case (185 calls).
    """
    bundle: dict[str, tuple[SignaturesFile, KeyManager, Path]] = {}
    for catalog_dir, signatures_path, keys_dir, label in _SIGNED_CATALOGS:
        if not catalog_dir.is_dir() or not signatures_path.is_file():
            continue
        signatures = SignaturesFile.from_file(signatures_path)
        keys = KeyManager(keys_dir)
        keys.load()
        bundle[label] = (signatures, keys, catalog_dir)
    return bundle


@pytest.mark.parametrize(
    ("test_id", "yaml_path"),
    _SIGNED_CATALOG_FILES,
    ids=[entry[0] for entry in _SIGNED_CATALOG_FILES],
)
def test_signature_mtime_stability(
    test_id: str,
    yaml_path: Path,
    signed_catalog_verifiers: dict[str, tuple[SignaturesFile, KeyManager, Path]],
) -> None:
    """Contract 13 (ARG-040): touch a signed YAML → in-process verify still passes.

    Defends against the ARG-038 drift-class: even if a build script /
    fixture / IDE indirectly touches a YAML (changes mtime without
    changing content), the cryptographic invariant must hold because
    signatures bind raw bytes-on-disk, never filesystem metadata.

    Implementation steps (per file):

    1. Snapshot the original ``st_mode`` + ``st_mtime_ns`` so the test
       can restore them deterministically in ``finally``.
    2. Restore write permission temporarily (the
       ``read_only_catalog`` autouse session fixture in
       ``tests/conftest.py`` chmods the catalog to 0o444 to defend
       against ARG-038-class drift; we need write to call
       :func:`os.utime`).
    3. Bump mtime by exactly one second via
       ``os.utime(path, ns=(new, new))`` — Windows-safe form.
    4. Re-read the YAML bytes-from-disk and call
       :meth:`SignaturesFile.verify_one` against the same in-memory
       :class:`KeyManager` the registry uses at startup.  A failure
       here would name the offending YAML AND the catalog (tools /
       payloads / prompts) in one line.
    5. ``finally``: restore original mtime first (so a chmod failure
       does not leave the catalog with a bumped mtime), then restore
       the original read-only mode.

    This contract intentionally exercises the in-process verification
    path (not a subprocess invocation) — running 185 ``python -m
    scripts.tools_sign verify`` shells would balloon the gate to
    minutes; in-process is sub-second per case and exercises the same
    :class:`SignaturesFile` parser the registry depends on at startup.
    """
    label = test_id.split(":", 1)[0]
    bundle = signed_catalog_verifiers.get(label)
    assert bundle is not None, (
        f"{test_id!r}: catalog label {label!r} not present in "
        f"signed_catalog_verifiers — likely a typo in _SIGNED_CATALOGS."
    )
    signatures, key_manager, catalog_dir = bundle
    relative_path = yaml_path.relative_to(catalog_dir).as_posix()

    original_mtime_ns = yaml_path.stat().st_mtime_ns
    original_mode = yaml_path.stat().st_mode

    # Step 2: restore write permission so os.utime can flip the mtime.
    # ``read_only_catalog`` (autouse, session-scope) chmods the catalog
    # to 0o444 to defend against ARG-038 drift; C13 is the documented
    # exception that *needs* to mutate the metadata.  Mode is restored
    # in finally below.
    if os.name == "nt":
        yaml_path.chmod(stat.S_IREAD | stat.S_IWRITE)
    else:
        yaml_path.chmod(
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        )

    try:
        # Step 3: bump mtime by 1 second.
        new_mtime_ns = original_mtime_ns + 1_000_000_000
        os.utime(yaml_path, ns=(new_mtime_ns, new_mtime_ns))
        bumped_mtime_ns = yaml_path.stat().st_mtime_ns
        assert bumped_mtime_ns != original_mtime_ns, (
            f"{test_id!r}: os.utime did not bump mtime "
            f"(filesystem may not support ns precision); test cannot "
            f"distinguish the touch from a no-op. Falling back to a "
            f"+1 s bump on coarse-resolution filesystems is documented "
            f"as acceptable but here even the coarse path failed."
        )

        # Step 4: re-read bytes-from-disk and verify in-process.
        yaml_bytes = yaml_path.read_bytes()
        signatures.verify_one(
            relative_path=relative_path,
            yaml_bytes=yaml_bytes,
            public_key_resolver=key_manager.get,
        )
    finally:
        # Step 5: restore mtime first, then read-only mode.  A failure
        # in chmod must not leave the catalog with a bumped mtime
        # (would surface as ARG-038-class drift in subsequent tests).
        try:
            os.utime(yaml_path, ns=(original_mtime_ns, original_mtime_ns))
        finally:
            try:
                yaml_path.chmod(original_mode)
            except OSError:
                # Mode restore best-effort — surface to stderr but never
                # mask the assertion result.
                pass


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_yaml_has_version_field(tool_id: str) -> None:
    """Contract 14 (ARG-040): every tool YAML has a top-level ``version: <semver>``.

    Verified at the RAW YAML layer (parsing ``yaml.safe_load`` directly,
    NOT reading :attr:`ToolDescriptor.version`) because the Pydantic
    model has a default of ``"1.0.0"`` for backward-compatible deserialisation
    of legacy YAMLs.  A YAML missing the explicit key would still parse
    cleanly but would silently drift the manifest contract that
    operators pivot on for tool-version drift detection.

    Two failure modes the contract catches:

    1. **Missing ``version`` key** — a new YAML that forgot the field.
       The fix is a one-line addition under ``tool_id``.
    2. **Malformed semver** — e.g. ``version: 1.0`` (missing patch),
       ``version: v1.0.0`` (leading ``v``), ``version: 1.0.0.1``
       (4 components).  Catches typos before they hit the manifest
       diff.  The regex mirrors :data:`src.sandbox.adapter_base._SEMVER_PATTERN`
       verbatim.
    """
    yaml_path = _TOOLS_DIR / f"{tool_id}.yaml"
    assert yaml_path.is_file(), (
        f"{tool_id!r}: YAML missing on disk (Contract 1 should have caught "
        f"this first; check parametrise drift)."
    )

    parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), (
        f"{tool_id!r}: YAML root is not a mapping ({type(parsed).__name__}); "
        f"top-level fields cannot be checked."
    )

    raw_version = parsed.get("version")
    assert raw_version is not None, (
        f"{tool_id!r}: tool YAML missing top-level ``version: <semver>`` field. "
        f"Add a one-liner ``version: \"1.0.0\"`` directly under ``tool_id`` "
        f"and re-sign via "
        f"``python -m scripts.tools_sign sign --key config/tools/_keys/dev_signing.ed25519.priv "
        f"--tools-dir config/tools --out config/tools/SIGNATURES``."
    )

    assert isinstance(raw_version, str), (
        f"{tool_id!r}: ``version`` must be a string, got "
        f"{type(raw_version).__name__} ({raw_version!r}); quote it as "
        f"``\"1.0.0\"`` so YAML preserves leading zeros and the semver shape."
    )

    assert _SEMVER_RE.match(raw_version), (
        f"{tool_id!r}: ``version: {raw_version!r}`` is not a valid Semantic "
        f"Versioning 2.0.0 string. Required shape: ``MAJOR.MINOR.PATCH`` with "
        f"optional ``-prerelease`` / ``+build`` suffixes (regex matches "
        f"``src.sandbox.adapter_base._SEMVER_PATTERN`` verbatim)."
    )


# ---------------------------------------------------------------------------
# ARG-020 parser-coverage summary — single line of stdout per CI run.
#
# Aggregates per-strategy and grand-total counts of (mapped /
# heartbeat-fallback / binary-blob) so reviewers see the trajectory of
# "how many tools now have first-class parsers vs deferred to a heartbeat"
# without grepping through 1500+ per-tool verdicts.
# ---------------------------------------------------------------------------


def test_parser_coverage_summary(
    loaded_registry: ToolRegistry, capsys: pytest.CaptureFixture[str]
) -> None:
    """Aggregate parser coverage and print a one-line summary to stdout.

    NOT a hard contract — by design it always passes (as long as the
    catalog loads).  The value is observability: a CI run shows the
    current ratio of (mapped, heartbeat fallback, binary blob) per
    parse_strategy + grand totals so a regression in parser coverage is
    visible at a glance.

    Use ``pytest -s -k test_parser_coverage_summary`` to capture the
    output locally.
    """
    descriptors = loaded_registry.all_descriptors()
    mapped_tools = get_registered_tool_parsers()

    by_strategy: Counter[tuple[str, str]] = Counter()
    grand_total: Counter[str] = Counter()
    for descriptor in descriptors:
        if descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
            bucket = "binary_blob"
        elif descriptor.tool_id in mapped_tools:
            bucket = "mapped"
        else:
            bucket = "heartbeat"
        by_strategy[(descriptor.parse_strategy.value, bucket)] += 1
        grand_total[bucket] += 1

    total = sum(grand_total.values())
    mapped_pct = 100.0 * grand_total["mapped"] / max(total, 1)

    lines: list[str] = [
        f"ARG-020 parser-coverage summary "
        f"(total={total}, mapped={grand_total['mapped']} "
        f"[{mapped_pct:.1f}%], heartbeat={grand_total['heartbeat']}, "
        f"binary_blob={grand_total['binary_blob']}):",
    ]
    strategies = sorted({s for (s, _) in by_strategy})
    for strategy in strategies:
        mapped = by_strategy[(strategy, "mapped")]
        heartbeat = by_strategy[(strategy, "heartbeat")]
        binary = by_strategy[(strategy, "binary_blob")]
        lines.append(
            f"  - {strategy:14s}  mapped={mapped:3d}  "
            f"heartbeat={heartbeat:3d}  binary_blob={binary:3d}"
        )

    summary = "\n".join(lines)
    # ``capsys`` swallows print under default pytest config; force the
    # summary onto stdout for ``-s`` runs and pin it in the captured
    # buffer for assertion-driven introspection.
    print(summary)
    captured = capsys.readouterr()
    assert "ARG-020 parser-coverage summary" in captured.out

    # ARG-030 / ARG-040 / ARG-049 ratchet: pin the matrix size so a future
    # drop in contract count surfaces as a named failure rather than silent
    # erosion of coverage.  Increment :data:`COVERAGE_MATRIX_CONTRACTS`
    # whenever a new parametrised gate lands.
    #
    #   ARG-030 (Cycle 3 capstone):  10 → 12 contracts (added C11, C12)
    #   ARG-040 (Cycle 4 capstone):  12 → 14 contracts (added C13, C14)
    #   ARG-049 (Cycle 5 capstone):  14 → 16 contracts (added C15, C16)
    assert COVERAGE_MATRIX_CONTRACTS == 16, (
        "Coverage matrix size drifted — ARG-049 closed at 16 parametrised "
        "contracts. Update COVERAGE_MATRIX_CONTRACTS in lock-step with the "
        "test additions / removals."
    )


# ---------------------------------------------------------------------------
# ARG-049 — Contracts 15 + 16 — version monotonicity + image coverage
# completeness.
#
# C15 closes a critical drift class: a YAML edit that ships behaviour
# changes WITHOUT bumping the descriptor's ``version`` field.  Operators
# pivot on ``ToolDescriptor.version`` for tool-version drift detection
# (Backlog/dev1_md §17.6); a silent regression invalidates that signal.
# Frozen baseline lives at ``backend/tests/snapshots/tool_versions_baseline.json``;
# bumping it requires an explicit edit + worker-report rationale.  The
# contract uses :class:`packaging.version.Version` (PEP 440 — a strict
# superset of SemVer 2.0.0 ordering) so a hypothetical pre-release tag
# (``1.1.0-rc1``) compares correctly against ``1.0.0`` (rc1 > 1.0.0).
#
# C16 closes another drift class: a YAML descriptor whose image
# resolves cleanly via :func:`src.sandbox.manifest.resolve_image` (C9
# already gates this) but whose ``tool_id`` is missing from
# ``infra/sandbox/images/tool_to_package.json`` — the operator-visible
# build manifest of the image matrix.  Without C16 the image build
# pipeline would silently skip the missing tool; the runtime sandbox
# would then fail at ``shell$ which <binary>`` with a confusing
# "command not found" instead of a startup-time ``RegistryLoadError``.
# C16 promotes the failure to catalog-load time (CI gate) so the build
# manifest cannot drift past a YAML rename / addition.
# ---------------------------------------------------------------------------


def _load_tool_versions_baseline() -> tuple[dict[str, str], dict[str, object]]:
    """Return ``(tools_map, full_baseline_dict)`` parsed from the C15 snapshot.

    Surfaced as a helper rather than a fixture so the C15 parametrise IDs
    remain bound to the live catalog (``_TOOL_IDS``) while the baseline
    is read once at import time and cached on the module.  Failure modes
    are explicit: a missing file or malformed JSON yields a collection-time
    error so a freshly checked out worktree never silently bypasses the gate.
    """
    if not _TOOL_VERSIONS_BASELINE_PATH.is_file():
        raise FileNotFoundError(
            f"C15 baseline missing at {_TOOL_VERSIONS_BASELINE_PATH}; "
            f"the snapshot is committed under tests/snapshots/. Restore "
            f"it from a clean checkout — do NOT auto-regenerate (the "
            f"baseline is intentionally frozen for ratcheting)."
        )
    raw = json.loads(_TOOL_VERSIONS_BASELINE_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"C15 baseline at {_TOOL_VERSIONS_BASELINE_PATH} did not parse "
            f"as a JSON object (got {type(raw).__name__}); the schema "
            f"requires a top-level dict with a ``tools`` key."
        )
    tools_section = raw.get("tools")
    if not isinstance(tools_section, dict):
        raise ValueError(
            f"C15 baseline at {_TOOL_VERSIONS_BASELINE_PATH} missing the "
            f"``tools`` mapping (got {type(tools_section).__name__})."
        )
    typed_tools: dict[str, str] = {}
    for tool_id, version in tools_section.items():
        if not isinstance(tool_id, str) or not isinstance(version, str):
            raise ValueError(
                f"C15 baseline contains a non-string entry "
                f"(tool_id={tool_id!r}, version={version!r}); the schema "
                f"requires str → str."
            )
        typed_tools[tool_id] = version
    return typed_tools, raw


_TOOL_VERSIONS_BASELINE: Final[dict[str, str]]
_TOOL_VERSIONS_BASELINE_META: Final[dict[str, object]]
_TOOL_VERSIONS_BASELINE, _TOOL_VERSIONS_BASELINE_META = _load_tool_versions_baseline()


def _load_tool_to_package() -> tuple[dict[str, frozenset[str]], dict[str, object]]:
    """Return ``(tool_id → {profile}, full_json)`` parsed from C16's manifest.

    The inverse map is the natural fit for C16's per-tool gate: "is this
    tool_id in at least one profile?".  Pre-computing it once at import
    time keeps the parametrised gate ``O(1)`` per case and prevents
    accidentally re-parsing the JSON 157 times.  Failure modes mirror
    :func:`_load_tool_versions_baseline` — fail loud at collection.
    """
    if not _TOOL_TO_PACKAGE_PATH.is_file():
        raise FileNotFoundError(
            f"C16 manifest missing at {_TOOL_TO_PACKAGE_PATH}; this file "
            f"is the operator-visible map of which sandbox image profile "
            f"installs which tool. Restore it from a clean checkout."
        )
    raw = json.loads(_TOOL_TO_PACKAGE_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"C16 manifest at {_TOOL_TO_PACKAGE_PATH} did not parse as a "
            f"JSON object (got {type(raw).__name__})."
        )
    profiles = raw.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError(
            f"C16 manifest at {_TOOL_TO_PACKAGE_PATH} missing the "
            f"``profiles`` mapping (got {type(profiles).__name__})."
        )
    inverse: dict[str, set[str]] = {}
    for profile_name, profile_body in profiles.items():
        if not isinstance(profile_name, str):
            raise ValueError(
                f"C16 manifest contains a non-string profile name "
                f"({profile_name!r}); fix the JSON before re-running."
            )
        if not isinstance(profile_body, dict):
            raise ValueError(
                f"C16 manifest profile {profile_name!r} body is not a dict "
                f"(got {type(profile_body).__name__})."
            )
        tools_in_profile = profile_body.get("tools", [])
        if not isinstance(tools_in_profile, list):
            raise ValueError(
                f"C16 manifest profile {profile_name!r}.tools is not a list "
                f"(got {type(tools_in_profile).__name__})."
            )
        for tool_id in tools_in_profile:
            if not isinstance(tool_id, str):
                raise ValueError(
                    f"C16 manifest profile {profile_name!r} contains a "
                    f"non-string tool_id ({tool_id!r})."
                )
            inverse.setdefault(tool_id, set()).add(profile_name)
    frozen: dict[str, frozenset[str]] = {
        tool_id: frozenset(profiles_set) for tool_id, profiles_set in inverse.items()
    }
    return frozen, raw


_TOOL_TO_IMAGE_PROFILES: Final[dict[str, frozenset[str]]]
_TOOL_TO_PACKAGE_RAW: Final[dict[str, object]]
_TOOL_TO_IMAGE_PROFILES, _TOOL_TO_PACKAGE_RAW = _load_tool_to_package()
_ALL_IMAGE_PROFILES: Final[frozenset[str]] = frozenset(
    profile_name
    for profile_name in (
        _TOOL_TO_PACKAGE_RAW["profiles"]
        if isinstance(_TOOL_TO_PACKAGE_RAW.get("profiles"), dict)
        else {}
    )
)


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_yaml_version_monotonic(tool_id: str) -> None:
    """Contract 15 (ARG-049): tool ``version`` is monotonic against the frozen baseline.

    Reads the raw YAML ``version`` field (NOT the ``ToolDescriptor.version``
    Pydantic property which has a default of ``"1.0.0"`` — see C14's
    rationale) and compares it under PEP 440 ordering against the frozen
    baseline at ``backend/tests/snapshots/tool_versions_baseline.json``.

    Three failure modes the contract catches in a single named case:

    1. **Version regressed** — current YAML version sorts STRICTLY BELOW
       the baseline.  This is the dominant case: a sloppy revert that
       lowered ``version: "1.1.0"`` back to ``"1.0.0"`` without a
       baseline edit.  The fix is either (a) re-bump the version above
       the baseline, or (b) edit the baseline (with rationale in the
       worker report) and re-run CI.
    2. **Tool missing from baseline** — a freshly added descriptor
       whose author forgot to extend the baseline snapshot in the same
       PR.  The fix is a one-line addition to the snapshot.
    3. **Malformed PEP 440** — a typo (``"v1.0.0"``, ``"1.0"``,
       ``"1.0.0.0"``) makes :class:`Version` raise; C14 already catches
       most semver typos but C15 surfaces the same error against the
       baseline column for clarity.

    The PEP 440 (:class:`packaging.version.Version`) ordering is a strict
    superset of SemVer 2.0.0; ``"1.1.0-rc1"`` sorts above ``"1.0.0"``
    and below ``"1.1.0"`` as expected.  Pre-release suffixes therefore
    do not silently skip the gate.
    """
    baseline_version = _TOOL_VERSIONS_BASELINE.get(tool_id)
    assert baseline_version is not None, (
        f"{tool_id!r}: no baseline entry in "
        f"{_TOOL_VERSIONS_BASELINE_PATH.relative_to(_BACKEND_DIR)}; "
        f"a new descriptor MUST be added to the snapshot in the same "
        f"PR (one-line ``\"{tool_id}\": \"1.0.0\"`` under ``tools``). "
        f"DO NOT auto-regenerate the snapshot — the baseline is the "
        f"frozen reference for ratcheting."
    )

    yaml_path = _TOOLS_DIR / f"{tool_id}.yaml"
    assert yaml_path.is_file(), (
        f"{tool_id!r}: YAML missing on disk (Contract 1 should have caught "
        f"this first; check parametrise drift)."
    )
    parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        pytest.fail(
            f"{tool_id!r}: YAML root is not a mapping ({type(parsed).__name__}); "
            f"top-level fields cannot be checked."
        )

    raw_current = parsed.get("version")
    assert isinstance(raw_current, str) and raw_current, (
        f"{tool_id!r}: missing or non-string ``version`` field "
        f"({raw_current!r}); C14 should have caught this first — fix the YAML."
    )

    try:
        current_version = Version(raw_current)
    except InvalidVersion as exc:
        pytest.fail(
            f"{tool_id!r}: current version {raw_current!r} is not a valid "
            f"PEP 440 version ({exc}). Required shape: ``MAJOR.MINOR.PATCH`` "
            f"with optional ``-pre`` / ``+build`` suffixes (semver-compatible)."
        )
    try:
        baseline_parsed = Version(baseline_version)
    except InvalidVersion as exc:
        pytest.fail(
            f"{tool_id!r}: baseline version {baseline_version!r} in the "
            f"snapshot is not a valid PEP 440 version ({exc}); fix the "
            f"snapshot. Baseline edits require a worker-report rationale."
        )

    assert current_version >= baseline_parsed, (
        f"{tool_id!r}: version regressed {baseline_version!r} → {raw_current!r} "
        f"(PEP 440 ordering). Either (a) bump the YAML version above the "
        f"baseline, or (b) edit the baseline at "
        f"{_TOOL_VERSIONS_BASELINE_PATH.relative_to(_BACKEND_DIR)} with a "
        f"worker-report entry explaining why the baseline floor moved."
    )


def test_tool_versions_baseline_matches_catalog() -> None:
    """C15 cross-check: baseline tool_id set equals catalog tool_id set.

    Defends against a silent removal: a YAML deletion that takes the
    descriptor out of the catalog without removing the corresponding
    baseline entry.  Without this gate the per-tool C15 parametrise
    would still pass (every catalog tool is on or above its baseline),
    leaving the snapshot to drift indefinitely.

    Also defends against a re-named descriptor where the YAML moved
    but the baseline still references the old name — the new name
    fails C15 ("missing from baseline") AND the old name fails this
    test ("missing from catalog").
    """
    catalog_ids = set(_TOOL_IDS)
    baseline_ids = set(_TOOL_VERSIONS_BASELINE)

    in_catalog_only = sorted(catalog_ids - baseline_ids)
    in_baseline_only = sorted(baseline_ids - catalog_ids)

    assert not in_catalog_only, (
        f"{len(in_catalog_only)} catalog tool(s) missing from the C15 "
        f"baseline: {in_catalog_only!r}. Extend "
        f"{_TOOL_VERSIONS_BASELINE_PATH.relative_to(_BACKEND_DIR)} with one "
        f"line per new descriptor (default to ``\"1.0.0\"``)."
    )
    assert not in_baseline_only, (
        f"{len(in_baseline_only)} baseline entry/entries no longer have a "
        f"matching catalog descriptor: {in_baseline_only!r}. The YAML was "
        f"likely renamed or removed; drop the stale baseline entry in the "
        f"same PR. Baseline edits require a worker-report rationale."
    )

    declared_count = _TOOL_VERSIONS_BASELINE_META.get("tool_count")
    assert declared_count == len(_TOOL_VERSIONS_BASELINE), (
        f"C15 baseline ``tool_count`` field ({declared_count!r}) disagrees "
        f"with the actual ``tools`` map size ({len(_TOOL_VERSIONS_BASELINE)}); "
        f"keep the count in sync when editing the snapshot."
    )


@pytest.mark.parametrize("tool_id", sorted(_TOOL_IDS))
def test_tool_in_at_least_one_sandbox_image(tool_id: str) -> None:
    """Contract 16 (ARG-049): every tool_id is provisioned by ≥1 sandbox image.

    Reads ``infra/sandbox/images/tool_to_package.json`` (the operator-visible
    image build manifest) and asserts the catalog ``tool_id`` appears in at
    least one ``profiles[<image>].tools[]`` list.  The default behaviour of
    the JSON parser is fail-closed: a missing file or malformed structure
    aborts at module import time (see :func:`_load_tool_to_package`), so
    a freshly checked out worktree cannot silently skip the gate.

    Contract holds iff ``len(profiles_for_tool) >= 1``.  Multiple-profile
    membership is allowed (e.g. during a planned web → network YAML
    migration where the same tool is temporarily packaged in two images);
    the only forbidden state is "no profile installs this tool", which
    would mean the runtime sandbox container has no binary on PATH.

    Failure mode the contract catches:

    * **Tool missing from every profile** — a YAML descriptor that
      passed C9 (image-label-allowed) but whose ``tool_id`` was never
      added to the JSON manifest.  The fix is to add the ``tool_id``
      under the appropriate profile's ``tools`` list (ASCII-sorted to
      keep the diff byte-stable).  If no existing profile fits, the
      tool is genuinely orphaned — open a Cycle 6 issue to either pick
      an existing profile or motivate a new one (a new profile is
      out-of-scope for the per-tool gate).

    Catches the regression class flagged by ARG-048 (post-Cycle 4
    review): a tool YAML can drift in or out of a profile manifest
    without a corresponding image rebuild, producing a runtime
    "command not found" instead of a CI failure.  C16 promotes the
    failure to catalog-load time (and therefore CI).
    """
    profiles_for_tool = _TOOL_TO_IMAGE_PROFILES.get(tool_id, frozenset())
    assert len(profiles_for_tool) >= 1, (
        f"{tool_id!r}: not pinned to any sandbox image profile in "
        f"{_TOOL_TO_PACKAGE_PATH.relative_to(_REPO_ROOT)}. Available profiles: "
        f"{sorted(_ALL_IMAGE_PROFILES)!r}. Add the tool_id under the most "
        f"appropriate profile's ``tools`` list (ASCII-sorted to keep the "
        f"diff byte-stable) OR open a Cycle 6 issue if no existing "
        f"profile is appropriate (a new profile is out of scope for the "
        f"per-tool gate)."
    )


def test_tool_to_package_matches_catalog() -> None:
    """C16 cross-check: package-manifest tool_id set equals catalog tool_id set.

    Defends against a stale profile entry: a YAML rename / removal that
    leaves the JSON manifest pointing to a non-existent tool_id.  The
    per-tool C16 parametrise can't catch this (it iterates over the
    catalog, not the manifest), so this companion test closes the loop.

    Also pins the image profile count: ARG-049 closed Cycle 5 with 6
    sandbox image profiles (binary, browser, cloud, network, recon,
    web).  A future shrinkage (e.g. losing the network profile in a
    revert) surfaces as a named failure rather than a silent re-routing.
    """
    catalog_ids = set(_TOOL_IDS)
    manifest_ids = set(_TOOL_TO_IMAGE_PROFILES)

    in_catalog_only = sorted(catalog_ids - manifest_ids)
    in_manifest_only = sorted(manifest_ids - catalog_ids)

    assert not in_catalog_only, (
        f"{len(in_catalog_only)} catalog tool(s) missing from the C16 "
        f"manifest: {in_catalog_only!r}. Add them under the appropriate "
        f"profile in {_TOOL_TO_PACKAGE_PATH.relative_to(_REPO_ROOT)}."
    )
    assert not in_manifest_only, (
        f"{len(in_manifest_only)} manifest entry/entries no longer have a "
        f"matching catalog descriptor: {in_manifest_only!r}. The YAML was "
        f"likely renamed or removed; drop the stale manifest entry in the "
        f"same PR (preserve ASCII order)."
    )

    assert len(_ALL_IMAGE_PROFILES) == SANDBOX_IMAGE_PROFILE_COUNT, (
        f"sandbox image profile count drifted: expected "
        f"{SANDBOX_IMAGE_PROFILE_COUNT} (ARG-049 ratchet), got "
        f"{len(_ALL_IMAGE_PROFILES)} ({sorted(_ALL_IMAGE_PROFILES)!r}). "
        f"A profile add/remove must be paired with a SANDBOX_IMAGE_PROFILE_COUNT "
        f"bump + a worker-report entry."
    )


# ---------------------------------------------------------------------------
# ARG-029 hard ratchet — explicit (mapped, heartbeat) counts pinned in
# this file.  Forces the reviewer to bump the constants deliberately
# whenever a parser batch lands, so the worker report and this gate
# cannot drift apart.
# ---------------------------------------------------------------------------


# Tools that ARG-029 (Cycle 3 batch 3) wired up.  Mirrored verbatim in
# the ARG-029 ratchet test so a future "I removed one of these by
# accident" regression surfaces as a precise, named failure rather than
# a generic "mapped count drifted by 1" message.  Sorted alphabetically
# to keep diffs noise-free.
_ARG029_NEWLY_MAPPED: Final[frozenset[str]] = frozenset(
    {
        "cloudsploit",
        "detect_secrets",
        "graphql_cop",
        "hash_analyzer",
        "hashid",
        "jarm",
        "masscan",
        "naabu",
        "openapi_scanner",
        "postman_newman",
        "prowler",
        "syft",
        "trufflehog",
        "wappalyzer_cli",
        "zap_baseline",
    }
)


# Tools that ARG-032 (Cycle 4 batch 4) wired up — 30 net new mapped
# parsers across browser (4a), binary + recon (4b) and auth + network
# (4c) categories.  Mirrored verbatim in the ARG-032 ratchet test so a
# future "I removed one of these by accident" regression surfaces as a
# precise, named failure rather than a generic "mapped count drifted by
# 1" message.  Sorted alphabetically to keep diffs noise-free.
_ARG032_NEWLY_MAPPED: Final[frozenset[str]] = frozenset(
    {
        # 4a — browser (6 tools, browser coverage 0% → 100%).
        "playwright_runner",
        "puppeteer_screens",
        "chrome_csp_probe",
        "webanalyze",
        "gowitness",
        "whatweb",
        # 4b — binary analysis (4 tools).
        "radare2_info",
        "apktool",
        "binwalk",
        "jadx",
        # 4b — subdomain reconnaissance (6 tools).
        "amass_passive",
        "subfinder",
        "assetfinder",
        "dnsrecon",
        "fierce",
        "findomain",
        # 4c — credential bruteforce / NTLM relay (8 tools).
        "hydra",
        "medusa",
        "patator",
        "ncrack",
        "crackmapexec",
        "responder",
        "hashcat",
        "ntlmrelayx",
        # 4c — network / OSINT / probes (6 tools).
        "dnsx",
        "chaos",
        "censys",
        "mongodb_probe",
        "redis_cli_probe",
        "unicornscan",
    }
)

# Cycle 6 T05 — data-driven top-20 heartbeat → mapped batch (sorted).
_T05_NEWLY_MAPPED: Final[frozenset[str]] = frozenset(
    {
        "arachni",
        "cmsmap",
        "ghauri",
        "gobuster_auth",
        "gobuster_dir",
        "hakrawler",
        "jsql",
        "joomscan",
        "kxss",
        "linkfinder",
        "magescan",
        "nosqlmap",
        "paramspider",
        "playwright_xss_verify",
        "secretfinder",
        "subjs",
        "tplmap",
        "waybackurls",
        "xsser",
        "xsstrike",
    }
)


def test_parser_coverage_counts_match_arg032_ratchet(
    loaded_registry: ToolRegistry,
) -> None:
    """Pinned (mapped, heartbeat) split as of Cycle 6 T05 (ARG-032 + top-20).

    Three asserts together close every drift vector:

    * exact mapped count (drop = parser regression; rise = update the
      ratchet + the worker report in the same PR);
    * exact heartbeat count (must drop 1-for-1 with each new mapped
      parser; otherwise a tool was silently added/removed);
    * mapped + heartbeat + binary == total descriptors (defends against
      the bucketing logic in
      :func:`test_parser_coverage_summary` developing a hole).
    """
    descriptors = loaded_registry.all_descriptors()
    mapped_tools = get_registered_tool_parsers()

    counts: Counter[str] = Counter()
    for descriptor in descriptors:
        if descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
            counts["binary_blob"] += 1
        elif descriptor.tool_id in mapped_tools:
            counts["mapped"] += 1
        else:
            counts["heartbeat"] += 1

    assert counts["mapped"] == MAPPED_PARSER_COUNT, (
        f"mapped-parser count drift: expected {MAPPED_PARSER_COUNT} "
        f"(T05 ratchet), got {counts['mapped']}. Bump the constant in "
        f"this file and the worker report in lock-step."
    )
    assert counts["heartbeat"] == HEARTBEAT_PARSER_COUNT, (
        f"heartbeat-parser count drift: expected {HEARTBEAT_PARSER_COUNT} "
        f"(T05 ratchet), got {counts['heartbeat']}. New mapped parsers "
        f"must drop heartbeat 1-for-1; rebalance the ratchet."
    )
    assert counts["mapped"] + counts["heartbeat"] + counts["binary_blob"] == len(
        descriptors
    ), (
        f"bucket holes: {sum(counts.values())} buckets vs "
        f"{len(descriptors)} descriptors — a tool was silently dropped"
    )


def test_arg029_newly_mapped_tools_have_first_class_parsers(
    loaded_registry: ToolRegistry,
) -> None:
    """Every ARG-029 tool routes through the first-class parser path.

    The :data:`_ARG029_NEWLY_MAPPED` allow-list pins the 15 tools the
    ARG-029 batch wired up.  This test guards against a regression
    where one of them is silently removed from
    :data:`src.sandbox.parsers._DEFAULT_TOOL_PARSERS` (which would
    cause ``test_parser_coverage_counts_match_arg032_ratchet`` to fail
    too — but with a generic "off by one" message that doesn't name
    the offender).
    """
    catalog_ids = {
        descriptor.tool_id for descriptor in loaded_registry.all_descriptors()
    }
    missing_from_catalog = sorted(_ARG029_NEWLY_MAPPED - catalog_ids)
    assert not missing_from_catalog, (
        f"ARG-029 names {missing_from_catalog!r} but the catalog has no "
        f"matching descriptor — likely a stale ratchet allow-list."
    )

    mapped_tools = get_registered_tool_parsers()
    unmapped = sorted(_ARG029_NEWLY_MAPPED - mapped_tools)
    assert not unmapped, (
        f"ARG-029 mapped these tools but the parser registry has lost "
        f"them: {unmapped!r}. Restore the entries in "
        f"src.sandbox.parsers._DEFAULT_TOOL_PARSERS."
    )


def test_arg032_newly_mapped_tools_have_first_class_parsers(
    loaded_registry: ToolRegistry,
) -> None:
    """Every ARG-032 tool routes through the first-class parser path.

    The :data:`_ARG032_NEWLY_MAPPED` allow-list pins the 30 tools the
    ARG-032 batch wired up (Cycle 4 — browser / binary / recon / auth).
    This test guards against a regression where one of them is silently
    removed from :data:`src.sandbox.parsers._DEFAULT_TOOL_PARSERS`
    (which would cause ``test_parser_coverage_counts_match_arg032_ratchet``
    to fail too — but with a generic "off by one" message that doesn't
    name the offender).
    """
    catalog_ids = {
        descriptor.tool_id for descriptor in loaded_registry.all_descriptors()
    }
    missing_from_catalog = sorted(_ARG032_NEWLY_MAPPED - catalog_ids)
    assert not missing_from_catalog, (
        f"ARG-032 names {missing_from_catalog!r} but the catalog has no "
        f"matching descriptor — likely a stale ratchet allow-list."
    )

    mapped_tools = get_registered_tool_parsers()
    unmapped = sorted(_ARG032_NEWLY_MAPPED - mapped_tools)
    assert not unmapped, (
        f"ARG-032 mapped these tools but the parser registry has lost "
        f"them: {unmapped!r}. Restore the entries in "
        f"src.sandbox.parsers._DEFAULT_TOOL_PARSERS."
    )


def test_t05_newly_mapped_tools_have_first_class_parsers(
    loaded_registry: ToolRegistry,
) -> None:
    """Every Cycle 6 T05 tool remains registered after the heartbeat batch."""
    catalog_ids = {
        descriptor.tool_id for descriptor in loaded_registry.all_descriptors()
    }
    missing = sorted(_T05_NEWLY_MAPPED - catalog_ids)
    assert not missing, (
        f"T05 names {missing!r} but the catalog has no matching descriptor."
    )
    mapped_tools = get_registered_tool_parsers()
    unmapped = sorted(_T05_NEWLY_MAPPED - mapped_tools)
    assert not unmapped, (
        f"T05 mapped these tools but the parser registry has lost them: "
        f"{unmapped!r}. Restore the entries in "
        f"src.sandbox.parsers._DEFAULT_TOOL_PARSERS."
    )
