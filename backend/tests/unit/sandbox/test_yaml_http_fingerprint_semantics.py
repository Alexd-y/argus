"""Per-§4.4 invariant tests for the HTTP-fingerprinting tool YAMLs (ARG-011).

Sister suite to ``test_yaml_schema_per_tool.py`` — that file enforces *catalog
wide* schema invariants (file present, parses, allow-listed placeholders,
``argus-kali-*`` image namespace, sane timeout). This file pins the *§4.4
specific* invariants laid out by the ARG-011 cycle plan that the parametrised
catalog suite cannot express:

* ``phase: recon``, ``risk_level: passive``, ``requires_approval: false`` —
  every §4.4 tool is read-only HTTP fingerprinting.
* ``image: argus-kali-web:latest`` AND the corresponding Dockerfile stub
  exists at ``sandbox/images/argus-kali-web/Dockerfile``. The runtime
  contract and the build artefact must agree at lockstep.
* ``network_policy.name`` is one of the templates seeded in
  :mod:`src.sandbox.network_policies` — a typo there ships a job that the
  k8s adapter would reject at run-time.
* ``evidence_artifacts`` is non-empty (paths under ``/out`` or a sub-dir),
  so the evidence pipeline has something to upload.
* ``cwe_hints`` is present (may be ``[]`` for fingerprinting — explicit
  empty list keeps the field schema-stable across batches).
* Parser dispatch split: ``httpx.yaml`` declares ``json_lines`` (cycle 2
  parser ARG-011 ships); the eight others declare ``json_object`` (their
  parsers land in cycle 3).
* ``default_timeout_s ≥ 60`` (a 30-second bound is too tight for a TLS
  handshake fan-out). cpu / memory limits are set.
* The ``command_template`` argv carries no shell metacharacters that a
  hypothetical bypass of :func:`render_argv` could weaponise.

These tests parse the raw YAML directly (no signature verification) so they
stay collection-cheap and re-runnable without keys.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import ParseStrategy, ToolCategory, ToolDescriptor
from src.sandbox.network_policies import NETWORK_POLICY_NAMES


# §4.4 tools added by ARG-011. Hard-coded so a silent shrink of the
# fingerprinting batch breaks CI immediately.
HTTP_FINGERPRINT_TOOL_IDS: Final[tuple[str, ...]] = (
    "httpx",
    "whatweb",
    "wappalyzer_cli",
    "webanalyze",
    "aquatone",
    "gowitness",
    "eyewitness",
    "favfreak",
    "jarm",
)


# Single tool that ships a real parser in this cycle (ARG-011); the rest
# declare json_object because their parsers land later.
JSON_LINES_TOOL: Final[str] = "httpx"


# Shell metacharacters that must NOT appear in a YAML argv. The sandbox
# templating layer already refuses them in placeholder VALUES at render
# time; pinning them here in raw template TOKENS guards against an author
# adding e.g. ``"sh -c ..."`` constructions in a future descriptor.
SHELL_METACHARS: Final[tuple[str, ...]] = (
    ";",
    "|",
    "&&",
    "||",
    "&",
    "`",
    "$(",
    ">",
    "<",
    "\n",
    "\r",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _catalog_dir() -> Path:
    """Locate ``backend/config/tools/`` from this test file's path.

    ``parents`` indices for ``backend/tests/unit/sandbox/<file>.py``:
    ``[0]=sandbox, [1]=unit, [2]=tests, [3]=backend``.
    """
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    return backend_dir / "config" / "tools"


def _images_dir() -> Path:
    """Locate ``sandbox/images/`` from this test file's path.

    Repo root sits one above the ``backend/`` directory, so we walk four
    levels up from ``backend/tests/unit/sandbox/<file>.py``.
    """
    here = Path(__file__).resolve()
    repo_root = here.parents[4]
    return repo_root / "sandbox" / "images"


@pytest.fixture(scope="module")
def catalog_dir() -> Path:
    catalog = _catalog_dir()
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def images_dir() -> Path:
    images = _images_dir()
    assert images.is_dir(), f"expected sandbox images dir at {images}"
    return images


def _load_descriptor(catalog_dir: Path, tool_id: str) -> ToolDescriptor:
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert isinstance(payload, dict), (
        f"{tool_id}.yaml must be a YAML mapping at the top level"
    )
    return ToolDescriptor(**payload)


# ---------------------------------------------------------------------------
# Inventory completeness
# ---------------------------------------------------------------------------


def test_inventory_contains_exactly_nine_tools() -> None:
    """The §4.4 batch is exactly nine tools — drift breaks alignment with
    Backlog/dev1_md §4.4 and the HTTP_FINGERPRINT_TOOLS set in the
    integration suite ``test_tool_catalog_load.py``.
    """
    assert len(HTTP_FINGERPRINT_TOOL_IDS) == 9
    assert len(set(HTTP_FINGERPRINT_TOOL_IDS)) == 9


# ---------------------------------------------------------------------------
# Phase / risk / approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_phase_recon_risk_passive_no_approval(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.4 tool is read-only passive recon — no approval required."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.phase is ScanPhase.RECON, (
        f"{tool_id} phase must be recon, got {descriptor.phase}"
    )
    assert descriptor.risk_level is RiskLevel.PASSIVE, (
        f"{tool_id} risk_level must be passive, got {descriptor.risk_level}"
    )
    assert descriptor.requires_approval is False
    assert descriptor.category is ToolCategory.RECON


# ---------------------------------------------------------------------------
# Image namespace + Dockerfile existence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_image_is_argus_kali_web_latest(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.image == "argus-kali-web:latest", (
        f"{tool_id} image must be argus-kali-web:latest, got {descriptor.image!r}"
    )


def test_argus_kali_web_dockerfile_stub_exists(images_dir: Path) -> None:
    """The image referenced by every §4.4 YAML must have a buildable stub.

    The actual tool installation graph lands in cycle 3 (per the stub
    Dockerfile header); for now we only require the file to exist so the
    CI build pipeline can `docker build` the placeholder image without a
    "no such file" failure.
    """
    dockerfile = images_dir / "argus-kali-web" / "Dockerfile"
    assert dockerfile.is_file(), (
        f"missing Dockerfile stub at {dockerfile} — every YAML referencing "
        "argus-kali-web:latest needs a corresponding image directory"
    )
    head = dockerfile.read_text(encoding="utf-8").splitlines()[0]
    assert head.startswith("#") or head.startswith("FROM "), (
        f"unexpected first line in {dockerfile}: {head!r}"
    )


# ---------------------------------------------------------------------------
# Network policy — name must resolve in the seeded template registry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_network_policy_name_is_a_known_template(
    catalog_dir: Path, tool_id: str
) -> None:
    """A YAML cannot reference a NetworkPolicy template that doesn't exist."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name in NETWORK_POLICY_NAMES, (
        f"{tool_id} references unknown network policy "
        f"{descriptor.network_policy.name!r}; "
        f"known: {sorted(NETWORK_POLICY_NAMES)}"
    )


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_network_policy_is_recon_passive(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.4 tool sits behind the ``recon-passive`` policy template."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name == "recon-passive", (
        f"{tool_id} expected recon-passive, got {descriptor.network_policy.name!r}"
    )


# ---------------------------------------------------------------------------
# Evidence + CWE field presence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_evidence_artifacts_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """The evidence pipeline needs at least one artefact path per tool."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.evidence_artifacts, f"{tool_id} must declare evidence_artifacts"
    for path in descriptor.evidence_artifacts:
        assert path.startswith("/out"), (
            f"{tool_id} evidence path {path!r} must live under /out"
        )


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_cwe_hints_field_present_even_if_empty(catalog_dir: Path, tool_id: str) -> None:
    """``cwe_hints`` is a stable field; an empty list is acceptable for
    fingerprinting but ``None`` / missing key would slip past the
    integration tests because Pydantic defaults to ``[]``. This test
    re-reads the raw YAML and verifies the key is explicitly present so
    the YAML stays self-documenting.
    """
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert "cwe_hints" in payload, f"{tool_id}.yaml is missing the cwe_hints key"
    assert isinstance(payload["cwe_hints"], list), (
        f"{tool_id}.yaml cwe_hints must be a list (may be empty)"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_parse_strategy_split_httpx_jsonl_others_object(
    catalog_dir: Path, tool_id: str
) -> None:
    """ARG-011 ships a single JSONL parser (httpx); the others declare
    ``json_object`` until their parsers land in cycle 3.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    if tool_id == JSON_LINES_TOOL:
        assert descriptor.parse_strategy is ParseStrategy.JSON_LINES
    else:
        assert descriptor.parse_strategy is ParseStrategy.JSON_OBJECT, (
            f"{tool_id} expected json_object until its parser lands, "
            f"got {descriptor.parse_strategy.value!r}"
        )


# ---------------------------------------------------------------------------
# Resource limits + timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_default_timeout_at_least_60s(catalog_dir: Path, tool_id: str) -> None:
    """Below 60s some tools (aquatone, eyewitness) fail to even cold-start."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.default_timeout_s >= 60, (
        f"{tool_id} default_timeout_s={descriptor.default_timeout_s}s too low"
    )


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_cpu_and_memory_limits_set(catalog_dir: Path, tool_id: str) -> None:
    """``cpu_limit`` / ``memory_limit`` are k8s-style strings; non-empty."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.cpu_limit, f"{tool_id} has empty cpu_limit"
    assert descriptor.memory_limit, f"{tool_id} has empty memory_limit"
    assert descriptor.seccomp_profile == "runtime/default", (
        f"{tool_id} must use seccomp_profile=runtime/default, "
        f"got {descriptor.seccomp_profile!r}"
    )


# ---------------------------------------------------------------------------
# Argv shell-metachar audit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HTTP_FINGERPRINT_TOOL_IDS)
def test_command_template_has_no_shell_metacharacters(
    catalog_dir: Path, tool_id: str
) -> None:
    """No argv token may contain shell metacharacters.

    Defence-in-depth on top of the templating allow-list: an author who
    accidentally inlined a ``"sh -c ..."`` form would slip past the
    placeholder check (no ``{...}`` in the string) but produce a
    shell-injectable argv element here. Pinning the raw token charset
    closes that loophole at YAML-author time.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    offenders: list[tuple[str, str]] = []
    for token in descriptor.command_template:
        for meta in SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"{tool_id} command_template contains shell metacharacters: {offenders}"
    )
