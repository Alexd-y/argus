"""ARG-058 (Cycle 6, T03) — network-tool YAML migration regression suite.

T03 flipped 16 dual-listed tools from ``image: argus-kali-web:latest`` to
``image: argus-kali-network:latest`` in ``backend/config/tools/`` and
synchronised the operator-visible image manifest at
``infra/sandbox/images/tool_to_package.json`` (schema_version bumped
1.1.0 → 1.2.0; dual-listed count 16 → 0; ``argus-kali-web.tools`` shrank
91 → 75 entries; ``argus-kali-network.tools`` now has the migrated 16).

This module pins the migration outcome with seven targeted regression
tests so a future YAML edit / manifest revert / metadata typo cannot
silently undo the work. The broad invariants (image-label-allowed,
image-coverage-completeness) remain owned by
``test_tool_catalog_coverage.py`` (C9 + C16). The cases here are
migration-aware:

1. Per-tool YAML ``image`` is exactly ``argus-kali-network:latest``.
2. Per-tool YAML still has the full set of pre-migration top-level
   keys (the worker contract was "only touch the ``image`` field").
3. ``tool_to_package.json`` has zero pairwise profile intersection
   (dual-listed count = 0).
4. ``argus-kali-network.tools`` equals the 16 migrated ``tool_id`` set.
5. ``argus-kali-web.tools`` is disjoint from the 16 migrated ``tool_id``
   set (the migration removed them from web).
6. ``tool_to_package.json::schema_version == "1.2.0"``.
7. ``ai_docs/develop/issues/ISS-cycle6-carry-over.md`` marks ARG-058
   as RESOLVED in the surrounding section.

Hard isolation rules (do NOT relax):

* No imports from ``src.sandbox.tool_registry`` — the YAML edits
  invalidated 16 entries in ``backend/config/tools/SIGNATURES`` and
  the re-sign step is a CI/operator concern out-of-scope for the
  test-writer (worker had no private-key access). Reading raw YAML /
  JSON via :func:`yaml.safe_load` / :func:`json.load` keeps this
  module green on a worker checkout (pre-resign) AND on a CI checkout
  (post-resign) — the contract is fail-closed at the file layer, not
  at the cryptographic layer.
* No subprocess, no Docker, no network — pure file IO. Module
  runtime budget < 200 ms.
* The autouse parent ``override_auth`` fixture (from
  ``backend/tests/conftest.py``) is shadowed by a no-op so this
  module does not transitively import ``main.app`` (FastAPI + DB
  stack) at collection time.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
import yaml

# ---------------------------------------------------------------------------
# Single source of truth for the 16 ``tool_id`` s migrated by ARG-058.
#
# Sorted ASCII to match the byte layout of
# ``argus-kali-network.tools`` in ``infra/sandbox/images/tool_to_package.json``
# (the file is byte-stable across Git diffs because every list is
# alphabetised at write time). Drift in this tuple = migration drift.
# ---------------------------------------------------------------------------
MIGRATED_TOOL_IDS: Final[tuple[str, ...]] = (
    "bloodhound_python",
    "crackmapexec",
    "evil_winrm",
    "ike_scan",
    "impacket_examples",
    "impacket_secretsdump",
    "kerbrute",
    "ldapsearch",
    "mongodb_probe",
    "ntlmrelayx",
    "onesixtyone",
    "redis_cli_probe",
    "responder",
    "smbclient",
    "snmp_check",
    "snmpwalk",
)


# Expected post-migration target image label.
_TARGET_IMAGE_LABEL: Final[str] = "argus-kali-network:latest"

# Expected pre-migration source image label (must be ABSENT from every
# migrated YAML now). Surfaced as a constant so the failure assertion can
# reference it explicitly without copy-pasting the string.
_SOURCE_IMAGE_LABEL: Final[str] = "argus-kali-web:latest"

# tool_to_package.json schema version pin (worker bumped 1.1.0 → 1.2.0
# alongside the migration; the bump signals to JSON consumers that the
# ``$comment`` / ``generated_by`` / per-profile ``purpose`` semantics
# changed).
_EXPECTED_SCHEMA_VERSION: Final[str] = "1.2.0"

# YAML top-level keys that every migrated descriptor must STILL carry —
# proves the worker only touched the ``image`` field. Derived from the
# raw YAML pre-edit (all 16 share the same uniform 18-key schema). A
# missing key means the worker accidentally dropped a field; the test
# does NOT pin "no extra keys" because a brand-new key would also
# surface in the strict-mode :class:`ToolDescriptor` parser at registry
# load time (covered by ``test_tool_catalog_coverage.py`` C3).
_REQUIRED_YAML_KEYS: Final[frozenset[str]] = frozenset(
    {
        "tool_id",
        "version",
        "category",
        "phase",
        "risk_level",
        "requires_approval",
        "default_timeout_s",
        "cpu_limit",
        "memory_limit",
        "seccomp_profile",
        "network_policy",
        "image",
        "command_template",
        "parse_strategy",
        "evidence_artifacts",
        "cwe_hints",
        "owasp_wstg",
        "description",
    }
)


# ---------------------------------------------------------------------------
# Path constants — every read is bounded to one of these three roots.
# ---------------------------------------------------------------------------


_BACKEND_DIR: Final[Path] = Path(__file__).resolve().parent.parent
_REPO_ROOT: Final[Path] = _BACKEND_DIR.parent

_TOOLS_DIR: Final[Path] = _BACKEND_DIR / "config" / "tools"
_TOOL_TO_PACKAGE_PATH: Final[Path] = (
    _REPO_ROOT / "infra" / "sandbox" / "images" / "tool_to_package.json"
)
_ISS_CYCLE6_PATH: Final[Path] = (
    _REPO_ROOT / "ai_docs" / "develop" / "issues" / "ISS-cycle6-carry-over.md"
)


# ---------------------------------------------------------------------------
# Auto-use override: shadow the heavy parent ``override_auth`` fixture so
# this module does not pull in ``main.app`` (FastAPI + DB stack) for what
# is a pure-file inspection. Mirrors the approach used by
# ``test_tool_catalog_coverage.py`` — see ``backend/tests/conftest.py``
# for the upstream override that takes ``app`` as a dependency.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """No-op shadow of ``backend/tests/conftest.py::override_auth``.

    The parent autouse fixture takes ``app`` as a dependency, which
    imports ``main`` and therefore the whole FastAPI / DB stack.  ARG-058
    regression tests are pure file inspection; we MUST not pay that
    startup cost (and MUST not require those services to be available).
    """
    yield


# ---------------------------------------------------------------------------
# Module-scoped fixtures — each computed once per session, not per-test.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tool_to_package_json() -> dict[str, object]:
    """Load ``infra/sandbox/images/tool_to_package.json`` exactly once.

    Failure here surfaces as a fixture-error so every dependent test is
    skipped with a single named cause rather than N lookalike failures.
    """
    if not _TOOL_TO_PACKAGE_PATH.is_file():
        pytest.fail(
            f"tool_to_package.json missing at "
            f"{_TOOL_TO_PACKAGE_PATH.relative_to(_REPO_ROOT)} — the "
            f"operator-visible image build manifest must be present for "
            f"ARG-058 regression tests to run."
        )
    raw = json.loads(_TOOL_TO_PACKAGE_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        pytest.fail(
            f"{_TOOL_TO_PACKAGE_PATH.relative_to(_REPO_ROOT)} did not "
            f"parse as a JSON object (got {type(raw).__name__})."
        )
    return raw


@pytest.fixture(scope="module")
def profile_tool_sets(
    tool_to_package_json: dict[str, object],
) -> dict[str, frozenset[str]]:
    """Return ``profile_name → frozenset(tool_ids)`` extracted from the JSON.

    Centralised because every set-based contract (no-dual-listing,
    network-equality, web-disjoint) needs the same view of the JSON.
    Returns a frozen mapping so a downstream test cannot accidentally
    mutate the manifest view.
    """
    profiles = tool_to_package_json.get("profiles")
    if not isinstance(profiles, dict):
        pytest.fail(
            f"tool_to_package.json missing the ``profiles`` mapping "
            f"(got {type(profiles).__name__})."
        )
    extracted: dict[str, frozenset[str]] = {}
    for profile_name, profile_body in profiles.items():
        if not isinstance(profile_name, str) or not isinstance(profile_body, dict):
            pytest.fail(
                f"tool_to_package.json contains a malformed profile entry "
                f"(name={profile_name!r}, body type="
                f"{type(profile_body).__name__})."
            )
        tools = profile_body.get("tools")
        if not isinstance(tools, list) or not all(
            isinstance(entry, str) for entry in tools
        ):
            pytest.fail(
                f"tool_to_package.json profile {profile_name!r}.tools is "
                f"not a list[str] (got {type(tools).__name__})."
            )
        extracted[profile_name] = frozenset(tools)
    return extracted


# ---------------------------------------------------------------------------
# Per-tool YAML contracts — each must hold for every migrated tool.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", MIGRATED_TOOL_IDS)
def test_arg058_image_pinned_to_network(tool_id: str) -> None:
    """For each migrated tool, YAML ``image`` is exactly the network image.

    Defends against a YAML revert that flips the field back to the
    pre-migration ``argus-kali-web:latest`` value or to any other image
    family. Intentionally a strict equality check (not a startswith /
    family-prefix scan) so a typo like ``argus-kali-network-latest`` or
    ``argus-kali-network:edge`` fails loud at the catalog gate, not at
    pod-start time.
    """
    yaml_path = _TOOLS_DIR / f"{tool_id}.yaml"
    assert yaml_path.is_file(), (
        f"{tool_id!r}: YAML descriptor missing at "
        f"{yaml_path.relative_to(_BACKEND_DIR)}"
    )
    parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), (
        f"{tool_id!r}: YAML root is not a mapping ({type(parsed).__name__})"
    )
    image = parsed.get("image")
    assert image == _TARGET_IMAGE_LABEL, (
        f"{tool_id!r}: image={image!r}, expected {_TARGET_IMAGE_LABEL!r}. "
        f"ARG-058 migrated this tool from {_SOURCE_IMAGE_LABEL!r} → "
        f"{_TARGET_IMAGE_LABEL!r}; a revert here is a migration regression. "
        f"Restore the field and re-sign via "
        f"`python -m scripts.tools_sign sign-all`."
    )


@pytest.mark.parametrize("tool_id", MIGRATED_TOOL_IDS)
def test_arg058_yaml_field_count_unchanged_for_migrated(tool_id: str) -> None:
    """Migrated YAMLs must still carry every pre-migration top-level key.

    The worker contract for T03 was "only touch the ``image`` field".
    The 18 keys in :data:`_REQUIRED_YAML_KEYS` are the union pre-edit;
    if any key is missing post-edit the worker accidentally dropped
    data and the descriptor would either fail Pydantic strict-mode
    parsing at registry load time (best case) or silently drift the
    schema (catastrophe).

    This is a subset-check, not an exact-equality check: a brand-new
    key would also surface at :class:`src.sandbox.adapter_base.ToolDescriptor`
    parse time (covered by ``test_tool_catalog_coverage.py`` C3 with
    ``extra=forbid``), so we keep the regression message focused on
    the more likely failure mode (a removed field).
    """
    yaml_path = _TOOLS_DIR / f"{tool_id}.yaml"
    parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict), (
        f"{tool_id!r}: YAML root is not a mapping ({type(parsed).__name__})"
    )
    actual_keys = frozenset(parsed.keys())
    missing = _REQUIRED_YAML_KEYS - actual_keys
    assert not missing, (
        f"{tool_id!r}: YAML lost top-level key(s) after the ARG-058 "
        f"migration: {sorted(missing)!r}. The migration contract was "
        f"'only touch image:'; a missing key means the worker "
        f"accidentally dropped data — restore from the pre-migration "
        f"baseline (e.g. `git show HEAD~1:backend/config/tools/{tool_id}.yaml`) "
        f"and re-sign."
    )


# ---------------------------------------------------------------------------
# Manifest-level contracts — derived from ``tool_to_package.json``.
# ---------------------------------------------------------------------------


def test_arg058_no_dual_listing_in_tool_to_package_json(
    profile_tool_sets: dict[str, frozenset[str]],
) -> None:
    """Every pair of profiles is disjoint — i.e. dual-listed count == 0.

    Pre-ARG-058 the JSON had 16 ``tool_id`` s in BOTH ``argus-kali-web``
    and ``argus-kali-network`` (a deliberate transition state to spread
    risk across cycles). Post-ARG-058 the only acceptable count is 0;
    any non-empty pairwise intersection is a migration regression.

    The check is profile-pairwise so a future regression also catches
    e.g. an accidental copy of a ``recon`` tool into ``web`` (not just
    web ↔ network), without needing to enumerate each pair manually.
    """
    profile_names = sorted(profile_tool_sets)
    duplicates: list[tuple[str, str, list[str]]] = []
    for left in range(len(profile_names)):
        for right in range(left + 1, len(profile_names)):
            left_name = profile_names[left]
            right_name = profile_names[right]
            shared = profile_tool_sets[left_name] & profile_tool_sets[right_name]
            if shared:
                duplicates.append((left_name, right_name, sorted(shared)))
    assert not duplicates, (
        f"tool_to_package.json contains {len(duplicates)} dual-listing(s): "
        f"{duplicates!r}. ARG-058 closed the dual-listed migration; the "
        f"only acceptable inter-profile intersection is the empty set. "
        f"Drop the offending tool_ids from the secondary profile."
    )


def test_arg058_argus_kali_network_contains_exactly_16_migrated_tools(
    profile_tool_sets: dict[str, frozenset[str]],
) -> None:
    """``argus-kali-network.tools`` equals the 16 migrated ``tool_id`` set.

    Strict equality (not a superset check) because the network profile
    was carved specifically to host these 16 binaries (Backlog/dev1_md
    §4.17). A future addition of a new network-protocol tool to the
    profile is a deliberate scope expansion that MUST extend
    :data:`MIGRATED_TOOL_IDS` in lock-step with the JSON edit — the
    test failure here is the trigger to do so, not noise to silence.
    """
    network_tools = profile_tool_sets.get("argus-kali-network")
    assert network_tools is not None, (
        "tool_to_package.json missing the ``argus-kali-network`` profile — "
        "ARG-048 introduced it and ARG-058 depends on it; do not remove "
        "the profile without an explicit migration plan."
    )
    expected = frozenset(MIGRATED_TOOL_IDS)
    missing = sorted(expected - network_tools)
    extra = sorted(network_tools - expected)
    assert network_tools == expected, (
        f"argus-kali-network.tools drift: missing={missing!r}, "
        f"extra={extra!r}. The profile must contain EXACTLY the "
        f"{len(MIGRATED_TOOL_IDS)} ARG-058 migrated tool_ids; either "
        f"restore the missing entries (and re-sign the corresponding "
        f"YAMLs if applicable) OR extend MIGRATED_TOOL_IDS in lock-step "
        f"with a worker-report rationale (a new network-protocol tool "
        f"is a scope expansion, not a silent edit)."
    )


def test_arg058_argus_kali_web_no_longer_contains_migrated_tools(
    profile_tool_sets: dict[str, frozenset[str]],
) -> None:
    """``argus-kali-web.tools`` is disjoint from the 16 migrated ``tool_id`` set.

    The migration's whole point was to remove the 16 dual-listed tools
    from the web image. A reappearance here is a manifest regression
    (e.g. a sloppy revert of the JSON edit that re-introduces dual-
    listing) and breaks the image-isolation invariant ("each tool runs
    in the narrowest possible sandbox").
    """
    web_tools = profile_tool_sets.get("argus-kali-web")
    assert web_tools is not None, (
        "tool_to_package.json missing the ``argus-kali-web`` profile — "
        "this is the largest profile by tool count; do not remove."
    )
    leaked = sorted(web_tools & frozenset(MIGRATED_TOOL_IDS))
    assert not leaked, (
        f"argus-kali-web.tools still contains ARG-058 migrated tool_id(s): "
        f"{leaked!r}. The dual-listing migration removed them from web; "
        f"a reappearance here is a regression. Drop the entries from "
        f"``profiles.argus-kali-web.tools`` (preserve ASCII order to keep "
        f"the diff byte-stable)."
    )


def test_arg058_schema_version_bumped(
    tool_to_package_json: dict[str, object],
) -> None:
    """``schema_version`` was bumped 1.1.0 → 1.2.0 by the migration worker.

    The bump is the operator-visible signal that the JSON shape
    semantics changed (the ``$comment``, ``generated_by``, and
    per-profile ``purpose`` strings all reference ARG-058 closure now).
    A missing bump means the manifest was edited without updating the
    version pointer — a downstream consumer reading the file by version
    would silently apply stale semantics.
    """
    actual = tool_to_package_json.get("schema_version")
    assert actual == _EXPECTED_SCHEMA_VERSION, (
        f"tool_to_package.json schema_version={actual!r}, expected "
        f"{_EXPECTED_SCHEMA_VERSION!r}. ARG-058 worker bumped 1.1.0 → "
        f"{_EXPECTED_SCHEMA_VERSION!r} alongside the migration; a revert "
        f"or a missed bump is manifest drift."
    )


# ---------------------------------------------------------------------------
# Documentation contract — the resolution status is locked in the issue file.
# ---------------------------------------------------------------------------


def test_arg058_iss_cycle6_marked_resolved() -> None:
    """``ISS-cycle6-carry-over.md`` marks ARG-058 as RESOLVED in-section.

    Light textual check (no Markdown parser): assert the file mentions
    ``ARG-058`` and the resolution marker (``Status: RESOLVED`` /
    ``**Status:** RESOLVED`` / ``RESOLVED (Cycle 6, T03``) within a
    generous window of the ARG-058 anchor. Defends against an accidental
    status revert in the issue tracker that would orphan the migration
    from its documented closure.
    """
    assert _ISS_CYCLE6_PATH.is_file(), (
        f"ISS-cycle6-carry-over.md missing at "
        f"{_ISS_CYCLE6_PATH.relative_to(_REPO_ROOT)} — the operator-"
        f"visible issue tracker entry for ARG-058 must be present."
    )
    text = _ISS_CYCLE6_PATH.read_text(encoding="utf-8")

    arg058_index = text.find("ARG-058")
    assert arg058_index != -1, (
        f"{_ISS_CYCLE6_PATH.relative_to(_REPO_ROOT)} contains no ARG-058 "
        f"anchor; the migration entry was likely renamed or removed. "
        f"Restore the section heading."
    )

    # Patterns accepted (single regex, case-insensitive):
    #   * ``Status: RESOLVED``
    #   * ``**Status:** RESOLVED``
    #   * ``RESOLVED (Cycle 6, T03 ...)``
    # Window size of 4000 chars (~80 lines @ 50 c/line) is generous
    # enough to cover the full ARG-058 section without leaking into
    # the unrelated next-section "Capacity for additional candidates".
    resolved_re = re.compile(
        r"(?:\*\*Status:\*\*|Status:)\s*RESOLVED|RESOLVED\s*\(Cycle\s*6",
        re.IGNORECASE,
    )
    window = text[arg058_index : arg058_index + 4000]
    assert resolved_re.search(window) is not None, (
        f"{_ISS_CYCLE6_PATH.relative_to(_REPO_ROOT)} mentions ARG-058 but "
        f"the surrounding section does not carry a 'RESOLVED' status "
        f"marker. Restore the closure note (see worker report for the "
        f"exact phrasing — accepted forms: ``Status: RESOLVED``, "
        f"``**Status:** RESOLVED``, or ``RESOLVED (Cycle 6, T03 ...)``)."
    )
