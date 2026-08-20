"""Integration test: load and audit the production payload catalog.

Loads the real ``backend/config/payloads/`` registry and asserts the
invariants documented in the ARG-005 cycle plan and Backlog/dev1_md §7:

* Every YAML descriptor passes Ed25519 signature verification.
* All expected ``family_id`` s are present (see ``EXPECTED_FAMILIES``).
* Approval gating matches the policy (only the HIGH/DESTRUCTIVE families
  in ``APPROVAL_REQUIRED`` carry ``requires_approval=True``).
* Mutation/encoder rule names referenced by the catalog only use the
  registry-allowed names.

The fixture ``loaded_registry`` loads once per session — Ed25519
verification is the slow path and re-running it per family would dominate
the test wall time for no extra coverage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from src.payloads.encoders import ENCODER_NAMES
from src.payloads.mutations import MUTATION_NAMES
from src.payloads.registry import PayloadFamily, PayloadRegistry


EXPECTED_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "sqli",
        "xss",
        "xss_stored",
        "xss_dom",
        "ssrf",
        "rce",
        "lfi_rfi",
        "crlf",
        "open_redirect",
        "oauth",
        "oauth_misconfig",
        "jwt",
        "jwt_none_alg",
        "graphql",
        "proto_smuggle",
        "http_smuggling",
        "cache_poisoning",
        "prototype_pollution",
        "path_traversal",
        "nosqli",
        "ldapi",
        "ldap_injection",
        "xxe",
        "ssti",
        "auth_bypass",
        "idor",
        "mass_assignment",
        "race_condition",
        "cors_misconfig",
        "csrf_token_bypass",
        "deserialization",
        "format_string",
        "integer_overflow",
        "buffer_overflow",
        "smtp_injection",
        "type_juggling",
        "xpath_injection",
        # Phase 2 — signed safe curriculum families (P2-005)
        "xss_contextual",
        "sqli_safe",
        "nosqli_safe",
        "ldapi_safe",
        "xpathi_safe",
        "ssti_safe",
        "ssrf_oast_safe",
        "xxe_oast_safe",
        "command_injection_safe",
        "crlf_safe",
        "csrf_safe",
        "traversal_safe",
        "prototype_pollution_safe",
        "graphql_safe",
        "jwt_safe",
        "mass_assignment_safe",
        "open_redirect_safe",
        # Seed families — additional attack surfaces (all SAFE/conservative)
        "file_upload_polyglot",
        "http_parameter_pollution",
        "web_cache_deception",
        "saml_validation",
        "client_side_path_traversal",
        "dns_rebinding",
        "xs_leak",
        "business_logic_transition",
        "api_bola",
        "api_bopla",
        "api_bfla",
        "resource_consumption_safe",
        "unsafe_api_consumption",
    }
)

APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {
        "rce",
        "proto_smuggle",
        "http_smuggling",
        "race_condition",
        "buffer_overflow",
        "deserialization",
        "format_string",
        "integer_overflow",
        "jwt_none_alg",
        "ldap_injection",
        "oauth_misconfig",
        "type_juggling",
        "xpath_injection",
    }
)


@pytest.fixture(scope="session")
def catalog_dir() -> Path:
    """Resolve ``backend/config/payloads/`` from this test file's location."""
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "payloads"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="session")
def loaded_registry(catalog_dir: Path) -> PayloadRegistry:
    """Load the real signed catalog exactly as the application does at startup."""
    registry = PayloadRegistry(payloads_dir=catalog_dir)
    summary = registry.load()
    assert summary.total >= len(EXPECTED_FAMILIES), (
        f"catalog shrunk: expected at least {len(EXPECTED_FAMILIES)} families, "
        f"got {summary.total}"
    )
    return registry


# ---------------------------------------------------------------------------
# Catalog inventory
# ---------------------------------------------------------------------------


def test_catalog_loads_and_contains_every_expected_family(
    loaded_registry: PayloadRegistry,
) -> None:
    loaded = set(loaded_registry)
    missing = EXPECTED_FAMILIES - loaded
    assert not missing, f"missing family ids: {sorted(missing)}"


def test_catalog_total_matches_expected(loaded_registry: PayloadRegistry) -> None:
    assert len(loaded_registry) == len(EXPECTED_FAMILIES)


# ---------------------------------------------------------------------------
# Per-family invariants on the signed catalog
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_returns_pydantic_instance(
    loaded_registry: PayloadRegistry, family_id: str
) -> None:
    family = loaded_registry.get_family(family_id)
    assert isinstance(family, PayloadFamily)
    assert family.family_id == family_id


@pytest.mark.parametrize("family_id", sorted(APPROVAL_REQUIRED))
def test_approval_required_families(
    loaded_registry: PayloadRegistry, family_id: str
) -> None:
    family = loaded_registry.get_family(family_id)
    assert family.requires_approval is True


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES - APPROVAL_REQUIRED))
def test_non_approval_families(
    loaded_registry: PayloadRegistry, family_id: str
) -> None:
    family = loaded_registry.get_family(family_id)
    assert family.requires_approval is False


def test_families_requiring_approval_helper_matches_expected(
    loaded_registry: PayloadRegistry,
) -> None:
    found = {f.family_id for f in loaded_registry.families_requiring_approval()}
    assert found == APPROVAL_REQUIRED


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_uses_registered_mutations_only(
    loaded_registry: PayloadRegistry, family_id: str
) -> None:
    family = loaded_registry.get_family(family_id)
    for mutation in family.mutations:
        assert mutation.name in MUTATION_NAMES, (
            f"{family_id} references unknown mutation {mutation.name!r}"
        )


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_uses_registered_encoders_only(
    loaded_registry: PayloadRegistry, family_id: str
) -> None:
    family = loaded_registry.get_family(family_id)
    for pipeline in family.encodings:
        for stage in pipeline.stages:
            assert stage in ENCODER_NAMES, (
                f"{family_id} pipeline {pipeline.name!r} references unknown "
                f"encoder stage {stage!r}"
            )


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_payload_seeds_have_unique_ids(
    loaded_registry: PayloadRegistry, family_id: str
) -> None:
    family = loaded_registry.get_family(family_id)
    ids = [p.id for p in family.payloads]
    assert len(set(ids)) == len(ids)


# ---------------------------------------------------------------------------
# Summary fields
# ---------------------------------------------------------------------------


def test_summary_records_oast_required_count(
    catalog_dir: Path,
) -> None:
    """Re-load to inspect the summary directly (helper not exposed otherwise)."""
    registry = PayloadRegistry(payloads_dir=catalog_dir)
    summary = registry.load()
    assert summary.oast_required_count >= 1
    assert summary.requires_approval_count == len(APPROVAL_REQUIRED)
    # by_risk must add up to the total.
    assert sum(summary.by_risk.values()) == summary.total
