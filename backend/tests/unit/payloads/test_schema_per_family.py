"""Per-family schema-level tests for the production payload catalog.

These tests parse the production ``backend/config/payloads/*.yaml`` files
straight into the :class:`~src.payloads.registry.PayloadFamily` Pydantic
model **without** signature verification — they are dedicated to schema
regressions: shape, enums, allow-listed mutation/encoder names,
approval-gate consistency, and OWASP/CWE invariants.

Loading via the signed registry is exercised by the integration test
``backend/tests/integration/payloads/test_catalog_load.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml

from src.payloads.registry import PayloadFamily
from src.pipeline.contracts.tool_job import RiskLevel


_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_CATALOG_DIR: Final[Path] = _BACKEND_ROOT / "config" / "payloads"


# ---------------------------------------------------------------------------
# Catalog inventory (matches ARG-005 cycle plan §7).
# Hard-coded so adding/removing a family is a deliberate test edit.
# ---------------------------------------------------------------------------


EXPECTED_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "sqli",
        "xss",
        "ssrf",
        "rce",
        "lfi_rfi",
        "crlf",
        "open_redirect",
        "oauth",
        "jwt",
        "graphql",
        "proto_smuggle",
        "http_smuggling",
        "cache_poisoning",
        "prototype_pollution",
        "path_traversal",
        "nosqli",
        "ldapi",
        "xxe",
        "ssti",
        "auth_bypass",
        "idor",
        "mass_assignment",
        "race_condition",
    }
)


APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"rce", "proto_smuggle", "http_smuggling", "race_condition"}
)


# ---------------------------------------------------------------------------
# Catalog inventory checks
# ---------------------------------------------------------------------------


def test_catalog_dir_exists() -> None:
    assert _CATALOG_DIR.is_dir(), f"missing catalog dir at {_CATALOG_DIR}"


def test_catalog_has_exactly_expected_families() -> None:
    yaml_files = sorted(p.stem for p in _CATALOG_DIR.glob("*.yaml"))
    found = set(yaml_files)
    missing = EXPECTED_FAMILIES - found
    extras = found - EXPECTED_FAMILIES
    assert not missing, f"missing families: {sorted(missing)}"
    assert not extras, f"unexpected families: {sorted(extras)}"


# ---------------------------------------------------------------------------
# Per-family schema validation (parametrised)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_yaml_parses_into_pydantic_model(family_id: str) -> None:
    yaml_path = _CATALOG_DIR / f"{family_id}.yaml"
    payload = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    family = PayloadFamily(**payload)
    assert family.family_id == family_id


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_id_matches_filename(family_id: str) -> None:
    yaml_path = _CATALOG_DIR / f"{family_id}.yaml"
    payload = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert payload["family_id"] == yaml_path.stem


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_has_minimum_three_payload_seeds(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert len(family.payloads) >= 3, (
        f"{family_id} has {len(family.payloads)} payloads, expected >= 3"
    )


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_has_at_most_ten_payload_seeds(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert len(family.payloads) <= 10, (
        f"{family_id} has {len(family.payloads)} payloads, expected <= 10"
    )


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_declares_at_least_one_encoding(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert family.encodings, f"{family_id} declares no encoding pipelines"


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_declares_at_least_one_mutation(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert family.mutations, f"{family_id} declares no mutation rules"


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_has_non_empty_description(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert family.description.strip(), f"{family_id} has empty description"


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_owasp_entries_match_expected_format(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    for entry in family.owasp_top10:
        assert entry.startswith("A"), entry
        # Format: AXX:YYYY
        assert ":" in entry, entry


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_family_cwe_ids_are_positive_ints(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert all(cwe > 0 for cwe in family.cwe_ids)


# ---------------------------------------------------------------------------
# Approval-gate consistency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family_id", sorted(APPROVAL_REQUIRED))
def test_high_risk_families_require_approval(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert family.requires_approval is True, (
        f"{family_id} is high-risk but requires_approval=False"
    )
    assert family.risk_level in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}, (
        f"{family_id} is in APPROVAL_REQUIRED but risk_level={family.risk_level.value}"
    )


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES - APPROVAL_REQUIRED))
def test_low_risk_families_do_not_require_approval(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert family.requires_approval is False, (
        f"{family_id} is not in APPROVAL_REQUIRED but requires_approval=True"
    )
    assert family.risk_level not in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}, (
        f"{family_id} has risk_level={family.risk_level.value} but is not in "
        "APPROVAL_REQUIRED"
    )


# ---------------------------------------------------------------------------
# Per-payload-entry sanity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_payload_entry_ids_are_unique_within_family(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    ids = [p.id for p in family.payloads]
    assert len(set(ids)) == len(ids), f"{family_id} has duplicate payload ids"


@pytest.mark.parametrize("family_id", sorted(EXPECTED_FAMILIES))
def test_payload_entry_templates_are_non_empty(family_id: str) -> None:
    payload = yaml.safe_load(
        (_CATALOG_DIR / f"{family_id}.yaml").read_text(encoding="utf-8")
    )
    family = PayloadFamily(**payload)
    assert all(p.template for p in family.payloads)
