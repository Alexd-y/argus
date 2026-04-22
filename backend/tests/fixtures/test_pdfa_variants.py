"""C7-T02 / ARG-058-followup — unit tests for ``tests/fixtures/pdfa_variants``.

Pins the public surface of the closed-taxonomy variant registry so a
future contributor cannot quietly add / drop / rename a variant without
the corresponding update landing in:

* ``backend/scripts/render_pdfa_sample.py`` (``--fixture-variant`` choices),
* ``.github/workflows/pdfa-validation.yml`` (``matrix.fixture`` legs), and
* ``backend/tests/scripts/test_render_pdfa_sample.py`` (parametrised renders).

The tests are intentionally hostile to drift: they assert the cardinality
of ``VARIANTS``, the specific keys, immutability of the dataclass,
fingerprintable invariants of each body (Cyrillic codepoints, longtable
row count, image sentinel tokens), and the per-tenant override pinning
to the closed-taxonomy literal exported by :mod:`src.db.models`.

Why test the registry at all?
-----------------------------
Adding a fixture variant is a 4-place edit (registry + CLI + workflow +
tests). Every place except this one is enforced by argparse / GitHub
Actions / pytest collection — but the registry's *content* is only
validated by these assertions. Without them, a contributor could swap
the longtable variant's body for a one-line paragraph and the renderer
would happily compile a PDF that no longer exercises the longtable
bookmark cluster, defeating the purpose of the matrix.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Final

import pytest

from src.db.models import PDF_ARCHIVAL_FORMAT_VALUES
from tests.fixtures.pdfa_variants import (
    PDFAVariant,
    PNG_TOKEN_1,
    PNG_TOKEN_2,
    VARIANTS,
    get_variant,
)

# Closed taxonomy of variant names. Mirrors the matrix in
# ``.github/workflows/pdfa-validation.yml`` — adding / removing a variant
# requires a coordinated update there AND in
# ``backend/scripts/render_pdfa_sample.py``.
_EXPECTED_VARIANT_NAMES: Final[frozenset[str]] = frozenset(
    {"basic", "cyrillic", "longtable", "images", "per_tenant"}
)


# ---------------------------------------------------------------------------
# Section A — registry shape
# ---------------------------------------------------------------------------


class TestVariantRegistryShape:
    """Cardinality + key set of :data:`VARIANTS`."""

    def test_exactly_five_variants(self) -> None:
        assert len(VARIANTS) == 5, (
            f"VARIANTS cardinality drifted: expected 5, got {len(VARIANTS)} "
            f"(keys={sorted(VARIANTS)}). Update the workflow matrix and the "
            "renderer's --fixture-variant choices in lock-step."
        )

    def test_expected_variant_keys(self) -> None:
        assert set(VARIANTS) == _EXPECTED_VARIANT_NAMES, (
            f"VARIANTS keys drifted: missing="
            f"{sorted(_EXPECTED_VARIANT_NAMES - set(VARIANTS))}, extra="
            f"{sorted(set(VARIANTS) - _EXPECTED_VARIANT_NAMES)}"
        )

    @pytest.mark.parametrize("name", sorted(_EXPECTED_VARIANT_NAMES))
    def test_each_variant_name_matches_dict_key(self, name: str) -> None:
        """``VARIANTS[name].name`` must equal ``name``.

        Decoupling the dict key from the dataclass ``name`` field would
        let the renderer log one identifier and the CI matrix surface a
        different one — a confusing audit trail on a failing PR check.
        """
        assert VARIANTS[name].name == name


# ---------------------------------------------------------------------------
# Section B — get_variant() helper
# ---------------------------------------------------------------------------


class TestGetVariantHelper:
    """Behavioural contract of :func:`get_variant`."""

    def test_returns_pdfavariant_instance(self) -> None:
        variant = get_variant("basic")
        assert isinstance(variant, PDFAVariant)

    def test_returns_dataclass_with_required_fields(self) -> None:
        variant = get_variant("basic")
        # ``slots=True`` removes ``__dict__`` so the explicit field
        # introspection below uses ``dataclasses.fields`` rather than
        # ``vars(variant)``.
        field_names = {f.name for f in dataclasses.fields(variant)}
        assert field_names == {
            "name",
            "latex_body",
            "tenant_id",
            "tenant_format_override",
            "description",
        }

    def test_returns_immutable_instance(self) -> None:
        """``frozen=True`` should make field assignment a hard error."""
        variant = get_variant("basic")
        with pytest.raises(dataclasses.FrozenInstanceError):
            # mypy: assignment-target intentionally exercises frozen guard.
            variant.name = "tampered"  # type: ignore[misc]

    def test_unknown_variant_raises_keyerror_with_sorted_names(self) -> None:
        with pytest.raises(KeyError) as excinfo:
            get_variant("does-not-exist")
        # KeyError stringifies as ``"'<msg>'"`` (extra quotes) — assert on
        # ``args[0]`` to compare against the raw message we emit.
        message = excinfo.value.args[0]
        assert "does-not-exist" in message, message
        # The valid-names list must be alphabetically sorted so users
        # eyeballing the error get a deterministic ordering across runs.
        valid_match = re.search(r"valid names: \[(.+)\]", message)
        assert valid_match is not None, (
            f"KeyError message missing 'valid names: [...]' segment: {message!r}"
        )
        valid_list = [n.strip() for n in valid_match.group(1).split(",")]
        assert valid_list == sorted(_EXPECTED_VARIANT_NAMES), valid_list

    def test_unknown_variant_does_not_chain_inner_keyerror(self) -> None:
        """``raise ... from None`` suppresses the inner ``dict[]`` KeyError.

        Otherwise the user sees two KeyErrors stacked, one of which is the
        meaningless ``'does-not-exist'`` from the dict lookup itself.
        """
        with pytest.raises(KeyError) as excinfo:
            get_variant("nope")
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is not None  # always True for raise-in-except
        assert excinfo.value.__suppress_context__ is True


# ---------------------------------------------------------------------------
# Section C — variant body invariants
# ---------------------------------------------------------------------------


class TestVariantBodyInvariants:
    """Each variant's ``latex_body`` carries the feature it claims."""

    def test_basic_body_is_non_empty_plain_text(self) -> None:
        body = VARIANTS["basic"].latex_body
        assert body.strip(), "basic body must not be empty / whitespace-only"
        # basic must NOT carry tables, images, or Cyrillic — those are
        # exercised by dedicated variants.
        assert r"\begin{longtable}" not in body
        assert "includegraphics" not in body
        assert not any(0x0400 <= ord(c) <= 0x04FF for c in body)

    def test_cyrillic_body_contains_cyrillic_codepoint(self) -> None:
        body = VARIANTS["cyrillic"].latex_body
        assert any(0x0400 <= ord(c) <= 0x04FF for c in body), (
            "cyrillic variant body must contain at least one codepoint in "
            "the U+0400..U+04FF block (basic Cyrillic)"
        )

    def test_cyrillic_body_carries_lowercase_yo(self) -> None:
        """U+0451 (ё) is the smoke-test glyph for T2A coverage."""
        body = VARIANTS["cyrillic"].latex_body
        assert "\u0451" in body, (
            "cyrillic body must include U+0451 (ё) — the smoke-test "
            "glyph for T2A / lmodern font coverage"
        )

    def test_longtable_body_uses_longtable_environment(self) -> None:
        body = VARIANTS["longtable"].latex_body
        assert r"\begin{longtable}" in body, (
            "longtable variant must use the longtable environment, "
            "not a plain tabular — only longtable can break across pages "
            "which is the failure mode this fixture targets"
        )
        assert r"\end{longtable}" in body

    def test_longtable_body_has_at_least_40_row_terminators(self) -> None:
        body = VARIANTS["longtable"].latex_body
        # Each row in a longtable ends with ``\\``. We count occurrences
        # of the literal four-character sequence ``\\`` (one backslash
        # escaped twice in the source-string format).
        terminator = "\\\\"
        count = body.count(terminator)
        assert count >= 40, (
            f"longtable variant must have ≥40 row terminators ('\\\\'); "
            f"got {count}. Page-break exercise needs enough rows to "
            "force pagination."
        )

    def test_images_body_carries_both_png_sentinels(self) -> None:
        body = VARIANTS["images"].latex_body
        assert PNG_TOKEN_1 in body, (
            f"images body must carry the {PNG_TOKEN_1!r} sentinel for the "
            "renderer to substitute with the first PNG path"
        )
        assert PNG_TOKEN_2 in body
        # The sentinels are intentionally distinct so the renderer can't
        # substitute the same path twice by accident.
        assert PNG_TOKEN_1 != PNG_TOKEN_2

    def test_images_body_uses_includegraphics(self) -> None:
        body = VARIANTS["images"].latex_body
        assert r"\includegraphics" in body, (
            "images body must invoke graphicx — otherwise the embedded "
            "raster's OutputIntent is never tested"
        )

    def test_per_tenant_body_is_non_empty(self) -> None:
        assert VARIANTS["per_tenant"].latex_body.strip()


# ---------------------------------------------------------------------------
# Section D — per-tenant override pinning
# ---------------------------------------------------------------------------


class TestPerTenantWiring:
    """``per_tenant`` variant fields drive the resolver path in the renderer."""

    def test_tenant_id_is_acme(self) -> None:
        assert VARIANTS["per_tenant"].tenant_id == "acme"

    def test_tenant_format_override_is_pdfa_2u(self) -> None:
        """Override must equal the closed-taxonomy ``"pdfa-2u"`` literal.

        Pinning to the literal here (rather than the tuple member) catches
        both a rename in :data:`PDF_ARCHIVAL_FORMAT_VALUES` and a quiet
        edit to the variant override in lock-step.
        """
        assert VARIANTS["per_tenant"].tenant_format_override == "pdfa-2u"
        # Also assert the override is one of the closed-taxonomy values
        # — guards against the literal slipping out of the union.
        assert (
            VARIANTS["per_tenant"].tenant_format_override
            in PDF_ARCHIVAL_FORMAT_VALUES
        )

    @pytest.mark.parametrize(
        "name", sorted(_EXPECTED_VARIANT_NAMES - {"per_tenant"})
    )
    def test_non_per_tenant_variants_have_null_resolver_fields(
        self, name: str
    ) -> None:
        """Only ``per_tenant`` may carry tenant_id / tenant_format_override."""
        variant = VARIANTS[name]
        assert variant.tenant_id is None, (
            f"variant {name!r} unexpectedly carries tenant_id="
            f"{variant.tenant_id!r}; only per_tenant exercises the resolver"
        )
        assert variant.tenant_format_override is None, (
            f"variant {name!r} unexpectedly carries tenant_format_override="
            f"{variant.tenant_format_override!r}; only per_tenant exercises "
            "the resolver"
        )


# ---------------------------------------------------------------------------
# Section E — descriptions
# ---------------------------------------------------------------------------


class TestDescriptions:
    """Every variant ships a non-trivial human description."""

    @pytest.mark.parametrize("name", sorted(_EXPECTED_VARIANT_NAMES))
    def test_description_is_non_empty(self, name: str) -> None:
        desc = VARIANTS[name].description
        assert desc.strip(), f"variant {name!r} has empty description"
        # 30 chars is the minimum to convey what the variant exercises;
        # shorter descriptions historically read like placeholder text.
        assert len(desc) >= 30, (
            f"variant {name!r} description suspiciously short ({len(desc)} "
            f"chars): {desc!r}"
        )
