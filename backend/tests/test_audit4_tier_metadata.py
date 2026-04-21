"""M-9: TIER_STUBS renamed to TIER_METADATA."""

from __future__ import annotations


class TestTierMetadata:
    """TIER_METADATA must exist and TIER_STUBS must be its alias."""

    def test_tier_metadata_exists(self) -> None:
        from src.services.reporting import TIER_METADATA

        assert isinstance(TIER_METADATA, dict)
        assert len(TIER_METADATA) > 0

    def test_tier_metadata_has_expected_tiers(self) -> None:
        from src.services.reporting import TIER_METADATA

        expected = {"midgard", "asgard", "valhalla"}
        assert expected.issubset(set(TIER_METADATA.keys()))

    def test_tier_stubs_alias(self) -> None:
        from src.services.reporting import TIER_METADATA, TIER_STUBS

        assert TIER_STUBS is TIER_METADATA, "TIER_STUBS should be alias for TIER_METADATA"

    def test_tier_metadata_values_have_label(self) -> None:
        from src.services.reporting import TIER_METADATA

        for tier_name, meta in TIER_METADATA.items():
            assert "label" in meta, f"Tier {tier_name!r} missing 'label' key"
            assert isinstance(meta["label"], str)
