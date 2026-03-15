"""Tests for recon storage — key building and path traversal protection."""

import pytest

from src.recon.storage import build_recon_object_key, get_stage_name


class TestObjectKeyBuilding:
    """Test hierarchical MinIO key construction."""

    def test_valid_key(self):
        key = build_recon_object_key("eng-1", "tgt-1", "job-1", 2, "subdomains_raw.txt")
        assert key == "engagements/eng-1/targets/tgt-1/jobs/job-1/02_subdomains/subdomains_raw.txt"

    def test_stage_name_mapping(self):
        assert get_stage_name(0) == "00_scope"
        assert get_stage_name(18) == "18_reporting"
        assert get_stage_name(99).startswith("99_")

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError):
            build_recon_object_key("../etc", "tgt-1", "job-1", 0, "scope.txt")

    def test_backslash_rejected(self):
        with pytest.raises(ValueError):
            build_recon_object_key("eng-1", "tgt-1", "job-1", 0, "..\\etc\\passwd")

    def test_empty_component_rejected(self):
        with pytest.raises(ValueError):
            build_recon_object_key("", "tgt-1", "job-1", 0, "scope.txt")

    def test_all_stages_have_names(self):
        for stage in range(19):
            name = get_stage_name(stage)
            assert name.startswith(f"{stage:02d}_")
