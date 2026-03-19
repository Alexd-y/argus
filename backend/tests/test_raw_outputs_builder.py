"""Tests for raw_outputs_builder — REC-004 raw_tool_outputs aggregation."""

import json
from pathlib import Path

import pytest

from src.recon.reporting.raw_outputs_builder import (
    RAW_OUTPUTS_DIR,
    aggregate_raw_tool_outputs,
)


class TestAggregateRawToolOutputs:
    """Test aggregate_raw_tool_outputs function."""

    def test_empty_recon_dir_returns_empty_list(self, tmp_path: Path) -> None:
        """Empty recon dir returns empty list, no raw_tool_outputs created."""
        result = aggregate_raw_tool_outputs(tmp_path, tmp_path / "out")
        assert result == []
        raw_dir = tmp_path / "out" / RAW_OUTPUTS_DIR
        assert not raw_dir.exists()

    def test_nonexistent_recon_dir_returns_empty(self, tmp_path: Path) -> None:
        """Nonexistent recon dir returns empty list."""
        missing = tmp_path / "nonexistent"
        result = aggregate_raw_tool_outputs(missing, tmp_path / "out")
        assert result == []

    def test_subfinder_plain_text_copied_as_txt(self, tmp_path: Path) -> None:
        """subdomains_raw.txt in 02_subdomains -> subfinder_output.txt."""
        sub_dir = tmp_path / "02_subdomains"
        sub_dir.mkdir(parents=True)
        (sub_dir / "subdomains_raw.txt").write_text(
            "www.example.com\napi.example.com\nmail.example.com",
            encoding="utf-8",
        )
        out_dir = tmp_path / "artifacts"
        result = aggregate_raw_tool_outputs(tmp_path, out_dir)
        assert len(result) == 1
        dest = out_dir / RAW_OUTPUTS_DIR / "subfinder_output.txt"
        assert dest in result
        assert dest.exists()
        assert "www.example.com" in dest.read_text(encoding="utf-8")

    def test_subfinder_json_lines_copied_as_json(self, tmp_path: Path) -> None:
        """subfinder JSON lines -> subfinder_output.json."""
        sub_dir = tmp_path / "02_subdomains"
        sub_dir.mkdir(parents=True)
        (sub_dir / "subdomains_raw.txt").write_text(
            '{"host":"www.example.com","source":"crtsh"}\n{"host":"api.example.com","source":"crtsh"}',
            encoding="utf-8",
        )
        out_dir = tmp_path / "artifacts"
        result = aggregate_raw_tool_outputs(tmp_path, out_dir)
        assert len(result) == 1
        dest = out_dir / RAW_OUTPUTS_DIR / "subfinder_output.json"
        assert dest in result
        assert dest.exists()
        first_line = dest.read_text(encoding="utf-8").strip().split("\n")[0]
        assert json.loads(first_line)["host"] == "www.example.com"

    def test_httpx_output_copied(self, tmp_path: Path) -> None:
        """httpx_output.json in 04_live_hosts -> httpx_output.json."""
        live_dir = tmp_path / "04_live_hosts"
        live_dir.mkdir(parents=True)
        (live_dir / "httpx_output.json").write_text(
            '{"url":"https://example.com/","status_code":200}\n'
            '{"url":"https://www.example.com/","status_code":200}',
            encoding="utf-8",
        )
        out_dir = tmp_path / "artifacts"
        result = aggregate_raw_tool_outputs(tmp_path, out_dir)
        assert len(result) == 1
        dest = out_dir / RAW_OUTPUTS_DIR / "httpx_output.json"
        assert dest in result
        assert "https://example.com" in dest.read_text(encoding="utf-8")

    def test_httpx_raw_json_alternative_name(self, tmp_path: Path) -> None:
        """httpx_raw.json in 04_live_hosts is also accepted."""
        live_dir = tmp_path / "04_live_hosts"
        live_dir.mkdir(parents=True)
        (live_dir / "httpx_raw.json").write_text(
            '{"url":"https://test.com/","status_code":200}',
            encoding="utf-8",
        )
        out_dir = tmp_path / "artifacts"
        result = aggregate_raw_tool_outputs(tmp_path, out_dir)
        assert len(result) == 1
        dest = out_dir / RAW_OUTPUTS_DIR / "httpx_output.json"
        assert dest.exists()
        assert "https://test.com" in dest.read_text(encoding="utf-8")

    def test_nuclei_output_copied_from_live_hosts(self, tmp_path: Path) -> None:
        """nuclei_output_initial.json in 04_live_hosts -> nuclei_output_initial.json."""
        live_dir = tmp_path / "04_live_hosts"
        live_dir.mkdir(parents=True)
        (live_dir / "nuclei_output_initial.json").write_text(
            '[{"template":"ssl-dns-names","host":"example.com"}]',
            encoding="utf-8",
        )
        out_dir = tmp_path / "artifacts"
        result = aggregate_raw_tool_outputs(tmp_path, out_dir)
        assert len(result) == 1
        dest = out_dir / RAW_OUTPUTS_DIR / "nuclei_output_initial.json"
        assert dest in result
        assert "example.com" in dest.read_text(encoding="utf-8")

    def test_all_three_aggregated(self, tmp_path: Path) -> None:
        """Subfinder, httpx, nuclei all copied when present."""
        (tmp_path / "02_subdomains").mkdir()
        (tmp_path / "02_subdomains" / "subdomains_raw.txt").write_text(
            "a.example.com\nb.example.com",
            encoding="utf-8",
        )
        (tmp_path / "04_live_hosts").mkdir()
        (tmp_path / "04_live_hosts" / "httpx_output.json").write_text(
            '{"url":"https://a.example.com/"}',
            encoding="utf-8",
        )
        (tmp_path / "04_live_hosts" / "nuclei_output_initial.json").write_text(
            '[]',
            encoding="utf-8",
        )
        out_dir = tmp_path / "artifacts"
        result = aggregate_raw_tool_outputs(tmp_path, out_dir)
        assert len(result) == 3
        names = {p.name for p in result}
        assert "subfinder_output.txt" in names
        assert "httpx_output.json" in names
        assert "nuclei_output_initial.json" in names

    def test_returns_list_of_paths(self, tmp_path: Path) -> None:
        """Return value is list of Path objects."""
        (tmp_path / "02_subdomains").mkdir()
        (tmp_path / "02_subdomains" / "subdomains_raw.txt").write_text("x.example.com", encoding="utf-8")
        result = aggregate_raw_tool_outputs(tmp_path, tmp_path / "out")
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)
        assert all(p.exists() for p in result)
