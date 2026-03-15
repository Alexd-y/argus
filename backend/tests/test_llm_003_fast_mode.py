"""LLM-003: AI runs in --fast mode when keys exist.

When --fast is used (use_mcp=False, skip_intel=True, fetch_func=mock),
build_anomalies and build_stage2_inputs must still receive non-None call_llm
when has_any_llm_key() is True.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from src.recon.reporting.stage1_report_generator import generate_stage1_report


def _mock_fetch(_url: str) -> dict:
    """Mock fetch for endpoint inventory (--fast mode)."""
    return {"status": 200, "content_type": "text/plain", "exists": True, "notes": "mock"}


def _mock_headers_fetch(_url: str, _timeout: float = 10.0) -> dict:
    """Mock fetch for headers summary."""
    return {"status_code": 200, "headers": {}, "url": _url}


def _create_minimal_recon_dir(tmp_path: Path) -> Path:
    """Create minimal recon dir with artifacts needed for anomalies + stage2."""
    for sub in ["00_scope", "01_domains", "02_subdomains", "03_dns", "04_live_hosts"]:
        (tmp_path / sub).mkdir(exist_ok=True)

    (tmp_path / "00_scope" / "scope.txt").write_text("Target: example.com", encoding="utf-8")
    (tmp_path / "00_scope" / "targets.txt").write_text("example.com", encoding="utf-8")
    (tmp_path / "02_subdomains" / "subdomains_clean.txt").write_text(
        "www.example.com\napi.example.com", encoding="utf-8"
    )
    (tmp_path / "03_dns" / "resolved.txt").write_text(
        "www.example.com -> 93.184.216.34", encoding="utf-8"
    )
    (tmp_path / "03_dns" / "cname_map.csv").write_text(
        "host,record_type,value,comment\n", encoding="utf-8", newline=""
    )
    (tmp_path / "04_live_hosts" / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "subdomain_classification.csv").write_text(
        "subdomain,role,confidence,priority,notes\nwww.example.com,web,high,1,\n",
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "live_hosts_detailed.csv").write_text(
        "host,url,scheme,status,title,server\n"
        "example.com,https://example.com/,https,200,Example,nginx\n",
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "tech_profile.csv").write_text(
        "host,tech,version\nexample.com,nginx,\n",
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "anomalies.md").write_text("# Anomalies\n\nNone.", encoding="utf-8")
    (tmp_path / "endpoint_inventory.csv").write_text(
        "url,status,content_type,exists,notes\n",
        encoding="utf-8",
        newline="",
    )
    return tmp_path


class TestLLM003FastMode:
    """LLM-003: --fast mode with LLM keys still passes call_llm to anomaly/stage2 builders."""

    def test_fast_mode_with_llm_keys_passes_call_llm_to_builders(
        self, tmp_path: Path
    ) -> None:
        """When --fast + has_any_llm_key()=True, build_anomalies and build_stage2_inputs receive non-None call_llm."""
        recon_dir = _create_minimal_recon_dir(tmp_path)

        mock_call_llm = MagicMock(return_value='{"interpretations": [], "summary": ""}')
        build_anomalies_calls: list[dict] = []
        build_stage2_calls: list[dict] = []

        def _capture_build_anomalies(recon_dir_arg, call_llm=None):
            build_anomalies_calls.append({"call_llm": call_llm})
            return ("# Anomalies\n", {"anomalies": [], "hypotheses": [], "coverage_gaps": []})

        def _capture_build_stage2(recon_dir_arg, call_llm=None):
            build_stage2_calls.append({"call_llm": call_llm})
            return ("# Stage 2\n", {"critical_assets": [], "entry_points": []})

        with (
            patch("src.recon.reporting.stage1_report_generator.has_any_llm_key", return_value=True),
            patch("src.recon.reporting.stage1_report_generator.get_llm_client", return_value=mock_call_llm),
            patch(
                "src.recon.reporting.anomaly_builder.build_anomalies",
                side_effect=_capture_build_anomalies,
            ),
            patch(
                "src.recon.reporting.stage2_builder.build_stage2_inputs",
                side_effect=_capture_build_stage2,
            ),
        ):
            generate_stage1_report(
                recon_dir,
                use_mcp=False,
                skip_intel=True,
                fetch_func=_mock_fetch,
                headers_fetch_func=_mock_headers_fetch,
            )

        assert len(build_anomalies_calls) >= 1, "build_anomalies should be called"
        assert len(build_stage2_calls) >= 1, "build_stage2_inputs should be called"

        anomaly_call_llm = build_anomalies_calls[0].get("call_llm")
        stage2_call_llm = build_stage2_calls[0].get("call_llm")

        assert anomaly_call_llm is not None, (
            "build_anomalies must receive non-None call_llm in --fast with keys"
        )
        assert stage2_call_llm is not None, (
            "build_stage2_inputs must receive non-None call_llm in --fast with keys"
        )
