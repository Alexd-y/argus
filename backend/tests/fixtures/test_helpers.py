"""Tests for fixture artifacts — validate test data used by other suites.

The ``fixtures/`` directory holds signed ground-truth files consumed by
parser, sandbox, and snapshot tests. Ensuring they exist and are parseable
is a regression gate — missing or truncated fixture files silently disable
coverage in downstream test runs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent


class TestFixtureArtifactIntegrity:
    """Every named fixture file in the directory must exist and be non-empty."""

    _REQUIRED_FILES: tuple[str, ...] = (
        "dalfox_alf_nu_alert1_xss.jsonl",
        "xsstrike_alf_nu_alert1_level.txt",
        "xsstrike_single_payload.txt",
        "xsstrike_two_params.txt",
    )

    @pytest.mark.parametrize("file_name", _REQUIRED_FILES)
    def test_fixture_file_exists_and_non_empty(self, file_name: str) -> None:
        path = FIXTURES_DIR / file_name
        assert path.exists(), f"Missing fixture: {file_name}"
        assert path.is_file()
        content = path.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, f"Fixture is empty: {file_name}"

    def test_dalfox_jsonl_is_valid(self) -> None:
        """Each line in the dalfox JSONL fixture must parse as valid JSON."""
        path = FIXTURES_DIR / "dalfox_alf_nu_alert1_xss.jsonl"
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 1, "Expected at least one JSONL entry"
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            parsed = json.loads(line)
            assert isinstance(parsed, dict), f"Line {i} is not a JSON object"

    def test_xsstrike_fixtures_not_accidentally_truncated(self) -> None:
        """Verify xsstrike fixtures exceed a minimum reasonable size."""
        for name, min_bytes in (
            ("xsstrike_alf_nu_alert1_level.txt", 128),
            ("xsstrike_single_payload.txt", 64),
            ("xsstrike_two_params.txt", 128),
        ):
            size = (FIXTURES_DIR / name).stat().st_size
            assert size >= min_bytes, f"{name} is too small ({size} B < {min_bytes} B)"


class TestFixtureHeartbeatDir:
    """``fixtures/heartbeat/`` subdirectory exists (consumed by observability tests)."""

    def test_heartbeat_dir_exists(self) -> None:
        hb = FIXTURES_DIR / "heartbeat"
        assert hb.exists()
        assert hb.is_dir()


class TestFixtureSandboxOutputsDir:
    """``fixtures/sandbox_outputs/`` subdirectory exists (parser integration tests)."""

    def test_sandbox_outputs_dir_exists(self) -> None:
        so = FIXTURES_DIR / "sandbox_outputs"
        assert so.exists()
        assert so.is_dir()


@pytest.mark.skip(reason="fixture infrastructure — no testable Python code in this package")
class TestPlaceholder:
    """Explicit placeholder — fixture package contains only data, no helpers."""

    def test_nothing(self) -> None:
        pass
