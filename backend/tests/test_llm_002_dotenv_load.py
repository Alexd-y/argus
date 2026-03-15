"""LLM-002: Load .env in run_stage1_report.py.

Ensures backend/.env is loaded via load_dotenv before importing stage1_report_generator,
so has_any_llm_key() sees LLM keys when running locally.
"""

import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

from dotenv import load_dotenv
import pytest

# ARGUS root: backend/tests/ -> parent=backend, parent.parent=ARGUS
ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = ARGUS_ROOT / "scripts"
RUN_SCRIPT = SCRIPTS_DIR / "run_stage1_report.py"

LLM_KEYS = [
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "KIMI_API_KEY",
    "PERPLEXITY_API_KEY",
]


def _clear_llm_keys() -> dict[str, str]:
    """Remove LLM keys from os.environ, return saved values for restore."""
    saved = {}
    for key in LLM_KEYS:
        if key in os.environ:
            saved[key] = os.environ.pop(key)
    return saved


def _restore_llm_keys(saved: dict[str, str]) -> None:
    """Restore LLM keys to os.environ."""
    for key, val in saved.items():
        os.environ[key] = val


class TestLLM002DotenvLoad:
    """LLM-002: .env loading ensures has_any_llm_key() sees LLM keys."""

    def test_load_dotenv_with_llm_key_sets_has_any_llm_key_true(
        self, tmp_path: Path
    ) -> None:
        """When .env contains OPENROUTER_API_KEY, load_dotenv + has_any_llm_key is True."""
        env_file = tmp_path / ".env"
        env_file.write_text("OPENROUTER_API_KEY=sk-test-key-123\n", encoding="utf-8")

        saved = _clear_llm_keys()
        try:
            load_dotenv(env_file)
            from src.core.llm_config import has_any_llm_key

            assert has_any_llm_key() is True
        finally:
            _restore_llm_keys(saved)
            os.environ.pop("OPENROUTER_API_KEY", None)

    def test_load_dotenv_without_llm_key_has_any_llm_key_false(
        self, tmp_path: Path
    ) -> None:
        """When .env has no LLM keys, has_any_llm_key remains False."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "SOME_OTHER_VAR=value\nDATABASE_URL=postgres://x\n", encoding="utf-8"
        )

        saved = _clear_llm_keys()
        try:
            load_dotenv(env_file)
            from src.core.llm_config import has_any_llm_key

            assert has_any_llm_key() is False
        finally:
            _restore_llm_keys(saved)

    def test_patched_load_dotenv_sets_env_before_import(self) -> None:
        """When load_dotenv is patched to set OPENROUTER_API_KEY, has_any_llm_key is True."""
        saved = _clear_llm_keys()
        try:

            def _mock_load_dotenv(_path: Path | str) -> bool:
                os.environ["OPENROUTER_API_KEY"] = "sk-patched"
                return True

            with patch("dotenv.load_dotenv", side_effect=_mock_load_dotenv):
                spec = importlib.util.spec_from_file_location(
                    "run_stage1_report", RUN_SCRIPT
                )
                if spec is None or spec.loader is None:
                    pytest.skip("Could not load run_stage1_report script")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

            from src.core.llm_config import has_any_llm_key

            assert has_any_llm_key() is True
        finally:
            _restore_llm_keys(saved)
            os.environ.pop("OPENROUTER_API_KEY", None)

    def test_run_stage1_report_calls_load_dotenv_with_backend_env(self) -> None:
        """Script calls load_dotenv with backend/.env path before importing stage1_report_generator."""
        with patch("dotenv.load_dotenv") as mock_load:
            spec = importlib.util.spec_from_file_location(
                "run_stage1_report", RUN_SCRIPT
            )
            if spec is None or spec.loader is None:
                pytest.skip("Could not load run_stage1_report script")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

        mock_load.assert_called_once()
        call_arg = mock_load.call_args[0][0]
        assert "backend" in str(call_arg)
        assert ".env" in str(call_arg)
