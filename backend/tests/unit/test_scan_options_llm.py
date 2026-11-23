"""WP C integration — multi-LLM rotation controls on scan options.

Pure/offline (unit/). ``llm_profile_ids`` + ``llm_rotate`` reach the scan options so
a caller can request rotation for the safe (non-sensitive) roles.
"""

from __future__ import annotations

from src.api.schemas import ScanOptions


def test_llm_options_default_off() -> None:
    opts = ScanOptions()
    assert opts.llm.llm_rotate is False
    assert opts.llm.llm_profile_ids == []


def test_llm_options_can_be_set() -> None:
    opts = ScanOptions(
        llm={"llm_rotate": True, "llm_profile_ids": ["argus-report", "argus-nvidia-hosted"]}
    )
    assert opts.llm.llm_rotate is True
    assert opts.llm.llm_profile_ids == ["argus-report", "argus-nvidia-hosted"]


def test_llm_options_ignore_unknown_keys() -> None:
    opts = ScanOptions(llm={"llm_rotate": True, "bogus": 1})
    assert opts.llm.llm_rotate is True
