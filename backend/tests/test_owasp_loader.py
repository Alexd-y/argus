"""OWASP-001 — JSON loader for RU OWASP Top 10:2025 reference."""

from __future__ import annotations

import json

from src.owasp.owasp_loader import get_all_owasp_categories_ru, get_owasp_category_info
from src.owasp_top10_2025 import OWASP_TOP10_2025_CATEGORY_IDS


def test_get_owasp_category_info_a05_has_four_string_keys() -> None:
    info = get_owasp_category_info("A05")
    assert "title_ru" in info
    assert "example_attack" in info
    assert "how_to_find" in info
    assert "how_to_fix" in info
    for k in ("title_ru", "example_attack", "how_to_find", "how_to_fix"):
        assert isinstance(info[k], str) and len(info[k]) > 0


def test_get_owasp_category_info_case_insensitive_id() -> None:
    assert get_owasp_category_info("a01") == get_owasp_category_info("A01")


def test_get_owasp_category_info_unknown_returns_empty() -> None:
    assert get_owasp_category_info("A99") == {}
    assert get_owasp_category_info("") == {}


def test_get_all_owasp_categories_ru_covers_all_ids() -> None:
    all_ru = get_all_owasp_categories_ru()
    for cid in OWASP_TOP10_2025_CATEGORY_IDS:
        assert cid in all_ru
        entry = all_ru[cid]
        assert isinstance(entry, dict)
        assert set(entry.keys()) <= {
            "title_ru",
            "example_attack",
            "how_to_find",
            "how_to_fix",
        }


def test_owasp_json_file_validates_against_repo_file() -> None:
    """Sanity: on-disk JSON matches expected top-level keys."""
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "data" / "owasp_top_10_2025_ru.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert set(raw.keys()) == set(OWASP_TOP10_2025_CATEGORY_IDS)
