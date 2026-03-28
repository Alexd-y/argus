"""Load OWASP Top 10:2025 Russian reference copy from JSON (OWASP-001).

Thread-safe lazy load: first call reads and caches; subsequent calls reuse cache.
Assumption: settings.owasp_json_path is not mutated at runtime after first load.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from src.core.config import settings
from src.owasp_top10_2025 import OWASP_TOP10_2025_CATEGORY_IDS

logger = logging.getLogger(__name__)

_OWP_KEYS: tuple[str, ...] = (
    "title_ru",
    "example_attack",
    "how_to_find",
    "how_to_fix",
)

_lock = threading.Lock()
_cache: dict[str, dict[str, Any]] | None = None


def _backend_root() -> Path:
    """Directory containing ``src/`` (ARGUS backend root)."""
    return Path(__file__).resolve().parent.parent.parent


def _resolved_json_path() -> Path:
    raw = (settings.owasp_json_path or "").strip()
    if not raw:
        return _backend_root() / "data" / "owasp_top_10_2025_ru.json"
    p = Path(raw)
    if not p.is_absolute():
        return _backend_root() / p
    return p


def _load_file_into_dict(path: Path) -> dict[str, Any]:
    if not path.is_file():
        logger.warning(
            "OWASP reference JSON not found at configured path",
            extra={"event": "owasp_json_missing", "path": str(path)},
        )
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        logger.warning(
            "OWASP reference JSON could not be loaded",
            extra={
                "event": "owasp_json_load_failed",
                "path": str(path),
                "error_type": type(exc).__name__,
            },
        )
        return {}
    if not isinstance(data, dict):
        logger.warning(
            "OWASP reference JSON root must be an object",
            extra={"event": "owasp_json_invalid_root", "path": str(path)},
        )
        return {}
    return data


def _normalize_category_entry(entry: Any) -> dict[str, str]:
    if not isinstance(entry, dict):
        return {}
    out: dict[str, str] = {}
    for key in _OWP_KEYS:
        val = entry.get(key)
        if isinstance(val, str):
            out[key] = val
    return out


def _build_cache(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for cat_id in OWASP_TOP10_2025_CATEGORY_IDS:
        normalized = _normalize_category_entry(raw.get(cat_id))
        if normalized:
            out[cat_id] = normalized
    return out


def _ensure_loaded() -> dict[str, dict[str, Any]]:
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        if _cache is not None:
            return _cache
        path = _resolved_json_path()
        raw = _load_file_into_dict(path)
        _cache = _build_cache(raw)
        return _cache


def get_owasp_category_info(category_id: str) -> dict[str, Any]:
    """Return RU fields for ``A01``…``A10``; empty dict if unknown or missing block.

    Keys when present: ``title_ru``, ``example_attack``, ``how_to_find``, ``how_to_fix`` (strings).
    Partial dict if only some keys exist in JSON.
    """
    cid = (category_id or "").strip().upper()
    if not cid:
        return {}
    entry = _ensure_loaded().get(cid)
    if not entry:
        return {}
    return dict(entry)


def get_all_owasp_categories_ru() -> dict[str, dict[str, Any]]:
    """All loaded categories (typically A01…A10) for Jinja / templates."""
    return {k: dict(v) for k, v in _ensure_loaded().items()}
