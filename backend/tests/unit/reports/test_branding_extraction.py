"""Wave 4 / Stage 6 — branding section extracted from the monolith.

Pins the branding behaviour (BrandModel defaults, cached get_brand, logo resolution) and
that it is re-exported from valhalla_report_context so consumers import unchanged.
"""

from __future__ import annotations

from src.reports.valhalla_sections.branding import (
    BRAND_NAME,
    BrandModel,
    _resolve_logo_path,
    get_brand,
)


def test_brand_defaults() -> None:
    b = BrandModel()
    assert b.name == BRAND_NAME == "Svalbard Security Inc."
    assert b.logo_file == "logo.svg"
    assert b.logo_mime == "image/svg+xml"


def test_get_brand_is_cached() -> None:
    assert get_brand() is get_brand()


def test_logo_path_resolution_env(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_LOGO_PATH", "/custom/logo.svg")
    assert str(_resolve_logo_path()) in ("/custom/logo.svg", "\\custom\\logo.svg")


def test_reexported_from_monolith() -> None:
    import src.reports.valhalla_report_context as m

    assert m.get_brand is get_brand
    assert m.BrandModel is BrandModel
    assert m.BRAND_NAME == BRAND_NAME
