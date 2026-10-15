"""Report branding: logo resolution + hydration (Wave 4 / Stage 6).

Extracted verbatim from ``valhalla_report_context``. Self-contained (stdlib + pydantic +
optional cairosvg); no monolith import, so no cycle. The monolith re-exports these names.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict

BRAND_NAME = "Svalbard Security Inc."
LOGO_FILENAME = "logo.svg"
LOGO_MIME = "image/svg+xml"
_LOGO_PATH_ENV = "ARGUS_LOGO_PATH"


def _resolve_logo_path() -> Path:
    env_path = os.environ.get(_LOGO_PATH_ENV)
    if env_path:
        return Path(env_path)
    candidates = [
        Path(__file__).parent.parent.parent.parent / "templates" / "reports" / LOGO_FILENAME,
        Path("/app/templates/reports") / LOGO_FILENAME,
        Path.cwd() / "templates" / "reports" / LOGO_FILENAME,
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


class BrandModel(BaseModel):
    """Report branding: logo, name, integrity hashes for all export formats."""

    model_config = ConfigDict(extra="forbid")

    name: str = BRAND_NAME
    logo_file: str = LOGO_FILENAME
    logo_mime: str = LOGO_MIME
    logo_sha256: str = ""
    logo_base64_svg: str = ""
    logo_base64_png: str = ""
    alt_text: str = "Svalbard Security Inc. logo"

    def hydrate_logo(self) -> None:
        logo_path = _resolve_logo_path()
        if not logo_path.exists():
            return
        raw = logo_path.read_bytes()
        self.logo_sha256 = hashlib.sha256(raw).hexdigest()
        self.logo_base64_svg = base64.b64encode(raw).decode("ascii")
        try:
            import cairosvg

            png_bytes = cairosvg.svg2png(bytestring=raw, output_width=240, output_height=101)
            self.logo_base64_png = base64.b64encode(png_bytes).decode("ascii")
        except Exception:  # noqa: BLE001 — PNG is best-effort; SVG always present
            self.logo_base64_png = ""


_CACHED_BRAND: BrandModel | None = None


def get_brand() -> BrandModel:
    global _CACHED_BRAND
    if _CACHED_BRAND is None:
        _CACHED_BRAND = BrandModel()
        _CACHED_BRAND.hydrate_logo()
    return _CACHED_BRAND


__all__ = [
    "BRAND_NAME",
    "LOGO_FILENAME",
    "LOGO_MIME",
    "BrandModel",
    "get_brand",
]
