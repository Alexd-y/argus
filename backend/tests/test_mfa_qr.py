"""P2 — MFA enrollment QR data-URI via optional QR library (segno/qrcode)."""

from __future__ import annotations

import base64
import sys
import types

from src.api.admin.mfa import _build_qr_data_uri

_URI = "otpauth://totp/ARGUS:admin?secret=ABC&issuer=ARGUS"


def test_qr_none_when_no_library(monkeypatch) -> None:
    # Force both optional imports to fail even if installed in the env.
    monkeypatch.setitem(sys.modules, "segno", None)
    monkeypatch.setitem(sys.modules, "qrcode", None)
    assert _build_qr_data_uri(_URI) is None


def test_qr_png_data_uri_with_segno(monkeypatch) -> None:
    fake = types.ModuleType("segno")

    class _QR:
        def save(self, buf, kind=None, scale=None) -> None:  # noqa: ARG002
            buf.write(b"\x89PNG\r\n\x1a\nFAKE")

    fake.make = lambda _uri, error=None: _QR()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "segno", fake)

    out = _build_qr_data_uri(_URI)
    assert out is not None
    assert out.startswith("data:image/png;base64,")
    decoded = base64.b64decode(out.split(",", 1)[1])
    assert decoded.startswith(b"\x89PNG")


def test_qr_falls_back_to_qrcode(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "segno", None)  # segno import fails
    fake = types.ModuleType("qrcode")

    class _Img:
        def save(self, buf, format=None) -> None:  # noqa: A002, ARG002
            buf.write(b"\x89PNGqrcode")

    fake.make = lambda _uri: _Img()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "qrcode", fake)

    out = _build_qr_data_uri(_URI)
    assert out is not None and out.startswith("data:image/png;base64,")
    assert base64.b64decode(out.split(",", 1)[1]) == b"\x89PNGqrcode"
