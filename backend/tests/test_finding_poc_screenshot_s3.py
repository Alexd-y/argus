"""PoC screenshot MinIO keys and presign tenant/scan scope (POC-002)."""

from __future__ import annotations

from unittest.mock import patch

from src.storage.s3 import (
    build_finding_poc_screenshot_object_key,
    get_finding_poc_screenshot_presigned_url,
)


def test_build_finding_poc_screenshot_object_key_shape() -> None:
    k = build_finding_poc_screenshot_object_key("ten1", "scan1", "fid-9")
    assert k == "ten1/scan1/poc/screenshots/fid-9.png"


def test_build_finding_poc_screenshot_object_key_strips_duplicate_png_suffix() -> None:
    k = build_finding_poc_screenshot_object_key("t", "s", "x.png")
    assert k == "t/s/poc/screenshots/x.png"


def test_get_finding_poc_screenshot_presigned_url_rejects_wrong_tenant_prefix() -> None:
    key = "ten1/scan1/poc/screenshots/f.png"
    assert get_finding_poc_screenshot_presigned_url(key, "other", "scan1") is None


def test_get_finding_poc_screenshot_presigned_url_rejects_non_png_suffix() -> None:
    key = "ten1/scan1/poc/screenshots/f.jpg"
    assert get_finding_poc_screenshot_presigned_url(key, "ten1", "scan1") is None


def test_get_finding_poc_screenshot_presigned_url_rejects_nested_basename() -> None:
    key = "ten1/scan1/poc/screenshots/evil/extra.png"
    assert get_finding_poc_screenshot_presigned_url(key, "ten1", "scan1") is None


@patch("src.storage.s3.get_presigned_url_by_key")
def test_get_finding_poc_screenshot_presigned_url_delegates(mock_presign) -> None:
    mock_presign.return_value = "https://signed.example/x"
    key = "ten1/scan1/poc/screenshots/f.png"
    out = get_finding_poc_screenshot_presigned_url(key, "ten1", "scan1")
    assert out == "https://signed.example/x"
    mock_presign.assert_called_once()
