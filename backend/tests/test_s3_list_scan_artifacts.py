"""list_scan_artifacts — prefix, raw filter, pagination (mock boto3)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from src.core.config import settings
from src.storage.s3 import list_scan_artifacts


@pytest.fixture
def mock_s3_client() -> MagicMock:
    return MagicMock()


class TestListScanArtifacts:
    def test_phase_raw_uses_tenant_scan_phase_raw_prefix(self, mock_s3_client: MagicMock) -> None:
        mock_s3_client.list_objects_v2.return_value = {"Contents": [], "IsTruncated": False}
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            out = list_scan_artifacts(
                "tenant-a",
                "scan-b",
                phase="recon",
                raw_only=True,
            )
        assert out == []
        mock_s3_client.list_objects_v2.assert_called()
        call_kw = mock_s3_client.list_objects_v2.call_args.kwargs
        assert call_kw["Bucket"] == settings.minio_bucket
        assert call_kw["Prefix"] == "tenant-a/scan-b/recon/raw/"

    def test_raw_only_without_phase_filters_non_raw_keys(self, mock_s3_client: MagicMock) -> None:
        mock_s3_client.list_objects_v2.return_value = {
            "Contents": [
                {
                    "Key": "t1/s1/screenshots/x.png",
                    "Size": 1,
                    "LastModified": datetime(2025, 1, 2, tzinfo=UTC),
                },
                {
                    "Key": "t1/s1/recon/raw/1_log.txt",
                    "Size": 2,
                    "LastModified": datetime(2025, 1, 3, tzinfo=UTC),
                },
                {
                    "Key": "t1/s1/raw/legacy.txt",
                    "Size": 3,
                    "LastModified": datetime(2025, 1, 4, tzinfo=UTC),
                },
            ],
            "IsTruncated": False,
        }
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            out = list_scan_artifacts("t1", "s1", phase=None, raw_only=True)
        assert out is not None
        keys = [x["key"] for x in out]
        assert "t1/s1/screenshots/x.png" not in keys
        assert "t1/s1/recon/raw/1_log.txt" in keys
        assert "t1/s1/raw/legacy.txt" in keys

    def test_invalid_tenant_returns_none(self, mock_s3_client: MagicMock) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            out = list_scan_artifacts("../evil", "s1", phase=None, raw_only=False)
        assert out is None
        mock_s3_client.list_objects_v2.assert_not_called()

    def test_no_client_returns_none(self) -> None:
        with patch("src.storage.s3._get_client", return_value=None):
            out = list_scan_artifacts("t1", "s1", phase=None, raw_only=False)
        assert out is None

    def test_lists_both_buckets_when_full_scan_prefix(self, mock_s3_client: MagicMock) -> None:
        def _list(**kwargs: object) -> dict:
            b = kwargs["Bucket"]
            if b == settings.minio_bucket:
                return {
                    "Contents": [
                        {
                            "Key": "t1/s1/evidence/a.txt",
                            "Size": 5,
                            "LastModified": datetime(2025, 1, 1, tzinfo=UTC),
                        }
                    ],
                    "IsTruncated": False,
                }
            return {
                "Contents": [
                    {
                        "Key": "t1/s1/reports/midgard/r1.pdf",
                        "Size": 9,
                        "LastModified": datetime(2025, 1, 2, tzinfo=UTC),
                    }
                ],
                "IsTruncated": False,
            }

        mock_s3_client.list_objects_v2.side_effect = _list
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            out = list_scan_artifacts("t1", "s1", phase=None, raw_only=False)
        assert out is not None
        assert len(out) == 2
        assert {x["key"] for x in out} == {
            "t1/s1/evidence/a.txt",
            "t1/s1/reports/midgard/r1.pdf",
        }

    def test_invalid_phase_raises(self, mock_s3_client: MagicMock) -> None:
        with (
            patch("src.storage.s3._get_client", return_value=mock_s3_client),
            pytest.raises(ValueError, match="Invalid phase"),
        ):
            list_scan_artifacts("t1", "s1", phase="not_a_phase", raw_only=False)
