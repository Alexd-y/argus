"""Tests for Stage 4 MinIO storage — upload, download, key building, path traversal."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.recon.stage_object_download import StageObjectFetchError
from src.recon.stage4_storage import (
    STAGE4_ROOT_FILES,
    _build_object_key,
    _content_type_for,
    download_stage4_artifact,
    ensure_stage4_artifacts_bucket,
    upload_stage4_artifacts,
)


# ---------------------------------------------------------------------------
# _build_object_key
# ---------------------------------------------------------------------------


class TestBuildObjectKey:
    def test_valid_key(self) -> None:
        key = _build_object_key("scan-123", "exploitation_plan.json")
        assert key == "scan-123/exploitation_plan.json"

    def test_path_traversal_rejected(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            _build_object_key("scan-1", "../../../etc/passwd")

    def test_backslash_rejected(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            _build_object_key("scan-1", "..\\etc\\passwd")

    def test_empty_relative_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            _build_object_key("scan-1", "")

    def test_forward_slash_converted(self) -> None:
        key = _build_object_key("scan-1", "subdir/file.json")
        assert "\\" not in key


# ---------------------------------------------------------------------------
# _content_type_for
# ---------------------------------------------------------------------------


class TestContentTypeFor:
    def test_json(self) -> None:
        assert _content_type_for(Path("file.json")) == "application/json"

    def test_txt(self) -> None:
        assert _content_type_for(Path("file.txt")) == "text/plain"

    def test_md(self) -> None:
        assert _content_type_for(Path("file.md")) == "text/plain"

    def test_csv(self) -> None:
        assert _content_type_for(Path("file.csv")) == "text/plain"

    def test_unknown(self) -> None:
        assert _content_type_for(Path("file.xyz")) == "application/octet-stream"

    def test_json_uppercase(self) -> None:
        assert _content_type_for(Path("file.JSON")) == "application/json"


# ---------------------------------------------------------------------------
# ensure_stage4_artifacts_bucket
# ---------------------------------------------------------------------------


class TestEnsureBucket:
    @patch("src.recon.stage4_storage.ensure_bucket", return_value=True)
    def test_bucket_created(self, mock_ensure) -> None:
        assert ensure_stage4_artifacts_bucket() is True
        mock_ensure.assert_called_once()

    @patch("src.recon.stage4_storage.ensure_bucket", return_value=False)
    def test_bucket_unavailable(self, mock_ensure) -> None:
        assert ensure_stage4_artifacts_bucket() is False


# ---------------------------------------------------------------------------
# upload_stage4_artifacts
# ---------------------------------------------------------------------------


class TestUploadStage4Artifacts:
    @patch("src.recon.stage4_storage._get_client")
    def test_no_client_returns_empty(self, mock_client) -> None:
        mock_client.return_value = None
        result = upload_stage4_artifacts(Path("/tmp/artifacts"), "scan-1", "run-1")
        assert result == []

    @patch("src.recon.stage4_storage.ensure_stage4_artifacts_bucket", return_value=False)
    @patch("src.recon.stage4_storage._get_client")
    def test_no_bucket_returns_empty(self, mock_client, mock_ensure) -> None:
        mock_client.return_value = MagicMock()
        result = upload_stage4_artifacts(Path("/tmp/artifacts"), "scan-1", "run-1")
        assert result == []

    @patch("src.recon.stage4_storage.ensure_stage4_artifacts_bucket", return_value=True)
    @patch("src.recon.stage4_storage._get_client")
    def test_nonexistent_dir_returns_empty(self, mock_client, mock_ensure) -> None:
        mock_client.return_value = MagicMock()
        result = upload_stage4_artifacts(Path("/nonexistent/dir"), "scan-1", "run-1")
        assert result == []

    @patch("src.recon.stage4_storage.ensure_stage4_artifacts_bucket", return_value=True)
    @patch("src.recon.stage4_storage._get_client")
    def test_successful_upload(self, mock_client, mock_ensure, tmp_path: Path) -> None:
        client = MagicMock()
        mock_client.return_value = client

        for filename in STAGE4_ROOT_FILES:
            (tmp_path / filename).write_text("{}", encoding="utf-8")

        result = upload_stage4_artifacts(tmp_path, "scan-1", "run-1")

        assert len(result) == len(STAGE4_ROOT_FILES)
        assert client.put_object.call_count == len(STAGE4_ROOT_FILES)

        for call_args in client.put_object.call_args_list:
            kwargs = call_args[1]
            assert kwargs["ContentType"] == "application/json"
            assert "scan-1" in kwargs["Metadata"]["scan_id"]
            assert "run-1" in kwargs["Metadata"]["run_id"]

    @patch("src.recon.stage4_storage.ensure_stage4_artifacts_bucket", return_value=True)
    @patch("src.recon.stage4_storage._get_client")
    def test_partial_files_uploaded(self, mock_client, mock_ensure, tmp_path: Path) -> None:
        client = MagicMock()
        mock_client.return_value = client

        (tmp_path / "exploitation_plan.json").write_text("{}", encoding="utf-8")
        (tmp_path / "stage4_results.json").write_text("{}", encoding="utf-8")
        # shells.json and ai_exploitation_summary.json are missing

        result = upload_stage4_artifacts(tmp_path, "scan-1", "run-1")

        assert len(result) == 2
        assert client.put_object.call_count == 2

    @patch("src.recon.stage4_storage.ensure_stage4_artifacts_bucket", return_value=True)
    @patch("src.recon.stage4_storage._get_client")
    def test_upload_error_skips_file(self, mock_client, mock_ensure, tmp_path: Path) -> None:
        client = MagicMock()
        client.put_object.side_effect = [None, OSError("Network error"), None, None]
        mock_client.return_value = client

        for filename in STAGE4_ROOT_FILES:
            (tmp_path / filename).write_text("{}", encoding="utf-8")

        result = upload_stage4_artifacts(tmp_path, "scan-1", "run-1")

        # 3 succeeded, 1 failed
        assert len(result) == 3


# ---------------------------------------------------------------------------
# download_stage4_artifact
# ---------------------------------------------------------------------------


class TestDownloadStage4Artifact:
    @patch("src.recon.stage4_storage._get_client")
    def test_no_client_raises_storage_error(self, mock_client) -> None:
        mock_client.return_value = None
        with pytest.raises(StageObjectFetchError) as ei:
            download_stage4_artifact("scan-1", "stage4_results.json")
        assert ei.value.code == "storage_error"

    @patch("src.recon.stage4_storage._get_client")
    def test_successful_download(self, mock_client) -> None:
        body = MagicMock()
        body.read.return_value = b'{"results": []}'
        client = MagicMock()
        client.get_object.return_value = {"Body": body}
        mock_client.return_value = client

        data = download_stage4_artifact("scan-1", "stage4_results.json")
        assert data == b'{"results": []}'

    @patch("src.recon.stage4_storage._get_client")
    def test_object_missing_returns_none(self, mock_client) -> None:
        client = MagicMock()
        client.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "not found"}},
            "GetObject",
        )
        mock_client.return_value = client

        assert download_stage4_artifact("scan-1", "nonexistent.json") is None

    @patch("src.recon.stage4_storage._get_client")
    def test_download_other_error_raises_fetch_failed(self, mock_client) -> None:
        client = MagicMock()
        client.get_object.side_effect = RuntimeError("timeout")
        mock_client.return_value = client

        with pytest.raises(StageObjectFetchError) as ei:
            download_stage4_artifact("scan-1", "nonexistent.json")
        assert ei.value.code == "fetch_failed"

    @patch("src.recon.stage4_storage._get_client")
    def test_download_path_traversal_rejected(self, mock_client) -> None:
        client = MagicMock()
        mock_client.return_value = client

        with pytest.raises(ValueError, match="path traversal"):
            download_stage4_artifact("scan-1", "../../etc/passwd")


# ---------------------------------------------------------------------------
# STAGE4_ROOT_FILES constant
# ---------------------------------------------------------------------------


class TestStage4RootFiles:
    def test_expected_files(self) -> None:
        expected = {
            "exploitation_plan.json",
            "stage4_results.json",
            "shells.json",
            "ai_exploitation_summary.json",
        }
        assert set(STAGE4_ROOT_FILES) == expected

    def test_all_json(self) -> None:
        for f in STAGE4_ROOT_FILES:
            assert f.endswith(".json")
