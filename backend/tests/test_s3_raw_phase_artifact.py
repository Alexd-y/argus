"""Phase-scoped raw MinIO keys and upload_raw_artifact (mocked S3 client)."""

import io
from unittest.mock import MagicMock, patch

import pytest
from src.core.config import settings
from src.storage.s3 import (
    RAW_ARTIFACT_PHASES,
    build_raw_phase_object_key,
    upload_raw_artifact,
)


class TestBuildRawPhaseObjectKey:
    def test_key_matches_template(self) -> None:
        key = build_raw_phase_object_key(
            "00000000-0000-0000-0000-000000000001",
            "scan-abc",
            "vuln_analysis",
            "2026-03-23T12:00:00Z",
            "tool_xsstrike_stdout",
            "txt",
        )
        assert (
            key
            == "00000000-0000-0000-0000-000000000001/scan-abc/vuln_analysis/raw/"
            "2026-03-23T12:00:00Z_tool_xsstrike_stdout.txt"
        )

    @pytest.mark.parametrize("phase", sorted(RAW_ARTIFACT_PHASES))
    def test_each_valid_phase(self, phase: str) -> None:
        key = build_raw_phase_object_key("t1", "s1", phase, "ts1", "a", "json")
        assert key.startswith(f"t1/s1/{phase}/raw/")
        assert key.endswith("_a.json")

    def test_rejects_invalid_phase(self) -> None:
        with pytest.raises(ValueError, match="Invalid phase"):
            build_raw_phase_object_key("t", "s", "reconnaissance", "ts", "a", "log")

    @pytest.mark.parametrize("bad_phase", ["", "RECON", "post-exploitation", "vuln analysis"])
    def test_rejects_invalid_phase_variants(self, bad_phase: str) -> None:
        with pytest.raises(ValueError, match="Invalid phase"):
            build_raw_phase_object_key("t", "s", bad_phase, "ts1", "a", "txt")

    def test_rejects_path_traversal_tenant(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            build_raw_phase_object_key("../x", "s", "recon", "ts", "a", "txt")

    def test_rejects_path_traversal_scan_id(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            build_raw_phase_object_key("t", "../scan", "recon", "ts", "a", "txt")

    def test_rejects_path_traversal_timestamp(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            build_raw_phase_object_key("t", "s", "recon", "../ts", "a", "txt")

    def test_rejects_backslash_in_scan_id(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            build_raw_phase_object_key("t", r"s\evil", "recon", "ts", "a", "txt")

    def test_rejects_non_string_tenant_id(self) -> None:
        with pytest.raises(ValueError, match="tenant_id"):
            build_raw_phase_object_key(123, "s", "recon", "ts", "a", "txt")  # type: ignore[arg-type]

    def test_rejects_empty_tenant_after_strip(self) -> None:
        with pytest.raises(ValueError, match="tenant_id"):
            build_raw_phase_object_key("   ", "s", "recon", "ts", "a", "txt")

    @pytest.mark.parametrize(
        "bad_type",
        ["", "123a", "CamelCase", "a-b", "a/b", "../../../etc", "a..b"],
    )
    def test_rejects_invalid_artifact_type(self, bad_type: str) -> None:
        with pytest.raises(ValueError, match="artifact_type"):
            build_raw_phase_object_key("t", "s", "recon", "ts1", bad_type, "txt")

    @pytest.mark.parametrize("bad_ext", ["", ".", "a/b", "..", "tool.exe.bat"])
    def test_rejects_invalid_ext(self, bad_ext: str) -> None:
        with pytest.raises(ValueError, match="ext"):
            build_raw_phase_object_key("t", "s", "recon", "ts1", "ok", bad_ext)

    def test_strips_leading_dot_on_ext(self) -> None:
        key = build_raw_phase_object_key("t", "s", "recon", "ts1", "blob", ".json")
        assert key.endswith("_blob.json")


@pytest.fixture
def mock_s3_client() -> MagicMock:
    client = MagicMock()
    client.exceptions.ClientError = type("ClientError", (Exception,), {})
    client.put_object = MagicMock(return_value={})
    return client


class TestUploadRawArtifact:
    def test_put_object_minio_bucket_and_key(self, mock_s3_client: MagicMock) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            key = upload_raw_artifact(
                "tenant-1",
                "scan-1",
                "recon",
                "2026-03-23T10:00:00Z",
                "state_input",
                "json",
                b'{"x":1}',
                content_type=None,
            )
        expected = (
            "tenant-1/scan-1/recon/raw/2026-03-23T10:00:00Z_state_input.json"
        )
        assert key == expected
        mock_s3_client.put_object.assert_called_once()
        kwargs = mock_s3_client.put_object.call_args.kwargs
        assert kwargs["Bucket"] == settings.minio_bucket
        assert kwargs["Key"] == expected
        assert kwargs["Body"] == b'{"x":1}'
        assert kwargs["ContentType"] == "application/json"

    def test_explicit_content_type_overrides_ext(self, mock_s3_client: MagicMock) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            upload_raw_artifact(
                "t",
                "s",
                "threat_modeling",
                "ts",
                "ai_task",
                "bin",
                b"\x00",
                content_type="application/custom",
            )
        assert (
            mock_s3_client.put_object.call_args.kwargs["ContentType"]
            == "application/custom"
        )

    def test_returns_none_without_client(self) -> None:
        with patch("src.storage.s3._get_client", return_value=None):
            out = upload_raw_artifact(
                "t", "s", "exploitation", "ts", "x", "log", b"line\n"
            )
        assert out is None

    def test_returns_none_on_validation_error(self, mock_s3_client: MagicMock) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            out = upload_raw_artifact(
                "t", "s", "not_a_phase", "ts", "ok", "txt", b"x"
            )
        assert out is None
        mock_s3_client.put_object.assert_not_called()

    def test_returns_none_on_put_failure(self, mock_s3_client: MagicMock) -> None:
        mock_s3_client.put_object.side_effect = OSError("network")
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            out = upload_raw_artifact(
                "t", "s", "post_exploitation", "ts", "stderr", "txt", b"err"
            )
        assert out is None

    def test_empty_body_uploads_and_put_object_called(self, mock_s3_client: MagicMock) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            key = upload_raw_artifact(
                "t", "s", "recon", "ts", "empty_blob", "bin", b"", content_type=None
            )
        assert key == "t/s/recon/raw/ts_empty_blob.bin"
        mock_s3_client.put_object.assert_called_once()
        assert mock_s3_client.put_object.call_args.kwargs["Body"] == b""
        assert (
            mock_s3_client.put_object.call_args.kwargs["ContentType"]
            == "application/octet-stream"
        )

    def test_binary_io_body_read_and_uploaded(self, mock_s3_client: MagicMock) -> None:
        stream = io.BytesIO(b"stream-bytes")
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            key = upload_raw_artifact(
                "t", "s", "vuln_analysis", "ts", "tool_out", "log", stream, content_type=None
            )
        assert key == "t/s/vuln_analysis/raw/ts_tool_out.log"
        assert mock_s3_client.put_object.call_args.kwargs["Body"] == b"stream-bytes"

    @pytest.mark.parametrize(
        ("ext", "expected_ct"),
        [
            ("json", "application/json"),
            ("JSON", "application/json"),
            ("jsonl", "application/x-ndjson"),
            ("txt", "text/plain; charset=utf-8"),
            ("log", "text/plain; charset=utf-8"),
            ("html", "text/html; charset=utf-8"),
            ("htm", "text/html; charset=utf-8"),
            ("xml", "application/xml"),
            ("csv", "text/csv; charset=utf-8"),
            ("pdf", "application/pdf"),
            ("png", "image/png"),
            ("jpg", "image/jpeg"),
            ("jpeg", "image/jpeg"),
            ("gif", "image/gif"),
            ("webp", "image/webp"),
            ("weird", "application/octet-stream"),
        ],
    )
    def test_content_type_inferred_from_ext(
        self, mock_s3_client: MagicMock, ext: str, expected_ct: str
    ) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            upload_raw_artifact(
                "t", "s", "exploitation", "ts", "artifact", ext, b"x", content_type=None
            )
        assert mock_s3_client.put_object.call_args.kwargs["ContentType"] == expected_ct

    def test_empty_string_content_type_triggers_inference(
        self, mock_s3_client: MagicMock
    ) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            upload_raw_artifact(
                "t", "s", "recon", "ts", "x", "csv", b"1,2", content_type=""
            )
        assert (
            mock_s3_client.put_object.call_args.kwargs["ContentType"]
            == "text/csv; charset=utf-8"
        )
