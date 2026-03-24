"""Roundtrip upload_raw_artifact + list_scan_artifacts per phase (in-memory fake S3; no MinIO)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest

from src.storage.s3 import RAW_ARTIFACT_PHASES, list_scan_artifacts, upload_raw_artifact


class _FakeS3Client:
    """Minimal boto3 S3 client: put_object stores keys; list_objects_v2 filters by prefix with pagination."""

    def __init__(self) -> None:
        self._store: dict[str, list[dict[str, Any]]] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, ContentType: str) -> dict[str, Any]:
        lst = self._store.setdefault(Bucket, [])
        lst.append(
            {
                "Key": Key,
                "Size": len(Body),
                "LastModified": datetime.now(UTC),
            }
        )
        return {}

    def list_objects_v2(
        self,
        *,
        Bucket: str,
        Prefix: str,
        MaxKeys: int = 1000,
        ContinuationToken: str | None = None,
    ) -> dict[str, Any]:
        all_keys = self._store.get(Bucket, [])
        matching = [o for o in all_keys if str(o["Key"]).startswith(Prefix)]
        matching.sort(key=lambda o: o["Key"])
        start = int(ContinuationToken or "0")
        page = matching[start : start + MaxKeys]
        next_start = start + len(page)
        out: dict[str, Any] = {
            "Contents": page,
            "IsTruncated": next_start < len(matching),
        }
        if out["IsTruncated"]:
            out["NextContinuationToken"] = str(next_start)
        return out


@pytest.fixture
def fake_s3() -> _FakeS3Client:
    return _FakeS3Client()


@pytest.mark.storage_contract
def test_full_scan_concept_each_phase_raw_key_upload_then_listable(fake_s3: _FakeS3Client) -> None:
    """
    After uploads for every RAW_ARTIFACT_PHASE, list_scan_artifacts(phase, raw_only=True)
    returns at least one key under that phase — acceptance proxy for MinIO without real MinIO.
    """
    tenant_id = "00000000-0000-0000-0000-0000000000aa"
    scan_id = "scan-roundtrip-1"
    ts = "2026-03-24T00:00:00Z"

    with patch("src.storage.s3._get_client", return_value=fake_s3):
        for phase in sorted(RAW_ARTIFACT_PHASES):
            key = upload_raw_artifact(
                tenant_id,
                scan_id,
                phase,
                ts,
                "ci_phase_probe",
                "txt",
                f"probe-{phase}\n".encode(),
            )
            assert key is not None
            assert f"/{phase}/raw/" in key

            listed = list_scan_artifacts(
                tenant_id,
                scan_id,
                phase=phase,
                raw_only=True,
            )
            assert listed is not None
            keys = [row["key"] for row in listed]
            assert key in keys, f"missing listed key for phase={phase}"

        listed_all_raw = list_scan_artifacts(tenant_id, scan_id, phase=None, raw_only=True)
        assert listed_all_raw is not None
        all_keys = {row["key"] for row in listed_all_raw}
        assert len(all_keys) >= len(RAW_ARTIFACT_PHASES)
        for phase in RAW_ARTIFACT_PHASES:
            assert any(
                k.startswith(f"{tenant_id}/{scan_id}/{phase}/raw/") for k in all_keys
            ), f"no raw key under phase prefix {phase}"


@pytest.mark.storage_contract
def test_list_pagination_still_finds_all_phase_keys(fake_s3: _FakeS3Client) -> None:
    """list_scan_artifacts paginates; fake client returns multiple pages."""
    from src.storage import s3 as s3_mod

    tenant_id = "t-paginate"
    scan_id = "s-paginate"
    with patch.object(s3_mod, "_LIST_OBJECTS_PAGE_SIZE", 2):
        with patch("src.storage.s3._get_client", return_value=fake_s3):
            for i, phase in enumerate(sorted(RAW_ARTIFACT_PHASES)):
                upload_raw_artifact(
                    tenant_id,
                    scan_id,
                    phase,
                    f"ts{i}",
                    "probe",
                    "bin",
                    b"x",
                )
            out = list_scan_artifacts(tenant_id, scan_id, phase=None, raw_only=True)
    assert out is not None
    assert len(out) >= len(RAW_ARTIFACT_PHASES)
