"""Wave 2 / stage 7 — scan evidence manifest persisted with a reproducible root hash (PG)."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.db.session import set_session_tenant
from src.evidence.manifest import ManifestEntry, build_and_persist_manifest, compute_root_hash

pytestmark = pytest.mark.requires_postgres

_RAW = os.environ.get("DATABASE_URL", "")
_HAS_PG = _RAW.startswith(("postgresql://", "postgresql+", "postgres://"))
pytestmark_pg = pytest.mark.skipif(not _HAS_PG, reason="DATABASE_URL is not a Postgres URL")

_BACKEND_ROOT = Path(__file__).resolve().parents[3]


def _async_url(url: str) -> str:
    return url if "+asyncpg" in url else url.replace("postgresql://", "postgresql+asyncpg://", 1)


def _sync_url(url: str) -> str:
    return url.replace("+asyncpg", "")


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    if not _HAS_PG:
        return
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _async_url(_RAW))
    command.upgrade(cfg, "head")


@pytestmark_pg
async def test_manifest_root_hash_is_reproducible() -> None:
    tenant_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    sha_a = hashlib.sha256(b"alpha").hexdigest()
    sha_b = hashlib.sha256(b"beta").hexdigest()
    key_a = f"{tenant_id}/{scan_id}/evidence/raw_output-a.bin"
    key_b = f"{tenant_id}/{scan_id}/evidence/raw_output-b.bin"

    sync_engine = sa.create_engine(_sync_url(_RAW), future=True)
    try:
        with sync_engine.begin() as conn:
            conn.execute(
                text("INSERT INTO tenants (id, name) VALUES (:id, :n)"),
                {"id": tenant_id, "n": "w2-manifest-test"},
            )
    finally:
        sync_engine.dispose()

    engine = create_async_engine(_async_url(_RAW), future=True)
    try:
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            await set_session_tenant(session, tenant_id)
            await session.execute(
                text("INSERT INTO scans (id, tenant_id, target_url) VALUES (:id, :t, :u)"),
                {"id": scan_id, "t": tenant_id, "u": "http://target.example"},
            )
            for ev_id, key, sha in ((uuid.uuid4(), key_a, sha_a), (uuid.uuid4(), key_b, sha_b)):
                await session.execute(
                    text(
                        "INSERT INTO evidence (id, tenant_id, scan_id, object_key, kind, "
                        "checksum_algorithm, checksum_value, size_bytes) "
                        "VALUES (:id, :t, :s, :k, 'raw_output', 'sha256', :c, :sz)"
                    ),
                    {"id": str(ev_id), "t": tenant_id, "s": scan_id, "k": key, "c": sha, "sz": 5},
                )

            manifest = await build_and_persist_manifest(
                session, tenant_id=tenant_id, scan_id=scan_id, audit_logger=None
            )
            await session.flush()

            expected_root = compute_root_hash(
                [ManifestEntry(key_a, sha_a), ManifestEntry(key_b, sha_b)]
            )
            assert manifest["root_hash"] == expected_root
            assert manifest["artifact_count"] == 2

            row = (
                await session.execute(
                    text(
                        "SELECT root_hash, artifact_count, total_size_bytes "
                        "FROM evidence_manifests WHERE scan_id = :s"
                    ),
                    {"s": scan_id},
                )
            ).one()
            assert row.root_hash == expected_root
            assert row.artifact_count == 2
            assert row.total_size_bytes == 10

            await session.rollback()
    finally:
        cleanup = sa.create_engine(_sync_url(_RAW), future=True)
        try:
            with cleanup.begin() as conn:
                conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        finally:
            cleanup.dispose()
        await engine.dispose()
