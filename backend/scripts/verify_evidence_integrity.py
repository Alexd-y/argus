"""Evidence-base integrity check (wave 2, R-5.6.3).

Verifies a scan's stored evidence against its manifest and audit chain using
only the data — no trust in the running ARGUS application. For the given scan
it: reads the manifest + evidence rows, downloads each artifact from object
storage and recomputes its SHA-256, re-derives the root hash, and replays the
tamper-evident audit chain. Prints a report and exits non-zero on any
discrepancy, so an auditor can confirm an evidence base was not edited after
release.

Usage::

    cd backend
    DATABASE_URL=postgresql+asyncpg://argus:...@host:5432/argus \\
        python -m scripts.verify_evidence_integrity --scan-id <uuid> --tenant-id <uuid>
"""

from __future__ import annotations

import argparse
import sys
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import text
from src.evidence.manifest import ManifestEntry, verify_integrity
from src.policy.audit import AuditChainError, AuditLogger
from src.policy.audit_db import DatabaseAuditSink, _sync_url


def _engine() -> sa.engine.Engine:
    from src.core.config import settings

    url = settings.database_url or ""
    if not url.startswith(("postgresql://", "postgresql+", "postgres://")):
        raise SystemExit("DATABASE_URL must be a Postgres URL for the integrity check")
    return sa.create_engine(_sync_url(url), future=True)


def _load(
    engine: sa.engine.Engine, tenant_id: str, scan_id: str
) -> tuple[str | None, list[ManifestEntry]]:
    with engine.begin() as conn:
        conn.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))
        manifest = conn.execute(
            text(
                "SELECT root_hash FROM evidence_manifests "
                "WHERE tenant_id = :t AND scan_id = :s ORDER BY created_at DESC LIMIT 1"
            ),
            {"t": tenant_id, "s": scan_id},
        ).first()
        rows = conn.execute(
            text(
                "SELECT object_key, checksum_value, size_bytes FROM evidence "
                "WHERE tenant_id = :t AND scan_id = :s"
            ),
            {"t": tenant_id, "s": scan_id},
        ).all()
    entries = [
        ManifestEntry(
            object_key=str(r.object_key),
            sha256=str(r.checksum_value or ""),
            size_bytes=r.size_bytes,
        )
        for r in rows
    ]
    return (manifest.root_hash if manifest else None), entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a scan's evidence-base integrity")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args(argv)

    engine = _engine()
    root_hash, entries = _load(engine, args.tenant_id, args.scan_id)
    if root_hash is None:
        print(f"FAIL: no manifest found for scan {args.scan_id}")
        return 2

    from src.storage.s3 import download_by_key

    report = verify_integrity(
        scan_id=args.scan_id,
        manifest_root_hash=root_hash,
        entries=entries,
        download=download_by_key,
    )

    audit_ok = True
    try:
        verified = AuditLogger(DatabaseAuditSink(engine)).verify_chain(
            tenant_id=UUID(args.tenant_id)
        )
        print(f"audit chain: {verified} events verified")
    except AuditChainError as exc:
        audit_ok = False
        print(f"audit chain: TAMPERED — {exc}")

    print(f"evidence: checked {report.checked} / {len(entries)} artifacts")
    for d in report.discrepancies:
        print(f"  DISCREPANCY [{d.reason}] {d.object_key} expected={d.expected} actual={d.actual}")

    if report.ok and audit_ok:
        print("OK: evidence base intact")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
