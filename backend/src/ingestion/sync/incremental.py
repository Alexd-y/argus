"""Incremental sync engine — webhook-driven + scheduled backfill."""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def compute_content_hash(content: str | bytes) -> str:
    """Compute SHA-256 hash of content for provenance tracking."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_file_fingerprint(path: str, content_hash: str, modified_at: datetime | None = None) -> str:
    """Stable fingerprint combining path + hash + optional timestamp."""
    ts = modified_at.isoformat() if modified_at else ""
    return hashlib.blake2b(
        f"{path}|{content_hash}|{ts}".encode(), digest_size=16
    ).hexdigest()


class IncrementalSync:
    """Tracks what has been synced and determines what needs updating.

    Uses content hashing to avoid re-processing unchanged files.
    """

    def __init__(self, tenant_id: str, repo_id: str) -> None:
        self.tenant_id = tenant_id
        self.repo_id = repo_id
        self._fingerprints: dict[str, str] = {}  # path → fingerprint

    def has_changed(self, path: str, content: str | bytes, modified_at: datetime | None = None) -> bool:
        content_hash = compute_content_hash(content)
        fingerprint = compute_file_fingerprint(path, content_hash, modified_at)
        previous = self._fingerprints.get(path)
        if previous == fingerprint:
            return False
        self._fingerprints[path] = fingerprint
        return True

    def mark_synced(self, path: str, content: str | bytes, modified_at: datetime | None = None) -> None:
        content_hash = compute_content_hash(content)
        fingerprint = compute_file_fingerprint(path, content_hash, modified_at)
        self._fingerprints[path] = fingerprint

    def get_changed_paths(
        self, current: dict[str, str], modified_dates: dict[str, datetime] | None = None
    ) -> list[str]:
        """Compare current state against tracked fingerprints, return changed paths."""
        modified_dates = modified_dates or {}
        changed = []
        for path, content_hash in current.items():
            fingerprint = compute_file_fingerprint(path, content_hash, modified_dates.get(path))
            if self._fingerprints.get(path) != fingerprint:
                changed.append(path)
        return changed

    def snapshot(self) -> dict[str, str]:
        return dict(self._fingerprints)

    @staticmethod
    def from_snapshot(tenant_id: str, repo_id: str, snapshot: dict[str, str]) -> "IncrementalSync":
        sync = IncrementalSync(tenant_id, repo_id)
        sync._fingerprints = dict(snapshot)
        return sync


class ProvenanceTracker:
    """Tracks provenance of artifacts: source commit, sync time, content hash."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id

    def build_record(
        self,
        repo_id: str,
        path: str,
        content: str | bytes,
        commit_sha: str = "",
        source: str = "webhook",
    ) -> dict[str, Any]:
        content_hash = compute_content_hash(content)
        return {
            "tenant_id": self.tenant_id,
            "repo_id": repo_id,
            "path": path,
            "content_hash": content_hash,
            "commit_sha": commit_sha,
            "source": source,
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "size_bytes": len(content),
        }
