"""NucleiUpdateController — release activate/rollback stubs with provenance (§9.11)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from src.nuclei.schemas import NucleiReleaseRecord


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _provenance_hash(provenance: dict[str, Any]) -> str:
    canonical = json.dumps(provenance, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class NucleiUpdateController:
    """Stub release controller — pins provenance; full supply chain in later stages."""

    def __init__(self) -> None:
        self._releases: dict[str, NucleiReleaseRecord] = {}
        self._active_release_id: str | None = None

    @property
    def active_release_id(self) -> str | None:
        return self._active_release_id

    def get_release(self, release_id: str) -> NucleiReleaseRecord | None:
        return self._releases.get(release_id)

    def list_releases(self) -> tuple[NucleiReleaseRecord, ...]:
        return tuple(
            sorted(
                self._releases.values(),
                key=lambda rec: (rec.version, rec.release_id),
            )
        )

    def register_release(
        self,
        release_id: str,
        version: str,
        digest_sha256: str,
        provenance: dict[str, Any] | None = None,
    ) -> NucleiReleaseRecord:
        prov = dict(provenance or {})
        prov.update(
            {
                "release_id": release_id,
                "version": version,
                "digest_sha256": digest_sha256,
            }
        )
        record = NucleiReleaseRecord(
            release_id=release_id,
            version=version,
            digest_sha256=digest_sha256,
            provenance=prov,
            provenance_hash=_provenance_hash(prov),
            status="pending",
        )
        self._releases[release_id] = record
        return record

    def activate_release(
        self,
        release_id: str,
        provenance: dict[str, Any] | None = None,
    ) -> NucleiReleaseRecord:
        record = self._releases.get(release_id)
        if record is None:
            raise KeyError(f"nuclei_release_not_found:{release_id}")

        prov = dict(record.provenance)
        if provenance:
            prov.update(provenance)
        prov["action"] = "activate"
        prov["activated_at"] = _utcnow().isoformat()

        previous = self._active_release_id
        if previous and previous in self._releases:
            prev_record = self._releases[previous]
            self._releases[previous] = prev_record.model_copy(update={"status": "rolled_back"})

        activated = record.model_copy(
            update={
                "status": "active",
                "provenance": prov,
                "provenance_hash": _provenance_hash(prov),
                "activated_at": _utcnow(),
                "previous_release_id": previous,
            }
        )
        self._releases[release_id] = activated
        self._active_release_id = release_id
        return activated

    def rollback_release(
        self,
        release_id: str,
        provenance: dict[str, Any] | None = None,
    ) -> NucleiReleaseRecord:
        record = self._releases.get(release_id)
        if record is None:
            raise KeyError(f"nuclei_release_not_found:{release_id}")

        prov = dict(record.provenance)
        if provenance:
            prov.update(provenance)
        prov["action"] = "rollback"
        prov["rolled_back_at"] = _utcnow().isoformat()

        rolled = record.model_copy(
            update={
                "status": "rolled_back",
                "provenance": prov,
                "provenance_hash": _provenance_hash(prov),
            }
        )
        self._releases[release_id] = rolled
        if self._active_release_id == release_id:
            previous = record.previous_release_id
            self._active_release_id = previous
            if previous and previous in self._releases:
                restored = self._releases[previous].model_copy(update={"status": "active"})
                self._releases[previous] = restored
        return rolled
