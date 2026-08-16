"""LabScopeManifest — immutable LAB boundary definition."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)

from src.execution_mode.mode import ExecutionMode


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class LabScopeManifest(BaseModel):
    """Signed LAB boundary. Mode is always lab_unrestricted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_id: StrictStr = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    mode: ExecutionMode = ExecutionMode.LAB_UNRESTRICTED
    asset_ids: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=10_000)
    cidrs: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=1_000)
    dns_suffixes: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=1_000)
    k8s_namespace: StrictStr | None = Field(default=None, max_length=253)
    vm_network_ids: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=256)
    internet_attached: StrictBool = False
    capture_full: StrictBool = False
    resource_limits: dict[str, Any] | None = None
    expires_at: datetime
    created_by: StrictStr = Field(min_length=1, max_length=36)
    created_at: datetime = Field(default_factory=_utcnow)
    signature: StrictStr | None = None

    @field_validator("mode")
    @classmethod
    def _mode_must_be_lab(cls, value: ExecutionMode) -> ExecutionMode:
        if value is not ExecutionMode.LAB_UNRESTRICTED:
            raise ValueError("lab_scope_manifest_mode_must_be_lab_unrestricted")
        return value

    @field_validator("cidrs", "dns_suffixes", "asset_ids", "vm_network_ids", mode="before")
    @classmethod
    def _coerce_tuple(cls, value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, (list, tuple, set, frozenset)):
            return tuple(value)
        raise TypeError("expected_sequence")

    @model_validator(mode="after")
    def _require_boundary(self) -> LabScopeManifest:
        if not (self.asset_ids or self.cidrs or self.dns_suffixes or self.vm_network_ids):
            raise ValueError("lab_scope_manifest_empty_boundary")
        if self.expires_at.tzinfo is None:
            raise ValueError("lab_scope_manifest_expires_at_must_be_timezone_aware")
        return self

    def is_expired(self, *, now: datetime | None = None) -> bool:
        ref = now or _utcnow()
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        return ref >= self.expires_at

    def canonical_payload(self) -> dict[str, Any]:
        """Deterministic payload for HMAC (excludes signature)."""
        data = self.model_dump(mode="json", exclude={"signature"})
        return data

    def unsigned_digest(self) -> str:
        blob = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def sign(self, secret: str | bytes) -> LabScopeManifest:
        key = secret.encode("utf-8") if isinstance(secret, str) else secret
        digest = hmac.new(key, self.unsigned_digest().encode("utf-8"), hashlib.sha256).hexdigest()
        return self.model_copy(update={"signature": digest})

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature:
            return False
        key = secret.encode("utf-8") if isinstance(secret, str) else secret
        expected = hmac.new(
            key, self.unsigned_digest().encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def to_storage_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_storage_dict(cls, raw: dict[str, Any]) -> LabScopeManifest:
        return cls.model_validate(raw)
