"""Evidence provenance for Quick findings — hash, versions, policy, lease.

Secrets never appear in JSON destined for an LLM. Raw artifacts stay in
MinIO; this module only records hashes and non-secret identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.findings.fingerprint import FINGERPRINT_VERSION
from src.rag.ingestion import redact_secrets

_SECRET_KEY_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "set-cookie",
        "credential",
        "credentials",
        "private_key",
        "access_key",
        "refresh_token",
        "session",
        "bearer",
        "jwt",
        "x-api-key",
        "auth",
    }
)
_SECRET_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|bearer|jwt)",
    re.IGNORECASE,
)


class QuickProvenance(BaseModel):
    """Non-secret provenance attached to a finding / evidence record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_hash: StrictStr = Field(min_length=64, max_length=64)
    tool_id: StrictStr = Field(min_length=1, max_length=128)
    tool_version: StrictStr = Field(min_length=1, max_length=64)
    template_id: StrictStr | None = Field(default=None, max_length=256)
    template_digest: StrictStr | None = Field(default=None, max_length=64)
    policy_decision_id: StrictStr | None = Field(default=None, max_length=36)
    lease_id: StrictStr | None = Field(default=None, max_length=36)
    task_id: StrictStr | None = Field(default=None, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    artifact_key: StrictStr | None = Field(default=None, max_length=512)
    fingerprint_version: StrictStr = FINGERPRINT_VERSION


def compute_evidence_hash(payload: Mapping[str, Any] | str | bytes) -> str:
    """SHA-256 of canonical evidence material (already redacted by caller)."""
    if isinstance(payload, bytes):
        blob = payload
    elif isinstance(payload, str):
        blob = payload.encode("utf-8")
    else:
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    return hashlib.sha256(blob).hexdigest()


def mint_evidence_id(*, scan_id: str, task_id: str | None, evidence_hash: str) -> str:
    """Deterministic 36-char evidence id bound to scan + hash."""
    material = f"{scan_id.strip()}:{(task_id or '').strip()}:{evidence_hash.strip().lower()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:36]


def _key_is_secret(key: str) -> bool:
    lowered = key.strip().lower().replace("-", "_")
    if lowered in _SECRET_KEY_TOKENS:
        return True
    return bool(_SECRET_KEY_RE.search(lowered))


def redact_mapping_for_llm(value: Any) -> Any:
    """Drop secret keys and redact secret-shaped strings. Never raises."""
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for raw_key, raw_val in value.items():
            key = str(raw_key)
            if _key_is_secret(key):
                continue
            cleaned[key] = redact_mapping_for_llm(raw_val)
        return cleaned
    if isinstance(value, list | tuple):
        return [redact_mapping_for_llm(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, bytes):
        return redact_secrets(value.decode("utf-8", errors="replace"))
    return value


def evidence_json_for_llm(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Evidence JSON safe to send to an LLM — no secrets, no raw credentials."""
    if not payload:
        return {}
    redacted = redact_mapping_for_llm(dict(payload))
    return redacted if isinstance(redacted, dict) else {}


def public_fingerprint(*, fingerprint_key: str, version: str = FINGERPRINT_VERSION) -> dict[str, str]:
    """Fingerprint identity without asset/url/parameter secrets."""
    return {
        "fingerprint_key": fingerprint_key.strip(),
        "fingerprint_version": version,
    }


def build_provenance(
    *,
    evidence_hash: str,
    tool_id: str,
    tool_version: str,
    scan_id: str,
    template_id: str | None = None,
    template_digest: str | None = None,
    policy_decision_id: str | None = None,
    lease_id: str | None = None,
    task_id: str | None = None,
    artifact_key: str | None = None,
) -> QuickProvenance:
    """Construct frozen provenance. Identifiers only — no evidence bodies."""
    return QuickProvenance(
        evidence_hash=evidence_hash.strip().lower(),
        tool_id=tool_id.strip()[:128] or "unknown",
        tool_version=(tool_version or "unknown").strip()[:64] or "unknown",
        template_id=(template_id.strip()[:256] if template_id else None),
        template_digest=(template_digest.strip().lower()[:64] if template_digest else None),
        policy_decision_id=(policy_decision_id.strip()[:36] if policy_decision_id else None),
        lease_id=(lease_id.strip()[:36] if lease_id else None),
        task_id=(task_id.strip()[:36] if task_id else None),
        scan_id=scan_id.strip()[:36] or "unknown",
        artifact_key=(artifact_key.strip()[:512] if artifact_key else None),
    )


def provenance_public_dict(provenance: QuickProvenance) -> dict[str, Any]:
    """API-safe provenance dump (no secrets by construction)."""
    return provenance.model_dump(mode="json")


def digest_template_ids(template_ids: Sequence[str]) -> str:
    """Stable sha256 over sorted template ids (manifest digest helper)."""
    canonical = json.dumps(
        sorted({item.strip() for item in template_ids if item and item.strip()}),
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
