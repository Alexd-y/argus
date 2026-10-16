"""Redact-then-store LLM prompt/response text for telemetry (Wave 5, R-9.1/R-9.3).

The telemetry row keeps only hashes by default. When
``settings.llm_telemetry_store_text`` is enabled (per tenant policy + retention),
the full input/output text is captured — but through the SAME wave-2 discipline
as evidence:

* redacted FIRST (``src/evidence/redaction.py``) so secrets never reach storage;
* hashed over the REDACTED bytes (matches the evidence pipeline's
  redact-then-hash contract);
* written to object storage under a dedicated ``llm_telemetry`` object type
  (NOT the finding-evidence ``EvidenceKind`` taxonomy — these are telemetry
  data, not provable artifacts);
* only the returned object key is stored on the telemetry row.

Target data never leaves the perimeter: no external service, redaction on the
way IN (never post-hoc). The helper is best-effort and never raises into the
LLM call path; a failure simply yields an empty object key.
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)

LLM_TELEMETRY_OBJECT_TYPE = "llm_telemetry"
_FILENAME_HASH_PREFIX = 16

# Bound the exposure of a single stored blob AND keep redaction within the
# redactor's internal match cap: beyond ~this size a pattern sweep can hit the
# 10_000-match ceiling and leave a tail unredacted, so we refuse oversize text
# rather than store possibly-underredacted content (fail-closed).
_MAX_TEXT_BYTES = 256 * 1024
# Mirrors the Redactor's internal total-match cap (src/evidence/redaction.py).
# If a redaction run reaches it, redaction may be incomplete → do not store.
_REDACTION_MATCH_CAP = 10_000


def _tenant_capture_allowed(tenant_id: str) -> bool:
    """Per-tenant authorization for text capture (R-9.3: governed by tenant policy).

    Fail-closed: requires BOTH the global master switch AND the tenant to be
    explicitly allow-listed. ``"*"`` in the allowlist opts every tenant in
    (single-tenant / lab deployments); an empty allowlist authorizes no tenant,
    so enabling the global flag alone never starts storing any tenant's text.
    """
    from src.core.config import settings

    if not getattr(settings, "llm_telemetry_store_text", False):
        return False
    raw = getattr(settings, "llm_telemetry_text_tenant_allowlist", "") or ""
    allowed = {t.strip() for t in raw.split(",") if t.strip()}
    if not allowed:
        return False
    return "*" in allowed or tenant_id in allowed


def store_redacted_text(
    *,
    tenant_id: str,
    scan_id: str,
    kind: str,
    text: str | None,
) -> str:
    """Redact ``text``, hash the redacted bytes, upload, return the object key.

    Returns ``""`` when capture is not authorized for the tenant, when inputs
    are missing, when the text is too large to redact safely, when redaction may
    be incomplete, or on any failure (storage must never break an LLM call).
    ``kind`` is a short label (``"prompt"``/``"response"``) used only in the
    deterministic filename.
    """
    if not text or not tenant_id or not scan_id:
        return ""
    if not _tenant_capture_allowed(tenant_id):
        return ""
    try:
        from src.evidence.redaction import Redactor
        from src.storage.s3 import upload

        raw_bytes = text.encode("utf-8")
        if len(raw_bytes) > _MAX_TEXT_BYTES:
            # Fail-closed: do not risk an incomplete redaction of a huge blob.
            logger.debug(
                "store_redacted_text: text exceeds cap, not stored",
                extra={"size_bytes": len(raw_bytes), "cap_bytes": _MAX_TEXT_BYTES},
            )
            return ""
        redacted = Redactor().redact(raw_bytes)
        if redacted.redactions_applied >= _REDACTION_MATCH_CAP:
            # Redaction may be incomplete (hit the match ceiling) → do not store.
            logger.warning(
                "store_redacted_text: redaction cap reached, not stored",
                extra={"event": "llm_telemetry_redaction_cap", "scan_id": scan_id},
            )
            return ""
        sha = hashlib.sha256(redacted.content).hexdigest()
        filename = f"{kind}-{sha[:_FILENAME_HASH_PREFIX]}.txt"
        key = upload(
            tenant_id=tenant_id,
            scan_id=scan_id,
            object_type=LLM_TELEMETRY_OBJECT_TYPE,
            filename=filename,
            data=redacted.content,
            content_type="text/plain; charset=utf-8",
        )
        return key or ""
    except Exception:  # pragma: no cover - defensive; storage never breaks calls
        logger.debug("store_redacted_text: suppressed best-effort error", exc_info=True)
        return ""


__all__ = ["LLM_TELEMETRY_OBJECT_TYPE", "store_redacted_text"]
