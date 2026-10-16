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


def store_redacted_text(
    *,
    tenant_id: str,
    scan_id: str,
    kind: str,
    text: str | None,
) -> str:
    """Redact ``text``, hash the redacted bytes, upload, return the object key.

    Returns ``""`` when disabled, when inputs are missing, or on any failure
    (storage must never break an LLM call). ``kind`` is a short label such as
    ``"prompt"`` or ``"response"`` used only in the deterministic filename.
    """
    from src.core.config import settings

    if not getattr(settings, "llm_telemetry_store_text", False):
        return ""
    if not text or not tenant_id or not scan_id:
        return ""
    try:
        from src.evidence.redaction import Redactor
        from src.storage.s3 import upload

        redacted = Redactor().redact(text.encode("utf-8"))
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
