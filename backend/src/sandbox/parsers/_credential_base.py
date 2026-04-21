"""Shared building blocks for ARG-032 credential-bruteforce parsers.

The auth batch (``hydra`` / ``medusa`` / ``patator`` / ``ncrack`` /
``crackmapexec``) all share the same finding shape: one CRITICAL
AUTH finding per discovered ``(host, service, username)`` triple,
with the password value redacted before any DTO is built.

* :func:`build_credential_finding` — single-place FindingDTO factory
  for the cred-leak shape (CWE-307 / CWE-521 / CWE-798).
* :func:`build_credential_evidence` — canonical evidence-dict shape.
  The password value is **never** stored in plain text; the helper
  replaces it with the canonical
  :data:`src.sandbox.parsers._text_base.REDACTED_PASSWORD_MARKER`.
"""

from __future__ import annotations

from typing import Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._text_base import (
    REDACTED_PASSWORD_MARKER,
)


_CRED_DUMP_CVSS_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
_CRED_DUMP_CVSS_SCORE: Final[float] = 9.1


def build_credential_finding() -> FindingDTO:
    """Build the canonical AUTH finding for a discovered credential.

    Severity is fixed at HIGH (CVSS 9.1) — a verified weak credential
    on an exposed service is, by definition, an immediately
    actionable risk per the ARGUS Cycle 4 SSVC ladder.
    """
    return make_finding_dto(
        category=FindingCategory.AUTH,
        cwe=[287, 307, 521, 798],
        cvss_v3_vector=_CRED_DUMP_CVSS_VECTOR,
        cvss_v3_score=_CRED_DUMP_CVSS_SCORE,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ACT,
        owasp_wstg=["WSTG-ATHN-02", "WSTG-ATHN-07"],
        mitre_attack=["T1110.001", "T1110.003"],
    )


def build_credential_evidence(
    *,
    tool_id: str,
    host: str,
    service: str,
    username: str,
    password_length: int = 0,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return the canonical credential-evidence dict.

    The password value is replaced with the redaction marker plus a
    length hint (``"length": 8``) so the operator can see *that* a
    cleartext credential was found without leaking the password
    itself.  ``extra`` is folded in last and overrides any baseline
    field.
    """
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "host": host.lower(),
        "service": service.lower(),
        "username": username,
        "password": REDACTED_PASSWORD_MARKER,
        "password_length": int(password_length) if password_length else 0,
        "fingerprint_hash": stable_hash_12(
            f"{host.lower()}|{service.lower()}|{username}"
        ),
    }
    if extra:
        payload.update(extra)
    return payload


__all__ = [
    "build_credential_evidence",
    "build_credential_finding",
]
