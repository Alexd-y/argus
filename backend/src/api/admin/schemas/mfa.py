"""ARGUS Cycle 7 / C7-T03 — Pydantic schemas for the admin MFA surface.

Design source
-------------
Implements the request / response envelopes specified in
``ai_docs/develop/issues/ISS-T20-003-phase2.md`` (admin MFA HTTP API)
and the Cycle 7 plan ``ai_docs/develop/plans/2026-04-22-argus-cycle7.md``
(section "C7-T03 — MFA Endpoints + Super-Admin Enforcement").

Invariants enforced by this module
----------------------------------
* ``model_config = ConfigDict(extra="forbid")`` on every model — unknown
  fields are rejected with HTTP 422 so a hostile client cannot smuggle
  unsupported keys through (defence in depth against parameter pollution
  and forward-compat surprises when new optional fields are added).
* TOTP codes are constrained to exactly 6 ASCII digits via Pydantic
  ``Field(pattern=...)`` so the route handler never has to validate the
  shape itself (one source of truth for input validation; matches the
  Hard Rule "Endpoints validate input via Pydantic ONLY").
* Backup codes are constrained to the operator-typeable alphabet used
  by :func:`src.auth.admin_mfa.generate_backup_codes` (16 chars from
  ``0-9 A-H J-N P-Z`` minus ``I`` / ``O``) — the DAO normaliser will
  uppercase + strip dashes, so the schema accepts ``XXXX-XXXX-XXXX-XXXX``
  formatting too.
* ``MFAVerifyRequest`` and ``MFADisableRequest`` use a
  ``model_validator(mode="after")`` to enforce *exactly one of*
  ``totp_code`` / ``backup_code`` (XOR). Pydantic raises 422 on
  violation, matching the FastAPI default behaviour.
* No PII / secret material is ever serialised back to the client other
  than the one-shot ``backup_codes`` and ``secret_uri`` returned at
  enrolment time. Subsequent reads (e.g. ``MFAStatusResponse``) only
  return counts and timestamps.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: TOTP code regex — exactly 6 ASCII digits. The DAO normaliser strips
#: spaces (``"123 456"``) but the public API contract is the canonical
#: 6-digit form so OpenAPI consumers see an unambiguous shape.
_TOTP_CODE_PATTERN: Final[str] = r"^\d{6}$"

#: Backup-code regex — accepts 16 chars from the operator-typeable
#: alphabet (matches ``src.auth.admin_mfa._BACKUP_CODE_ALPHABET``) with
#: optional dashes / spaces every 4 chars for readability. The DAO
#: normaliser then uppercases + strips. Length bounded to 32 chars to
#: cap the worst case (``XXXX XXXX XXXX XXXX`` with extra whitespace).
_BACKUP_CODE_PATTERN: Final[str] = r"^[0-9A-HJ-NP-Z\- ]{16,32}$"


class MFAEnrollRequest(BaseModel):
    """``POST /enroll`` request envelope — empty body.

    Enrolment is initiated by the *currently authenticated* admin against
    their own account; identity is taken from the session cookie. No body
    fields are accepted: a future caller that needs to enrol a *different*
    subject (operator-driven recovery) must use a separate, super-admin
    only endpoint, never overload this one.
    """

    model_config = ConfigDict(extra="forbid")


class MFAEnrollResponse(BaseModel):
    """``POST /enroll`` response — secret URI, optional QR, plaintext codes.

    ``secret_uri`` is the canonical ``otpauth://totp/...`` URL the operator
    pastes into their authenticator. ``qr_data_uri`` carries the same
    payload as a base64-encoded PNG (``data:image/png;base64,...``) when
    the deployment ships a QR encoder; when the QR library is absent (no
    ``qrcode`` / ``segno`` pinned in ``requirements.txt`` as of C7-T03)
    the field is ``None`` and the frontend renders the URI as text /
    user-side QR (TODO: add ``segno`` once SCA review approves).
    """

    model_config = ConfigDict(extra="forbid")

    secret_uri: str = Field(
        ...,
        description=(
            "otpauth:// URL the admin pastes into their authenticator app."
        ),
    )
    qr_data_uri: str | None = Field(
        default=None,
        description=(
            "data:image/png;base64,... QR encoding of secret_uri. "
            "``None`` when no QR encoder is pinned in requirements.txt."
        ),
    )
    backup_codes: list[str] = Field(
        ...,
        description=(
            "Plaintext one-shot backup codes (returned ONCE; persisted as "
            "bcrypt hashes). The admin MUST store them out-of-band before "
            "calling /confirm — a re-issue requires /backup-codes/regenerate."
        ),
    )


class MFAConfirmRequest(BaseModel):
    """``POST /confirm`` request — first 6-digit TOTP code from the authenticator."""

    model_config = ConfigDict(extra="forbid")

    totp_code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        pattern=_TOTP_CODE_PATTERN,
        description="6-digit TOTP code from the authenticator app.",
    )


class MFAConfirmResponse(BaseModel):
    """``POST /confirm`` response — final ``mfa_enabled=True`` ack."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        ...,
        description="Always ``True`` on a 200 — the row was flipped to enabled.",
    )
    enabled_at: datetime = Field(
        ...,
        description=(
            "Server-clock UTC timestamp at which the row was flipped to "
            "enabled. Same instant as ``mfa_passed_at`` on the calling "
            "session — confirm doubles as the first MFA challenge."
        ),
    )


class MFAVerifyRequest(BaseModel):
    """``POST /verify`` request — exactly one of ``totp_code`` / ``backup_code``."""

    model_config = ConfigDict(extra="forbid")

    totp_code: str | None = Field(
        default=None,
        min_length=6,
        max_length=6,
        pattern=_TOTP_CODE_PATTERN,
        description="6-digit TOTP code from the authenticator app.",
    )
    backup_code: str | None = Field(
        default=None,
        min_length=16,
        max_length=32,
        pattern=_BACKUP_CODE_PATTERN,
        description=(
            "16-char operator-typeable backup code (dashes / spaces are "
            "stripped server-side). Single-use — consumed atomically."
        ),
    )

    @model_validator(mode="after")
    def _exactly_one_credential(self) -> "MFAVerifyRequest":
        if (self.totp_code is None) == (self.backup_code is None):
            raise ValueError("provide exactly one of totp_code or backup_code")
        return self


class MFAVerifyResponse(BaseModel):
    """``POST /verify`` response — ``mfa_passed_at`` stamp + remaining codes."""

    model_config = ConfigDict(extra="forbid")

    verified: bool = Field(
        ...,
        description="Always ``True`` on a 200; mirrors the HTTP status for clients.",
    )
    mfa_passed_at: datetime = Field(
        ...,
        description=(
            "Server-clock UTC timestamp written onto the calling session's "
            "``mfa_passed_at`` column. Used by ``require_admin_mfa_passed`` "
            "to gate sensitive admin actions for the next "
            "``ADMIN_MFA_REAUTH_WINDOW_SECONDS``."
        ),
    )
    remaining_backup_codes: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Number of unused backup codes left after this call. ``None`` "
            "when the verify path was TOTP (the count never changes for "
            "TOTP verifications). Always ``int`` on a backup-code path."
        ),
    )


class MFADisableRequest(BaseModel):
    """``POST /disable`` request — fresh MFA proof (TOTP or backup code).

    ``mfa_passed_at`` on the session is NOT enough on its own: disable is
    privileged enough that the admin must re-prove possession in the
    request body so a stolen but already-MFA'd session cookie cannot
    silently strip MFA from the account.
    """

    model_config = ConfigDict(extra="forbid")

    totp_code: str | None = Field(
        default=None,
        min_length=6,
        max_length=6,
        pattern=_TOTP_CODE_PATTERN,
        description="6-digit TOTP code (XOR with backup_code).",
    )
    backup_code: str | None = Field(
        default=None,
        min_length=16,
        max_length=32,
        pattern=_BACKUP_CODE_PATTERN,
        description="One-shot backup code (XOR with totp_code).",
    )

    @model_validator(mode="after")
    def _exactly_one_credential(self) -> "MFADisableRequest":
        if (self.totp_code is None) == (self.backup_code is None):
            raise ValueError("provide exactly one of totp_code or backup_code")
        return self


class MFADisableResponse(BaseModel):
    """``POST /disable`` response — ack + server timestamp."""

    model_config = ConfigDict(extra="forbid")

    disabled: bool = Field(
        ...,
        description="Always ``True`` on a 200 — the row was wiped.",
    )
    disabled_at: datetime = Field(
        ...,
        description="Server-clock UTC timestamp at which the row was wiped.",
    )


class MFAStatusResponse(BaseModel):
    """``GET /status`` response — read-only enrolment + session view."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        ...,
        description=(
            "True iff the admin has completed enrolment "
            "(``admin_users.mfa_enabled`` is True)."
        ),
    )
    enrolled_at: datetime | None = Field(
        default=None,
        description=(
            "Reserved for future use. The current schema (Alembic 032) "
            "does not persist a dedicated enrolment timestamp; the field "
            "is reported as ``None`` for now and a follow-up migration "
            "will introduce ``admin_users.mfa_enrolled_at``."
        ),
    )
    remaining_backup_codes: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Number of unused backup codes left. ``None`` when MFA is not "
            "enabled OR when the row was loaded with ``backup_codes_hash`` "
            "NULL (legacy rows). Always ``int`` on an enrolled account."
        ),
    )
    mfa_passed_for_session: bool = Field(
        ...,
        description=(
            "True iff the calling session has a non-NULL ``mfa_passed_at`` "
            "AND it is within ``ADMIN_MFA_REAUTH_WINDOW_SECONDS`` of now. "
            "Mirrors the gate enforced by ``require_admin_mfa_passed``."
        ),
    )


class MFARegenerateBackupCodesResponse(BaseModel):
    """``POST /backup-codes/regenerate`` response — fresh plaintext codes ONCE."""

    model_config = ConfigDict(extra="forbid")

    backup_codes: list[str] = Field(
        ...,
        min_length=1,
        description=(
            "Plaintext one-shot backup codes (returned ONCE; persisted as "
            "bcrypt hashes that immediately invalidate any prior batch). "
            "The admin MUST store them out-of-band before navigating away."
        ),
    )


__all__ = [
    "MFAConfirmRequest",
    "MFAConfirmResponse",
    "MFADisableRequest",
    "MFADisableResponse",
    "MFAEnrollRequest",
    "MFAEnrollResponse",
    "MFARegenerateBackupCodesResponse",
    "MFAStatusResponse",
    "MFAVerifyRequest",
    "MFAVerifyResponse",
]
