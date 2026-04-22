"""Pydantic request / response models for the admin HTTP surface (C7).

Re-export every public model so consumers can write
``from src.api.admin.schemas import MFAEnrollResponse`` without knowing
the per-feature module layout.

Spec reference: ``ai_docs/develop/issues/ISS-T20-003-phase2.md`` §Phase 2a.
"""

from __future__ import annotations

from src.api.admin.schemas.mfa import (
    BackupCodesRegenerateResponse,
    MFAConfirmRequest,
    MFAConfirmResponse,
    MFADisableRequest,
    MFADisableResponse,
    MFAEnrollRequest,
    MFAEnrollResponse,
    MFAStatusResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
)

__all__ = [
    "BackupCodesRegenerateResponse",
    "MFAConfirmRequest",
    "MFAConfirmResponse",
    "MFADisableRequest",
    "MFADisableResponse",
    "MFAEnrollRequest",
    "MFAEnrollResponse",
    "MFAStatusResponse",
    "MFAVerifyRequest",
    "MFAVerifyResponse",
]
