"""Scan-indexed OAST traces — correlator computes status, clients do not."""

from __future__ import annotations

import hashlib
import re
from threading import Lock
from typing import Any
from uuid import UUID, uuid4

from src.oast.correlator import InteractionKind, OASTCorrelator, OASTInteraction
from src.oast.provisioner import InternalOASTProvisioner

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROTOCOL_KIND: dict[str, InteractionKind] = {
    "dns": InteractionKind.DNS_ANY,
    "dns_a": InteractionKind.DNS_A,
    "dns_aaaa": InteractionKind.DNS_AAAA,
    "dns_txt": InteractionKind.DNS_TXT,
    "dns_any": InteractionKind.DNS_ANY,
    "http": InteractionKind.HTTP_REQUEST,
    "https": InteractionKind.HTTPS_REQUEST,
    "smtp": InteractionKind.SMTP_RCPT,
}

_LOCK = Lock()
_TRACES: dict[str, list[dict[str, Any]]] = {}
_PROVISIONER: InternalOASTProvisioner | None = None
_CORRELATOR: OASTCorrelator | None = None


def get_oast_provisioner() -> InternalOASTProvisioner:
    global _PROVISIONER
    if _PROVISIONER is None:
        _PROVISIONER = InternalOASTProvisioner(base_domain="oast.argus.test")
    return _PROVISIONER


def get_oast_correlator() -> OASTCorrelator:
    global _CORRELATOR
    if _CORRELATOR is None:
        _CORRELATOR = OASTCorrelator(get_oast_provisioner())
    return _CORRELATOR


def reset_scan_oast_traces() -> None:
    global _PROVISIONER, _CORRELATOR
    with _LOCK:
        _TRACES.clear()
        _PROVISIONER = None
        _CORRELATOR = None


def list_scan_oast_traces(scan_id: str) -> list[dict[str, Any]]:
    with _LOCK:
        return list(_TRACES.get(scan_id, []))


def record_scan_oast_trace(
    *,
    scan_id: str,
    protocol: str,
    token_id: str | None = None,
    payload_hash: str | None = None,
) -> dict[str, Any]:
    """Store a scan-indexed interaction. Status is computed, never client-trusted."""
    status = _correlate(scan_id, protocol, token_id, payload_hash)
    row = {
        "scan_id": scan_id,
        "protocol": protocol,
        "correlation_status": status,
        "token_id": token_id,
        "payload_hash": payload_hash,
    }
    with _LOCK:
        _TRACES.setdefault(scan_id, []).append(row)
    return row


def _correlate(
    scan_id: str,
    protocol: str,
    token_id: str | None,
    payload_hash: str | None,
) -> str:
    parsed = _parse_token_id(token_id)
    if parsed is None:
        return "uncorrelated"
    kind = _PROTOCOL_KIND.get((protocol or "").strip().lower(), InteractionKind.DNS_ANY)
    try:
        interaction = OASTInteraction(
            id=uuid4(),
            token_id=parsed,
            kind=kind,
            source_ip="0.0.0.0",
            raw_request_hash=_raw_request_hash(payload_hash, scan_id, protocol),
            metadata={"scan_id": scan_id[:32], "protocol": (protocol or "dns")[:32]},
        )
    except ValueError:
        return "uncorrelated"
    stored = get_oast_correlator().ingest(interaction)
    if stored:
        return "correlated"
    return "unknown_token"


def _parse_token_id(token_id: str | None) -> UUID | None:
    raw = (token_id or "").strip()
    if not raw:
        return None
    try:
        return UUID(raw)
    except ValueError:
        return None


def _raw_request_hash(payload_hash: str | None, scan_id: str, protocol: str) -> str:
    digest = (payload_hash or "").strip().lower()
    if _SHA256_RE.fullmatch(digest):
        return digest
    material = f"{scan_id}:{protocol}:{payload_hash or ''}".encode()
    return hashlib.sha256(material).hexdigest()
