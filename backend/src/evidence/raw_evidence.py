"""Raw evidence candidate gathered from a tool run before persistence.

Wave 2 (R-5.3.1 / R-5.3.3). A :class:`RawEvidence` is what an adapter's
``collect_evidence`` yields from a tool's working directory: the still-unhashed,
not-yet-uploaded bytes plus their kind, content type, origin, and truncation
metadata. :class:`~src.evidence.pipeline.EvidencePipeline` turns each candidate
into a redacted, hashed, uploaded :class:`~src.pipeline.contracts.finding_dto.EvidenceDTO`.

This is deliberately separate from ``EvidenceDTO``: the candidate exists *before*
upload (no ``s3_key`` / ``sha256`` yet) and carries the truncation fields the
minimal wave-1 ``EvidenceDTO`` does not model — so "truncated from 4 GB to 10 MB"
is recorded honestly instead of silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.pipeline.contracts.finding_dto import EvidenceKind

#: Conventional stdout/stderr file-name stems a sandbox driver writes to workdir.
_STREAM_PREFIXES: tuple[str, ...] = ("stdout", "stderr")

#: File extension -> (EvidenceKind, content_type). Unknown extensions fall back
#: to RAW_OUTPUT / octet-stream. Classification is extension-based only — an
#: adapter that genuinely produces a .har / .pcap / screenshot gets the right
#: kind, but nothing is invented for a kind no file actually carries.
_EXT_KIND: dict[str, tuple[EvidenceKind, str]] = {
    ".png": (EvidenceKind.SCREENSHOT, "image/png"),
    ".jpg": (EvidenceKind.SCREENSHOT, "image/jpeg"),
    ".jpeg": (EvidenceKind.SCREENSHOT, "image/jpeg"),
    ".gif": (EvidenceKind.SCREENSHOT, "image/gif"),
    ".webp": (EvidenceKind.SCREENSHOT, "image/webp"),
    ".har": (EvidenceKind.HAR, "application/json"),
    ".pcap": (EvidenceKind.PCAP, "application/vnd.tcpdump.pcap"),
    ".pcapng": (EvidenceKind.PCAP, "application/vnd.tcpdump.pcap"),
    ".webm": (EvidenceKind.VIDEO, "video/webm"),
    ".mp4": (EvidenceKind.VIDEO, "video/mp4"),
    ".json": (EvidenceKind.RAW_OUTPUT, "application/json"),
    ".jsonl": (EvidenceKind.RAW_OUTPUT, "application/json"),
    ".xml": (EvidenceKind.RAW_OUTPUT, "application/xml"),
    ".txt": (EvidenceKind.RAW_OUTPUT, "text/plain"),
    ".log": (EvidenceKind.RAW_OUTPUT, "text/plain"),
    ".csv": (EvidenceKind.RAW_OUTPUT, "text/csv"),
}


@dataclass(frozen=True)
class RawEvidence:
    """A single evidence candidate gathered before hashing / upload."""

    kind: EvidenceKind
    data: bytes
    content_type: str
    #: Where it came from, for the audit trail (``stdout`` / ``artifact:nmap.xml``).
    source: str
    #: Size of the original artifact before any truncation.
    original_size: int
    #: ``True`` when ``data`` is a truncated prefix of a larger original.
    truncated: bool = False

    @property
    def size(self) -> int:
        """Size of the (possibly truncated) stored bytes."""
        return len(self.data)


def classify_artifact(name: str) -> tuple[EvidenceKind, str]:
    """Return ``(EvidenceKind, content_type)`` for an artifact file name."""
    lowered = name.lower()
    stem = lowered.rsplit("/", 1)[-1]
    if stem.startswith(_STREAM_PREFIXES):
        return EvidenceKind.RAW_OUTPUT, "text/plain"
    suffix = Path(lowered).suffix
    return _EXT_KIND.get(suffix, (EvidenceKind.RAW_OUTPUT, "application/octet-stream"))


def raw_evidence_from_bytes(
    *,
    kind: EvidenceKind,
    data: bytes,
    content_type: str,
    source: str,
    max_bytes: int,
) -> RawEvidence:
    """Build a :class:`RawEvidence`, truncating ``data`` to ``max_bytes``.

    Truncation never drops the artifact silently: the prefix is kept and
    ``truncated`` / ``original_size`` record the loss.
    """
    original_size = len(data)
    if max_bytes >= 0 and original_size > max_bytes:
        return RawEvidence(
            kind=kind,
            data=data[:max_bytes],
            content_type=content_type,
            source=source,
            original_size=original_size,
            truncated=True,
        )
    return RawEvidence(
        kind=kind,
        data=data,
        content_type=content_type,
        source=source,
        original_size=original_size,
        truncated=False,
    )


def gather_workdir_evidence(
    workdir: Path,
    *,
    max_artifact_bytes: int,
    max_run_bytes: int,
) -> list[RawEvidence]:
    """Walk ``workdir`` and return a :class:`RawEvidence` for every file.

    Each file is capped at ``max_artifact_bytes``; the cumulative run is capped
    at ``max_run_bytes``. When the run budget is exhausted an artifact is still
    recorded (possibly as an empty, ``truncated=True`` marker with its real
    ``original_size``) rather than silently skipped.
    """
    out: list[RawEvidence] = []
    root = Path(workdir)
    if not root.is_dir():
        return out
    total = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            original_size = path.stat().st_size
        except OSError:
            continue
        kind, content_type = classify_artifact(path.name)
        remaining = max(max_run_bytes - total, 0)
        per_artifact = min(max_artifact_bytes, remaining)
        try:
            with path.open("rb") as handle:
                data = handle.read(per_artifact)
        except OSError:
            continue
        truncated = original_size > len(data)
        total += len(data)
        out.append(
            RawEvidence(
                kind=kind,
                data=data,
                content_type=content_type,
                source=f"artifact:{path.relative_to(root).as_posix()}",
                original_size=original_size,
                truncated=truncated,
            )
        )
    return out


__all__ = [
    "RawEvidence",
    "classify_artifact",
    "gather_workdir_evidence",
    "raw_evidence_from_bytes",
]
