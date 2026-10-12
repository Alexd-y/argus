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

import os
import stat as _stat
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


def _read_regular_file_capped(path: Path, limit: int) -> tuple[int, bytes] | None:
    """Open ``path`` without following symlinks and read up to ``limit`` bytes.

    Returns ``(original_size, data)`` for a regular file, or ``None`` if the
    path is not a regular file (e.g. a symlink / device / fifo) or cannot be
    read. ``O_NOFOLLOW`` closes the TOCTOU window between the symlink check in
    the caller and the open here; ``fstat`` confirms it is a regular file.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            return None
        data = os.read(fd, limit) if limit > 0 else b""
        return st.st_size, data
    except OSError:
        return None
    finally:
        os.close(fd)


def gather_workdir_evidence(
    workdir: Path,
    *,
    max_artifact_bytes: int,
    max_run_bytes: int,
) -> list[RawEvidence]:
    """Walk ``workdir`` and return a :class:`RawEvidence` for every regular file.

    Each file is capped at ``max_artifact_bytes``; the cumulative run is capped
    at ``max_run_bytes``. When the run budget is exhausted an artifact is still
    recorded (possibly as an empty, ``truncated=True`` marker with its real
    ``original_size``) rather than silently skipped.

    Security: the workdir is populated by a potentially hostile tool, so the
    walk must never follow a symlink out of the tree (a ``evil -> /etc/passwd``
    symlink must not be exfiltrated as "evidence"). Symlinked files and
    directories are skipped, reads are confined to the resolved root, and
    :func:`_read_regular_file_capped` opens with ``O_NOFOLLOW`` + ``fstat``.
    """
    out: list[RawEvidence] = []
    try:
        root = Path(workdir).resolve(strict=True)
    except (OSError, RuntimeError):
        return out
    if not root.is_dir():
        return out

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Never descend into a symlinked subdirectory (sandbox-escape guard).
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        files.extend(Path(dirpath) / name for name in filenames)

    total = 0
    for path in sorted(files):
        if path.is_symlink():
            continue
        try:
            real = path.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not real.is_relative_to(root) or not real.is_file():
            continue
        remaining = max(max_run_bytes - total, 0)
        per_artifact = min(max_artifact_bytes, remaining)
        read = _read_regular_file_capped(real, per_artifact)
        if read is None:
            continue
        original_size, data = read
        kind, content_type = classify_artifact(path.name)
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
