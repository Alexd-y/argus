"""Binary-safe redaction of sensitive material from tool evidence.

Redacts tokens, secrets, cookies, and credentials from arbitrary evidence
bytes BEFORE they hit S3. Operates on raw bytes (not text) so binary
artefacts (HAR, PCAP, screenshots, gzipped responses) cannot crash the
pipeline on a malformed UTF-8 boundary.

Threat model
------------
* The pipeline trusts neither the tool author nor the target. Evidence may
  contain the tester's own credentials (Bearer tokens, AWS keys, JWTs),
  cookies issued by the target, or PEM-encoded private keys discovered in
  exfiltration tests.
* All matched secrets are replaced in-place with a fixed marker. The
  output retains the original byte length only for non-overlapping
  fixed-length matches; do NOT rely on offset stability for downstream
  parsing.
* No matched material is logged. Only counts are surfaced via
  :class:`RedactedContent.report`.

Performance
-----------
* Patterns are compiled once at module import and cached per
  :class:`RedactionSpec` (see :func:`_compile_pattern`).
* Single-pass over the input per pattern (no nested scans).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


_logger = logging.getLogger(__name__)


# Bytes patterns are stored alongside their string source so:
# 1. Construction can validate the regex without compiling twice.
# 2. The bytes form is reused on every call (avoids per-call ``encode()``).
_PATTERN_CACHE: Final[dict[str, re.Pattern[bytes]]] = {}


class RedactionReport(BaseModel):
    """Per-spec hit count produced by :class:`Redactor.redact`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64)
    matches: StrictInt = Field(ge=0, le=10_000)


class RedactionSpec(BaseModel):
    """Single redaction rule: name + regex + replacement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    pattern: StrictStr = Field(min_length=1, max_length=4096)
    replacement: bytes = Field(default=b"")
    enabled: StrictBool = True

    def model_post_init(self, _context: object) -> None:
        # Validate (and cache) the pattern at construction time so a malformed
        # regex is rejected immediately rather than at first use.
        _compile_pattern(self.pattern)


class RedactedContent(BaseModel):
    """Output of :class:`Redactor.redact`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    content: bytes
    redactions_applied: StrictInt = Field(ge=0, le=10_000)
    report: tuple[RedactionReport, ...] = Field(default_factory=tuple, max_length=128)


def _compile_pattern(pattern: str) -> re.Pattern[bytes]:
    """Return a cached :mod:`re` byte pattern for ``pattern`` (DOTALL)."""
    cached = _PATTERN_CACHE.get(pattern)
    if cached is not None:
        return cached
    try:
        compiled = re.compile(pattern.encode("utf-8"), flags=re.DOTALL)
    except re.error as exc:
        raise ValueError(f"invalid regex pattern: {exc}") from exc
    _PATTERN_CACHE[pattern] = compiled
    return compiled


def _replacement_bytes(name: str, replacement: bytes) -> bytes:
    """Return the literal replacement bytes; defaults to ``[REDACTED:<name>]``."""
    if replacement:
        return replacement
    return f"[REDACTED:{name}]".encode("ascii", errors="replace")


def default_specs() -> tuple[RedactionSpec, ...]:
    """Return the canonical set of always-on redaction rules.

    The list mirrors the cycle plan §10 — extending it requires updating
    the corresponding test in ``tests/unit/evidence/test_redaction.py``.
    """
    return _DEFAULT_SPECS


# Order matters: bearer tokens before generic cookie scrub so the more
# specific rule runs first (counts attribute correctly).
_DEFAULT_SPECS: Final[tuple[RedactionSpec, ...]] = (
    RedactionSpec(name="bearer_token", pattern=r"Bearer\s+[A-Za-z0-9._\-]+"),
    RedactionSpec(name="aws_access_key", pattern=r"AKIA[0-9A-Z]{16}"),
    RedactionSpec(name="github_pat", pattern=r"ghp_[A-Za-z0-9]{20,}"),
    RedactionSpec(name="slack_token", pattern=r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    RedactionSpec(
        name="private_key_pem",
        pattern=r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    RedactionSpec(name="set_cookie", pattern=r"(?i)Set-Cookie:\s*[^;\r\n]+"),
    RedactionSpec(name="cookie_header", pattern=r"(?i)Cookie:\s*[^\r\n]+"),
    RedactionSpec(name="password_in_url", pattern=r"://[^:/@\s]+:[^@\s]+@"),
    RedactionSpec(
        name="password_kv",
        pattern=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[^\s&\"']+",
    ),
    RedactionSpec(
        name="jwt",
        pattern=r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    ),
    RedactionSpec(name="openai_key", pattern=r"sk-[A-Za-z0-9]{20,}"),
)


class Redactor:
    """Apply a sequence of :class:`RedactionSpec` rules to evidence bytes."""

    def __init__(self, specs: Sequence[RedactionSpec] | None = None) -> None:
        self._specs: tuple[RedactionSpec, ...] = (
            tuple(specs) if specs is not None else default_specs()
        )

    @property
    def specs(self) -> tuple[RedactionSpec, ...]:
        """Return the active spec tuple (read-only)."""
        return self._specs

    def redact(
        self,
        content: bytes,
        *,
        specs: Sequence[RedactionSpec] | None = None,
    ) -> RedactedContent:
        """Return ``content`` with every enabled spec applied."""
        if not isinstance(content, (bytes, bytearray)):
            raise TypeError(f"content must be bytes-like, got {type(content).__name__}")
        if not content:
            return RedactedContent(content=b"", redactions_applied=0, report=())

        active_specs = tuple(specs) if specs is not None else self._specs
        working = bytes(content)
        report: list[RedactionReport] = []
        total = 0
        for spec in active_specs:
            if not spec.enabled:
                continue
            pattern = _compile_pattern(spec.pattern)
            replacement = _replacement_bytes(spec.name, spec.replacement)
            matches_iter = pattern.findall(working)
            count = len(matches_iter)
            if count == 0:
                continue
            working = pattern.sub(replacement, working)
            capped = min(count, 10_000)
            report.append(RedactionReport(name=spec.name, matches=capped))
            total += capped
            if total >= 10_000:
                _logger.warning(
                    "redaction.cap_reached",
                    extra={
                        "event": "redaction_cap_reached",
                        "spec": spec.name,
                        "total": total,
                    },
                )
                total = 10_000
                break

        return RedactedContent(
            content=working,
            redactions_applied=total,
            report=tuple(report),
        )


__all__ = [
    "RedactedContent",
    "RedactionReport",
    "RedactionSpec",
    "Redactor",
    "default_specs",
]
