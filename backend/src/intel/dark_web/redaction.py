"""PII / secret redaction for DWM — produce report-safe summaries.

Hard rule: a plaintext password, API key, private key, or full credit-card /
SSN NEVER appears in a ``redacted_summary`` or anywhere outside the encrypted
MinIO raw object. This module masks aggressively and is covered by a
leak-contract test.
"""

from __future__ import annotations

import re

# Placeholders deliberately contain NO ':' so later passes (combolist, email) do
# not re-match and corrupt them.
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)
# key=value / key: value secret assignments -> redact the rest of the line.
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|authorization|bearer)\b\s*[:=]\s*[^\n\r]+"
)
_SK_RE = re.compile(r"\b(sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|pplx-[A-Za-z0-9]{8,})\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# combolist: ``id:secret`` with NO spaces around the colon (distinguishes a real
# ``email:password`` pair from ordinary prose like "Source: Pastebin").
_COMBO_RE = re.compile(
    r"(?P<id>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|[A-Za-z0-9._\-]{3,}):(?P<secret>[^\s<:]{4,})"
)
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")

_MAX_SUMMARY = 2000


def mask_email(email: str) -> str:
    """``alice@example.com`` -> ``a***@example.com`` (domain kept, local masked)."""

    email = (email or "").strip()
    if "@" not in email:
        return email
    local, _, domain = email.partition("@")
    if not local:
        return f"***@{domain}"
    if len(local) == 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"


def redact_text(text: str) -> str:
    """Mask secrets/PII in free text. Order matters (most specific first)."""

    if not text:
        return ""
    out = _PRIVATE_KEY_RE.sub("<redacted_private_key>", text)
    out = _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}=<redacted>", out)
    out = _SK_RE.sub("<redacted_key>", out)
    out = _BEARER_RE.sub("bearer <redacted>", out)
    out = _AWS_RE.sub("<redacted_aws_key>", out)
    out = _SSN_RE.sub("<redacted_ssn>", out)
    out = _CARD_RE.sub("<redacted_card>", out)
    # combolist id:secret (no spaces) -> keep masked id, drop secret.
    out = _COMBO_RE.sub(lambda m: f"{_mask_identifier(m.group('id'))}:<redacted>", out)
    # mask any remaining bare emails.
    out = _EMAIL_RE.sub(lambda m: mask_email(f"{m.group(1)}@{m.group(2)}"), out)
    return out


def _mask_identifier(identifier: str) -> str:
    if "@" in identifier:
        return mask_email(identifier)
    if len(identifier) <= 2:
        return "***"
    return f"{identifier[0]}***"


def build_redacted_summary(content: str, *, prefix: str = "") -> str:
    """Produce a bounded, report-safe summary from a raw record."""

    redacted = redact_text(content or "")
    redacted = " ".join(redacted.split())  # collapse whitespace/newlines
    if prefix:
        redacted = f"{prefix} {redacted}".strip()
    return redacted[:_MAX_SUMMARY]


__all__ = ["build_redacted_summary", "mask_email", "redact_text"]
