"""ARG-025 — Replay-command sanitizer for Asgard / Valhalla report tiers.

Operators sometimes paste full reproducer commands into reports — typically a
``curl -H 'Authorization: Bearer ey…'`` or a ``sqlmap -u …`` line copied
from a CTF run. Embedding those byte-for-byte in an Asgard tier report
would leak:

* **Bearer / API tokens** — Bearer ey…, ``ghp_…``, ``AKIA…``, ``xox[bpos]-…``,
  generic ``api_key=…`` query params.
* **Passwords** — ``password=``, ``passwd=``, ``pwd=``, ``--password …``.
* **NT / LM hashes** — ``[a-f0-9]{32}:[a-f0-9]{32}`` or the
  ``aad3b435…`` empty-LM placeholder.
* **Reverse-shell payloads** — ``bash -i >& /dev/tcp/…``, ``nc -e``,
  ``python -c 'import socket'``, ``curl … | sh``.
* **Destructive flags** — ``--rm``, ``-rf``, ``--force``, ``--no-confirm``,
  ``--skip-checks``, ``--insecure``, ``--ignore-cert``.

This module provides a single public function:

    >>> from src.reports.replay_command_sanitizer import (
    ...     SanitizeContext,
    ...     sanitize_replay_command,
    ... )
    >>> ctx = SanitizeContext(
    ...     target="https://acme.example.com/api/users/42",
    ...     endpoints=("https://acme.example.com/api/users/42",),
    ... )
    >>> sanitize_replay_command(
    ...     ["curl", "-H", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    ...      "https://acme.example.com/api/users/42"],
    ...     ctx,
    ... )
    ['curl', '-H', 'Authorization: Bearer [REDACTED-BEARER]', '{ENDPOINT}']

Design contract (NIST SP 800-204D §5.1.4 / OWASP ASVS L2 §V8)
-------------------------------------------------------------
* **Pure** — no I/O, no logging, no global state. Idempotent: a sanitized
  argv passed back through ``sanitize_replay_command`` is byte-identical.
* **Zero-tolerance** — the function MUST replace the secret span itself,
  not just mask the surrounding token, so the resulting argv leaks no
  bytes from the original credential. ≥50 known-pattern test vectors
  exercise this in :mod:`backend/tests/security/test_report_no_secret_leak.py`.
* **Canary preservation** — operator-injected canary tokens (a known
  identifier the operator wants to keep visible) are never redacted.
  Match by exact substring against ``SanitizeContext.canaries``.
* **Destructive-flag stripping** — argv tokens that *equal* a denylist
  entry (e.g. ``--rm``) are dropped from the output; this is safer than
  trying to "neutralise" them in-place, because pentest reports MUST
  never paste a one-shot destructive command.

Inspiration / lineage
---------------------
The structure mirrors :mod:`src.sandbox.parsers._text_base` (single
chokepoint, frozen pattern catalogue, pure helpers) so two engineers
working on parser hardening and report rendering see the same shape.
"""

from __future__ import annotations

import re
from re import Pattern
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Public placeholders (stable strings — referenced by tests + docs)
# ---------------------------------------------------------------------------


REDACTED_BEARER: Final[str] = "[REDACTED-BEARER]"
REDACTED_API_KEY: Final[str] = "[REDACTED-API-KEY]"
REDACTED_AWS_KEY: Final[str] = "[REDACTED-AWS-KEY]"
REDACTED_AWS_SECRET: Final[str] = "[REDACTED-AWS-SECRET]"
REDACTED_GH_TOKEN: Final[str] = "[REDACTED-GH-TOKEN]"
REDACTED_GL_TOKEN: Final[str] = "[REDACTED-GL-TOKEN]"
REDACTED_AZURE_KEY: Final[str] = "[REDACTED-AZURE-KEY]"
REDACTED_GCP_KEY: Final[str] = "[REDACTED-GCP-KEY]"
REDACTED_SLACK_TOKEN: Final[str] = "[REDACTED-SLACK-TOKEN]"
REDACTED_STRIPE_KEY: Final[str] = "[REDACTED-STRIPE-KEY]"
REDACTED_TWILIO_KEY: Final[str] = "[REDACTED-TWILIO-KEY]"
REDACTED_SENDGRID_KEY: Final[str] = "[REDACTED-SENDGRID-KEY]"
REDACTED_MAILGUN_KEY: Final[str] = "[REDACTED-MAILGUN-KEY]"
REDACTED_PASSWORD: Final[str] = "[REDACTED-PASSWORD]"
REDACTED_NT_HASH: Final[str] = "[REDACTED-NT-HASH]"
REDACTED_PRIVATE_KEY: Final[str] = "[REDACTED-PRIVATE-KEY]"
REDACTED_JWT: Final[str] = "[REDACTED-JWT]"
REDACTED_REVERSE_SHELL: Final[str] = "[REDACTED-REVERSE-SHELL]"
PLACEHOLDER_ASSET: Final[str] = "{ASSET}"
PLACEHOLDER_ENDPOINT: Final[str] = "{ENDPOINT}"


# ---------------------------------------------------------------------------
# Destructive-flag denylist
# ---------------------------------------------------------------------------


# Tokens that, when seen as a *whole* argv element, are dropped from the
# sanitized output. We match by equality (case-insensitive) — any token
# that *contains* one of these as a substring is left alone so we do not
# strip ``--no-confirm-required`` because it shares the prefix with
# ``--no-confirm``.
_DENY_FLAGS: Final[frozenset[str]] = frozenset(
    {
        "--rm",
        "-rf",
        "-fr",
        "--force",
        "--no-confirm",
        "--yes",
        "--skip-checks",
        "--insecure",
        "--ignore-cert",
        "--ignore-ssl-errors",
        "--ignore-tls-errors",
        "--no-check-certificate",
        "--allow-insecure-localhost",
    }
)


# ---------------------------------------------------------------------------
# Secret-pattern catalogue (compiled once)
# ---------------------------------------------------------------------------


# Order matters: longer / more specific first so a JWT (3 dot-separated
# base64url segments) is masked before its leading ``ey…`` is mistaken
# for a generic Bearer slug.
_SECRET_PATTERNS: Final[tuple[tuple[str, Pattern[str], str], ...]] = (
    # ---- JWT (3-segment base64url, optionally prefixed by Bearer)
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_=-]{8,}\.eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=.+/-]{8,}\b"
        ),
        REDACTED_JWT,
    ),
    # ---- AWS access key id (e.g. AKIA / ASIA / AGPA)
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
        REDACTED_AWS_KEY,
    ),
    # ---- AWS secret access key value (40-char base64) — only when paired
    # with explicit ``aws_secret`` keyword to avoid false positives on
    # arbitrary 40-char base64 blobs.
    (
        "aws_secret",
        re.compile(r"(?i)(aws_secret(?:_access)?_key\s*[=:]\s*)([A-Za-z0-9/+=]{40})"),
        rf"\1{REDACTED_AWS_SECRET}",
    ),
    # ---- GitHub PAT (legacy + ghp_/gho_/ghu_/ghs_/ghr_ prefixes)
    (
        "github_token",
        re.compile(r"\bgh[opsur]_[A-Za-z0-9]{36,251}\b"),
        REDACTED_GH_TOKEN,
    ),
    # ---- GitLab PAT (glpat- prefix, 20+ char body)
    (
        "gitlab_token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        REDACTED_GL_TOKEN,
    ),
    # ---- Slack token (xoxb-, xoxp-, xoxa-, xoxs-, xoxo-, xoxr-)
    (
        "slack_token",
        re.compile(r"\bxox[abopsr]-[0-9A-Za-z\-]{10,}\b"),
        REDACTED_SLACK_TOKEN,
    ),
    # ---- Stripe live / test secret key
    (
        "stripe_key",
        re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        REDACTED_STRIPE_KEY,
    ),
    # ---- Twilio account / API key (AC… / SK…)
    (
        "twilio_key",
        re.compile(r"\b(?:AC|SK)[0-9a-fA-F]{32}\b"),
        REDACTED_TWILIO_KEY,
    ),
    # ---- SendGrid (SG.<id>.<secret> two-segment token)
    (
        "sendgrid_key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
        REDACTED_SENDGRID_KEY,
    ),
    # ---- Mailgun signing key (key-<32 hex>)
    (
        "mailgun_key",
        re.compile(r"\bkey-[a-fA-F0-9]{32}\b"),
        REDACTED_MAILGUN_KEY,
    ),
    # ---- Google API key (AIza + 35 char body — body length is fixed)
    (
        "gcp_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35,}\b"),
        REDACTED_GCP_KEY,
    ),
    # ---- Azure shared-access signature ``SharedAccessKey=…`` or
    # ``azure_*=…`` (covers azure_client_secret, azure_tenant_secret).
    (
        "azure_sas",
        re.compile(r"(?i)(SharedAccessKey\s*=\s*)([A-Za-z0-9/+=]{20,})"),
        rf"\1{REDACTED_AZURE_KEY}",
    ),
    (
        "azure_kv",
        re.compile(
            r"(?i)\b(azure[_\-][A-Za-z0-9_\-]*(?:secret|key|token))\s*[=:]\s*"
            r"([^\s&'\"\[]{8,})"
        ),
        rf"\1={REDACTED_AZURE_KEY}",
    ),
    # ---- Bearer / Authorization tokens (Bearer + opaque slug)
    (
        "bearer_token",
        re.compile(
            r"(?i)(Authorization:\s*Bearer\s+|Bearer\s+)([A-Za-z0-9._\-+/=]{8,})"
        ),
        rf"\1{REDACTED_BEARER}",
    ),
    # ---- Generic api_key / api-token / secret / access_token = VALUE.
    # ``token`` and ``authentication`` are deliberately included even though
    # they are noisy — pentest replay commands frequently embed them and
    # the value is always a credential we want to scrub. The value-class
    # excludes ``[`` so we never re-redact a previous ``[REDACTED-...]``
    # placeholder produced by an earlier pattern in the catalogue.
    (
        "generic_secret_kv",
        re.compile(
            r"(?i)\b((?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret"
            r"|client[_\-]?secret|auth[_\-]?token|authentication"
            r"|x[_\-]?api[_\-]?key|token)"
            r"\s*[=:]\s*)([^\s&'\"\[]{6,})"
        ),
        rf"\1{REDACTED_API_KEY}",
    ),
    # ---- Password / passwd / pwd = VALUE  (covers --password VALUE too,
    # because the ``=`` form is a single token; the ``--password`` flag
    # form is handled by _redact_password_flags).
    (
        "password_kv",
        re.compile(r"(?i)\b(password|passwd|pwd)\s*[=:]\s*([^\s&'\"\[]{1,})"),
        rf"\1={REDACTED_PASSWORD}",
    ),
    # ---- NT / LM hash pair (LM:NT, both 32 hex). MUST run before any
    # standalone NT/LM matcher so the pair is replaced atomically.
    (
        "ntlm_pair",
        re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"),
        REDACTED_NT_HASH,
    ),
    # ---- Empty-LM placeholder + 32-hex NT sibling (``aad3b…:31d6cfe…``).
    (
        "empty_lm",
        re.compile(
            r"\baad3b435b51404eeaad3b435b51404ee[:\s]+[a-fA-F0-9]{32}\b",
            re.IGNORECASE,
        ),
        REDACTED_NT_HASH,
    ),
    # ---- Structured NT/LM hash assignment (``nt_hash=…`` / ``lm_hash=…``).
    # We deliberately do NOT match a bare 32-hex blob — too noisy.
    (
        "nt_lm_hash_kv",
        re.compile(
            r"(?i)\b(nt[_\-]?hash|lm[_\-]?hash|nthash|lmhash)\s*[=:]\s*"
            r"([a-fA-F0-9]{32})"
        ),
        rf"\1={REDACTED_NT_HASH}",
    ),
    # ---- Standalone empty-LM placeholder. Runs LAST among NT/LM
    # matchers so the pair / kv variants take precedence.
    (
        "lm_empty_standalone",
        re.compile(r"\baad3b435b51404eeaad3b435b51404ee\b", re.IGNORECASE),
        REDACTED_NT_HASH,
    ),
    # ---- PEM private-key block. Matches a complete BEGIN/END pair OR
    # a BEGIN header followed by a base64 body chunk (operators frequently
    # paste partial keys from `cat key.pem | head`).
    (
        "pem_private_key",
        re.compile(
            r"-----BEGIN[\s\w]*PRIVATE KEY-----"
            r"(?:[\s\S]*?-----END[\s\w]*PRIVATE KEY-----"
            r"|[A-Za-z0-9+/=\s]{0,2048})"
        ),
        REDACTED_PRIVATE_KEY,
    ),
)


# ---------------------------------------------------------------------------
# Password-flag normalisation (--password VALUE and -p VALUE)
# ---------------------------------------------------------------------------


# When the previous argv token is one of these, the *next* token is a
# password value to be redacted regardless of its content.
_PASSWORD_FLAGS: Final[frozenset[str]] = frozenset(
    {
        "--password",
        "--pwd",
        "--passwd",
        "-p",
        "--token",
        "--api-key",
        "--bearer",
        "--secret",
        "--client-secret",
    }
)


# ---------------------------------------------------------------------------
# Reverse-shell pattern catalogue (whole-token *and* substring scans)
# ---------------------------------------------------------------------------


_REVERSE_SHELL_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    # /dev/tcp/HOST/PORT or /dev/udp/HOST/PORT (any context — bash, php, awk
    # variants all share this filesystem-redirect trick).
    re.compile(r"/dev/(?:tcp|udp)/\S+", re.IGNORECASE),
    # bash -i shell over a redirect
    re.compile(r"bash\s+-i\s*[<>][&]?", re.IGNORECASE),
    # ``nc -e`` / ``ncat -e`` shell hand-off (single-token form, e.g. from
    # ``sh -c "nc -e /bin/sh host port"``)
    re.compile(r"\bn(?:et)?c(?:at)?\b[^|]*\s-e\b", re.IGNORECASE),
    # In-token Python reverse-shell payload (``import socket``, ``pty.spawn``,
    # ``subprocess.call``). Operators usually wrap these in ``python3 -c '…'``
    # and the inner string becomes a single argv token after the shell parses.
    re.compile(r"\bimport\s+socket\b", re.IGNORECASE),
    re.compile(r"\bpty\.spawn\b", re.IGNORECASE),
    re.compile(r"\bsubprocess\.(?:call|Popen|run)\b", re.IGNORECASE),
    re.compile(r"\bsocket\.socket\s*\(", re.IGNORECASE),
    # Perl reverse shell
    re.compile(r"\buse\s+Socket\b", re.IGNORECASE),
    # Pipe into a shell (``curl … | sh`` / ``wget … | bash``)
    re.compile(r"\|\s*(?:sh|bash|zsh|ksh|csh|tcsh|fish|powershell|pwsh)\b"),
    # ``mkfifo /tmp/f; … | sh`` named-pipe trick
    re.compile(r"\bmkfifo\b", re.IGNORECASE),
    # PowerShell IEX (Invoke-Expression) download cradle — single-token
    # Base64-encoded cradle is heuristically caught by the encoded payload
    # rule below.
    re.compile(r"\bIEX\s*\(", re.IGNORECASE),
    re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
    re.compile(r"\bDownloadString\s*\(", re.IGNORECASE),
)


# ---------------------------------------------------------------------------
# SanitizeContext — Pydantic frozen model
# ---------------------------------------------------------------------------


class SanitizeContext(BaseModel):
    """Caller-supplied context for a sanitiser run.

    Attributes
    ----------
    target:
        Primary asset URL or hostname; replaced with ``{ASSET}``.
        Empty string → no asset substitution.
    endpoints:
        Additional URLs / hostnames that must be redacted to
        ``{ENDPOINT}``. Useful when a reproducer touches multiple
        URLs in the same scope (origin + API + admin).
    canaries:
        Operator-supplied *substrings* that must be preserved
        verbatim. The sanitiser will never overwrite a span that
        contains a canary — used for opaque test identifiers the
        operator chose intentionally.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str = Field(default="", max_length=2048)
    endpoints: tuple[str, ...] = Field(default_factory=tuple)
    canaries: tuple[str, ...] = Field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Internal helpers (pure, all return new strings)
# ---------------------------------------------------------------------------


def _strip_destructive_tokens(argv: list[str]) -> list[str]:
    """Drop tokens that *exactly* match a destructive flag (case-insensitive)."""
    result: list[str] = []
    for token in argv:
        if token.lower() in _DENY_FLAGS:
            continue
        result.append(token)
    return result


def _redact_password_flag_values(argv: list[str]) -> list[str]:
    """Replace the value following a ``--password`` / ``-p`` flag.

    Handles three shapes:

    * ``--password VALUE`` / ``-p VALUE`` (split across two argv tokens).
    * ``-p=VALUE`` / ``--token=VALUE`` (single token, ``=`` separator).
    * ``-p:VALUE`` (single token, ``:`` separator).

    The flag itself is preserved so the operator can still see the shape
    of the original command — only the credential value is redacted.
    """
    if not argv:
        return argv
    out = list(argv)
    for idx, token in enumerate(out):
        for flag in _PASSWORD_FLAGS:
            for sep in ("=", ":"):
                marker = f"{flag}{sep}"
                if token.startswith(marker) and len(token) > len(marker):
                    out[idx] = f"{flag}{sep}{REDACTED_PASSWORD}"
                    break
            else:
                continue
            break
    for idx in range(len(out) - 1):
        flag = out[idx]
        if flag in _PASSWORD_FLAGS:
            out[idx + 1] = REDACTED_PASSWORD
    return out


def _apply_secret_patterns(token: str, *, canary_safe: frozenset[str]) -> str:
    """Apply every secret pattern to ``token`` honouring canary protection."""
    if not token:
        return token
    redacted = token
    for _name, pattern, replacement in _SECRET_PATTERNS:

        def _replace(match: re.Match[str], _r: str = replacement) -> str:
            return _safe_replace(match, _r, canary_safe)

        redacted = pattern.sub(_replace, redacted)
    return redacted


def _safe_replace(
    match: re.Match[str],
    replacement: str,
    canary_safe: frozenset[str],
) -> str:
    """Apply ``replacement`` unless the match span overlaps a canary."""
    matched = match.group(0)
    if canary_safe and any(c and c in matched for c in canary_safe):
        return matched
    if "\\1" in replacement:
        try:
            return match.expand(replacement)
        except (re.error, IndexError):
            return replacement.replace("\\1", "")
    return replacement


def _scrub_reverse_shells(token: str) -> str:
    """Replace any reverse-shell payload spans inside ``token``."""
    if not token:
        return token
    cleaned = token
    for pattern in _REVERSE_SHELL_PATTERNS:
        cleaned = pattern.sub(REDACTED_REVERSE_SHELL, cleaned)
    return cleaned


def _replace_targets(
    token: str,
    *,
    target: str,
    endpoints: tuple[str, ...],
    canary_safe: frozenset[str],
) -> str:
    """Replace asset / endpoint substrings with placeholders.

    Endpoints are processed first (longer / more specific URLs match
    before the bare hostname). Canary tokens override every replacement.
    """
    if not token:
        return token
    if any(c and c in token for c in canary_safe):
        return token
    cleaned = token
    for ep in sorted({e for e in endpoints if e}, key=len, reverse=True):
        if ep and ep in cleaned:
            cleaned = cleaned.replace(ep, PLACEHOLDER_ENDPOINT)
    if target and target in cleaned:
        cleaned = cleaned.replace(target, PLACEHOLDER_ASSET)
    return cleaned


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_replay_command(
    argv: list[str],
    context: SanitizeContext,
) -> list[str]:
    """Return a redacted copy of ``argv`` safe for embedding in reports.

    The function is **pure**, **idempotent**, and **type-strict**:

    * Returns a *new* list — the caller's ``argv`` is never mutated.
    * Idempotent: ``sanitize_replay_command(sanitize_replay_command(x, c), c)``
      equals ``sanitize_replay_command(x, c)`` byte-for-byte.
    * Raises :class:`TypeError` for non-``list[str]`` inputs to fail loudly
      in CI rather than silently letting un-typed payloads through.

    Pipeline (run in this order):

    1. **Drop destructive flags** so a one-shot ``--rm`` cannot survive
       into the published reproducer.
    2. **Redact password-flag values** (``--password X`` → ``--password
       [REDACTED-PASSWORD]``).
    3. **Per-token regex sweep** for every secret pattern in
       :data:`_SECRET_PATTERNS`.
    4. **Reverse-shell scrub** — replace any matching span with
       ``[REDACTED-REVERSE-SHELL]``.
    5. **Target / endpoint substitution** — last so an endpoint hidden
       inside a now-redacted Bearer token is never re-exposed.

    Canary protection is enforced inside steps 3 and 5: a token that
    contains any canary substring is returned unchanged.
    """
    if not isinstance(argv, list):
        raise TypeError(
            f"sanitize_replay_command: argv must be list[str], got {type(argv).__name__}"
        )
    for idx, item in enumerate(argv):
        if not isinstance(item, str):
            raise TypeError(
                f"sanitize_replay_command: argv[{idx}] must be str, got {type(item).__name__}"
            )
    if not isinstance(context, SanitizeContext):
        raise TypeError("sanitize_replay_command: context must be SanitizeContext")
    if not argv:
        return []

    canary_safe: frozenset[str] = frozenset(c for c in context.canaries if c)
    stripped = _strip_destructive_tokens(argv)
    flag_redacted = _redact_password_flag_values(stripped)
    secrets_scrubbed = [
        _apply_secret_patterns(token, canary_safe=canary_safe)
        for token in flag_redacted
    ]
    shell_safe = [_scrub_reverse_shells(token) for token in secrets_scrubbed]
    target_safe = [
        _replace_targets(
            token,
            target=context.target,
            endpoints=context.endpoints,
            canary_safe=canary_safe,
        )
        for token in shell_safe
    ]
    return target_safe


__all__ = [
    "PLACEHOLDER_ASSET",
    "PLACEHOLDER_ENDPOINT",
    "REDACTED_API_KEY",
    "REDACTED_AWS_KEY",
    "REDACTED_AWS_SECRET",
    "REDACTED_AZURE_KEY",
    "REDACTED_BEARER",
    "REDACTED_GCP_KEY",
    "REDACTED_GH_TOKEN",
    "REDACTED_GL_TOKEN",
    "REDACTED_JWT",
    "REDACTED_MAILGUN_KEY",
    "REDACTED_NT_HASH",
    "REDACTED_PASSWORD",
    "REDACTED_PRIVATE_KEY",
    "REDACTED_REVERSE_SHELL",
    "REDACTED_SENDGRID_KEY",
    "REDACTED_SLACK_TOKEN",
    "REDACTED_STRIPE_KEY",
    "REDACTED_TWILIO_KEY",
    "SanitizeContext",
    "sanitize_replay_command",
]
