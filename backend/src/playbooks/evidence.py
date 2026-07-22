"""Evidence collection with mandatory secret redaction (P2-PLAYBOOKS-002).

Playbook evidence bundles capture the baseline (control) and mutated (attack)
HTTP exchanges plus a normalised diff. Before anything is persisted, secrets
(cookies, ``Authorization``, tokens, passwords, OTPs) are **always** redacted
by :func:`redact_exchange` — there is no unredacted persistence path.

The redacted bundle exposes a stable SHA-256 and a redaction count so it can
be attached to the existing :class:`~src.pipeline.contracts.finding_dto.EvidenceDTO`
(``kind=EvidenceKind.DIFF``) via :meth:`EvidenceBundle.to_evidence_dto`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from src.playbooks.actions import HttpExchange, HttpRequestSpec, HttpResponse
from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind

REDACTED: Final[str] = "[REDACTED]"

# Header names whose value is always a secret and is redacted wholesale.
_SECRET_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-session-token",
        "x-access-token",
        "x-refresh-token",
    }
)

# Substrings that, when found in a (lowercased) JSON key or form field name,
# mark the associated value as a secret.
_SECRET_KEY_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "otp",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "authorization",
    "session",
    "jwt",
    "private_key",
    "client_secret",
    "credential",
)

# Matches ``password=...`` / ``token: ...`` style secrets inside raw
# (non-JSON) bodies and query strings.
_RAW_SECRET_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|secret|token|otp|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|authorization|session|jwt|client[_-]?secret"
    r")\b(\s*[:=]\s*)(\"?)([^\"'&\s,}]+)"
)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def _is_secret_key(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in _SECRET_KEY_SUBSTRINGS)


def redact_headers(headers: Mapping[str, str]) -> tuple[dict[str, str], int]:
    """Redact secret-bearing headers. Returns ``(redacted, count)``."""
    redacted: dict[str, str] = {}
    count = 0
    for key, value in headers.items():
        if key.lower() in _SECRET_HEADERS or _is_secret_key(key):
            redacted[key] = REDACTED
            count += 1
        else:
            redacted[key] = value
    return redacted, count


def _redact_json(value: object) -> tuple[object, int]:
    if isinstance(value, Mapping):
        out: dict[str, object] = {}
        count = 0
        for key, child in value.items():
            if isinstance(key, str) and _is_secret_key(key):
                out[key] = REDACTED
                count += 1
            else:
                redacted_child, child_count = _redact_json(child)
                out[str(key)] = redacted_child
                count += child_count
        return out, count
    if isinstance(value, list):
        out_list: list[object] = []
        count = 0
        for item in value:
            redacted_item, item_count = _redact_json(item)
            out_list.append(redacted_item)
            count += item_count
        return out_list, count
    return value, 0


def redact_body(body: str | None) -> tuple[str | None, int]:
    """Redact secrets from a request/response body.

    JSON bodies are redacted structurally (secret keys → ``[REDACTED]``);
    other bodies fall back to a regex over ``key=value`` / ``key: value``
    secret patterns. Returns ``(redacted_body, count)``.
    """
    if body is None:
        return None, 0
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        parsed = None
    if parsed is not None:
        redacted, count = _redact_json(parsed)
        if count:
            return json.dumps(redacted, sort_keys=True, separators=(",", ":")), count
        return body, 0

    count = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}"

    redacted_text = _RAW_SECRET_RE.sub(_sub, body)
    return redacted_text, count


def redact_exchange(exchange: HttpExchange) -> tuple[HttpExchange, int]:
    """Return a fully-redacted copy of ``exchange`` and the redaction count."""
    req_headers, req_hcount = redact_headers(exchange.request.headers)
    req_query, req_qcount = _redact_mapping(exchange.request.query)
    req_body, req_bcount = redact_body(exchange.request.body)
    resp_headers, resp_hcount = redact_headers(exchange.response.headers)
    resp_body, resp_bcount = redact_body(exchange.response.body)

    redacted = HttpExchange(
        request=HttpRequestSpec(
            method=exchange.request.method,
            url=_redact_url(exchange.request.url),
            headers=req_headers,
            query=req_query,
            body=req_body,
        ),
        response=HttpResponse(
            status=exchange.response.status,
            headers=resp_headers,
            body=resp_body or "",
            elapsed_ms=exchange.response.elapsed_ms,
        ),
    )
    total = req_hcount + req_qcount + req_bcount + resp_hcount + resp_bcount
    return redacted, total


def _redact_mapping(mapping: Mapping[str, str]) -> tuple[dict[str, str], int]:
    out: dict[str, str] = {}
    count = 0
    for key, value in mapping.items():
        if _is_secret_key(key):
            out[key] = REDACTED
            count += 1
        else:
            out[key] = value
    return out, count


def _redact_url(url: str) -> str:
    if "?" not in url:
        return url
    base, _, query = url.partition("?")
    redacted, _count = redact_body(query)
    return f"{base}?{redacted}" if redacted is not None else base


def redact(value: object) -> object:
    """Redact secrets from an arbitrary JSON-like value (mappings/lists/str).

    Convenience wrapper used by callers that hold loose data rather than a
    full :class:`HttpExchange`.
    """
    if isinstance(value, HttpExchange):
        redacted, _ = redact_exchange(value)
        return redacted
    if isinstance(value, str):
        redacted_body, _ = redact_body(value)
        return redacted_body
    redacted_value, _ = _redact_json(value)
    return redacted_value


# ---------------------------------------------------------------------------
# Diff + bundle
# ---------------------------------------------------------------------------


class NormalizedDiff(BaseModel):
    """A normalised, redaction-safe diff between two exchanges."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status_changed: bool
    baseline_status: StrictInt
    mutated_status: StrictInt
    differing_body_fields: list[StrictStr] = Field(default_factory=list, max_length=512)
    changed_headers: list[StrictStr] = Field(default_factory=list, max_length=128)


def _diff_body_fields(baseline_body: str, mutated_body: str) -> list[str]:
    left = _safe_json(baseline_body)
    right = _safe_json(mutated_body)
    if left is None or right is None:
        return [] if baseline_body == mutated_body else ["<body>"]
    return sorted(_json_diff_paths(left, right))


def _safe_json(body: str) -> object | None:
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def _json_diff_paths(left: object, right: object, prefix: str = "") -> set[str]:
    here = prefix.rstrip(".") or "<root>"
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        paths: set[str] = set()
        for key in set(left) | set(right):
            child = f"{prefix}{key}"
            if key not in left or key not in right:
                paths.add(child)
            else:
                paths |= _json_diff_paths(left[key], right[key], child + ".")
        return paths
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return {here}
        paths = set()
        for index, (lft, rgt) in enumerate(zip(left, right)):
            paths |= _json_diff_paths(lft, rgt, f"{prefix}{index}.")
        return paths
    return set() if left == right else {here}


class EvidenceBundle(BaseModel):
    """Redacted baseline + mutated exchanges with a diff and stable hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline: HttpExchange
    mutated: HttpExchange
    diff: NormalizedDiff
    redactions_applied: StrictInt = Field(ge=0, le=100_000)

    def canonical_json(self) -> str:
        """Return a deterministic JSON serialisation of the redacted bundle."""
        return json.dumps(
            {
                "baseline": self.baseline.model_dump(mode="json"),
                "mutated": self.mutated.model_dump(mode="json"),
                "diff": self.diff.model_dump(mode="json"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def sha256(self) -> str:
        """SHA-256 (lowercase hex) of the canonical redacted bundle."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def to_evidence_dto(
        self,
        *,
        id: UUID,
        finding_id: UUID,
        tool_run_id: UUID,
        s3_key: str,
    ) -> EvidenceDTO:
        """Build an :class:`EvidenceDTO` (``kind=DIFF``) for this bundle."""
        return EvidenceDTO(
            id=id,
            finding_id=finding_id,
            tool_run_id=tool_run_id,
            kind=EvidenceKind.DIFF,
            s3_key=s3_key,
            sha256=self.sha256(),
            redactions_applied=min(self.redactions_applied, 10_000),
        )


def build_evidence_bundle(baseline: HttpExchange, mutated: HttpExchange) -> EvidenceBundle:
    """Redact both exchanges, compute the diff, and assemble a bundle.

    Redaction happens *before* the bundle is constructed, so the persisted
    representation never contains secrets.
    """
    redacted_baseline, baseline_count = redact_exchange(baseline)
    redacted_mutated, mutated_count = redact_exchange(mutated)

    diff = NormalizedDiff(
        status_changed=(redacted_baseline.response.status != redacted_mutated.response.status),
        baseline_status=redacted_baseline.response.status,
        mutated_status=redacted_mutated.response.status,
        differing_body_fields=_diff_body_fields(
            redacted_baseline.response.body, redacted_mutated.response.body
        ),
        changed_headers=_changed_headers(
            redacted_baseline.response.headers, redacted_mutated.response.headers
        ),
    )
    return EvidenceBundle(
        baseline=redacted_baseline,
        mutated=redacted_mutated,
        diff=diff,
        redactions_applied=baseline_count + mutated_count,
    )


def _changed_headers(baseline: Mapping[str, str], mutated: Mapping[str, str]) -> list[str]:
    names = {k.lower() for k in baseline} | {k.lower() for k in mutated}
    lowered_base = {k.lower(): v for k, v in baseline.items()}
    lowered_mut = {k.lower(): v for k, v in mutated.items()}
    changed = [name for name in names if lowered_base.get(name) != lowered_mut.get(name)]
    return sorted(changed)


__all__ = [
    "REDACTED",
    "EvidenceBundle",
    "NormalizedDiff",
    "build_evidence_bundle",
    "redact",
    "redact_body",
    "redact_exchange",
    "redact_headers",
]
