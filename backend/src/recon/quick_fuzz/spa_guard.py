"""SPA (Single-Page Application) baseline guard.

Detects when an HTTP response is a generic SPA shell (Angular, React, Vue)
that returns the same HTML regardless of the injected parameter. Quick-fuzz
results against SPA shells are almost always false positives and should be
discarded.
"""

from __future__ import annotations

_SPA_INDICATORS: tuple[str, ...] = (
    "<app-root>",
    '<div id="root">',
    "ng-version=",
    "data-reactroot",
    "<!-- built with",
    "data-beasties-container",
    "<!doctype html>",
)


def is_spa_shell(response_body: str) -> bool:
    """Return ``True`` when *response_body* looks like a generic SPA index.

    A SPA shell returns the same HTML regardless of query parameters because
    routing happens client-side. Sending payloads to such responses is not
    useful — the fuzzer should skip them.
    """
    lower = response_body.lower()
    return any(ind.lower() in lower for ind in _SPA_INDICATORS)


def is_same_response(
    body_a: str,
    body_b: str,
    status_a: int,
    status_b: int,
    size_tolerance: int = 50,
) -> bool:
    """Return ``True`` when two responses are effectively identical.

    This catches the common case where an SPA returns the same boilerplate
    HTML for every URL: same status code, same size (within *size_tolerance*).
    """
    if status_a != status_b:
        return False
    return abs(len(body_a) - len(body_b)) <= size_tolerance
