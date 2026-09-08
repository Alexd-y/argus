"""Humanize raw tool-token finding titles for display (VHL-TITLE-001).

Active-scan intel findings that carry no vendor-supplied ``name`` fall back to a
raw ``"<RAW_TYPE> finding"`` title (e.g. ``"WHATWEB_PLUGIN finding"``,
``"TLS_PROBE finding"``). These leak internal tokens into customer-facing
reports. This module maps known raw tokens to human-readable labels and
title-cases unknown snake/kebab tokens, preserving any trailing
`` — <locator>`` suffix (typically the matched URL) intact.

The transformation is idempotent: an already-human title is returned unchanged.
"""

from __future__ import annotations

import re

#: Known raw producer tokens → human-readable labels.
_RAW_TYPE_LABELS: dict[str, str] = {
    "whatweb_plugin": "Technology fingerprint (WhatWeb)",
    "whatweb": "Technology fingerprint (WhatWeb)",
    "tls_probe": "TLS/SSL configuration observation",
    "ssl_probe": "TLS/SSL configuration observation",
    "http_probe": "HTTP service observation",
    "dns_probe": "DNS configuration observation",
    "dns_record": "DNS record observation",
    "port_scan": "Open port observation",
    "tech_detect": "Technology detection",
    "banner_grab": "Service banner disclosure",
    "fuzz_hit": "Fuzzing candidate",
    "unknown": "Unclassified observation",
}

#: ``"<TOKEN> finding"`` where TOKEN is a raw identifier (letters/digits/_/-/.).
_RAW_TITLE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s+finding$", re.IGNORECASE)
#: A bare raw token such as ``TLS_PROBE`` / ``WHATWEB_PLUGIN`` (upper snake/kebab).
_BARE_TOKEN_RE = re.compile(r"^[A-Z0-9]+(?:[_\-.][A-Z0-9]+)+$")

_SUFFIX_SEP = " — "


def _label_for_token(token: str) -> str:
    key = token.strip().lower()
    if key in _RAW_TYPE_LABELS:
        return _RAW_TYPE_LABELS[key]
    words = [w for w in re.split(r"[_\-.]+", token.strip()) if w]
    titled = " ".join(w.capitalize() for w in words)
    return titled or token.strip()


def _humanize_base(base: str) -> str:
    s = base.strip()
    if not s:
        return s
    m = _RAW_TITLE_RE.match(s)
    if m:
        return _label_for_token(m.group(1))
    if _BARE_TOKEN_RE.match(s):
        return _label_for_token(s)
    return s


def humanize_finding_title(title: str | None, vuln_type: str | None = None) -> str:
    """Return a human-readable finding title, preserving any `` — <locator>`` suffix.

    ``"WHATWEB_PLUGIN finding — https://x"`` → ``"Technology fingerprint (WhatWeb) — https://x"``.
    Already-human titles (``"SQL Injection in login"``) are returned unchanged.
    """
    s = (title or "").strip()
    if not s:
        return _label_for_token(vuln_type) if vuln_type else "Security finding"
    base, sep, suffix = s.partition(_SUFFIX_SEP)
    human = _humanize_base(base)
    return f"{human}{sep}{suffix}" if sep else human


__all__ = ["humanize_finding_title"]
