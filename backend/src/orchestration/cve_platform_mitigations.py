"""CVE applicability vs hosting / stack (T5) — downgrade platform-mitigated CVE findings."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from src.reports.finding_metadata import extract_cve_ids_from_finding, normalize_confidence

# CVE IDs known to be addressed or materially mitigated on specific managed platforms
# (conservative allowlist; extend via product security advisories).
_PLATFORM_MITIGATED: dict[str, frozenset[str]] = {
    # Next.js / React Server Components — Vercel platform protections for hosted deployments.
    "CVE-2024-51479": frozenset({"vercel"}),
}

_NEXT_VER_RE = re.compile(
    r"next(?:\.js)?\s*[@\s:\"/']{0,16}([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)


def _hostname_hints(text: str) -> set[str]:
    out: set[str] = set()
    t = (text or "").lower()
    for token in t.replace(",", " ").split():
        token = token.strip().strip("[]()'\"")
        if not token:
            continue
        if "://" in token:
            try:
                host = (urlparse(token).hostname or "").lower()
                if host:
                    out.add(host)
            except Exception:
                pass
        elif "." in token and " " not in token:
            out.add(token.lower())
    return out


def infer_hosting_platforms(*blobs: str) -> set[str]:
    """Detect managed hosting hints from assets, target URL, and free-text context."""
    found: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        low = blob.lower()
        hosts = _hostname_hints(blob)
        for h in hosts:
            if h.endswith(".vercel.app") or h.endswith(".vercel.com"):
                found.add("vercel")
            if h.endswith(".netlify.app") or "netlify" in h:
                found.add("netlify")
        if "vercel" in low or "x-vercel-id" in low:
            found.add("vercel")
        if "netlify" in low:
            found.add("netlify")
    return found


def parse_nextjs_version(text: str) -> str | None:
    """Best-effort Next.js semver from manifest / tech blob."""
    if not text:
        return None
    m = _NEXT_VER_RE.search(text)
    if not m:
        return None
    return m.group(1)


def apply_platform_cve_mitigations(
    findings: list[dict[str, Any]],
    *,
    assets: list[str],
    target: str = "",
    extra_context_blob: str = "",
) -> None:
    """
    When a CVE is mitigated on the inferred platform, avoid confirmed severity of applicability:
    set confidence to ``advisory`` and append applicability notes (mutates findings in-place).
    """
    blob = " ".join(str(a) for a in (assets or [])[:40])
    platforms = infer_hosting_platforms(blob, target or "", extra_context_blob or "")
    next_ver = parse_nextjs_version(f"{blob}\n{extra_context_blob}")

    for f in findings:
        cves = extract_cve_ids_from_finding(f)
        if not cves:
            continue
        notes: list[str] = []
        for cve in cves:
            mitigated_on = _PLATFORM_MITIGATED.get(cve)
            if not mitigated_on:
                continue
            overlap = platforms & mitigated_on
            if not overlap:
                continue
            plat = ", ".join(sorted(overlap))
            notes.append(
                f"{cve}: vendor/platform mitigations likely apply on {plat} for typical deployments; "
                "verify against your runtime and edge configuration."
            )
        if not notes:
            continue
        cur = normalize_confidence(f.get("confidence"), default="likely")
        if cur in ("confirmed", "likely"):
            f["confidence"] = "advisory"
        if not f.get("evidence_type"):
            f["evidence_type"] = "cve_correlation"
        existing = str(f.get("applicability_notes") or "").strip()
        block = " ".join(notes)
        combined = f"{existing}; {block}".strip("; ") if existing else block
        if next_ver:
            tail = f" Detected Next.js {next_ver} in scan context — confirm against vendor fixed releases."
            if tail.strip() not in combined:
                combined = (combined + tail)[:8000]
        else:
            combined = combined[:8000]
        f["applicability_notes"] = combined
