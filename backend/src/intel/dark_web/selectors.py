"""Build scope-validated DWM selectors from a domain + its emails, and from findings.

Scope note: :class:`src.policy.scope.ScopeEngine` has no EMAIL target kind, so an
email selector is scope-checked by its DOMAIN part (``alice@acme.com`` ->
``acme.com``). An out-of-scope selector is dropped here (the coordinator records
a ``DARKWEB_COLLECTION`` audit decision for the rejection).
"""

from __future__ import annotations

import logging
from typing import Any

from src.intel.dark_web.contracts import DarkWebSelector, SelectorKind

logger = logging.getLogger(__name__)

_DEFAULT_MAX_EMAILS = 128
_DEFAULT_MAX_SELECTORS = 256


def _email_domain(email: str) -> str:
    return email.split("@", 1)[1].strip().lower() if "@" in email else ""


def _in_scope(
    value: str,
    kind: SelectorKind,
    scope_engine: Any | None,
    target_domain: str = "",
) -> bool:
    """True when ``value`` is within engagement scope — FAIL CLOSED.

    When a :class:`ScopeEngine` is supplied it is authoritative. Otherwise we
    fall back to containment in the authorized ``target_domain`` (the scan's own
    domain): a selector is allowed only if it is that domain or a subdomain of
    it (emails by their domain part). KEYWORD selectors are brand strings derived
    from the authorized target and are allowed. With neither a scope engine nor a
    target domain we DENY — never fall open.
    """

    if scope_engine is not None:
        try:
            from src.pipeline.contracts.tool_job import TargetKind, TargetSpec

            domain = _email_domain(value) if kind == SelectorKind.EMAIL else value
            domain = (domain or "").strip().lower().lstrip(".")
            if not domain:
                return False
            spec = TargetSpec(kind=TargetKind.DOMAIN, domain=domain)
            return bool(scope_engine.check(spec).allowed)
        except Exception:  # noqa: BLE001 - never let scope plumbing break selector building
            logger.exception("darkweb_scope_check_failed", extra={"kind": kind.value})
            return False

    td = (target_domain or "").strip().lower().lstrip(".")
    if not td:
        return False  # no scope engine AND no target domain -> deny (fail closed)
    if kind == SelectorKind.KEYWORD:
        return True  # brand/keyword derived from the authorized target
    dom = _email_domain(value) if kind == SelectorKind.EMAIL else value.strip().lower().lstrip(".")
    if not dom:
        return False
    return dom == td or dom.endswith("." + td)


def build_domain_email_selectors(
    domain: str,
    emails: list[str] | None = None,
    *,
    scope_engine: Any | None = None,
    catalog: dict[str, Any] | None = None,
    brand: str | None = None,
    max_emails: int = _DEFAULT_MAX_EMAILS,
) -> list[DarkWebSelector]:
    """Requirement §8a — one DOMAIN selector, keyword selectors, and one per email."""

    domain = (domain or "").strip().lower().lstrip(".")
    out: list[DarkWebSelector] = []
    # The scan's own domain is the authorized target; it anchors the fail-closed
    # scope fallback when no ScopeEngine is supplied.
    if domain and _in_scope(domain, SelectorKind.DOMAIN, scope_engine, target_domain=domain):
        out.append(DarkWebSelector(kind=SelectorKind.DOMAIN, value=domain))

    # Keyword selectors from the signed catalog's domain_keywords templates.
    templates = []
    if catalog:
        templates = catalog.get("domain_keywords") or []
    brand = (brand or (domain.split(".")[0] if domain else "")).strip()
    seen_kw: set[str] = set()
    for tmpl in templates:
        if not isinstance(tmpl, str):
            continue
        kw = (
            tmpl.replace("{domain}", domain)
            .replace("{brand}", brand)
            .replace("{host}", domain)
            .strip()
        )
        if not kw or kw in seen_kw or kw == domain:
            continue
        seen_kw.add(kw)
        out.append(DarkWebSelector(kind=SelectorKind.KEYWORD, value=kw))

    # One selector per in-scope email (capped). An email is in scope only when
    # its domain is the target domain or a subdomain (fail-closed).
    for email in sorted({e.strip().lower() for e in (emails or []) if e and "@" in e})[:max_emails]:
        if _in_scope(email, SelectorKind.EMAIL, scope_engine, target_domain=domain):
            out.append(DarkWebSelector(kind=SelectorKind.EMAIL, value=email))
    return out[:_DEFAULT_MAX_SELECTORS]


def _finding_category(finding: Any) -> str:
    for attr in ("record_kind", "category", "owasp_category", "cwe"):
        val = getattr(finding, attr, None) if not isinstance(finding, dict) else finding.get(attr)
        if val:
            return str(val).strip().lower()
    return "default"


def _finding_get(finding: Any, key: str, default: str = "") -> str:
    val = getattr(finding, key, None) if not isinstance(finding, dict) else finding.get(key)
    return str(val).strip() if val else default


def build_finding_selectors(
    finding: Any,
    *,
    rules: dict[str, Any] | None = None,
    scope_engine: Any | None = None,
    target_domain: str = "",
    max_keywords: int = 6,
) -> list[DarkWebSelector]:
    """Requirement §8b — derive selectors for a single finding from selector_rules.

    ``target_domain`` anchors the fail-closed scope fallback when no ScopeEngine
    is supplied (host-like anchors must be within the authorized target domain).
    """

    rules = rules or {}
    f2s = (
        rules.get("finding_to_selectors")
        if isinstance(rules.get("finding_to_selectors"), dict)
        else {}
    )
    category = _finding_category(finding)
    rule = f2s.get(category) or f2s.get("default") or {}

    host = _finding_get(finding, "host") or _finding_get(finding, "code_location")
    product = _finding_get(finding, "product")
    version = _finding_get(finding, "version")
    cve = _finding_get(finding, "cve")
    cwe = _finding_get(finding, "cwe")
    fid = _finding_get(finding, "id") or _finding_get(finding, "finding_id")

    out: list[DarkWebSelector] = []
    # A FINDING selector keyed to the finding's host/identifier. A host-like anchor
    # (looks like a domain) is scope-checked; a product/category anchor is allowed.
    anchor = host or product or category
    if anchor:
        host_like = "." in anchor and " " not in anchor
        if not host_like or _in_scope(
            anchor, SelectorKind.DOMAIN, scope_engine, target_domain=target_domain
        ):
            out.append(DarkWebSelector(kind=SelectorKind.FINDING, value=anchor, finding_id=fid))

    templates = rule.get("keywords") if isinstance(rule.get("keywords"), list) else []
    seen: set[str] = set()
    for tmpl in templates[: max_keywords * 2]:
        if not isinstance(tmpl, str):
            continue
        kw = (
            tmpl.replace("{host}", host)
            .replace("{product}", product)
            .replace("{version}", version)
            .replace("{cve}", cve)
            .replace("{cwe}", cwe)
            .strip()
        )
        kw = " ".join(kw.split())  # drop empty substitutions' double spaces
        if not kw or kw in seen:
            continue
        seen.add(kw)
        out.append(DarkWebSelector(kind=SelectorKind.KEYWORD, value=kw, finding_id=fid))
        if len(out) >= max_keywords + 1:
            break
    return out


__all__ = ["build_domain_email_selectors", "build_finding_selectors"]
