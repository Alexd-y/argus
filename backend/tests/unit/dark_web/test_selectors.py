"""Selector building — domain+email coverage (§8a), finding coverage (§8b), scope."""

from __future__ import annotations

from src.intel.dark_web.catalog import load_catalog
from src.intel.dark_web.contracts import SelectorKind
from src.intel.dark_web.selectors import (
    build_domain_email_selectors,
    build_finding_selectors,
)

_CAT = load_catalog().selector_rules


def test_domain_and_emails_become_selectors() -> None:
    sels = build_domain_email_selectors(
        "acme.com", ["alice@acme.com", "bob@acme.com"], catalog=_CAT
    )
    kinds = {s.kind for s in sels}
    assert SelectorKind.DOMAIN in kinds
    assert SelectorKind.EMAIL in kinds
    emails = {s.value for s in sels if s.kind == SelectorKind.EMAIL}
    assert emails == {"alice@acme.com", "bob@acme.com"}
    # keyword templates expanded from the signed catalog
    assert any(s.kind == SelectorKind.KEYWORD for s in sels)


class _DenyAllScope:
    def check(self, spec):  # noqa: ANN001
        class _D:
            allowed = False
        return _D()


class _AllowScope:
    def check(self, spec):  # noqa: ANN001
        class _D:
            allowed = True
        return _D()


def test_scope_denies_out_of_scope_selectors() -> None:
    sels = build_domain_email_selectors(
        "evil.com", ["x@evil.com"], catalog=_CAT, scope_engine=_DenyAllScope()
    )
    # domain + email are both out of scope -> dropped. (keywords may remain as they
    # are brand strings, not scope targets — but domain/email selectors are gone)
    assert not any(s.kind in (SelectorKind.DOMAIN, SelectorKind.EMAIL) for s in sels)


def test_scope_allows_in_scope() -> None:
    sels = build_domain_email_selectors(
        "acme.com", ["a@acme.com"], catalog=_CAT, scope_engine=_AllowScope()
    )
    assert any(s.kind == SelectorKind.DOMAIN for s in sels)
    assert any(s.kind == SelectorKind.EMAIL for s in sels)


def test_email_cap() -> None:
    emails = [f"u{i}@acme.com" for i in range(300)]
    sels = build_domain_email_selectors("acme.com", emails, catalog=_CAT, max_emails=10)
    assert sum(1 for s in sels if s.kind == SelectorKind.EMAIL) == 10


def test_finding_selectors_from_rules() -> None:
    finding = {"id": "f1", "category": "known_cve", "product": "nginx", "version": "1.18", "cve": "CVE-2021-23017", "host": "acme.com"}
    sels = build_finding_selectors(finding, rules=_CAT, target_domain="acme.com")
    assert any(s.kind == SelectorKind.FINDING for s in sels)
    assert all(s.finding_id == "f1" for s in sels)
    # CVE keyword expanded
    assert any("CVE-2021-23017" in s.value for s in sels)


def test_finding_default_category() -> None:
    sels = build_finding_selectors({"id": "f2", "host": "acme.com"}, rules=_CAT, target_domain="acme.com")
    assert sels  # default rule yields at least the FINDING anchor


def test_finding_host_out_of_scope_dropped() -> None:
    # Host-like anchor NOT within the target domain -> FINDING selector dropped (fail-closed).
    finding = {"id": "f3", "category": "default", "host": "third-party.evil.com"}
    sels = build_finding_selectors(finding, rules=_CAT, target_domain="acme.com")
    assert not any(s.kind == SelectorKind.FINDING for s in sels)


def test_domain_selectors_fail_closed_without_scope_or_target() -> None:
    # Email whose domain differs from the target is dropped even with no scope engine.
    sels = build_domain_email_selectors("acme.com", ["x@other.com"], catalog=_CAT)
    assert not any(s.kind == SelectorKind.EMAIL for s in sels)
