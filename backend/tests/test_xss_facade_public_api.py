"""XSS VA facades — public re-exports match ``active_scan`` implementations (smoke)."""

from __future__ import annotations

import inspect

import src.recon.vulnerability_analysis.context_detector as ctx_facade
import src.recon.vulnerability_analysis.xss_payload_manager as pm_facade
import src.recon.vulnerability_analysis.xss_verifier as ver_facade
import src.recon.vulnerability_analysis.active_scan.context_detector as ctx_impl
import src.recon.vulnerability_analysis.active_scan.xss_payload_manager as pm_impl
import src.recon.vulnerability_analysis.active_scan.xss_verifier as ver_impl


def test_context_detector_facade_matches_active_scan() -> None:
    assert ctx_facade.__all__ == [
        "ContextType",
        "ReflectionContext",
        "ReflectionContextKey",
        "detect_reflection_context",
    ]
    assert ctx_facade.ContextType is ctx_impl.ContextType
    assert ctx_facade.ReflectionContext is ctx_impl.ReflectionContext
    assert ctx_facade.ReflectionContextKey is ctx_impl.ReflectionContextKey
    assert ctx_facade.detect_reflection_context is ctx_impl.detect_reflection_context
    unknown = ctx_facade.detect_reflection_context("", "x")
    assert unknown.context_type == "unknown"


def test_xss_payload_manager_facade_matches_active_scan() -> None:
    assert pm_facade.__all__ == ["XSSPayloadManager", "get_payload_manager"]
    assert pm_facade.XSSPayloadManager is pm_impl.XSSPayloadManager
    assert pm_facade.get_payload_manager is pm_impl.get_payload_manager
    mgr = pm_facade.get_payload_manager()
    assert isinstance(mgr, pm_facade.XSSPayloadManager)


def test_xss_verifier_facade_matches_active_scan() -> None:
    assert ver_facade.__all__ == [
        "XSSVerificationResult",
        "verify_xss_with_browser",
        "verify_xss_with_browser_async",
    ]
    assert ver_facade.XSSVerificationResult is ver_impl.XSSVerificationResult
    assert ver_facade.verify_xss_with_browser is ver_impl.verify_xss_with_browser
    assert ver_facade.verify_xss_with_browser_async is ver_impl.verify_xss_with_browser_async
    assert inspect.iscoroutinefunction(ver_facade.verify_xss_with_browser_async)
    bad = ver_facade.verify_xss_with_browser("not-a-url", "q", "<x>", "scan-1")
    assert bad.verified is False
    assert bad.error == "invalid url or param"
