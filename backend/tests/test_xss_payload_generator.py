"""XSS-004 — Adaptive Payload Generator: context-driven mutation and WAF bypass."""

from __future__ import annotations

import pytest

from src.recon.vulnerability_analysis.context_detector import ReflectionContext
from src.recon.vulnerability_analysis.active_scan.payload_generator import (
    AdaptivePayloadGenerator,
    _ATTR_EVENT_HANDLERS,
    _HTML_BASE,
    _JS_STRING_BASE,
    _WAF_BYPASS_TRANSFORMS,
)

_NO_ESCAPES: dict[str, bool] = {"<": False, ">": False, '"': False, "'": False, "(": False, ")": False}


def _make_ctx(
    context_type: str,
    quote_type: str | None = None,
    escape_hints: dict[str, bool] | None = None,
) -> ReflectionContext:
    return ReflectionContext(
        context_type=context_type,
        surrounding_chars="...test...",
        quote_type=quote_type,
        escape_hints=escape_hints or _NO_ESCAPES,
    )


class TestHtmlContextGeneration:
    """XSS-004-T1: HTML context → mutated HTML payloads."""

    def test_returns_html_base_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        for base in _HTML_BASE[:3]:
            assert base in result

    def test_includes_waf_bypass_variants(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=[], max_output=200)
        has_case_variant = any(
            "SCRIPT" in p or "ScRiPt" in p.lower() != p
            for p in result
            if "script" in p.lower()
        )
        assert has_case_variant or len(result) > len(_HTML_BASE)

    def test_includes_custom_base_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        custom = ["<custom-test-payload>"]
        result = gen.generate(ctx, base_payloads=custom, max_output=200)
        assert "<custom-test-payload>" in result


class TestAttributeContextGeneration:
    """XSS-004-T2: attribute context with double-quote → payloads break out of "."""

    def test_double_quote_breakout(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("attribute", quote_type='"')
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        breakout_payloads = [p for p in result if p.startswith('"')]
        assert len(breakout_payloads) > 0, "Expected payloads starting with double-quote breakout"

    def test_single_quote_breakout(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("attribute", quote_type="'")
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        breakout_payloads = [p for p in result if p.startswith("'")]
        assert len(breakout_payloads) > 0

    def test_contains_event_handler_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("attribute", quote_type='"')
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        has_event = any("onmouseover" in p or "onfocus" in p for p in result)
        assert has_event


class TestJsStringContextGeneration:
    """XSS-004-T3: JS string context → payloads with string termination."""

    def test_generates_string_termination_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("js_string", quote_type="'")
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        terminators = [p for p in result if p.startswith("'") and "alert" in p]
        assert len(terminators) > 0

    def test_template_literal_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("js_string", quote_type="`")
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        template_payloads = [p for p in result if "${" in p]
        assert len(template_payloads) > 0

    def test_script_tag_breakout_when_angles_not_escaped(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("js_string", quote_type="'")
        result = gen.generate(ctx, base_payloads=[], max_output=100)
        breakouts = [p for p in result if "</script>" in p]
        assert len(breakouts) > 0


class TestWafBypassVariants:
    """XSS-004-T4: WAF bypass transforms are applied."""

    def test_transforms_produce_different_payloads(self) -> None:
        base = "<script>alert(1)</script>"
        transformed = {fn(base) for fn in _WAF_BYPASS_TRANSFORMS}
        assert len(transformed) > 1, "WAF transforms should produce diverse payloads"

    def test_html_entity_encoding_present(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=[], max_output=200)
        entity_payloads = [p for p in result if "&#x" in p or "&#6" in p]
        assert len(entity_payloads) > 0

    def test_case_variation_present(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=[], max_output=200)
        upper_payloads = [p for p in result if "SCRIPT" in p or "IMG" in p or "SVG" in p]
        assert len(upper_payloads) > 0


class TestMaxOutputCap:
    """XSS-004-T5: max_output cap is respected."""

    def test_output_capped_at_max(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=list(_HTML_BASE), max_output=5)
        assert len(result) == 5

    def test_output_deduplicated(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=list(_HTML_BASE), max_output=200)
        assert len(result) == len(set(result))

    def test_max_output_floor_is_one(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("html")
        result = gen.generate(ctx, base_payloads=[], max_output=0)
        assert len(result) == 1

    def test_unknown_context_uses_fallback(self) -> None:
        gen = AdaptivePayloadGenerator()
        ctx = _make_ctx("unknown")
        result = gen.generate(ctx, base_payloads=["<test>"], max_output=100)
        assert len(result) > 0
        assert "<test>" in result
