"""XSS-003 — Context Detector: reflection context identification in HTML responses."""

from __future__ import annotations

import pytest

from src.recon.vulnerability_analysis.context_detector import (
    ReflectionContext,
    ReflectionContextKey,
    detect_reflection_context,
)

MARKER = "REFLECTED"


class TestReflectionContextReportStrings:
    """Stable ``reflection_context`` for reports maps from detection."""

    def test_html_body(self) -> None:
        html = f"<div>{MARKER}</div>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.reflection_context == ReflectionContextKey.HTML_BODY.value

    def test_attribute_value(self) -> None:
        html = f'<input value="{MARKER}">'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.reflection_context == ReflectionContextKey.ATTRIBUTE_VALUE.value

    def test_dom_event_handler(self) -> None:
        html = f'<button onclick="void(\'{MARKER}\')">x</button>'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.reflection_context == ReflectionContextKey.DOM_EVENT_HANDLER.value

    def test_js_string(self) -> None:
        html = f'<script>var u="{MARKER}";</script>'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.reflection_context == ReflectionContextKey.JS_STRING.value

    def test_js_block(self) -> None:
        html = f"<script>var n = {MARKER};</script>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.reflection_context == ReflectionContextKey.JS_BLOCK.value

    def test_url_attribute(self) -> None:
        html = f'<a href="{MARKER}">x</a>'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.reflection_context == ReflectionContextKey.URL_ATTRIBUTE.value

    def test_unknown(self) -> None:
        ctx = detect_reflection_context("<p>x</p>", MARKER)
        assert ctx.reflection_context == ReflectionContextKey.UNKNOWN.value


class TestHtmlContext:
    """XSS-003-T1: value in tag body → html context."""

    def test_div_body_text(self) -> None:
        html = f"<html><body><div>{MARKER}</div></body></html>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "html"
        assert ctx.tag_name == "div"

    def test_paragraph_body_text(self) -> None:
        html = f"<p>Hello {MARKER} world</p>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "html"


class TestAttributeContext:
    """XSS-003-T2: value in attribute → attribute context with quote detection."""

    def test_input_value_double_quote(self) -> None:
        html = f'<input type="text" value="{MARKER}">'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "attribute"
        assert ctx.quote_type == '"'
        assert ctx.tag_name == "input"
        assert ctx.attribute_name == "value"

    def test_input_value_single_quote(self) -> None:
        html = f"<input type='text' value='{MARKER}'>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "attribute"
        assert ctx.quote_type == "'"


class TestJsStringContext:
    """XSS-003-T3: value in JS string literal → js_string context."""

    def test_double_quoted_js_string(self) -> None:
        html = f'<script>var x="{MARKER}";</script>'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "js_string"
        assert ctx.quote_type == '"'
        assert ctx.in_script_block is True

    def test_single_quoted_js_string(self) -> None:
        html = f"<script>var x='{MARKER}';</script>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "js_string"
        assert ctx.quote_type == "'"


class TestJsBlockContext:
    """XSS-003-T4: value in JS block (not string) → js_block context."""

    def test_js_block_unquoted(self) -> None:
        html = f"<script>var x = {MARKER} + 1;</script>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "js_block"
        assert ctx.in_script_block is True
        assert ctx.quote_type is None


class TestUrlContext:
    """XSS-003-T5: value in URL attribute → url context."""

    def test_href_attribute(self) -> None:
        html = f'<a href="{MARKER}">click</a>'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "url"
        assert ctx.attribute_name == "href"
        assert ctx.tag_name == "a"

    def test_src_attribute(self) -> None:
        html = f'<img src="{MARKER}">'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "url"
        assert ctx.attribute_name == "src"

    def test_action_attribute(self) -> None:
        html = f'<form action="{MARKER}"><input></form>'
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "url"
        assert ctx.attribute_name == "action"


class TestUnknownContext:
    """XSS-003-T6: value not found → unknown context."""

    def test_reflection_not_found(self) -> None:
        html = "<html><body><div>nothing here</div></body></html>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type == "unknown"

    def test_empty_html(self) -> None:
        ctx = detect_reflection_context("", MARKER)
        assert ctx.context_type == "unknown"

    def test_empty_param_value(self) -> None:
        ctx = detect_reflection_context("<div>text</div>", "")
        assert ctx.context_type == "unknown"


class TestMalformedHtml:
    """XSS-003-T7: malformed HTML → no crash, returns valid context."""

    def test_unclosed_tags(self) -> None:
        html = f"<div><span>{MARKER}<div><p>"
        ctx = detect_reflection_context(html, MARKER)
        assert ctx.context_type in ("html", "unknown")
        assert isinstance(ctx, ReflectionContext)

    def test_deeply_nested_garbage(self) -> None:
        html = f"<<<<>>>>{MARKER}<<<>>>"
        ctx = detect_reflection_context(html, MARKER)
        assert isinstance(ctx, ReflectionContext)

    def test_mixed_encodings(self) -> None:
        html = f"<div>&lt;script&gt;{MARKER}&lt;/script&gt;</div>"
        ctx = detect_reflection_context(html, MARKER)
        assert isinstance(ctx, ReflectionContext)

    def test_null_bytes_in_html(self) -> None:
        html = f"<div>\x00{MARKER}\x00</div>"
        ctx = detect_reflection_context(html, MARKER)
        assert isinstance(ctx, ReflectionContext)
