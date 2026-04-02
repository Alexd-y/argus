"""VHQ-001 — Markdown-to-HTML Jinja2 filter for report templates."""

from __future__ import annotations

import pytest
from markupsafe import Markup
from src.reports.template_env import _md_filter, get_report_jinja_environment


def test_md_filter_basic_markdown_bold_headers_lists() -> None:
    md = """# Title

**bold** and *italic*

- first
- second
"""
    out = _md_filter(md)
    assert isinstance(out, Markup)
    html = str(out)
    assert "<h1" in html and "Title" in html
    assert "<strong>bold</strong>" in html
    assert ("<em>italic</em>" in html) or ("<i>italic</i>" in html)
    assert "<ul>" in html and "<li>" in html
    assert "first" in html and "second" in html


@pytest.mark.parametrize(
    "raw",
    [None, "", "   ", "\n\t  \n"],
)
def test_md_filter_none_empty_whitespace_returns_empty(raw: str | None) -> None:
    out = _md_filter(raw)  # type: ignore[arg-type]
    assert out == Markup("")
    assert str(out) == ""


def test_md_filter_fenced_code_block() -> None:
    md = """Intro

```
SELECT * FROM users;
```

After.
"""
    out = _md_filter(md)
    html = str(out)
    assert "<pre" in html or "<code" in html
    assert "SELECT * FROM users" in html


def test_md_filter_table_via_extra_extension() -> None:
    md = """| Col A | Col B |
| ----- | ----- |
| one   | two   |
"""
    out = _md_filter(md)
    html = str(out)
    assert "<table" in html
    assert "Col A" in html and "Col B" in html
    assert "one" in html and "two" in html


def test_md_filter_returns_markup_instance() -> None:
    out = _md_filter("plain")
    assert type(out) is Markup
    assert str(out)


def test_get_report_jinja_environment_registers_md_filter() -> None:
    env = get_report_jinja_environment()
    assert "md" in env.filters
    assert env.filters["md"] is _md_filter


def test_md_filter_via_jinja_template_render() -> None:
    env = get_report_jinja_environment()
    template = env.from_string("{{ body | md }}")
    html = template.render(body="# H\n\n**B**")
    assert "<h1" in html and "H" in html
    assert "<strong>B</strong>" in html or "strong" in html
