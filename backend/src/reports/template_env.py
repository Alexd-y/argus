"""RPT-008 — Jinja2 Environment for tiered HTML reports (FileSystemLoader, autoescape)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import markdown as md_lib
import nh3
from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

_REPORT_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates" / "reports"


def report_templates_directory() -> Path:
    return _REPORT_TEMPLATES_DIR


_ALLOWED_TAGS = {
    "p", "br", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "strong", "em", "code", "pre",
    "blockquote", "a", "table", "thead", "tbody", "tr", "th", "td",
    "hr", "dl", "dt", "dd", "abbr", "sup", "sub", "span", "div",
}

_ALLOWED_ATTRS: dict[str, set[str]] = {
    "a": {"href", "title"},
    "abbr": {"title"},
    "td": {"align"},
    "th": {"align"},
}


def _md_filter(text: str) -> Markup:
    """Convert markdown AI output to sanitized HTML for report slots."""
    if not text or not isinstance(text, str) or not text.strip():
        return Markup("")
    raw_html = md_lib.markdown(
        text,
        extensions=["extra", "nl2br", "sane_lists"],
        output_format="html",
    )
    safe_html = nh3.clean(
        raw_html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        link_rel="noopener noreferrer",
        url_schemes={"http", "https", "mailto"},
    )
    return Markup(safe_html)


@lru_cache(maxsize=1)
def get_report_jinja_environment() -> Environment:
    """HTML report templates only — autoescape all outputs (user + AI text)."""
    env = Environment(
        loader=FileSystemLoader(str(_REPORT_TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["md"] = _md_filter
    return env


def render_tier_report_html(tier: str, context: dict) -> str:
    from src.services.reporting import normalize_report_tier

    tier_norm = normalize_report_tier(tier)
    template_name = f"{tier_norm}.html.j2"
    env = get_report_jinja_environment()
    return env.get_template(template_name).render(context)
