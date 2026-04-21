"""RPT-008 — Jinja2 Environment for tiered HTML reports (FileSystemLoader, autoescape)."""

from __future__ import annotations

from pathlib import Path

import markdown as md_lib
import nh3
from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

_REPORT_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates" / "reports"


def report_templates_directory() -> Path:
    return _REPORT_TEMPLATES_DIR


# SECURITY: Allowlist for nh3 HTML sanitizer applied to AI-generated markdown.
# Only these tags survive the markdown → HTML → sanitize pipeline.
# Adding <script>, <iframe>, <object>, <embed>, <form>, or event-handler attributes
# would re-introduce XSS risk. Review with security team before expanding.
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


_ENV_CACHE: dict[str, Environment] = {}


def get_report_jinja_environment(template_dir: str = "") -> Environment:
    """Return cached Jinja2 Environment. Use reset_template_env_cache() for hot reload."""
    cache_key = template_dir or str(_REPORT_TEMPLATES_DIR)
    if cache_key not in _ENV_CACHE:
        env = Environment(
            loader=FileSystemLoader(cache_key),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        env.filters["md"] = _md_filter
        _ENV_CACHE[cache_key] = env
    return _ENV_CACHE[cache_key]


def reset_template_env_cache() -> None:
    """Clear template environment cache for hot reload during development."""
    _ENV_CACHE.clear()


def render_tier_report_html(tier: str, context: dict) -> str:
    from src.services.reporting import normalize_report_tier

    tier_norm = normalize_report_tier(tier)
    template_name = f"{tier_norm}.html.j2"
    env = get_report_jinja_environment()
    return env.get_template(template_name).render(context)
