"""RPT-008 — Jinja2 Environment for tiered HTML reports (FileSystemLoader, autoescape)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_REPORT_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates" / "reports"


def report_templates_directory() -> Path:
    return _REPORT_TEMPLATES_DIR


@lru_cache(maxsize=1)
def get_report_jinja_environment() -> Environment:
    """HTML report templates only — autoescape all outputs (user + AI text)."""
    return Environment(
        loader=FileSystemLoader(str(_REPORT_TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_tier_report_html(tier: str, context: dict) -> str:
    from src.services.reporting import normalize_report_tier

    tier_norm = normalize_report_tier(tier)
    template_name = f"{tier_norm}.html.j2"
    env = get_report_jinja_environment()
    return env.get_template(template_name).render(context)
