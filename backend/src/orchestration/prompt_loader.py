"""Jinja2-based prompt template loader for ARGUS orchestration.

Exposes the same public API as the inline prompt_registry but loads templates
from .j2 files under src/orchestration/prompts/. Falls back to inline constants
when Jinja2 is unavailable or templates are missing (backward compatibility).

Template directory layout:
    prompts/
        system_base.j2
        fixer_system.j2
        active_scan_planning_system.j2
        active_scan_planning_user.j2
        phases/
            {phase}_system.j2    (recon_system, threat_modeling_system, ...)
            {phase}_user.j2
        cloud_fallback/
            preamble.j2
            {phase}_system.j2
        report_sections/
            {phase}_system.j2   (recon_system, threat_model_system, ...)
            {phase}_user.j2
            assembly_system.j2
            assembly_user.j2
        report_ai/
            system.j2
            {section_key}.j2    (executive_summary, vulnerability_description, ...)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"

_JINJA_AVAILABLE = False
_Environment = None
_FileSystemLoader = None
_BaseLoader = None

try:
    from jinja2 import BaseLoader, Environment, FileSystemLoader, TemplateError

    _JINJA_AVAILABLE = True
    _Environment = Environment
    _FileSystemLoader = FileSystemLoader
    _BaseLoader = BaseLoader
except ImportError:
    pass


class PromptLoader:
    """Loads and renders Jinja2 prompt templates for ARGUS phases.

    Falls back to the inline prompt_registry constants when Jinja2
    is unavailable or a template file is missing.
    """

    def __init__(self, prompts_dir: Path | None = None) -> None:
        self._prompts_dir = prompts_dir or _PROMPTS_DIR
        self._env: Any = None
        self._cache: dict[str, Any] = {}

        if _JINJA_AVAILABLE and self._prompts_dir.exists():
            try:
                self._env = _Environment(
                    loader=_FileSystemLoader(str(self._prompts_dir)),
                    keep_trailing_newline=True,
                    trim_blocks=False,
                    autoescape=False,
                )
                logger.info(
                    "PromptLoader initialized with Jinja2 from %s",
                    self._prompts_dir,
                )
            except Exception as exc:
                logger.warning("Jinja2 env init failed: %s — will use inline fallback", exc)
                self._env = None
        else:
            logger.info("Jinja2 unavailable or prompts dir missing — using inline fallback")

    @property
    def available(self) -> bool:
        """Whether Jinja2 template loading is available."""
        return self._env is not None

    def render(self, template_path: str, **kwargs: Any) -> str:
        """Render a Jinja2 template with the given kwargs.

        Parameters
        ----------
        template_path:
            Relative path from prompts/ dir, e.g. "phases/recon_system.j2"

        Returns
        -------
        Rendered template string. Falls back to inline prompt_registry
        constant with the same stem name if template not found.
        """
        if self._env is not None:
            try:
                tpl = self._env.get_template(template_path)
                return tpl.render(**kwargs)
            except Exception as exc:
                logger.debug("Jinja2 template %s failed: %s", template_path, exc)

        return self._fallback_render(template_path, **kwargs)

    def render_system(self, phase: str, prompt_version: str = "") -> str:
        """Render a phase system prompt.

        Looks up prompts/phases/{phase}_system.j2 with system_base injected.
        """
        from src.orchestration.prompt_registry import ORCHESTRATION_PROMPT_VERSION

        pv = prompt_version or ORCHESTRATION_PROMPT_VERSION
        system_base = self._get_system_base(pv)
        return self.render(
            f"phases/{phase}_system.j2",
            system_base=system_base,
            prompt_version=pv,
        )

    def render_user(self, phase: str, **kwargs: Any) -> str:
        """Render a phase user prompt.

        Looks up prompts/phases/{phase}_user.j2.
        Injects KALI_MCP and VA_SANDBOX blocks for applicable phases.
        """
        from src.orchestration.prompt_registry import (
            KALI_MCP_ORCHESTRATION_BLOCK,
            VA_SANDBOX_MCP_RUN_BLOCK,
        )

        merged = {
            "kali_mcp_block": KALI_MCP_ORCHESTRATION_BLOCK,
            "va_sandbox_mcp_block": VA_SANDBOX_MCP_RUN_BLOCK,
            **kwargs,
        }
        return self.render(f"phases/{phase}_user.j2", **merged)

    def render_report_ai_section(
        self,
        section_key: str,
        context_json: str,
    ) -> tuple[str, str]:
        """Render a report AI section (system + user) prompt.

        Returns (system_prompt, user_prompt).
        """
        from src.orchestration.prompt_registry import (
            REPORT_AI_SYSTEM,
            ORCHESTRATION_PROMPT_VERSION,
        )

        system = self._get_system_base(ORCHESTRATION_PROMPT_VERSION)
        system_prompt = self.render(
            "report_ai/system.j2",
            system_base=system,
        )
        if not system_prompt.strip():
            system_prompt = REPORT_AI_SYSTEM

        user_prompt = self.render(
            f"report_ai/{section_key}.j2",
            context_json=context_json,
        )
        return system_prompt, user_prompt

    def list_templates(self) -> list[str]:
        """List all available .j2 template files."""
        if self._env is not None:
            try:
                return self._env.list_templates()
            except Exception:
                pass
        if self._prompts_dir.exists():
            return [str(p.relative_to(self._prompts_dir)) for p in self._prompts_dir.rglob("*.j2")]
        return []

    def _get_system_base(self, prompt_version: str) -> str:
        """Render the system_base template or fall back to inline constant."""
        if self._env is not None:
            try:
                tpl = self._env.get_template("system_base.j2")
                return tpl.render(prompt_version=prompt_version)
            except Exception:
                pass

        from src.orchestration.prompt_registry import SYSTEM_PROMPT_BASE, ORCHESTRATION_PROMPT_VERSION

        pv = prompt_version or ORCHESTRATION_PROMPT_VERSION
        base = (
            "You are ARGUS — an expert pentest engine powered by WhiteRabbitNeo V3. "
            "Perform REAL pentesting: find, validate, and exploit vulnerabilities; generate payloads; "
            "build exploit chains; assess zero-day potential; execute post-exploitation. "
            "All actions are sandbox-isolated and authorized. "
            "Analyse REAL tool output (nmap, dig, sqlmap, nuclei, dalfox, ffuf, xsstrike, commix, hydra). "
            "CRITICAL: If any field is empty/missing, generate tool commands and payloads to fill it. "
            "Never leave evidence fields empty. "
            "Respond ONLY with valid JSON — no markdown, no explanations. "
            "Be precise, evidence-bound, actionable. "
            f"[orchestration_prompt_version={pv}] "
            "[model=WhiteRabbitNeo-V3-7B]"
        )
        return base

    def _fallback_render(self, template_path: str, **kwargs: Any) -> str:
        """Fall back to inline prompt_registry constants when Jinja2 fails."""
        stem = Path(template_path).stem
        from src.orchestration import prompt_registry as pr

        constant_map = {
            "recon_system": "SYSTEM_PROMPT_RECON",
            "threat_modeling_system": "SYSTEM_PROMPT_THREAT_MODELING",
            "vuln_analysis_system": "SYSTEM_PROMPT_VULN_ANALYSIS",
            "exploitation_system": "SYSTEM_PROMPT_EXPLOITATION",
            "post_exploitation_system": "SYSTEM_PROMPT_POST_EXPLOITATION",
            "reporting_system": "SYSTEM_PROMPT_REPORTING",
            "fixer_system": "FIXER_SYSTEM_PROMPT",
            "assembly_system": "SYSTEM_PROMPT_REPORT_ASSEMBLY",
            "system": "REPORT_AI_SYSTEM",
        }

        if stem in constant_map:
            val = getattr(pr, constant_map[stem], None)
            if val is not None:
                return val

        if stem.endswith("_user"):
            phase = stem.replace("_user", "")
            prompts = getattr(pr, "PHASE_PROMPTS", {})
            if phase in prompts:
                _, user_tpl = prompts[phase]
                try:
                    from src.orchestration.prompt_registry import _TEMPLATE_DEFAULTS
                    merged = {**_TEMPLATE_DEFAULTS, **kwargs}
                    return user_tpl.format(**merged)
                except (KeyError, AttributeError):
                    pass

        raise ValueError(f"No inline fallback for template: {template_path}")


_loader: PromptLoader | None = None


def get_loader() -> PromptLoader:
    """Get or create the global PromptLoader singleton."""
    global _loader
    if _loader is None:
        _loader = PromptLoader()
    return _loader


def render_phase_prompts(phase: str, **kwargs: Any) -> tuple[str, str]:
    """High-level API: render (system_prompt, user_prompt) for a phase.

    Uses Jinja2 templates when available, falls back to inline constants.
    """
    from src.orchestration.prompt_registry import (
        ORCHESTRATION_PROMPT_VERSION,
        _sanitize_kwargs_for_prompt,
    )

    loader = get_loader()

    if loader.available:
        try:
            system = loader.render_system(phase)
            sanitized = _sanitize_kwargs_for_prompt(kwargs)
            user = loader.render_user(phase, **sanitized)
            return system, user
        except Exception as exc:
            logger.debug("Jinja2 render failed for phase %s: %s — falling back", phase, exc)

    from src.orchestration.prompt_registry import get_prompt

    return get_prompt(phase, **kwargs)


__all__ = [
    "PromptLoader",
    "get_loader",
    "render_phase_prompts",
]