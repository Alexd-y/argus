"""
Skills system for ARGUS AI pentest agents.

Loads Markdown skill files with YAML frontmatter containing vulnerability-specific
methodologies, tool commands, payloads, and validation requirements.
Skill content is injected into LLM system prompts during VA phases.
"""

from __future__ import annotations

import re
from pathlib import Path

SKILLS_DIR = Path(__file__).parent
_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)
_EXCLUDED = {"__pycache__", ".git"}

_CATEGORY_SKILL_MAP: dict[str, list[str]] = {
    "sqli": ["sql_injection"],
    "xss": ["xss"],
    "ssrf": ["ssrf", "xxe"],
    "csrf": ["csrf"],
    "auth": ["authentication_jwt", "business_logic"],
    "idor": ["idor"],
    "rce": ["rce", "path_traversal"],
    "race": ["race_conditions", "business_logic"],
    "xxe": ["xxe"],
    "file_upload": ["file_upload"],
    "open_redirect": ["open_redirect"],
    "mass_assignment": ["mass_assignment"],
    "info_disclosure": ["information_disclosure"],
    "subdomain_takeover": ["subdomain_takeover"],
    "graphql": ["graphql"],
    "jwt": ["jwt", "authentication_jwt"],
}


def get_available_skills() -> dict[str, list[str]]:
    """Return ``{category: [skill_names]}`` for every ``.md`` file."""
    result: dict[str, list[str]] = {}
    for category_dir in SKILLS_DIR.iterdir():
        if not category_dir.is_dir() or category_dir.name in _EXCLUDED:
            continue
        skills = [f.stem for f in category_dir.glob("*.md")]
        if skills:
            result[category_dir.name] = sorted(skills)
    return result


def load_skill(skill_name: str) -> str | None:
    """Load a single skill by name, stripping YAML frontmatter."""
    for md_file in SKILLS_DIR.rglob(f"{skill_name}.md"):
        content = md_file.read_text(encoding="utf-8")
        return _FRONTMATTER_RE.sub("", content).strip()
    return None


def load_skills(skill_names: list[str]) -> dict[str, str]:
    """Load multiple skills; skip missing ones."""
    return {
        name: content
        for name in skill_names
        if (content := load_skill(name))
    }


def get_skills_for_category(vuln_category: str) -> list[str]:
    """Map a vulnerability category key to relevant skill names."""
    return _CATEGORY_SKILL_MAP.get(vuln_category, [])


def build_skills_prompt_block(skill_names: list[str]) -> str:
    """Build an XML-tagged block of skill content for injection into prompts."""
    loaded = load_skills(skill_names)
    if not loaded:
        return ""
    parts = ["<specialized_knowledge>"]
    for name, content in loaded.items():
        parts.append(f"<skill name=\"{name}\">\n{content}\n</skill>")
    parts.append("</specialized_knowledge>")
    return "\n".join(parts)
