"""VHL-WRB-001 — WRB-powered dynamic payload and command generation.

Generates payloads for missing WSTG tests, credential testing, auth bypass,
and missing evidence collection. Called from the report pipeline when gaps are detected.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Prompt templates for WRB payload generation
_WRB_SYSTEM_PROMPTS: dict[str, str] = {}


def _get_wrb_system_prompt(context_type: str) -> str:
    """Return a cached WRB system prompt for the given context type."""
    if context_type not in _WRB_SYSTEM_PROMPTS:
        _WRB_SYSTEM_PROMPTS[context_type] = _build_wrb_system_prompt(context_type)
    return _WRB_SYSTEM_PROMPTS[context_type]


def _build_wrb_system_prompt(context_type: str) -> str:
    """Build a context-specific system prompt for WRB."""
    base = (
        "You are a senior penetration testing tool that produces executable "
        "security testing commands and payloads. Output ONLY valid JSON with "
        "no markdown, no explanations, no commentary. Every command must be "
        "safe to run against an authorized target, produce evidence, and include "
        "observable indicators of success. For credential testing, use strong "
        "password lists and include k-anonymity safe hash checking commands. "
        "For WSTG coverage, produce specific tool invocations that generate "
        "validated evidence artifacts. For missing evidence, produce curl/nmap/"
        "testssl/nuclei commands that would fill the gap.\n"
    )
    specifics: dict[str, str] = {
        "wstg_gap": (
            "Generate specific tool commands for missing WSTG tests. "
            "For each test ID provided, output the most effective tool and "
            "command combination that produces concrete evidence. Include "
            "payloads for SQLi, XSS, command injection, SSRF, XXE, path traversal, "
            "and other OWASP Top 10 categories. Use public wordlists and templates."
        ),
        "credential_testing": (
            "Generate commands for credential discovery, password guessing, "
            "brute-force testing, HIBP k-anonymity checking, and credential "
            "stuffing. Include safe payload generation for login forms, "
            "password policy validation, username enumeration, and session "
            "manipulation testing. Output masked credentials only."
        ),
        "auth_testing": (
            "Generate commands for authenticated testing including session "
            "management, JWT manipulation, CSRF token handling, MFA bypass "
            "testing, password reset flow testing, and username enumeration. "
            "Include role-based access control testing commands."
        ),
        "missing_evidence": (
            "Generate commands to collect missing evidence artifacts — raw "
            "HTTP request/response pairs, screenshot commands, SSL/TLS scans, "
            "port scans, technology fingerprinting, and OSINT data collection. "
            "Every command must produce timestamped, verifiable output."
        ),
    }
    return base + specifics.get(context_type, specifics["missing_evidence"])


def generate_wstg_payload_commands(
    missing_tests: list[dict[str, str]],
    target_url: str = "",
    target_host: str = "",
) -> dict[str, Any]:
    """Generate WRB-powered payload commands for missing WSTG tests."""

    from src.llm.facade import call_llm_sync
    from src.llm.task_router import LLMTask

    if not missing_tests:
        return {"commands": [], "status": "no_missing_tests"}

    user_prompt = json.dumps({
        "target_url": target_url,
        "target_host": target_host,
        "missing_tests": [
            {"id": t.get("wstg_id", t.get("id", "")),
             "name": t.get("test_name", t.get("name", "")),
             "category": t.get("category", "")}
            for t in missing_tests[:20]
        ],
        "instructions": (
            "For each missing test, generate the EXACT shell command to run "
            "with the proper tool, flags, and parameters. Include fallback "
            "tools if primary tool is unavailable. Output MUST be valid JSON: "
            '{"commands": [{"wstg_id": "...", "tool": "...", "command": "...", '
            '"fallback_command": "...", "expected_output": "...", "evidence_type": "..."}]}'
        ),
    })

    try:
        result = call_llm_sync(
            _get_wrb_system_prompt("wstg_gap"),
            user_prompt,
            task=LLMTask.REPORT_SECTION,
            phase="wstg_gap_closure",
        )
        parsed = json.loads(result)
        if isinstance(parsed, dict) and isinstance(parsed.get("commands"), list):
            return {"commands": parsed["commands"], "status": "generated"}
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("wrb_wstg_generation_failed", extra={"error": str(exc)})

    return {"commands": [], "status": "generation_failed"}


def generate_credential_testing_commands(
    target_domain: str = "",
    target_url: str = "",
    has_auth_form: bool = False,
) -> dict[str, Any]:
    """Generate WRB-powered credential testing commands."""

    from src.llm.facade import call_llm_sync
    from src.llm.task_router import LLMTask

    user_prompt = json.dumps({
        "target_domain": target_domain,
        "target_url": target_url,
        "has_auth_form": has_auth_form,
        "instructions": (
            "Generate complete credential testing commands including: "
            "1) username enumeration via forgot-password and registration endpoints "
            "2) password spray with weak/common passwords "
            "3) HIBP k-anonymity check for email hashes "
            "4) brute-force with hydra/patator against login form "
            "5) credential stuffing commands. "
            "Use realistic but harmless password lists. "
            "Output MUST be valid JSON: "
            '{"commands": [{"tool": "...", "command": "...", "purpose": "...", '
            '"risk_level": "safe|moderate|aggressive", '
            '"requires_auth": true/false, '
            '"output_evidence": "..."}]}'
        ),
    })

    try:
        result = call_llm_sync(
            _get_wrb_system_prompt("credential_testing"),
            user_prompt,
            task=LLMTask.REPORT_SECTION,
            phase="credential_testing",
        )
        parsed = json.loads(result)
        if isinstance(parsed, dict) and isinstance(parsed.get("commands"), list):
            return {"commands": parsed["commands"], "status": "generated"}
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("wrb_credential_generation_failed", extra={"error": str(exc)})

    return {"commands": [], "status": "generation_failed"}


def generate_auth_testing_commands(
    target_url: str = "",
    roles: list[str] | None = None,
    auth_method: str = "",
) -> dict[str, Any]:
    """Generate WRB-powered authenticated testing commands."""

    from src.llm.facade import call_llm_sync
    from src.llm.task_router import LLMTask

    roles = roles or ["admin", "user", "editor", "viewer", "moderator", "guest", "api", "support", "auditor", "developer"]
    user_prompt = json.dumps({
        "target_url": target_url,
        "roles": roles[:10],
        "auth_method": auth_method or "cookie/session/JWT",
        "instructions": (
            "Generate commands for authenticated testing: "
            "1) session management (cookie invalidation, session fixation, logout) "
            "2) JWT analysis (none alg, weak key, expiry tampering) "
            "3) CSRF token validation "
            "4) MFA bypass attempts "
            "5) password reset flow testing "
            "6) username enumeration "
            "7) role-based access control matrix testing "
            "Output MUST be valid JSON: "
            '{"commands": [{"tool": "...", "command": "...", "purpose": "...", '
            '"auth_method": "...", "roles_tested": [...], '
            '"expected_evidence": "..."}]}'
        ),
    })

    try:
        result = call_llm_sync(
            _get_wrb_system_prompt("auth_testing"),
            user_prompt,
            task=LLMTask.REPORT_SECTION,
            phase="auth_testing",
        )
        parsed = json.loads(result)
        if isinstance(parsed, dict) and isinstance(parsed.get("commands"), list):
            return {"commands": parsed["commands"], "status": "generated"}
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("wrb_auth_generation_failed", extra={"error": str(exc)})

    return {"commands": [], "status": "generation_failed"}


def generate_missing_evidence_commands(
    missing_artifacts: list[dict[str, str]],
    target_url: str = "",
    target_host: str = "",
) -> dict[str, Any]:
    """Generate WRB-powered commands for missing evidence collection."""

    from src.llm.facade import call_llm_sync
    from src.llm.task_router import LLMTask

    if not missing_artifacts:
        return {"commands": [], "status": "no_missing_artifacts"}

    user_prompt = json.dumps({
        "target_url": target_url,
        "target_host": target_host,
        "missing_artifacts": [a.get("description", a.get("finding_id", "")) for a in missing_artifacts[:20]],
        "instructions": (
            "Generate specific commands to collect each missing evidence type. "
            "Output MUST be valid JSON: "
            '{"commands": [{"artifact_type": "...", "tool": "...", "command": "...", '
            '"expected_output": "...", "collection_method": "curl|nmap|nuclei|trivy|whatweb"'
            "\n}]}"
        ),
    })

    try:
        result = call_llm_sync(
            _get_wrb_system_prompt("missing_evidence"),
            user_prompt,
            task=LLMTask.REPORT_SECTION,
            phase="missing_evidence",
        )
        parsed = json.loads(result)
        if isinstance(parsed, dict) and isinstance(parsed.get("commands"), list):
            return {"commands": parsed["commands"], "status": "generated"}
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("wrb_evidence_generation_failed", extra={"error": str(exc)})

    return {"commands": [], "status": "generation_failed"}
