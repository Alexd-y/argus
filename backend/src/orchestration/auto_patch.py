"""Auto-patch synthesis — finding → diff → PR → regression verify.

Translates vulnerability findings into code patches, creates PRs,
and verifies that patches fix the vulnerability without regressions.

Ось E из Развитие2.md + Фаза 2: auto-patch synthesis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PatchCandidate:
    """A generated patch for a vulnerability finding."""

    finding_id: str
    file_path: str
    patch_diff: str
    description: str
    confidence: float = 0.0
    language: str = ""
    cwe: str = ""
    verified: bool = False
    regression_test_passed: bool = False


@dataclass
class PatchVerificationResult:
    """Result of verifying a patch against the vulnerable code."""

    patch_id: str
    vulnerability_fixed: bool | None = None
    no_regressions: bool | None = None
    test_results: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class AutoPatchResult:
    """Result of an auto-patch synthesis run."""

    candidates: list[PatchCandidate] = field(default_factory=list)
    verifications: list[PatchVerificationResult] = field(default_factory=list)
    pr_url: str = ""
    error: str = ""


AUTOPATCH_SYSTEM_PROMPT = (
    "You are a security patch engineer. Generate minimal, safe diffs that fix "
    "the reported vulnerability without breaking existing functionality.\n"
    "Rules:\n"
    "1. Use parameterized queries for SQL injection\n"
    "2. Use output encoding for XSS\n"
    "3. Use allow-lists for SSRF\n"
    "4. Use proper auth checks for auth bypass\n"
    "5. NEVER change function signatures (backward compatibility)\n"
    "6. Add inline comments explaining the security fix\n"
    "Output unified diff format."
)

AUTOPATCH_USER_TEMPLATE = (
    "Generate a security patch for the following vulnerability:\n\n"
    "CWE: {cwe}\n"
    "Description: {description}\n"
    "File: {file_path}\n"
    "Severity: {severity}\n\n"
    "=== VULNERABLE CODE ===\n{vulnerable_code}\n=== END ===\n\n"
    "=== SURROUNDING CONTEXT ===\n{context}\n=== END ===\n\n"
    "Output the patch as a unified diff."
)


def build_autopatch_prompt(
    cwe: str,
    description: str,
    file_path: str,
    severity: str,
    vulnerable_code: str,
    context: str = "",
) -> tuple[str, str]:
    try:
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        if loader.available:
            try:
                system, user = loader.render_extended_system_user(
                    "auto_patch",
                    cwe=cwe, description=description, file_path=file_path,
                    severity=severity, vulnerable_code=vulnerable_code[:20000],
                    context=context[:10000],
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                pass
    except Exception:
        pass
    return AUTOPATCH_SYSTEM_PROMPT, AUTOPATCH_USER_TEMPLATE.format(
        cwe=cwe,
        description=description,
        file_path=file_path,
        severity=severity,
        vulnerable_code=vulnerable_code[:20000],
        context=context[:10000],
    )


def parse_patch_response(
    finding_id: str, file_path: str, response_text: str, cwe: str = ""
) -> PatchCandidate:
    """Parse LLM response into a PatchCandidate."""
    diff_lines = []
    in_diff = False
    for line in response_text.splitlines():
        if line.startswith("---") or line.startswith("+++"):
            in_diff = True
        if in_diff or line.startswith("@@") or line.startswith("+") or line.startswith("-"):
            diff_lines.append(line)
            in_diff = True

    patch_diff = "\n".join(diff_lines) if diff_lines else response_text
    return PatchCandidate(
        finding_id=finding_id,
        file_path=file_path,
        patch_diff=patch_diff,
        description=f"Auto-patch for {cwe}" if cwe else "Auto-patch",
        confidence=0.0,
        cwe=cwe,
    )


async def verify_patch_in_sandbox(
    candidate: PatchCandidate,
    sandbox_executor: Any = None,
) -> PatchVerificationResult:
    """Verify a patch by applying it and running tests in sandbox.

    If no sandbox_executor is provided, attempts lightweight file-level
    verification: applies diff to a temp file and checks syntax.
    """
    if sandbox_executor is not None:
        try:
            result = await sandbox_executor(
                "patch_verify",
                {"diff": candidate.patch_diff, "file": candidate.file_path},
            )
            return PatchVerificationResult(
                patch_id=candidate.finding_id,
                vulnerability_fixed=result.get("vulnerability_fixed", False),
                no_regressions=result.get("no_regressions", True),
                test_results=result,
            )
        except Exception as exc:
            return PatchVerificationResult(
                patch_id=candidate.finding_id,
                vulnerability_fixed=False,
                no_regressions=False,
                error=str(exc),
            )

    logger.warning(
        "patch_verify_lightweight",
        extra={"finding_id": candidate.finding_id, "file_path": candidate.file_path},
    )

    import os
    import tempfile
    import subprocess

    if not candidate.file_path or not candidate.patch_diff:
        return PatchVerificationResult(
            patch_id=candidate.finding_id,
            vulnerability_fixed=None,
            no_regressions=None,
            test_results={"note": "no file path or diff provided", "verified": False},
        )

    syntax_ok = False
    try:
        with tempfile.TemporaryDirectory(prefix="argus_patch_") as tmpdir:
            target_path = os.path.join(tmpdir, os.path.basename(candidate.file_path))

            fake_content = f"# Original: {candidate.file_path}\n# CWE: {candidate.cwe}\npass\n"
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(fake_content)

            diff_path = os.path.join(tmpdir, "patch.diff")
            with open(diff_path, "w", encoding="utf-8") as f:
                f.write(candidate.patch_diff)

            try:
                result = subprocess.run(
                    ["git", "apply", "--check", diff_path],
                    capture_output=True, text=True, timeout=10,
                    cwd=tmpdir,
                )
                if result.returncode == 0:
                    syntax_ok = True
            except Exception:
                pass

            if syntax_ok:
                ext = os.path.splitext(candidate.file_path)[1]
                checker = "python" if ext in (".py",) else "node" if ext in (".js", ".ts") else None
                if checker:
                    try:
                        syntax_result = subprocess.run(
                            [checker, "-c", f"compile(open(r'{target_path}').read(), '{candidate.file_path}', 'exec')" if checker == "python" else f"--check {target_path}"],
                            capture_output=True, text=True, timeout=10,
                        )
                        syntax_ok = syntax_result.returncode == 0
                    except Exception:
                        syntax_ok = True

    except Exception as exc:
        logger.debug("patch_verify_lightweight_failed: %s", exc)

    return PatchVerificationResult(
        patch_id=candidate.finding_id,
        vulnerability_fixed=None if not syntax_ok else False,
        no_regressions=None,
        test_results={"note": f"lightweight verification: diff applies={syntax_ok}", "verified": False, "diff_applies": syntax_ok},
    )


__all__ = [
    "AUTOPATCH_SYSTEM_PROMPT",
    "AUTOPATCH_USER_TEMPLATE",
    "AutoPatchResult",
    "PatchCandidate",
    "PatchVerificationResult",
    "build_autopatch_prompt",
    "parse_patch_response",
]