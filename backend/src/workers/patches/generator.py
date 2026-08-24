"""Patch Generation Worker — AI-powered remediation synthesis via WhiteRabbitNeo.

Generates: patch diffs, secure alternatives, root-cause analysis, regression tests.
Outputs: GitHub PR suggestions, patch bundles for review.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

logger = logging.getLogger(__name__)


class PatchType(str, Enum):
    MINIMAL = "minimal"       # Только фикс, минимальные изменения
    HARDENING = "hardening"   # Усиленная защита с дополнительными проверками


class PatchStatus(str, Enum):
    PENDING = "pending"
    GENERATED = "generated"
    VALIDATED = "validated"
    FAILED_VALIDATION = "failed_validation"
    PR_CREATED = "pr_created"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class PatchResult:
    id: str = ""
    finding_id: str = ""
    tenant_id: str = ""
    repo_id: str = ""
    patch_type: PatchType = PatchType.MINIMAL
    file_path: str = ""
    line_start: int = 0
    original_code: str = ""
    patched_code: str = ""
    diff: str = ""
    rationale: str = ""
    secure_alternative: str = ""  # Альтернативный безопасный подход
    blast_radius: str = ""
    backward_compat_risk: str = ""  # low | medium | high
    regression_test: str = ""
    validation_output: str = ""
    lint_passed: bool = False
    tests_passed: bool = False
    status: PatchStatus = PatchStatus.PENDING
    pr_url: str = ""
    error: str = ""


def _prompt_patch_generation(
    finding: dict[str, Any],
    original_code: str,
    patch_type: PatchType,
) -> str:
    return f"""Generate a security fix for this vulnerability.

=== FINDING ===
Title: {finding.get('title', 'N/A')}
Severity: {finding.get('severity', 'unknown')}
CWE: {finding.get('cwe', 'N/A')}
Description: {finding.get('description', '')[:1000]}
File: {finding.get('file_path', '')}
Line: {finding.get('line_start', 0)}

=== VULNERABLE CODE ===
{original_code[:3000]}

=== PATCH TYPE ===
{patch_type.value} — {'minimum fix only' if patch_type == PatchType.MINIMAL else 'hardened with extra guards'}

=== TASK ===
Output JSON with:
1. "patched_code": the fixed code
2. "diff": unified diff format
3. "rationale": why this fix works, root cause explanation
4. "secure_alternative": alternative secure design pattern
5. "blast_radius": what else might be affected by this change
6. "backward_compat_risk": "low" | "medium" | "high"
7. "regression_test": pytest-compatible test to verify the fix

Respond ONLY with valid JSON."""


async def generate_patch(
    finding: dict[str, Any],
    original_code: str,
    *,
    patch_type: PatchType = PatchType.MINIMAL,
    tenant_id: str = "",
    repo_id: str = "",
) -> PatchResult:
    """Generate security patch via WhiteRabbitNeo."""
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    result = PatchResult(
        id=str(uuid.uuid4()),
        finding_id=finding.get("id", finding.get("finding_id", "")),
        tenant_id=tenant_id,
        repo_id=repo_id,
        patch_type=patch_type,
        file_path=finding.get("file_path", ""),
        line_start=finding.get("line_start", 0) or 0,
        original_code=original_code,
    )

    if not original_code.strip():
        result.error = "No code to patch"
        result.status = PatchStatus.FAILED_VALIDATION
        return result

    prompt = _prompt_patch_generation(finding, original_code, patch_type)
    system = (
        "You are an expert security engineer writing production-grade fixes. "
        "Produce minimal, correct patches with clear rationale. "
        "Respond ONLY with valid JSON."
    )

    try:
        response = await call_llm_unified(
            system, prompt,
            task=LLMTask.REMEDIATION_PLAN,
            phase="patch_generation",
        )
        data = json.loads(response)

        result.patched_code = str(data.get("patched_code", ""))
        result.diff = str(data.get("diff", ""))
        result.rationale = str(data.get("rationale", ""))[:2000]
        result.secure_alternative = str(data.get("secure_alternative", ""))[:2000]
        result.blast_radius = str(data.get("blast_radius", ""))[:1000]
        result.backward_compat_risk = str(data.get("backward_compat_risk", "low")).lower()
        result.regression_test = str(data.get("regression_test", ""))[:3000]
        result.status = PatchStatus.GENERATED

    except Exception as exc:
        result.error = str(exc)
        result.status = PatchStatus.FAILED_VALIDATION

    return result


async def validate_patch(result: PatchResult) -> PatchResult:
    """Run lint + unit tests on generated patch."""
    if not result.patched_code.strip():
        result.lint_passed = False
        result.status = PatchStatus.FAILED_VALIDATION
        return result

    with TemporaryDirectory() as tmp:
        code_file = Path(tmp) / "patch_validate.py"
        code_file.write_text(result.patched_code, encoding="utf-8")

        # Syntax check
        try:
            compile(result.patched_code, code_file.name, "exec")
            result.lint_passed = True
        except SyntaxError as e:
            result.lint_passed = False
            result.validation_output = f"Syntax error: {e}"
            result.status = PatchStatus.FAILED_VALIDATION
            return result

        # Run regression test if provided
        if result.regression_test.strip():
            test_file = Path(tmp) / "test_patch.py"
            test_content = f"{result.patched_code}\n\n{result.regression_test}"
            test_file.write_text(test_content, encoding="utf-8")

            try:
                proc = await asyncio.create_subprocess_exec(
                    "python3", "-m", "pytest", str(test_file), "-q",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                result.tests_passed = proc.returncode == 0
                result.validation_output = (
                    (stdout or b"").decode(errors="replace")[:2000]
                )
            except TimeoutError:
                result.tests_passed = False
                result.validation_output = "Test execution timed out"
            except Exception as exc:
                result.tests_passed = False
                result.validation_output = str(exc)

        if result.lint_passed and result.tests_passed:
            result.status = PatchStatus.VALIDATED
        else:
            result.status = PatchStatus.FAILED_VALIDATION

    return result


async def generate_and_validate_patch(
    finding: dict[str, Any],
    original_code: str,
    **kwargs,
) -> PatchResult:
    """Generate patch and validate it in one pipeline."""
    result = await generate_patch(finding, original_code, **kwargs)
    if result.status == PatchStatus.GENERATED:
        result = await validate_patch(result)
    return result


async def batch_generate_patches(
    findings: list[tuple[dict[str, Any], str]],
    **kwargs,
) -> list[PatchResult]:
    """Generate patches for multiple findings concurrently."""
    tasks = []
    for finding, code in findings:
        tasks.append(generate_and_validate_patch(finding, code, **kwargs))
    return await asyncio.gather(*tasks)
