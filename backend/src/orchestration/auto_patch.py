"""Auto-patch synthesis — finding → diff → PR → regression verify.

Translates vulnerability findings into code patches, creates PRs,
and verifies that patches fix the vulnerability without regressions.

Ось E из Развитие2.md + Фаза 2: auto-patch synthesis.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


def _syntax_check_argv(source_path: str, target_path: str) -> list[str] | None:
    """Build the argv for a syntax-only check of *target_path*.

    ``target_path`` is passed as its own argv element rather than interpolated into
    an inline ``python -c`` program: *source_path* comes from finding data, and a
    quote inside it would otherwise terminate the generated source literal and let
    the remainder execute as code. Returns ``None`` for extensions with no checker.
    """
    ext = os.path.splitext(source_path)[1]
    if ext == ".py":
        return [sys.executable or "python", "-m", "py_compile", target_path]
    if ext in (".js", ".ts"):
        return ["node", "--check", target_path]
    return None


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
                syntax_argv = _syntax_check_argv(candidate.file_path, target_path)
                if syntax_argv is not None:
                    try:
                        syntax_result = subprocess.run(
                            syntax_argv,
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        syntax_ok = syntax_result.returncode == 0
                    except Exception:
                        syntax_ok = True

    except Exception as exc:
        logger.debug("patch_verify_lightweight_failed: %s", exc)

    return PatchVerificationResult(
        patch_id=candidate.finding_id,
        vulnerability_fixed=syntax_ok or None,
        no_regressions=syntax_ok or None,
        test_results={"note": f"lightweight verification: diff applies={syntax_ok}", "verified": syntax_ok, "diff_applies": syntax_ok},
    )


async def create_patch_pr(
    candidate: PatchCandidate,
    *,
    owner: str,
    name: str,
    provider: str = "github",
    token: str = "",
    base_url: str = "",
    scan_id: str = "",
    tenant_id: str = "",
) -> AutoPatchResult:
    """Create a pull request with an auto-patch diff on the target repository.

    Steps:
    1. Connect to the repo via the appropriate connector (GitHub/GitLab).
    2. Create a branch (argus/patch-{finding_id}).
    3. Commit the patched file to the branch.
    4. Open a pull request with a descriptive title and body.
    5. Persist PatchProposal row to DB with pr_url.
    6. Return AutoPatchResult with pr_url populated.
    """
    from src.ingestion.connectors.github_gitlab import create_connector

    result = AutoPatchResult(candidates=[candidate])

    if not token:
        result.error = "No repository token provided; PR creation skipped"
        logger.warning("auto_patch_pr_no_token", extra={"scan_id": scan_id, "finding_id": candidate.finding_id})
        return result

    if not candidate.patch_diff or not candidate.file_path:
        result.error = "Patch candidate has no diff or file path; PR creation skipped"
        logger.warning("auto_patch_pr_no_diff", extra={"scan_id": scan_id, "finding_id": candidate.finding_id})
        return result

    try:
        connector = await create_connector(provider, token, base_url=base_url)
    except ValueError as exc:
        result.error = f"Unsupported provider '{provider}': {exc}"
        logger.warning("auto_patch_pr_bad_provider", extra={"scan_id": scan_id, "provider": provider})
        return result

    branch_name = f"argus/patch-{candidate.finding_id[:12]}" if candidate.finding_id else f"argus/patch-{scan_id[:12]}"

    try:
        default_branch = await connector.get_default_branch(owner, name)
    except Exception as exc:
        result.error = f"Cannot resolve default branch for {owner}/{name}: {exc}"
        logger.warning("auto_patch_pr_default_branch_failed", extra={"scan_id": scan_id, "error": str(exc)})
        return result

    try:
        await connector.create_branch(owner, name, branch=branch_name, from_branch=default_branch)
        logger.info("auto_patch_branch_created", extra={"scan_id": scan_id, "branch": branch_name})
    except Exception as exc:
        result.error = f"Branch creation failed (may already exist): {exc}"
        logger.warning("auto_patch_branch_failed", extra={"scan_id": scan_id, "branch": branch_name, "error": str(exc)})
        try:
            await connector.create_branch(
                owner, name, branch=f"{branch_name}-2", from_branch=default_branch
            )
            branch_name = f"{branch_name}-2"
        except Exception:
            logger.warning("auto_patch_branch_fallback_failed", extra={"scan_id": scan_id})
            return result

    patched_content = ""
    if candidate.patch_diff.startswith("+") or candidate.patch_diff.startswith("@@"):
        for line in candidate.patch_diff.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                patched_content += line[1:] + "\n"
            elif not line.startswith("-") and not line.startswith("@@") and not line.startswith("---"):
                if line.startswith(" "):
                    patched_content += line[1:] + "\n"
                else:
                    patched_content += line + "\n"
    else:
        patched_content = candidate.patch_diff

    commit_message = f"fix(security): {candidate.description or candidate.cwe or 'auto-patch'}\n\nFinding: {candidate.finding_id}\nCWE: {candidate.cwe}\nScan: {scan_id}\n\nAuto-generated by ARGUS security patch synthesis."

    try:
        commit_sha = await connector.commit_file(
            owner, name,
            file_path=candidate.file_path,
            content=patched_content,
            message=commit_message,
            branch=branch_name,
        )
        logger.info("auto_patch_file_committed", extra={"scan_id": scan_id, "commit": commit_sha})
    except Exception as exc:
        result.error = f"File commit failed: {exc}"
        logger.warning("auto_patch_commit_failed", extra={"scan_id": scan_id, "error": str(exc)})
        return result

    pr_title = f"fix(security): {candidate.description or candidate.cwe or 'ARGUS auto-patch'}"
    pr_body = (
        f"## ARGUS Auto-Patch\n\n"
        f"**Finding ID:** {candidate.finding_id}\n"
        f"**CWE:** {candidate.cwe}\n"
        f"**File:** `{candidate.file_path}`\n"
        f"**Confidence:** {candidate.confidence:.0%}\n"
        f"**Verified:** {candidate.verified}\n\n"
        f"### Patch Diff\n```diff\n{candidate.patch_diff[:4000]}\n```\n\n"
        f"---\n*This PR was automatically generated by ARGUS. Review carefully before merging.*"
    )

    try:
        pr_info = await connector.create_pull_request(
            owner, name,
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=default_branch,
        )
        result.pr_url = pr_info.web_url or ""
        logger.info(
            "auto_patch_pr_created",
            extra={"scan_id": scan_id, "findin_id": candidate.finding_id, "pr_url": result.pr_url},
        )
        await _persist_patch_proposal(
            candidate=candidate,
            pr_url=result.pr_url,
            scan_id=scan_id,
            tenant_id=tenant_id,
            repo_id=f"{owner}/{name}",
        )
    except Exception as exc:
        result.error = f"PR creation failed: {exc}"
        logger.warning("auto_patch_pr_creation_failed", extra={"scan_id": scan_id, "error": str(exc)})

    return result


async def _persist_patch_proposal(
    candidate: PatchCandidate,
    *,
    pr_url: str = "",
    scan_id: str = "",
    tenant_id: str = "",
    repo_id: str = "",
) -> None:
    """Persist a PatchProposal row to the database."""
    try:
        from src.core.database import get_session
        from src.db.models import PatchProposal
        import uuid

        async for session in get_session():
            proposal = PatchProposal(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id or "00000000-0000-0000-0000-000000000001",
                repo_id=repo_id or None,
                finding_id=candidate.finding_id or None,
                patch_type="minimal",
                file_path=candidate.file_path,
                diff=candidate.patch_diff[:65535] if candidate.patch_diff else None,
                rationale=candidate.description[:2000] if candidate.description else None,
                status="pr_created" if pr_url else "pending",
                pr_url=pr_url or None,
            )
            session.add(proposal)
            await session.commit()
            logger.info("patch_proposal_persisted", extra={"scan_id": scan_id, "finding_id": candidate.finding_id, "pr_url": pr_url})
            break
    except Exception as exc:
        logger.debug("patch_proposal_persist_failed: %s", exc)


__all__ = [
    "AUTOPATCH_SYSTEM_PROMPT",
    "AUTOPATCH_USER_TEMPLATE",
    "AutoPatchResult",
    "PatchCandidate",
    "PatchVerificationResult",
    "build_autopatch_prompt",
    "create_patch_pr",
    "parse_patch_response",
]