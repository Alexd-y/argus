"""Source analyzer — orchestrates white-box source code analysis.

Clones (if needed) and analyzes the target application's source code
to identify frameworks, entry points, sinks, auth patterns, and API
endpoints. Produces a SourceAnalysisOutput for downstream phases.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.orchestration.phases import (
    CodeSink,
    CodeSource,
    SourceAnalysisInput,
    SourceAnalysisOutput,
    TaintPath,
)
from src.orchestration.source_analysis.tree_sitter_parser import (
    LanguageDetector,
    Language,
    TreeSitterParser,
)

logger = logging.getLogger(__name__)


class SourceAnalyzer:
    """Orchestrates source code analysis for a target application.

    The analyzer:
    1. Detects languages and frameworks
    2. Identifies security-relevant sinks (SQL, command exec, HTML render, HTTP)
    3. Identifies user-input sources
    4. Attempts taint path identification
    5. Discovers API endpoints and auth patterns

    This is the ARGUS equivalent of Shannon's Pre-Reconnaissance agent,
    but uses pattern-based static analysis instead of LLM-based code review.
    A future iteration will add LLM-assisted deep analysis.
    """

    def __init__(self, input_data: SourceAnalysisInput) -> None:
        self.input_data = input_data
        self.target = input_data.target
        self.repo_path = input_data.repo_path
        self.repo_url = input_data.repo_url

    async def analyze(self) -> SourceAnalysisOutput:
        """Run full source analysis pipeline.

        Returns SourceAnalysisOutput with all findings, or a skipped
        output if no repository is available.
        """
        if not self.repo_path:
            logger.info("source_analysis: no repo_path provided, skipping")
            return SourceAnalysisOutput(skipped=True, summary="No repository path provided; source analysis skipped.")

        repo = Path(self.repo_path)
        if not repo.exists():
            if self.repo_url:
                try:
                    logger.info("source_analysis: cloning %s into %s", self.repo_url, self.repo_path)
                    repo.parent.mkdir(parents=True, exist_ok=True)
                    proc = await asyncio.create_subprocess_exec(
                        "git", "clone", "--depth=1", self.repo_url, str(repo),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        _stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                        return SourceAnalysisOutput(skipped=True, summary=f"git clone timed out for {self.repo_url}")
                    if proc.returncode != 0:
                        err_msg = _stderr.decode(errors="replace")[:500] if _stderr else "unknown error"
                        logger.warning("source_analysis: git clone failed: %s", err_msg)
                        return SourceAnalysisOutput(skipped=True, summary=f"git clone failed: {err_msg}")
                    if not repo.exists():
                        return SourceAnalysisOutput(skipped=True, summary=f"Repository path missing after clone: {self.repo_path}")
                    logger.info("source_analysis: clone successful")
                except Exception as clone_exc:
                    logger.warning("source_analysis: clone error: %s", clone_exc)
                    return SourceAnalysisOutput(skipped=True, summary=f"git clone error: {clone_exc}")
            else:
                return SourceAnalysisOutput(skipped=True, summary=f"Repository path does not exist: {self.repo_path}")

        logger.info("source_analysis: analyzing %s", repo)

        detector = LanguageDetector(repo_path=repo)
        detection = detector.detect()

        primary_language = detection.get("primary_language", "unknown")
        frameworks = detection.get("frameworks", [])

        parser = TreeSitterParser(repo_path=repo)
        sinks_raw = parser.find_sinks(primary_language)

        sinks = [
            CodeSink(
                file_path=s.get("file_path", "unknown"),
                line_number=s.get("line_number"),
                sink_type=s.get("sink_type", "unknown"),
                code_snippet=s.get("code_snippet", ""),
                severity=s.get("severity", "medium"),
            )
            for s in sinks_raw
        ]

        sources = self._identify_sources(repo, primary_language)

        auth_patterns = self._identify_auth_patterns(repo, primary_language)
        api_endpoints = self._identify_api_endpoints(repo, primary_language)
        file_tree = self._build_file_tree(repo)

        taint_paths = self._build_taint_paths(sources, sinks)

        framework_str = ", ".join(frameworks) if frameworks else primary_language
        summary = (
            f"Source analysis of {repo.name}: {framework_str} application "
            f"({primary_language}, {len(sources)} entry points, {len(sinks)} sinks). "
            f"Identified {len(taint_paths)} potential taint paths."
        )

        # LLM-augmented deep source review for high-value findings
        llm_sinks, llm_taint_paths, llm_auth_gaps = await self._llm_deep_review(
            repo, primary_language, frameworks, sinks, sources, taint_paths, auth_patterns
        )
        if llm_sinks:
            sinks.extend(llm_sinks)
        if llm_taint_paths:
            taint_paths.extend(llm_taint_paths)
        if llm_auth_gaps:
            auth_patterns.extend(llm_auth_gaps)

        # Update summary with LLM-augmented counts
        summary = (
            f"Source analysis of {repo.name}: {framework_str} application "
            f"({primary_language}, {len(sources)} entry points, {len(sinks)} sinks). "
            f"Identified {len(taint_paths)} potential taint paths. "
            f"LLM deep review added {len(llm_sinks)} sinks, {len(llm_taint_paths)} taint paths, {len(llm_auth_gaps)} auth gaps."
        )

        return SourceAnalysisOutput(
            framework=frameworks[0] if frameworks else None,
            language=primary_language,
            entry_points=sources,
            sinks=sinks,
            taint_paths=taint_paths,
            auth_patterns=auth_patterns,
            api_endpoints=api_endpoints,
            file_tree=file_tree,
            summary=summary,
            skipped=False,
        )

    def _identify_sources(self, repo: Path, language: str) -> list[CodeSource]:
        """Identify user-input sources (HTTP params, form fields, headers)."""
        sources: list[CodeSource] = []
        source_patterns: dict[str, list[str]] = {
            "python": [
                r"request\.(args|form|json|values|headers|cookies|files)",
                r"request\.get_data\s*\(",
                r"flask\.request",
                r"fastapi\.Request",
                r"self\.request\.",
            ],
            "javascript": [
                r"req\.(body|query|params|headers|cookies)",
                r"request\.(body|query|params)",
                r"ctx\.request\.",
                r"\$request->",
            ],
            "java": [
                r"HttpServletRequest",
                r"@RequestParam|@PathVariable|@RequestBody|@RequestHeader",
                r"request\.getParameter",
            ],
        }

        import re as re_module
        patterns = source_patterns.get(language, [])
        ext = {"python": ".py", "javascript": ".js", "java": ".java", "typescript": ".ts"}.get(language, ".py")

        count = 0
        for path in repo.rglob(f"*{ext}"):
            if count >= 200:
                break
            if any(skip in path.parts for skip in ("node_modules", ".git", "__pycache__", "venv", "dist")):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            rel = str(path.relative_to(repo))
            for line_no, line in enumerate(content.splitlines(), 1):
                for pattern in patterns:
                    if re_module.search(pattern, line):
                        sources.append(CodeSource(
                            file_path=rel,
                            line_number=line_no,
                            source_type="http_param",
                            code_snippet=line.strip()[:200],
                        ))
                        count += 1
                        break

        return sources[:500]

    def _identify_auth_patterns(self, repo: Path, language: str) -> list[dict[str, Any]]:
        """Identify authentication/authorization patterns in the codebase."""
        patterns: list[dict[str, Any]] = []
        auth_files = [
            "auth.py", "authentication.py", "login.py", "middleware.py",
            "security.py", "permissions.py", "decorators.py",
            "auth.js", "auth.ts", "middleware.js", "middleware.ts",
            "AuthController.java", "SecurityConfig.java",
            "auth.go", "middleware.go",
            "sessions.py", "jwt.py", "token.py",
            "Passport.java",
        ]

        for auth_name in auth_files:
            for path in repo.rglob(auth_name):
                if any(skip in path.parts for skip in ("node_modules", ".git", "vendor")):
                    continue
                patterns.append({
                    "file": str(path.relative_to(repo)),
                    "type": "auth_file",
                    "name": auth_name,
                })

        return patterns[:50]

    def _identify_api_endpoints(self, repo: Path, language: str) -> list[dict[str, Any]]:
        """Identify API endpoints from route definitions."""
        import re as re_module
        endpoints: list[dict[str, Any]] = []
        route_patterns: dict[str, list[str]] = {
            "python": [
                r'@(?:app|router)\.(get|post|put|delete|patch|route)\s*\(\s*["\']([^"\']+)["\']',
                r'path\s*\(\s*["\']([^"\']+)["\']',
            ],
            "javascript": [
                r'(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                r'\.route\s*\(\s*["\']([^"\']+)["\']',
            ],
            "java": [
                r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["\']([^"\']+)["\']',
                r'@RequestMapping\s*\(\s*value\s*=\s*["\']([^"\']+)["\']',
            ],
        }

        ext = {"python": ".py", "javascript": ".js", "java": ".java", "typescript": ".ts"}.get(language, ".py")
        for path in repo.rglob(f"*{ext}"):
            if any(skip in path.parts for skip in ("node_modules", ".git", "__pycache__", "venv", "dist")):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            rel = str(path.relative_to(repo))
            for pattern in route_patterns.get(language, []):
                for match in re_module.finditer(pattern, content):
                    groups = match.groups()
                    method = groups[0].upper() if len(groups) > 1 else "ANY"
                    route_path = groups[-1] if groups else "/"
                    endpoints.append({
                        "file": rel,
                        "method": method,
                        "path": route_path,
                    })

        return endpoints[:500]

    def _build_file_tree(self, repo: Path, max_depth: int = 3) -> dict[str, Any]:
        """Build a simplified file tree representation."""
        tree: dict[str, Any] = {}
        skip_dirs = {"node_modules", ".git", "__pycache__", "venv", "dist", "build", ".next", "target", "vendor"}

        try:
            for item in sorted(repo.iterdir()):
                if item.name.startswith(".") or item.name in skip_dirs:
                    continue
                if item.is_dir():
                    if max_depth > 1:
                        subtree = self._build_file_tree(item, max_depth - 1)
                        if subtree:
                            tree[item.name + "/"] = subtree
                else:
                    tree[item.name] = None
        except PermissionError:
            pass

        return tree

    def _build_taint_paths(
        self, sources: list[CodeSource], sinks: list[CodeSink]
    ) -> list[TaintPath]:
        """Attempt to build taint paths from sources to sinks.

        This is a heuristic approach — a production version would use
        real AST-based data flow analysis (CodeQL/Joern).
        Currently links sources and sinks in the same file.
        """
        paths: list[TaintPath] = []

        sink_by_file: dict[str, list[CodeSink]] = {}
        for sink in sinks[:100]:
            key = sink.file_path.split("/")[0] if "/" in sink.file_path else sink.file_path
            sink_by_file.setdefault(key, []).append(sink)

        for source in sources[:100]:
            key = source.file_path.split("/")[0] if "/" in source.file_path else source.file_path
            matching_sinks = sink_by_file.get(key, [])
            for sink in matching_sinks[:3]:
                paths.append(TaintPath(
                    source=source,
                    sink=sink,
                    intermediate_nodes=[],
                    sanitizers=[],
                    is_sanitized=False,
                ))

        return paths[:200]

    async def _llm_deep_review(
        self,
        repo: Path,
        language: str,
        frameworks: list[str],
        sinks: list[CodeSink],
        sources: list[CodeSource],
        taint_paths: list[TaintPath],
        auth_patterns: list[dict[str, Any]],
    ) -> tuple[list[CodeSink], list[TaintPath], list[dict[str, Any]]]:
        """LLM-augmented deep source code review.

        Sends a summary of pattern-based findings + key source files to the LLM
        for deeper vulnerability discovery: missed sinks, cross-file taint paths,
        and authentication/authorization gaps that patterns miss.
        """
        llm_sinks: list[CodeSink] = []
        llm_taint_paths: list[TaintPath] = []
        llm_auth_gaps: list[dict[str, Any]] = []

        try:
            from src.llm.facade import call_llm_with_escalation
            from src.llm.task_router import LLMTask

            sink_summary = "\n".join(
                f"- {s.sink_type} at {s.file_path}:{s.line_number or '?'} ({s.severity})"
                for s in sinks[:20]
            )
            source_summary = "\n".join(
                f"- {s.source_type} at {s.file_path}:{s.line_number or '?'}"
                for s in sources[:20]
            )
            auth_summary = "\n".join(
                f"- {a.get('type', '?')}: {a.get('file_path', '?')}"
                for a in auth_patterns[:10]
            )
            framework_str = ", ".join(frameworks) if frameworks else language

            user_prompt = (
                f"You are reviewing source code for security vulnerabilities.\n\n"
                f"Language: {language}\nFrameworks: {framework_str}\n\n"
                f"Pattern-based analysis found:\n"
                f"SINKS:\n{sink_summary or 'None found'}\n\n"
                f"SOURCES:\n{source_summary or 'None found'}\n\n"
                f"AUTH PATTERNS:\n{auth_summary or 'None found'}\n\n"
                f"Based on your expertise, identify:\n"
                f"1. MISSED SINKS — dangerous function calls the pattern scanner missed\n"
                f"2. CROSS-FILE TAINT PATHS — data flows across files that patterns can't trace\n"
                f"3. AUTH/AUTHZ GAPS — missing authorization checks, privilege escalation vectors\n\n"
                f"Return JSON:\n"
                f'{{"missed_sinks": [{{"file_path": "...", "line_number": N, "sink_type": "...", "code_snippet": "...", "severity": "high|medium|low"}}], '
                f'"cross_file_taint": [{{"source_file": "...", "source_function": "...", "sink_file": "...", "sink_function": "..."}}], '
                f'"auth_gaps": [{{"type": "...", "file_path": "...", "description": "..."}}]}}'
            )

            response = await call_llm_with_escalation(
                system_prompt="You are a security source code auditor. Analyze findings and identify what patterns missed. Return ONLY valid JSON.",
                user_prompt=user_prompt,
                task=LLMTask.THREAT_MODELING,
                scan_id="",
                phase="source_analysis_llm_deep_review",
            )

            if not response:
                return llm_sinks, llm_taint_paths, llm_auth_gaps

            import json as _json
            try:
                data = _json.loads(response.strip())
            except _json.JSONDecodeError:
                for line in response.splitlines():
                    if line.strip().startswith("{"):
                        try:
                            data = _json.loads(line.strip())
                            break
                        except _json.JSONDecodeError:
                            continue
                else:
                    return llm_sinks, llm_taint_paths, llm_auth_gaps

            for ms in data.get("missed_sinks", [])[:15]:
                try:
                    llm_sinks.append(CodeSink(
                        file_path=str(ms.get("file_path", "unknown")),
                        line_number=ms.get("line_number"),
                        sink_type=str(ms.get("sink_type", "unknown")),
                        code_snippet=str(ms.get("code_snippet", ""))[:500],
                        severity=str(ms.get("severity", "medium")),
                    ))
                except Exception:
                    pass

            for ct in data.get("cross_file_taint", [])[:15]:
                try:
                    src = CodeSource(
                        file_path=str(ct.get("source_file", "unknown")),
                        line_number=None,
                        source_type="cross_file_source",
                        code_snippet=str(ct.get("source_function", ""))[:200],
                    )
                    snk = CodeSink(
                        file_path=str(ct.get("sink_file", "unknown")),
                        line_number=None,
                        sink_type="cross_file_sink",
                        code_snippet=str(ct.get("sink_function", ""))[:200],
                        severity="high",
                    )
                    llm_taint_paths.append(TaintPath(
                        source=src,
                        sink=snk,
                        intermediate_nodes=[],
                        sanitizers=[],
                        is_sanitized=False,
                    ))
                except Exception:
                    pass

            for ag in data.get("auth_gaps", [])[:10]:
                try:
                    llm_auth_gaps.append({
                        "type": str(ag.get("type", "unknown")),
                        "file_path": str(ag.get("file_path", "")),
                        "description": str(ag.get("description", ""))[:1000],
                        "source": "llm_deep_review",
                    })
                except Exception:
                    pass

            logger.info(
                "llm_deep_review_completed",
                extra={
                    "sinks_added": len(llm_sinks),
                    "taint_paths_added": len(llm_taint_paths),
                    "auth_gaps_added": len(llm_auth_gaps),
                },
            )

        except Exception as exc:
            logger.debug("llm_deep_review_failed (non-fatal): %s", exc)

        return llm_sinks, llm_taint_paths, llm_auth_gaps