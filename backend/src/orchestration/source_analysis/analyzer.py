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