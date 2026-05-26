"""Language detection and tree-sitter AST parsing for source analysis.

Uses file extensions, shebangs, and common config files to identify
the application's primary languages and frameworks, then parses
source files into ASTs for sink/source identification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


class Language(StrEnum):
    """Supported programming languages for source analysis."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    CSHARP = "csharp"
    RUST = "rust"
    C_CPP = "c_cpp"
    UNKNOWN = "unknown"


# File extension → language mapping
_EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".rb": Language.RUBY,
    ".php": Language.PHP,
    ".cs": Language.CSHARP,
    ".rs": Language.RUST,
    ".c": Language.C_CPP,
    ".cpp": Language.C_CPP,
    ".h": Language.C_CPP,
    ".hpp": Language.C_CPP,
}

# Framework indicators (filename/pattern → framework)
_FRAMEWORK_INDICATORS: dict[str, str] = {
    "manage.py": "django",
    "settings.py": "django",
    "next.config.js": "nextjs",
    "next.config.ts": "nextjs",
    "nuxt.config.js": "nuxt",
    "nuxt.config.ts": "nuxt",
    "package.json": "node",
    "go.mod": "go-stdlib",
    "Gemfile": "rails",
    "pom.xml": "spring-boot",
    "build.gradle": "spring-boot",
    "Cargo.toml": "rust-actix-rocket",
    "composer.json": "laravel",
    ".csproj": "aspnet",
    "requirements.txt": "flask-fastapi",
    "pyproject.toml": "python-poetry",
}


@dataclass
class LanguageDetector:
    """Detects programming languages and frameworks from a repository."""

    repo_path: Path

    def detect(self) -> dict[str, Any]:
        """Detect languages and frameworks from the repository.

        Returns a dict with:
        - languages: dict mapping language to file count
        - primary_language: most common language
        - frameworks: list of detected frameworks
        - total_files: total scanned files
        """
        if not self.repo_path.exists():
            logger.warning("repo_path does not exist: %s", self.repo_path)
            return self._empty_result()

        language_counts: dict[Language, int] = {}
        detected_frameworks: list[str] = []

        for path in self._iter_source_files():
            ext = path.suffix.lower()
            lang = _EXTENSION_MAP.get(ext)
            if lang and lang != Language.UNKNOWN:
                language_counts[lang] = language_counts.get(lang, 0) + 1

            name = path.name
            if name in _FRAMEWORK_INDICATORS:
                fw = _FRAMEWORK_INDICATORS[name]
                if fw not in detected_frameworks:
                    detected_frameworks.append(fw)

        for indicator_name, framework in _FRAMEWORK_INDICATORS.items():
            if (self.repo_path / indicator_name).exists():
                if framework not in detected_frameworks:
                    detected_frameworks.append(framework)

        primary = max(language_counts, key=language_counts.get) if language_counts else Language.UNKNOWN
        total = sum(language_counts.values())

        return {
            "languages": {lang.value: count for lang, count in language_counts.items()},
            "primary_language": primary.value,
            "frameworks": detected_frameworks,
            "total_files": total,
        }

    def _iter_source_files(self) -> list[Path]:
        """Iterate over source files in the repository."""
        skip_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".next", ".nuxt", "target", "vendor",
            ".idea", ".vscode", "coverage", ".tox", "env",
        }
        files: list[Path] = []
        try:
            for path in self.repo_path.rglob("*"):
                if any(skip in path.parts for skip in skip_dirs):
                    continue
                if path.is_file() and path.suffix.lower() in _EXTENSION_MAP:
                    files.append(path)
                    if len(files) >= 5000:
                        logger.info("Source file limit reached (5000), truncating")
                        break
        except PermissionError:
            logger.warning("Permission error scanning %s", self.repo_path)
        return files

    def _empty_result(self) -> dict[str, Any]:
        return {
            "languages": {},
            "primary_language": "unknown",
            "frameworks": [],
            "total_files": 0,
        }


@dataclass
class TreeSitterParser:
    """AST-based sink/source identification with tree-sitter when available.

    Uses real tree-sitter parsing when the tree-sitter Python bindings and
    language grammars are installed. Falls back to regex pattern matching
    when tree-sitter is unavailable.
    """

    repo_path: Path

    _TREE_SITTER_AVAILABLE: ClassVar[bool | None] = None
    _TREE_SITTER_LANGUAGE_MAP: ClassVar[dict[str, str]] = {
        "python": "python",
        "javascript": "javascript",
        "typescript": "typescript",
        "java": "java",
        "go": "go",
        "ruby": "ruby",
        "php": "php",
        "c_cpp": "c",
        "csharp": "c_sharp",
        "rust": "rust",
    }

    @classmethod
    def _check_tree_sitter(cls) -> bool:
        if cls._TREE_SITTER_AVAILABLE is not None:
            return cls._TREE_SITTER_AVAILABLE
        try:
            import tree_sitter_python
            cls._TREE_SITTER_AVAILABLE = True
        except ImportError:
            cls._TREE_SITTER_AVAILABLE = False
        return cls._TREE_SITTER_AVAILABLE

    def _parse_with_tree_sitter(self, file_path: Path, language: str) -> list[dict[str, Any]] | None:
        """Parse a file with tree-sitter and return AST nodes of interest.

        Returns None if tree-sitter is not available or parsing fails.
        """
        if not self._check_tree_sitter():
            return None

        ts_lang_name = self._TREE_SITTER_LANGUAGE_MAP.get(language)
        if ts_lang_name is None:
            return None

        try:
            import tree_sitter

            lang_module_name = f"tree_sitter_{ts_lang_name.replace('_', '')}"
            lang_module = __import__(lang_module_name)
            lang = tree_sitter.Language(lang_module.language())

            parser = tree_sitter.Parser(lang)
            content = file_path.read_bytes()
            tree = parser.parse(content)
            root = tree.root_node

            sinks: list[dict[str, Any]] = []
            rel_path = str(file_path.relative_to(self.repo_path))

            def _walk(node: Any, depth: int = 0) -> None:
                if depth > 50 or len(sinks) >= 500:
                    return
                node_type = node.type
                if node_type in ("call_expression", "function_call", "method_invocation"):
                    text = node.text.decode("utf-8", errors="replace")[:300] if hasattr(node, 'text') else ""
                    for pattern, sink_type in [
                        (r"cursor\.execute|\.raw\(|\.query\(|executeQuery|createStatement|nativeQuery|sequelize\.query", "sql_query"),
                        (r"os\.system|subprocess\.(call|run|Popen)|os\.popen|child_process\.(exec|spawn)|exec\s*\(", "command_exec"),
                        (r"innerHTML|document\.write|dangerouslySetInnerHTML|render_template_string|Markup\s*\(", "html_render"),
                        (r"requests\.(get|post|put|delete|patch)|urllib\.request\.urlopen|httpx\.Client\.(get|post)|axios\.(get|post)|fetch\s*\(|got\s*\(", "http_request"),
                    ]:
                        import re
                        if re.search(pattern, text):
                            sinks.append({
                                "file_path": rel_path,
                                "line_number": node.start_point[0] + 1,
                                "sink_type": sink_type,
                                "code_snippet": text[:200],
                                "severity": "high" if sink_type in ("sql_query", "command_exec") else "medium",
                                "parser": "tree_sitter",
                            })
                            break
                for child in node.children:
                    _walk(child, depth + 1)

            _walk(root)
            return sinks if sinks else None
        except Exception as exc:
            logger.debug("tree_sitter_parse_failed", extra={"file": str(file_path), "error": str(exc)})
            return None

    # Sink patterns by language (class-level constants)
    SQL_SINK_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "python": [
            r"cursor\.execute\s*\(",
            r"\.raw\s*\(",
            r"text\s*\(",
            r"execute\s*\(",
        ],
        "javascript": [
            r"\.query\s*\(",
            r"\.raw\s*\(",
            r"sequelize\.query\s*\(",
        ],
        "java": [
            r"createStatement\s*\(",
            r"executeQuery\s*\(",
            r"nativeQuery\s*\(",
        ],
    }

    COMMAND_SINK_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "python": [
            r"os\.system\s*\(",
            r"subprocess\.(call|run|Popen)\s*\(",
            r"os\.popen\s*\(",
        ],
        "javascript": [
            r"child_process\.(exec|spawn|execSync)\s*\(",
            r"exec\s*\(",
        ],
    }

    XSS_SINK_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "python": [
            r"render_template_string\s*\(",
            r"Markup\s*\(",
            r"\.write\s*\(.*request",
        ],
        "javascript": [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"dangerouslySetInnerHTML",
        ],
    }

    SSRF_SINK_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "python": [
            r"requests\.(get|post|put|delete|patch)\s*\(",
            r"urllib\.request\.urlopen\s*\(",
            r"httpx\.Client\.(get|post)\s*\(",
        ],
        "javascript": [
            r"axios\.(get|post)\s*\(",
            r"fetch\s*\(",
            r"got\s*\(",
        ],
    }

    def find_sinks(self, language: str, files: list[Path] | None = None) -> list[dict[str, Any]]:
        """Find security-relevant sinks in source files.

        Uses tree-sitter AST parsing when available for precise node identification.
        Falls back to regex-based pattern matching when tree-sitter is not installed.
        """
        import re

        source_files = files or self._get_source_files(language)
        sinks: list[dict[str, Any]] = []

        if self._check_tree_sitter():
            for file_path in source_files[:200]:
                ts_result = self._parse_with_tree_sitter(file_path, language)
                if ts_result is not None:
                    sinks.extend(ts_result)
            if sinks:
                logger.info("tree_sitter_sinks_found", extra={"count": len(sinks), "language": language})
                return sinks[:500]

        patterns = {}
        for pattern_dict, sink_type in [
            (self.SQL_SINK_PATTERNS, "sql_query"),
            (self.COMMAND_SINK_PATTERNS, "command_exec"),
            (self.XSS_SINK_PATTERNS, "html_render"),
            (self.SSRF_SINK_PATTERNS, "http_request"),
        ]:
            lang_patterns = pattern_dict.get(language, [])
            for p in lang_patterns:
                patterns[p] = sink_type

        for file_path in source_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(self.repo_path))
            for line_no, line in enumerate(content.splitlines(), 1):
                for pattern, sink_type in patterns.items():
                    if re.search(pattern, line):
                        sinks.append({
                            "file_path": rel_path,
                            "line_number": line_no,
                            "sink_type": sink_type,
                            "code_snippet": line.strip()[:200],
                            "severity": "high" if sink_type in ("sql_query", "command_exec") else "medium",
                        })

        return sinks[:500]

    def _get_source_files(self, language: str) -> list[Path]:
        """Get source files for a given language."""
        ext_map = {
            "python": ".py",
            "javascript": ".js",
            "typescript": ".ts",
            "java": ".java",
            "go": ".go",
            "ruby": ".rb",
            "php": ".php",
        }
        ext = ext_map.get(language, ".py")
        files: list[Path] = []
        skip_dirs = {"node_modules", ".git", "__pycache__", "venv", "dist", "build", "vendor"}
        try:
            for path in self.repo_path.rglob(f"*{ext}"):
                if any(skip in path.parts for skip in skip_dirs):
                    continue
                if path.is_file():
                    files.append(path)
                    if len(files) >= 2000:
                        break
        except (PermissionError, OSError):
            pass
        return files