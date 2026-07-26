"""``_syntax_check_argv`` must never place finding-controlled data inside code.

The previous implementation built ``python -c "compile(open(r'<tmp>').read(),
'<file_path>', 'exec')"``. ``file_path`` originates from finding data, so a single
quote in it escaped the source literal and the remainder ran as Python in the
verification subprocess. These tests pin the argv-based contract instead.
"""

from __future__ import annotations

import sys

import pytest

from src.orchestration.auto_patch import _syntax_check_argv

_TARGET = "/tmp/argus_patch_x/app.py"


class TestCheckerSelection:
    def test_python_uses_py_compile_module(self) -> None:
        argv = _syntax_check_argv("src/app.py", _TARGET)

        assert argv == [sys.executable or "python", "-m", "py_compile", _TARGET]

    @pytest.mark.parametrize("source", ["src/app.js", "src/app.ts"])
    def test_javascript_passes_path_as_own_argument(self, source: str) -> None:
        argv = _syntax_check_argv(source, _TARGET)

        assert argv == ["node", "--check", _TARGET]

    @pytest.mark.parametrize("source", ["src/app.go", "README.md", "noext", ""])
    def test_unsupported_extension_has_no_checker(self, source: str) -> None:
        assert _syntax_check_argv(source, _TARGET) is None


class TestInjectionResistance:
    """Hostile ``file_path`` values must not become executable content."""

    @pytest.mark.parametrize(
        "hostile",
        [
            "a', 'exec'); __import__('os').system('touch /tmp/pwned'); #.py",
            'a", "exec"); print("pwned"); #.py',
            "app.py; rm -rf /",
            "$(whoami).py",
            "`id`.py",
            "app.py\n__import__('os').system('id')",
        ],
    )
    def test_hostile_path_never_reaches_an_argument(self, hostile: str) -> None:
        argv = _syntax_check_argv(hostile, _TARGET)

        # Either no checker applies, or the hostile string is absent entirely —
        # only the sanitized temp path is ever passed through.
        if argv is not None:
            assert hostile not in argv
            assert all(hostile not in part for part in argv)
            assert argv[-1] == _TARGET

    def test_no_inline_code_is_ever_generated(self) -> None:
        """``-c`` would mean "run this source"; the checker must not use it."""
        for source in ("src/app.py", "src/app.js", "src/app.ts"):
            argv = _syntax_check_argv(source, _TARGET)
            assert argv is not None
            assert "-c" not in argv
            assert not any("compile(" in part for part in argv)
            assert not any("open(" in part for part in argv)
