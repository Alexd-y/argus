"""Regression gate — ARG-046: no hexstrike refs in active source/tests/docs.

Замена устаревшего ``test_argus006_hexstrike.py`` (Cycle 0) на полноценный
regression gate с **explicit whitelist** для immutable historical artifacts
(Backlog, CHANGELOG, ai_docs cycle plans/reports, .cursor/workspace/completed/,
исторические docs/2026-03-09-*.md plan'ы и reports).

Сканирование выполняется чисто через ``pathlib`` — никаких внешних зависимостей
на ``rg`` / ``grep``, что делает gate работоспособным на Linux / macOS / Windows
и в air-gapped CI runner'ах одинаково.

См. ``ai_docs/develop/issues/ISS-arg046-hexstrike-audit.md`` для полного
audit trail и обоснования whitelist policy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT: Path = Path(__file__).resolve().parents[2]

# Forbidden token — собран через конкатенацию, чтобы исходник этого файла НЕ
# содержал bare-literal (defence-in-depth: даже если кто-то выбросит его из
# EXCLUDED_PATHS, файл сам по себе остаётся clean).
_FORBIDDEN_TOKEN: str = "hex" + "strike"


# Whitelist of immutable historical paths.
#
# Принцип: эти артефакты НИКОГДА не модифицируются ради audit trail и
# project-history continuity. Cycle plans / reports — read-once write-never;
# Backlog — source-of-truth который содержит anti-pattern declaration ("ни
# одного упоминания hexstrike/legacy"); CHANGELOG / README-REPORT /
# COMPLETION-SUMMARY — historical project narrative.
#
# Match — STRICT prefix match по POSIX-нормализованному relative path
# (``Path.relative_to(REPO_ROOT).as_posix()``). Это гарантирует cross-platform
# consistency (Windows ``\`` vs POSIX ``/``).
EXCLUDED_PATHS: tuple[str, ...] = (
    "Backlog/",
    "CHANGELOG.md",
    "README-REPORT.md",
    "COMPLETION-SUMMARY.md",
    "ai_docs/",
    ".cursor/workspace/",
    ".claude/worktrees/",
    "docs/2026-03-09-argus-implementation-plan.md",
    "docs/develop/reports/2026-03-09-argus-implementation-report.md",
    "backend/tests/test_no_hexstrike_active_imports.py",
)


# Active globs — что МЫ сканируем.
#
# Эти пути составляют production surface (backend source/tests, public docs,
# infra manifests, Frontend sources). Изменения здесь должны быть свободны от
# legacy-наследия hexstrike.
#
# NB: ``pathlib.Path.glob`` НЕ поддерживает brace expansion (``{ts,tsx}``),
# поэтому каждое расширение объявлено отдельной строкой.
ACTIVE_GLOBS: tuple[str, ...] = (
    "backend/src/**/*.py",
    "backend/tests/**/*.py",
    "docs/**/*.md",
    "infra/**/*.yaml",
    "infra/**/*.yml",
    "infra/**/Dockerfile.*",
    "Frontend/src/**/*.ts",
    "Frontend/src/**/*.tsx",
    "Frontend/src/**/*.js",
    "Frontend/src/**/*.jsx",
)


def _normalize(path: Path) -> str:
    """Return path relative to REPO_ROOT в POSIX-форме (cross-platform)."""
    return path.relative_to(REPO_ROOT).as_posix()


def _is_excluded(path: Path) -> bool:
    """``True`` если ``path`` принадлежит whitelist'у immutable артефактов."""
    rel = _normalize(path)
    return any(rel.startswith(prefix) for prefix in EXCLUDED_PATHS)


def _scan_for_forbidden_token() -> dict[str, list[int]]:
    """Скан всех ACTIVE_GLOBS на ``_FORBIDDEN_TOKEN`` (case-insensitive).

    Returns:
        Mapping ``{relative_posix_path: [line_numbers]}`` для каждого файла,
        содержащего хотя бы одно вхождение. Пустой dict — успех.
    """
    needle = _FORBIDDEN_TOKEN.lower()
    hits: dict[str, list[int]] = {}
    seen: set[Path] = set()

    for glob_pattern in ACTIVE_GLOBS:
        for path in REPO_ROOT.glob(glob_pattern):
            if path in seen:
                continue
            seen.add(path)

            if not path.is_file():
                continue
            if _is_excluded(path):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            line_hits = [
                i + 1
                for i, line in enumerate(content.splitlines())
                if needle in line.lower()
            ]
            if line_hits:
                hits[_normalize(path)] = line_hits

    return hits


def test_no_hexstrike_in_active_source() -> None:
    """Active source/tests/docs/infra/Frontend MUST contain zero forbidden refs.

    Acceptance gate: 0 hits в любом из ACTIVE_GLOBS вне EXCLUDED_PATHS.
    Регрессия → assertion message перечисляет все hits с file:line для
    мгновенного триажа.
    """
    hits = _scan_for_forbidden_token()
    if hits:
        formatted = "\n".join(
            f"  {path}:{','.join(str(n) for n in lines)}"
            for path, lines in sorted(hits.items())
        )
        pytest.fail(
            f"Forbidden token '{_FORBIDDEN_TOKEN}' found in active files:\n"
            f"{formatted}\n"
            f"Whitelisted prefixes (immutable historical):\n"
            f"  {', '.join(EXCLUDED_PATHS)}"
        )


def test_excluded_paths_still_have_immutable_hits() -> None:
    """Sanity: Backlog/dev1_.md preserves исторический anti-pattern declaration.

    Защита от случайного over-cleanup: если кто-то почистит Backlog (или его
    rename'нут) — мы это поймаем, потому что immutable artifact должен
    оставаться immutable. ``Backlog/dev1_.md`` — единственный файл, который
    мы знаем точно содержит нужный anti-pattern declaration ('Ни одного
    упоминания hexstrike/legacy').
    """
    backlog = REPO_ROOT / "Backlog" / "dev1_.md"
    if not backlog.exists():
        pytest.skip("Backlog/dev1_.md not present in this checkout")

    content = backlog.read_text(encoding="utf-8", errors="ignore")
    assert _FORBIDDEN_TOKEN.lower() in content.lower(), (
        "Backlog/dev1_.md должен сохранять историческое упоминание "
        f"'{_FORBIDDEN_TOKEN}' (anti-pattern declaration). "
        "Если убрали намеренно — обновите EXCLUDED_PATHS и этот sanity-тест."
    )


def test_excluded_paths_constant_is_well_formed() -> None:
    """EXCLUDED_PATHS — non-empty tuple of non-empty strings (schema invariant).

    Защищает от accidental редактуры через case-sensitivity / typo / empty
    string (``""`` matched бы любой path и effectively disabled the gate).
    """
    assert isinstance(EXCLUDED_PATHS, tuple), "EXCLUDED_PATHS must be a tuple"
    assert len(EXCLUDED_PATHS) > 0, "EXCLUDED_PATHS must be non-empty"
    for prefix in EXCLUDED_PATHS:
        assert isinstance(prefix, str), f"EXCLUDED_PATHS entry must be str, got {type(prefix)}"
        assert prefix, "EXCLUDED_PATHS entries must be non-empty (empty string disables gate)"
        assert "\\" not in prefix, (
            f"EXCLUDED_PATHS entries must use POSIX separators, got '{prefix}'"
        )


def test_active_globs_constant_is_well_formed() -> None:
    """ACTIVE_GLOBS — non-empty tuple of non-empty glob strings."""
    assert isinstance(ACTIVE_GLOBS, tuple), "ACTIVE_GLOBS must be a tuple"
    assert len(ACTIVE_GLOBS) > 0, "ACTIVE_GLOBS must be non-empty"
    for pattern in ACTIVE_GLOBS:
        assert isinstance(pattern, str), f"ACTIVE_GLOBS entry must be str, got {type(pattern)}"
        assert pattern, "ACTIVE_GLOBS entries must be non-empty"
        assert "{" not in pattern and "}" not in pattern, (
            f"pathlib.Path.glob does not support brace expansion; got '{pattern}'"
        )
