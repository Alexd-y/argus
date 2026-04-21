"""ARG-038 — regression gate: signed catalog must remain immutable during pytest.

Companion to the session-scope ``read_only_catalog`` fixture in
``backend/tests/conftest.py``. The fixture chmods every YAML descriptor and
``SIGNATURES`` manifest under ``backend/config/{tools,payloads,prompts}/``
to read-only at session start. These tests verify that:

1. The chmod is actually in effect (mode bits) for a representative file
   in each catalog dir — catches regressions where the fixture stops running
   (e.g. someone removes ``autouse=True`` or refactors the path-resolution).
2. ``tools_sign verify`` / ``payloads_sign verify`` / ``prompts_sign verify``
   all exit 0 — i.e. the catalogs are still cryptographically valid after
   thousands of tests have read them.

If any of the five cases (1 chmod check + 1 dirs-populated sanity + 3
parametrized sign-CLI verifies) fail, a misbehaving test bypassed the
fixture or the fixture itself broke. Open
``ai_docs/develop/issues/ISS-apktool-drift-rootcause.md`` for historical
context on the original Cycle 3 drift symptom.
"""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest


_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
_CATALOG_DIRS: Final[tuple[Path, ...]] = (
    _BACKEND_ROOT / "config" / "tools",
    _BACKEND_ROOT / "config" / "payloads",
    _BACKEND_ROOT / "config" / "prompts",
)


def _expected_protected_files(catalog_dir: Path) -> list[Path]:
    """Return every file the fixture is supposed to lock down."""
    if not catalog_dir.is_dir():
        return []
    protected: list[Path] = []
    for entry in catalog_dir.iterdir():
        if not entry.is_file():
            continue
        if entry.suffix in {".yaml", ".yml"} or entry.name == "SIGNATURES":
            protected.append(entry)
    return sorted(protected)


def test_signed_catalog_is_read_only_during_pytest_session() -> None:
    """The session-scope ``read_only_catalog`` fixture must keep every file
    in ``config/{tools,payloads,prompts}/`` chmodded read-only.

    On POSIX we check that the owner-write bit (``stat.S_IWUSR``) is unset.
    On Windows ``Path.chmod`` only honours the read-only attribute, which
    Python exposes by clearing ``stat.S_IWRITE`` (== ``stat.S_IWUSR == 0o200``)
    in the resulting mode. The single-bit check works portably.
    """
    writable_files: list[str] = []
    for catalog_dir in _CATALOG_DIRS:
        for path in _expected_protected_files(catalog_dir):
            mode = path.stat().st_mode
            if mode & stat.S_IWUSR:
                writable_files.append(f"{path} (mode={oct(mode & 0o777)})")
    assert not writable_files, (
        "read_only_catalog fixture failed to chmod the following ground-truth files "
        "to read-only — a misbehaving test or fixture has restored write permission: "
        + "; ".join(writable_files)
    )


def test_signed_catalog_dirs_are_populated() -> None:
    """Sanity check: the protected directory set is non-empty on every
    catalog. Catches accidental cleanup of the production catalog before
    the chmod check above silently succeeds with zero files.
    """
    empty_dirs: list[str] = []
    for catalog_dir in _CATALOG_DIRS:
        if not _expected_protected_files(catalog_dir):
            empty_dirs.append(str(catalog_dir))
    assert not empty_dirs, (
        f"signed catalog dir(s) unexpectedly empty: {empty_dirs}. "
        "The read_only_catalog fixture relies on every catalog containing at "
        "least one *.yaml + SIGNATURES file."
    )


def _run_verify(
    module_name: str, dir_arg: str, dir_name: str
) -> subprocess.CompletedProcess[str]:
    """Invoke ``python -m scripts.<module_name> verify`` against the production catalog."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            f"scripts.{module_name}",
            "verify",
            dir_arg,
            f"config/{dir_name}",
            "--signatures",
            f"config/{dir_name}/SIGNATURES",
            "--keys-dir",
            f"config/{dir_name}/_keys",
        ],
        capture_output=True,
        text=True,
        cwd=_BACKEND_ROOT,
        check=False,
    )


@pytest.mark.parametrize(
    ("module_name", "dir_arg", "dir_name"),
    [
        ("tools_sign", "--tools-dir", "tools"),
        ("payloads_sign", "--payloads-dir", "payloads"),
        ("prompts_sign", "--prompts-dir", "prompts"),
    ],
    ids=["tools", "payloads", "prompts"],
)
def test_signed_catalog_verifies_after_pytest(
    module_name: str, dir_arg: str, dir_name: str
) -> None:
    """End-to-end check: each ``*_sign verify`` CLI must exit 0 against the
    production catalog. If a test mutated a YAML or SIGNATURES file, the
    Ed25519 signature mismatch surfaces here as a non-zero exit code.

    Combined with ``test_signed_catalog_is_read_only_during_pytest_session``,
    this gives both the *defensive* (chmod) and the *cryptographic* (signature)
    proof that the catalog was untouched by the test suite.
    """
    result = _run_verify(module_name, dir_arg, dir_name)
    assert result.returncode == 0, (
        f"`python -m scripts.{module_name} verify` failed with exit {result.returncode}; "
        f"this indicates the {dir_name} catalog drifted during the pytest session.\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
