"""Presence + structural guard for the sandbox tool-wrapper scripts.

Tools whose catalog ``command_template[0]`` is a launcher script (``kind: wrapper``
in ``infra/sandbox/expected_executables.json``) require a real script on ``PATH``
inside the sandbox image, otherwise the tool run fails with "command not found".
These scripts live in ``sandbox/images/_shared/wrappers/`` and are ``COPY``d into
the relevant Kali images at ``/usr/local/bin/``.

This test guards — without Docker — that:

1. **Manifest ↔ files are in sync** — every ``wrapper`` in the manifest has a
   matching script file and there are no orphan scripts.
2. **Each wrapper is structurally sound** — non-empty, ``#!`` shebang for a POSIX
   shell (or node), and creates its output directory (the fail-safe artifact
   discipline every wrapper follows so the parse strategy never faults).

Runtime behaviour of the wrapped tools remains an image-build/live boundary.
"""

from __future__ import annotations

from scripts.generate_tool_executables import (
    _DEFAULT_TOOLS_DIR,
    _REPO_ROOT,
    _load_descriptors,
    build_executable_index,
)

_WRAPPERS_DIR = _REPO_ROOT / "sandbox" / "images" / "_shared" / "wrappers"


def _manifest_wrapper_names() -> set[str]:
    manifest = build_executable_index(_load_descriptors(_DEFAULT_TOOLS_DIR))
    return {e["name"] for e in manifest["executables"] if e["kind"] == "wrapper"}


def test_wrappers_dir_exists() -> None:
    assert _WRAPPERS_DIR.is_dir(), f"missing wrappers dir: {_WRAPPERS_DIR}"


def test_every_manifest_wrapper_has_a_script() -> None:
    missing = sorted(
        name for name in _manifest_wrapper_names() if not (_WRAPPERS_DIR / name).is_file()
    )
    assert not missing, f"wrapper scripts missing for: {missing}"


def test_no_orphan_wrapper_scripts() -> None:
    on_disk = {p.name for p in _WRAPPERS_DIR.iterdir() if p.is_file()}
    manifest = _manifest_wrapper_names()
    orphans = sorted(on_disk - manifest)
    assert not orphans, f"wrapper scripts with no manifest entry: {orphans}"


def test_wrappers_are_structurally_sound() -> None:
    for name in sorted(_manifest_wrapper_names()):
        path = _WRAPPERS_DIR / name
        text = path.read_text(encoding="utf-8")
        assert text.strip(), f"{name} is empty"
        first_line = text.splitlines()[0]
        assert first_line.startswith("#!"), f"{name} lacks a shebang"
        assert any(
            sh in first_line for sh in ("bash", "sh", "node", "env")
        ), f"{name} shebang is not a recognized interpreter: {first_line!r}"
        # Fail-safe artifact discipline: every wrapper provisions its output dir.
        assert "mkdir -p" in text, f"{name} does not create its output directory"


def test_expected_wrapper_set() -> None:
    # The 11 wrappers the catalog declares today; keeps the manifest and the
    # shipped scripts anchored to a known set (update deliberately when adding tools).
    expected = {
        "hakrawler-wrapper",
        "waybackurls-wrapper",
        "subjs-wrapper",
        "linkfinder-wrapper",
        "kxss-runner",
        "secretfinder-wrapper",
        "xsstrike-runner",
        "tplmap-runner",
        "nosqlmap-runner",
        "jsql-cli",
        "playwright-verify-xss",
    }
    assert _manifest_wrapper_names() == expected
