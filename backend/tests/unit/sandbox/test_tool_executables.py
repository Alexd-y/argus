"""Drift guard + structural checks for the sandbox executable manifest.

The committed ``infra/sandbox/expected_executables.json`` is the byte-for-byte
output of ``scripts/generate_tool_executables.py`` over the 162 signed tool
descriptors. ``infra/validate_tools.sh`` consumes it at image-build time to
fail the build when a required binary is missing from ``PATH``. These tests
guard three properties without needing Docker:

1. **No drift** — regenerating the manifest matches the committed file, so a
   YAML edit that changes a ``command_template`` executable cannot silently
   diverge from the build-time validator.
2. **Full coverage** — every catalog ``tool_id`` is represented by exactly one
   executable entry group.
3. **Sane classification** — real binaries are ``binary``; ARGUS launcher
   scripts are ``wrapper``; every executable is provisioned by ≥1 image.
"""

from __future__ import annotations

from scripts.generate_tool_executables import (
    _DEFAULT_OUTPUT,
    _DEFAULT_TOOLS_DIR,
    _load_descriptors,
    _render,
    build_executable_index,
)


def _index() -> dict:
    return build_executable_index(_load_descriptors(_DEFAULT_TOOLS_DIR))


def test_manifest_has_no_drift() -> None:
    rendered = _render(_index())
    committed = _DEFAULT_OUTPUT.read_text(encoding="utf-8")
    assert rendered == committed, (
        "infra/sandbox/expected_executables.json is stale — run "
        "`python -m scripts.generate_tool_executables` from backend/."
    )


def test_every_tool_is_represented_exactly_once() -> None:
    descriptors = _load_descriptors(_DEFAULT_TOOLS_DIR)
    manifest = build_executable_index(descriptors)

    tool_ids = {d.tool_id for d in descriptors}
    represented: list[str] = []
    for entry in manifest["executables"]:
        represented.extend(entry["tools"])

    assert sorted(represented) == sorted(tool_ids)
    assert manifest["total_tools"] == len(tool_ids)


def test_every_executable_has_kind_and_image() -> None:
    manifest = _index()
    for entry in manifest["executables"]:
        assert entry["kind"] in {"binary", "wrapper"}
        assert entry["images"], f"{entry['name']} has no image profile"
        assert entry["name"].strip() == entry["name"]


def test_wrapper_and_binary_classification() -> None:
    manifest = _index()
    by_name = {e["name"]: e["kind"] for e in manifest["executables"]}
    # Known ARGUS launcher scripts must be flagged as wrappers (non-fatal).
    for wrapper in ("waybackurls-wrapper", "xsstrike-runner"):
        if wrapper in by_name:
            assert by_name[wrapper] == "wrapper"
    # A ubiquitous real binary must be a hard-required binary.
    assert by_name.get("nmap") == "binary"


def test_counts_are_consistent() -> None:
    manifest = _index()
    binaries = [e for e in manifest["executables"] if e["kind"] == "binary"]
    wrappers = [e for e in manifest["executables"] if e["kind"] == "wrapper"]
    assert manifest["binary_count"] == len(binaries)
    assert manifest["wrapper_count"] == len(wrappers)
    assert manifest["total_executables"] == len(manifest["executables"])
