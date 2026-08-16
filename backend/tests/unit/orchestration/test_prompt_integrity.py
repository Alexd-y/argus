"""Tests for the runtime prompt-template integrity gate (F-M04).

Covers three layers:

* the pure manifest helpers in :mod:`src.orchestration.prompt_integrity`,
* the opt-in / fail-closed wiring in :class:`PromptLoader`, and
* a drift-guard that keeps the committed ``MANIFEST.sha256`` in sync with the
  real templates shipped under ``src/orchestration/prompts/``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.orchestration.prompt_integrity import (
    PromptIntegrityError,
    compute_manifest,
    diff_manifest,
    load_manifest,
    manifest_path,
    parse_manifest,
    render_manifest,
    verify_templates,
    write_manifest,
)
from src.orchestration.prompt_loader import PromptLoader

_REPO_PROMPTS_DIR = Path(__file__).resolve().parents[3] / "src" / "orchestration" / "prompts"


def _make_prompts_dir(tmp_path: Path) -> Path:
    prompts = tmp_path / "prompts"
    (prompts / "phases").mkdir(parents=True)
    (prompts / "system_base.j2").write_text("base {{ x }}\n", encoding="utf-8")
    (prompts / "phases" / "recon_system.j2").write_text("recon\n", encoding="utf-8")
    return prompts


class TestManifestHelpers:
    def test_compute_and_roundtrip_render_parse(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        entries = compute_manifest(prompts)
        assert set(entries) == {"system_base.j2", "phases/recon_system.j2"}
        assert all(len(sha) == 64 for sha in entries.values())

        reparsed = parse_manifest(render_manifest(entries))
        assert reparsed == entries

    def test_write_and_load_roundtrip(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        path = write_manifest(prompts)
        assert path == manifest_path(prompts)
        assert load_manifest(prompts) == compute_manifest(prompts)

    def test_verify_passes_after_write(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        write_manifest(prompts)
        verify_templates(prompts)  # no raise

    def test_verify_detects_mismatch(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        write_manifest(prompts)
        (prompts / "system_base.j2").write_text("tampered\n", encoding="utf-8")
        with pytest.raises(PromptIntegrityError, match="mismatched"):
            verify_templates(prompts)

    def test_verify_detects_extra_template(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        write_manifest(prompts)
        (prompts / "phases" / "new_user.j2").write_text("new\n", encoding="utf-8")
        with pytest.raises(PromptIntegrityError, match="extra"):
            verify_templates(prompts)

    def test_verify_detects_missing_template(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        write_manifest(prompts)
        (prompts / "phases" / "recon_system.j2").unlink()
        with pytest.raises(PromptIntegrityError, match="missing"):
            verify_templates(prompts)

    def test_load_missing_manifest_fails_closed(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        with pytest.raises(PromptIntegrityError, match="missing"):
            load_manifest(prompts)

    def test_parse_rejects_malformed_line(self) -> None:
        with pytest.raises(PromptIntegrityError, match="malformed manifest line"):
            parse_manifest("deadbeef\n")

    def test_parse_rejects_bad_digest_length(self) -> None:
        with pytest.raises(PromptIntegrityError, match="malformed sha256"):
            parse_manifest("abc  system_base.j2\n")

    def test_parse_ignores_comments_and_blanks(self) -> None:
        text = "# comment\n\n" + "a" * 64 + "  system_base.j2\n"
        assert parse_manifest(text) == {"system_base.j2": "a" * 64}

    def test_diff_manifest_partitions_changes(self) -> None:
        expected = {"a.j2": "1" * 64, "b.j2": "2" * 64}
        actual = {"a.j2": "9" * 64, "c.j2": "3" * 64}
        missing, extra, mismatched = diff_manifest(expected, actual)
        assert missing == ["b.j2"]
        assert extra == ["c.j2"]
        assert mismatched == ["a.j2"]


class TestPromptLoaderIntegrityGate:
    def test_default_off_skips_verification(self, tmp_path: Path) -> None:
        # No manifest present, but integrity is off by default → must not raise.
        prompts = _make_prompts_dir(tmp_path)
        loader = PromptLoader(prompts_dir=prompts, enforce_integrity=False)
        assert loader.available is True

    def test_enforce_true_passes_with_valid_manifest(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        write_manifest(prompts)
        loader = PromptLoader(prompts_dir=prompts, enforce_integrity=True)
        assert loader.available is True

    def test_enforce_true_fails_closed_on_drift(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        write_manifest(prompts)
        (prompts / "system_base.j2").write_text("tampered\n", encoding="utf-8")
        with pytest.raises(PromptIntegrityError):
            PromptLoader(prompts_dir=prompts, enforce_integrity=True)

    def test_enforce_true_fails_closed_when_manifest_missing(self, tmp_path: Path) -> None:
        prompts = _make_prompts_dir(tmp_path)
        with pytest.raises(PromptIntegrityError, match="missing"):
            PromptLoader(prompts_dir=prompts, enforce_integrity=True)

    def test_explicit_flag_overrides_settings(self, tmp_path: Path, monkeypatch) -> None:
        # settings says "on", but the explicit False must win (no manifest → would raise).
        monkeypatch.setattr(
            "src.orchestration.prompt_loader.settings.prompt_integrity_enabled",
            True,
            raising=False,
        )
        prompts = _make_prompts_dir(tmp_path)
        loader = PromptLoader(prompts_dir=prompts, enforce_integrity=False)
        assert loader.available is True

    def test_settings_flag_drives_default(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "src.orchestration.prompt_loader.settings.prompt_integrity_enabled",
            True,
            raising=False,
        )
        prompts = _make_prompts_dir(tmp_path)  # no manifest
        with pytest.raises(PromptIntegrityError, match="missing"):
            PromptLoader(prompts_dir=prompts)


class TestCommittedManifestDriftGuard:
    """The committed manifest must always match the real templates in the repo."""

    def test_repo_manifest_is_in_sync(self) -> None:
        assert _REPO_PROMPTS_DIR.is_dir(), _REPO_PROMPTS_DIR
        # Raises PromptIntegrityError if someone edited a template without
        # re-running ``scripts/prompt_templates_manifest.py generate``.
        verify_templates(_REPO_PROMPTS_DIR)
