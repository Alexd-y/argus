"""T09 — offline unit tests for ``infra/scripts/sbom_drift_check``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_INFRA_SCRIPTS = _REPO_ROOT / "infra" / "scripts"
if str(_INFRA_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_INFRA_SCRIPTS))

import sbom_drift_check  # noqa: E402


def _minimal_cyclonedx(*components: dict[str, str]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": list(components),
    }


def _write_sbom(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_fingerprint_identical_components_same_hash_order_independent() -> None:
    a = _minimal_cyclonedx(
        {"type": "library", "name": "z", "version": "1", "purl": "pkg:a/z@1"},
        {"type": "library", "name": "a", "version": "2", "purl": "pkg:a/a@2"},
    )
    b = _minimal_cyclonedx(
        {"type": "library", "name": "a", "version": "2", "purl": "pkg:a/a@2"},
        {"type": "library", "name": "z", "version": "1", "purl": "pkg:a/z@1"},
    )
    fa, na = sbom_drift_check._fingerprint_sbom(a)
    fb, nb = sbom_drift_check._fingerprint_sbom(b)
    assert fa == fb
    assert na == nb == 2


def test_fingerprint_changed_component_list_different_hash() -> None:
    a = _minimal_cyclonedx(
        {"type": "library", "name": "lib", "version": "1.0.0", "purl": "pkg:deb/lib@1.0.0"},
    )
    b = _minimal_cyclonedx(
        {"type": "library", "name": "lib", "version": "1.0.1", "purl": "pkg:deb/lib@1.0.1"},
    )
    fa, _ = sbom_drift_check._fingerprint_sbom(a)
    fb, _ = sbom_drift_check._fingerprint_sbom(b)
    assert fa != fb


def test_fingerprint_non_list_components_empty_fingerprint() -> None:
    fp, count = sbom_drift_check._fingerprint_sbom({"components": "nope"})
    assert count == 0
    assert len(fp) == 64


def test_fingerprint_skips_non_dict_component_entries() -> None:
    doc = {"components": ["bad", {"type": "library", "name": "ok", "version": "", "purl": ""}]}
    _, count = sbom_drift_check._fingerprint_sbom(doc)
    assert count == 1


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: str,
    built: Path,
    baselines_dir: Path,
) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom_drift_check.py",
            "--profile",
            profile,
            "--built-sbom",
            str(built),
            "--baselines-dir",
            str(baselines_dir),
        ],
    )
    return sbom_drift_check.main()


def test_main_no_baseline_exits_zero_and_prints_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sbom_path = tmp_path / "built.json"
    doc = _minimal_cyclonedx(
        {"type": "library", "name": "curl", "version": "8", "purl": "pkg:deb/curl@8"},
    )
    _write_sbom(sbom_path, doc)
    baselines = tmp_path / "baselines"
    baselines.mkdir()

    rc = _run_main(monkeypatch, profile="web", built=sbom_path, baselines_dir=baselines)
    assert rc == 0
    out = capsys.readouterr().out
    assert "no baseline" in out
    assert "fingerprint_sha256=" in out
    fp, _ = sbom_drift_check._fingerprint_sbom(doc)
    assert fp in out
    assert "component_count=1" in out


def test_main_matching_baseline_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    doc = _minimal_cyclonedx(
        {"type": "library", "name": "curl", "version": "8", "purl": "pkg:deb/curl@8"},
    )
    fp, count = sbom_drift_check._fingerprint_sbom(doc)
    sbom_path = tmp_path / "built.json"
    _write_sbom(sbom_path, doc)
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    (baselines / "web.json").write_text(
        json.dumps({"fingerprint_sha256": fp, "component_count": count}),
        encoding="utf-8",
    )

    rc = _run_main(monkeypatch, profile="web", built=sbom_path, baselines_dir=baselines)
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK" in out
    assert "fingerprint matches" in out


def test_main_drift_exits_one_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    doc = _minimal_cyclonedx(
        {"type": "library", "name": "curl", "version": "8", "purl": "pkg:deb/curl@8"},
    )
    sbom_path = tmp_path / "built.json"
    _write_sbom(sbom_path, doc)
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    (baselines / "web.json").write_text(
        json.dumps({"fingerprint_sha256": "0" * 64, "component_count": 99}),
        encoding="utf-8",
    )

    rc = _run_main(monkeypatch, profile="web", built=sbom_path, baselines_dir=baselines)
    assert rc == 1
    err = capsys.readouterr().err
    assert "DRIFT" in err
    assert "0" * 64 in err or "baseline" in err


def test_main_invalid_built_sbom_json_exits_three(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{ not json", encoding="utf-8")
    baselines = tmp_path / "baselines"
    baselines.mkdir()

    rc = _run_main(monkeypatch, profile="web", built=p, baselines_dir=baselines)
    assert rc == 3
    assert "cannot read built SBOM" in capsys.readouterr().err


def test_main_missing_built_sbom_exits_three(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    missing = tmp_path / "nope.json"

    rc = _run_main(monkeypatch, profile="web", built=missing, baselines_dir=baselines)
    assert rc == 3
    assert "cannot read built SBOM" in capsys.readouterr().err


def test_main_built_sbom_root_not_object_exits_three(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    p = tmp_path / "arr.json"
    p.write_text("[1,2,3]", encoding="utf-8")
    baselines = tmp_path / "baselines"
    baselines.mkdir()

    rc = _run_main(monkeypatch, profile="web", built=p, baselines_dir=baselines)
    assert rc == 3
    assert "must be a JSON object" in capsys.readouterr().err


def test_main_invalid_baseline_json_exits_three(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    doc = _minimal_cyclonedx(
        {"type": "library", "name": "x", "version": "1", "purl": "pkg:x@1"},
    )
    sbom_path = tmp_path / "built.json"
    _write_sbom(sbom_path, doc)
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    (baselines / "web.json").write_text("{", encoding="utf-8")

    rc = _run_main(monkeypatch, profile="web", built=sbom_path, baselines_dir=baselines)
    assert rc == 3
    assert "cannot read baseline" in capsys.readouterr().err


def test_cli_requires_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sbom = tmp_path / "s.json"
    _write_sbom(sbom, _minimal_cyclonedx())
    monkeypatch.setattr(
        sys,
        "argv",
        ["sbom_drift_check.py", "--built-sbom", str(sbom)],
    )
    with pytest.raises(SystemExit) as exc:
        sbom_drift_check.main()
    assert exc.value.code == 2


def test_cli_requires_built_sbom(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["sbom_drift_check.py", "--profile", "web"],
    )
    with pytest.raises(SystemExit) as exc:
        sbom_drift_check.main()
    assert exc.value.code == 2


def test_main_profile_path_traversal_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sbom = tmp_path / "s.json"
    _write_sbom(sbom, _minimal_cyclonedx())
    baselines = tmp_path / "baselines"
    baselines.mkdir()

    rc = _run_main(monkeypatch, profile="../evil", built=sbom, baselines_dir=baselines)
    assert rc == 2
    err = capsys.readouterr().err
    assert "invalid --profile" in err
    assert "../evil" in err


def test_main_unknown_profile_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sbom = tmp_path / "s.json"
    _write_sbom(sbom, _minimal_cyclonedx())
    baselines = tmp_path / "baselines"
    baselines.mkdir()

    rc = _run_main(monkeypatch, profile="prod", built=sbom, baselines_dir=baselines)
    assert rc == 2
    err = capsys.readouterr().err
    assert "invalid --profile" in err
    assert "prod" in err


def test_cli_custom_baselines_dir_used_for_profile_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Baseline is ``<baselines-dir>/<profile>.json`` (no separate --baseline flag)."""
    doc = _minimal_cyclonedx(
        {"type": "library", "name": "z", "version": "1", "purl": "pkg:z@1"},
    )
    fp, count = sbom_drift_check._fingerprint_sbom(doc)
    sbom_path = tmp_path / "in" / "sbom.json"
    sbom_path.parent.mkdir(parents=True)
    _write_sbom(sbom_path, doc)
    alt = tmp_path / "custom-baselines"
    alt.mkdir()
    (alt / "cloud.json").write_text(
        json.dumps({"fingerprint_sha256": fp, "component_count": count}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom_drift_check.py",
            "--profile",
            "cloud",
            "--built-sbom",
            str(sbom_path),
            "--baselines-dir",
            str(alt),
        ],
    )
    assert sbom_drift_check.main() == 0
    out = capsys.readouterr().out
    assert "OK" in out


def test_main_oserror_on_read_built_sbom(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Graceful message when read_text raises OSError (simulated)."""
    p = tmp_path / "sbom.json"
    p.write_text("{}", encoding="utf-8")
    baselines = tmp_path / "b"
    baselines.mkdir()

    _orig_read = Path.read_text

    def selective_read(self: Path, *args: object, **kwargs: object) -> str:
        if self.resolve() == p.resolve():
            raise OSError("permission denied")
        return _orig_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", selective_read)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom_drift_check.py",
            "--profile",
            "web",
            "--built-sbom",
            str(p),
            "--baselines-dir",
            str(baselines),
        ],
    )
    rc = sbom_drift_check.main()
    assert rc == 3
    assert "cannot read built SBOM" in capsys.readouterr().err
