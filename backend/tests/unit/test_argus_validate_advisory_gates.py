"""T08 — offline unit tests for advisory SCA/SAST gates in ``scripts/argus_validate``.

Covers ``--only-advisory`` gate selection, :class:`Gate` fields (including
``requires_python_module``), and ``run_npm_audit_gate`` without invoking real
npm, trivy, bandit, or pip-audit.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import argus_validate  # noqa: E402
import run_npm_audit_gate  # noqa: E402

_EXPECTED_ADVISORY_ORDER: tuple[str, ...] = (
    "helm_kubeconform",
    "pip_audit",
    "npm_audit",
    "trivy_fs",
    "bandit",
)


def _registry() -> tuple[argus_validate.Gate, ...]:
    return argus_validate._build_gate_registry()


def test_only_advisory_selects_exactly_advisory_sca_gates_in_order() -> None:
    gates = _registry()
    selected = argus_validate._select_gates(gates, skip=[], only=None, only_advisory=True)
    names = tuple(g.name for g in selected)
    assert names == _EXPECTED_ADVISORY_ORDER
    assert frozenset(names) == argus_validate._ADVISORY_SCA_GATE_NAMES


def test_only_advisory_excludes_other_optional_gates() -> None:
    """Optional but non-T08 gates (e.g. mypy_capstone) must not appear."""
    gates = _registry()
    selected = argus_validate._select_gates(gates, skip=[], only=None, only_advisory=True)
    selected_names = {g.name for g in selected}
    assert "mypy_capstone" not in selected_names
    assert "ruff_backend_full" not in selected_names
    assert "backend_tests" not in selected_names


def test_only_advisory_mutually_exclusive_with_skip_gate() -> None:
    gates = _registry()
    with pytest.raises(SystemExit, match="mutually exclusive"):
        argus_validate._select_gates(
            gates,
            skip=["pip_audit"],
            only=None,
            only_advisory=True,
        )


def test_only_advisory_mutually_exclusive_with_only_gate() -> None:
    gates = _registry()
    with pytest.raises(SystemExit, match="mutually exclusive"):
        argus_validate._select_gates(
            gates,
            skip=[],
            only="pip_audit",
            only_advisory=True,
        )


def test_pip_audit_gate_parses_requires_python_module() -> None:
    pip = next(g for g in _registry() if g.name == "pip_audit")
    assert pip.requires_python_module == "pip_audit"
    assert pip.required is False
    assert pip.argv[:4] == (argus_validate._python_exe(), "-m", "pip_audit", "--strict")


def test_npm_audit_gate_argv_uses_run_npm_audit_helper() -> None:
    npm = next(g for g in _registry() if g.name == "npm_audit")
    assert npm.argv[0] == argus_validate._python_exe()
    assert npm.argv[1] == str(_REPO_ROOT / "scripts" / "run_npm_audit_gate.py")
    assert npm.requires_binary == "npm"
    assert npm.required is False


def test_trivy_fs_gate_argv_includes_skip_dirs_and_scanners() -> None:
    trivy = next(g for g in _registry() if g.name == "trivy_fs")
    argv = list(trivy.argv)
    assert argv[0] == "trivy"
    assert "--scanners" in argv
    idx = argv.index("--scanners")
    assert argv[idx + 1] == "vuln,secret,license"
    for skip_dir in argus_validate._TRIVY_FS_SKIP_DIRS:
        assert "--skip-dirs" in argv
        assert skip_dir in argv


def test_resolve_skip_reason_python_module_missing() -> None:
    pip = next(g for g in _registry() if g.name == "pip_audit")
    with patch.object(argus_validate.importlib.util, "find_spec", return_value=None):
        reason = argus_validate._resolve_skip_reason(pip)
    assert reason is not None
    assert "pip_audit" in reason
    assert "not installed" in reason


def test_run_npm_audit_gate_no_projects_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(run_npm_audit_gate, "_REPO_ROOT", tmp_path)
    for rel in run_npm_audit_gate._NODE_PROJECT_DIRS:
        (tmp_path / rel).mkdir(parents=True, exist_ok=True)

    rc = run_npm_audit_gate.main()
    assert rc == 0
    err = capsys.readouterr().err
    assert "no package.json" in err


def test_run_npm_audit_gate_success_all_projects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(run_npm_audit_gate, "_REPO_ROOT", tmp_path)
    fe = tmp_path / "Frontend"
    fe.mkdir(parents=True, exist_ok=True)
    (fe / "package.json").write_text("{}", encoding="utf-8")

    mock_run = MagicMock(return_value=MagicMock(returncode=0))
    monkeypatch.setattr(run_npm_audit_gate.subprocess, "run", mock_run)

    assert run_npm_audit_gate.main() == 0
    mock_run.assert_called_once()
    call_kw = mock_run.call_args.kwargs
    assert call_kw["cwd"] == fe
    assert call_kw["shell"] is False
    argv0 = mock_run.call_args.args[0]
    assert argv0[:3] == ["npm", "audit", "--audit-level=high"]
    assert "--json" in argv0


def test_run_npm_audit_gate_worst_exit_code_across_projects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(run_npm_audit_gate, "_REPO_ROOT", tmp_path)
    for name in ("Frontend", "admin-frontend"):
        p = tmp_path / name
        p.mkdir(parents=True, exist_ok=True)
        (p / "package.json").write_text("{}", encoding="utf-8")

    outcomes = iter([MagicMock(returncode=0), MagicMock(returncode=1)])

    def _next_run(*_a: object, **_k: object) -> MagicMock:
        return next(outcomes)

    monkeypatch.setattr(run_npm_audit_gate.subprocess, "run", _next_run)

    assert run_npm_audit_gate.main() == 1


def test_main_only_advisory_invokes_five_gates_with_mocked_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    def fake_run_gate(
        gate: argus_validate.Gate,
        logs_dir: Path,
        timeout_mult: float,
        logger: object,
    ) -> argus_validate.GateResult:
        captured.append(gate.name)
        log_path = logs_dir / f"{gate.name}.log"
        log_path.write_text("ok\n", encoding="utf-8")
        return argus_validate.GateResult(
            name=gate.name,
            status=argus_validate._STATUS_PASSED,
            required=gate.required,
            duration_seconds=0.0,
            exit_code=0,
            log_path=str(log_path),
        )

    monkeypatch.setattr(argus_validate, "_run_gate", fake_run_gate)
    out = tmp_path / "summary.json"
    logs = tmp_path / "logs"
    rc = argus_validate.main(
        [
            "--only-advisory",
            "--output",
            str(out),
            "--logs-dir",
            str(logs),
            "--log-level",
            "ERROR",
        ]
    )
    assert rc == 0
    assert captured == list(_EXPECTED_ADVISORY_ORDER)
    assert out.is_file()
