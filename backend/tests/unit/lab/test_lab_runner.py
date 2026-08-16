"""LAB runner executes scripts for real and never uses production sandbox."""

from __future__ import annotations

from src.lab.runner import (
    _PRODUCTION_SANDBOX_FORBIDDEN,
    IsolatedLabRunner,
    LabRunRequest,
)
from src.nuclei.profile_compiler import NucleiProfileCompiler


def test_python_script_executes_locally() -> None:
    result = IsolatedLabRunner().execute(
        LabRunRequest(language="python", source="print('lab-ok')")
    )
    assert result.status == "completed"
    assert result.return_code == 0
    assert result.runner == "local"
    assert "lab-ok" in result.stdout


def test_command_argv_executes_locally() -> None:
    result = IsolatedLabRunner().execute(
        LabRunRequest(language="python", argv=("python3", "-c", "print(7)"))
    )
    assert result.status == "completed"
    assert "7" in result.stdout


def test_production_sandbox_name_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(
        "src.lab.runner.settings.lab_runner_container_name",
        _PRODUCTION_SANDBOX_FORBIDDEN,
    )
    result = IsolatedLabRunner().execute(
        LabRunRequest(language="python", source="print(1)")
    )
    assert result.error_code == "lab_runner_must_not_be_production_sandbox"
    assert result.status == "failed"


def test_namespace_mismatch_refuses_docker_path(monkeypatch) -> None:
    monkeypatch.setattr("src.lab.runner.lab_runner_container_running", lambda _c: True)
    monkeypatch.setattr("src.lab.runner.read_lab_namespace", lambda _c: "other-ns")
    result = IsolatedLabRunner().execute(
        LabRunRequest(
            language="python",
            source="print(1)",
            k8s_namespace="argus-lab",
        )
    )
    assert result.error_code == "lab_namespace_mismatch"
    assert result.status == "failed"


def test_nuclei_lab_compile_enables_code_js_headless() -> None:
    argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        "lab_unrestricted",
        "https://example.com/",
        templates=["/tmp/t.yaml"],
        allow_code=True,
        allow_headless=True,
        allow_javascript=True,
    )
    assert argv[0] == "nuclei"
    assert "-code" in argv
    assert "-headless" in argv
    assert "-enable-javascript" in argv
    assert "-ni" not in argv
    assert "-rate-limit" not in argv


def test_nuclei_yaml_run_records_compiler_argv() -> None:
    result = IsolatedLabRunner().execute(
        LabRunRequest(
            language="nuclei",
            yaml_content="id: t1\ninfo:\n  name: demo\n",
            target_url="https://example.com/",
        )
    )
    assert result.argv
    assert result.argv[0] == "nuclei"
    assert "-code" in result.argv
    assert "-headless" in result.argv
    assert "-enable-javascript" in result.argv
    assert result.runner == "local"
    assert result.status in {"completed", "failed"}
