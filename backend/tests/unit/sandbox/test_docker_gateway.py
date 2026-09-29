"""F-H01 Stage 3 — unit tests for the Docker access gateway."""

from __future__ import annotations

import subprocess

import pytest
from pydantic import ValidationError
from src.core.config import Settings
from src.sandbox import docker_gateway
from src.sandbox.docker_gateway import (
    DockerGatewayError,
    ExecResult,
    build_exec_argv,
    exec_in_sync,
)


class TestBuildExecArgv:
    def test_basic(self) -> None:
        assert build_exec_argv("argus-sandbox", ["nuclei", "-version"]) == [
            "docker",
            "exec",
            "argus-sandbox",
            "nuclei",
            "-version",
        ]

    def test_workdir_and_env(self) -> None:
        argv = build_exec_argv(
            "argus-sandbox",
            ["ls"],
            workdir="/tmp/x",
            env={"FOO": "bar"},
        )
        assert argv == [
            "docker",
            "exec",
            "-w",
            "/tmp/x",
            "-e",
            "FOO=bar",
            "argus-sandbox",
            "ls",
        ]

    @pytest.mark.parametrize(
        "bad",
        ["", "bad name", "with;semi", "$(inject)", "a" * 65, "-leadingdash"],
    )
    def test_rejects_bad_container_names(self, bad: str) -> None:
        with pytest.raises(DockerGatewayError):
            build_exec_argv(bad, ["ls"])

    @pytest.mark.parametrize("bad_argv", [[], "sh -c 'x'", ["ok", 1]])
    def test_rejects_non_list_or_empty_argv(self, bad_argv) -> None:  # noqa: ANN001
        with pytest.raises(DockerGatewayError):
            build_exec_argv("argus-sandbox", bad_argv)  # type: ignore[arg-type]


class TestExecInSync:
    def test_runs_via_subprocess_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict = {}

        class _Proc:
            returncode = 0
            stdout = "hello"
            stderr = ""

        def _fake_run(argv, **kwargs):  # noqa: ANN001
            captured["argv"] = argv
            captured["shell"] = kwargs.get("shell")
            captured["timeout"] = kwargs.get("timeout")
            return _Proc()

        monkeypatch.setattr(docker_gateway.subprocess, "run", _fake_run)
        monkeypatch.setattr(docker_gateway.settings, "docker_transport", "socket", raising=False)

        result = exec_in_sync("argus-sandbox", ["id"], timeout=5.0)

        assert isinstance(result, ExecResult)
        assert result.success and result.stdout == "hello"
        assert captured["argv"] == ["docker", "exec", "argus-sandbox", "id"]
        assert captured["shell"] is False
        assert captured["timeout"] == 5.0

    def test_timeout_returns_failed_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _timeout(argv, **kwargs):  # noqa: ANN001
            raise subprocess.TimeoutExpired(cmd=argv, timeout=1.0)

        monkeypatch.setattr(docker_gateway.subprocess, "run", _timeout)
        monkeypatch.setattr(docker_gateway.settings, "docker_transport", "socket", raising=False)

        result = exec_in_sync("argus-sandbox", ["sleep", "10"], timeout=1.0)
        assert not result.success
        assert result.exit_code == -1
        assert "timed out" in result.stderr.lower()

    def test_broker_transport_posts_to_broker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict = {}

        class _Resp:
            status_code = 200

            @staticmethod
            def json() -> dict:
                return {"exit_code": 0, "stdout": "broker-out", "stderr": "", "duration_s": 0.02}

        def _fake_post(url, json, timeout):  # noqa: ANN001, A002
            captured["url"] = url
            captured["json"] = json
            return _Resp()

        monkeypatch.setattr(docker_gateway.settings, "docker_transport", "broker", raising=False)
        monkeypatch.setattr(
            docker_gateway.settings, "exec_broker_url", "http://broker:8080", raising=False
        )
        monkeypatch.setattr(docker_gateway.httpx, "post", _fake_post)

        result = exec_in_sync("argus-sandbox", ["nuclei", "-version"], timeout=5.0)
        assert result.success and result.stdout == "broker-out"
        assert captured["url"] == "http://broker:8080/v1/exec"
        assert captured["json"]["container"] == "argus-sandbox"
        assert captured["json"]["argv"] == ["nuclei", "-version"]

    def test_proxy_transport_sets_docker_host_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict = {}

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(argv, **kwargs):  # noqa: ANN001
            captured["env"] = kwargs.get("env")
            return _Proc()

        monkeypatch.setattr(docker_gateway.subprocess, "run", _fake_run)
        monkeypatch.setattr(docker_gateway.settings, "docker_transport", "proxy", raising=False)
        monkeypatch.setattr(
            docker_gateway.settings, "docker_host", "tcp://docker-socket-proxy:2375", raising=False
        )

        exec_in_sync("argus-sandbox", ["id"], timeout=5.0)
        assert captured["env"]["DOCKER_HOST"] == "tcp://docker-socket-proxy:2375"


class TestContainerNameValidator:
    """F-H01 Stage 3: Settings must reject a malformed container name at load."""

    def test_valid_default(self) -> None:
        s = Settings(sandbox_container_name="argus-sandbox")
        assert s.sandbox_container_name == "argus-sandbox"

    @pytest.mark.parametrize(
        "bad", ["bad name", "with;semi", "$(x)", "a/b", "-lead", "a" * 65]
    )
    def test_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            Settings(sandbox_container_name=bad)
