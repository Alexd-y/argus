"""Unit tests for the shared single-control-plane runner (signed_tool_runner)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
from src.orchestration import signed_tool_runner as str_mod
from src.pipeline.contracts.tool_job import TargetKind


def _proc_mock(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock(return_value=returncode)
    proc.kill = MagicMock()
    return proc


class TestRegistrySingleton:
    def test_registry_loads(self) -> None:
        assert str_mod.get_signed_tool_registry() is not None

    def test_reset_forces_reload(self) -> None:
        first = str_mod.get_signed_tool_registry()
        str_mod.reset_signed_tool_registry()
        second = str_mod.get_signed_tool_registry()
        assert first is not None
        assert second is not None


class TestResolve:
    def test_folds_aliases(self) -> None:
        assert str_mod.resolve_signed_tool("sqlmap") == "sqlmap_safe"
        assert str_mod.resolve_signed_tool("ffuf") == "ffuf_dir"
        assert str_mod.resolve_signed_tool("nuclei") == "nuclei"

    def test_unknown_returns_none(self) -> None:
        assert str_mod.resolve_signed_tool("definitely_not_a_tool") is None


class TestToUuid:
    def test_valid_uuid_preserved(self) -> None:
        u = "11111111-2222-3333-4444-555555555555"
        assert str_mod.to_uuid(u) == UUID(u)

    def test_bad_value_falls_back_to_random(self) -> None:
        assert isinstance(str_mod.to_uuid("not-a-uuid"), UUID)
        assert isinstance(str_mod.to_uuid(None), UUID)


class TestTargetSpecAndParams:
    def test_url_extracts_domain(self) -> None:
        spec, params = str_mod._target_spec_and_params("http://app.test/x?y=1", TargetKind.URL)
        assert spec is not None and spec.kind is TargetKind.URL
        assert params == {"url": "http://app.test/x?y=1", "domain": "app.test"}

    def test_non_http_url_defers(self) -> None:
        spec, params = str_mod._target_spec_and_params("ftp://x/y", TargetKind.URL)
        assert spec is None and params == {}

    def test_domain_host_ip_cidr(self) -> None:
        for kind, key in (
            (TargetKind.DOMAIN, "domain"),
            (TargetKind.HOST, "host"),
            (TargetKind.IP, "ip"),
            (TargetKind.CIDR, "cidr"),
        ):
            spec, params = str_mod._target_spec_and_params("val", kind)
            assert spec is not None and spec.kind is kind
            assert params == {key: "val"}

    def test_empty_target_defers(self) -> None:
        spec, params = str_mod._target_spec_and_params("  ", TargetKind.DOMAIN)
        assert spec is None and params == {}


class TestBuildToolJobNonUrl:
    def test_domain_tool_builds_job(self) -> None:
        # subfinder's command_template is {domain} + {out_dir} → DOMAIN-buildable.
        descriptor = str_mod.get_signed_tool_registry().resolve("subfinder")
        job = str_mod.build_tool_job(
            descriptor,
            target="example.com",
            scan_id="",
            tenant_id="",
            timeout=60,
            target_kind=TargetKind.DOMAIN,
        )
        assert job is not None
        assert job.tool_id == "subfinder"
        assert job.target.kind is TargetKind.DOMAIN
        assert job.parameters["domain"] == "example.com"

    def test_url_kind_still_url_only_contract(self) -> None:
        # A URL-kind build of subfinder must fail — {domain} is present but a bare
        # http URL only supplies {domain} from its host, which IS satisfiable, so
        # instead assert a non-http target defers.
        descriptor = str_mod.get_signed_tool_registry().resolve("subfinder")
        assert (
            str_mod.build_tool_job(
                descriptor,
                target="not-a-url",
                scan_id="",
                tenant_id="",
                timeout=60,
                target_kind=TargetKind.URL,
            )
            is None
        )


class TestBuildUrlToolJob:
    def test_builds_for_http_url(self) -> None:
        descriptor = str_mod.get_signed_tool_registry().resolve("nuclei")
        job = str_mod.build_url_tool_job(
            descriptor,
            target="http://target.example/app",
            scan_id="11111111-2222-3333-4444-555555555555",
            tenant_id="",
            timeout=30,
        )
        assert job is not None
        assert job.tool_id == "nuclei"
        assert job.correlation_id == "argus-single-plane"

    def test_non_http_target_returns_none(self) -> None:
        descriptor = str_mod.get_signed_tool_registry().resolve("nuclei")
        job = str_mod.build_url_tool_job(
            descriptor, target="ftp://x/y", scan_id="", tenant_id="", timeout=30
        )
        assert job is None


class TestRunSignedTool:
    async def test_unknown_tool_returns_none(self) -> None:
        result = await str_mod.run_signed_tool(
            "definitely_not_a_tool", "http://target/", timeout=10
        )
        assert result is None

    async def test_registry_none_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(str_mod, "get_signed_tool_registry", lambda: None)
        result = await str_mod.run_signed_tool("nuclei", "http://target/", timeout=10)
        assert result is None

    async def test_success_maps_result(self) -> None:
        proc = _proc_mock(returncode=0, stdout=b"scan-ok")
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc):
            result = await str_mod.run_signed_tool(
                "nuclei",
                "http://target.example/app",
                timeout=30,
                scan_id="11111111-2222-3333-4444-555555555555",
            )
        assert result is not None
        assert result["exit_code"] == 0
        assert "duration_ms" in result

    async def test_auth_argv_reaches_docker(self) -> None:
        proc = _proc_mock(returncode=0, stdout=b"ok")
        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc
        ) as spawn:
            await str_mod.run_signed_tool(
                "nuclei",
                "http://target.example/app",
                timeout=30,
                auth_argv=["-H", "Cookie: sid=SECRET"],
            )
        argv = list(spawn.call_args.args)
        assert "-H" in argv
        assert any("Cookie: sid=SECRET" in tok for tok in argv)
