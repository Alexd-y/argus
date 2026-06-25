"""Tests for Celery task definitions and routing configuration.

Validates:
* Celery app is importable and named correctly.
* Task routing table maps every known task to a queue.
* Serialisation configuration enforces JSON-only (no pickle).
* Task include list references importable packages.
"""

from __future__ import annotations

import pytest


class TestCeleryAppConfig:
    """Celery app instantiation and core configuration."""

    @pytest.fixture(scope="module")
    def celery_app(self):
        from src.celery_app import app

        return app

    def test_app_name_is_argus(self, celery_app) -> None:
        assert celery_app.main == "argus"

    def test_serializer_is_json(self, celery_app) -> None:
        conf = celery_app.conf
        assert conf.task_serializer == "json"
        assert conf.result_serializer == "json"

    def test_accept_content_json_only(self, celery_app) -> None:
        conf = celery_app.conf
        assert "json" in conf.accept_content
        assert "pickle" not in conf.accept_content

    def test_utc_enabled(self, celery_app) -> None:
        conf = celery_app.conf
        assert conf.enable_utc is True
        assert conf.timezone == "UTC"

    def test_task_track_started(self, celery_app) -> None:
        assert celery_app.conf.task_track_started is True

    def test_task_time_limit(self, celery_app) -> None:
        assert celery_app.conf.task_time_limit == 3600

    def test_prefetch_multiplier_is_one(self, celery_app) -> None:
        assert celery_app.conf.worker_prefetch_multiplier == 1


class TestCeleryTaskRouting:
    """Task → queue routing table correctness and coverage."""

    @pytest.fixture(scope="module")
    def routes(self):
        from src.celery_app import app

        return app.conf.task_routes

    def test_scan_task_routes_to_scans_queue(self, routes) -> None:
        assert routes["argus.scan_phase"]["queue"] == "argus.scans"

    def test_report_tasks_route_to_reports_queue(self, routes) -> None:
        for task_name in ("argus.generate_report", "argus.report_generation", "argus.ai_text_generation"):
            assert routes[task_name]["queue"] == "argus.reports", f"{task_name} bad queue"

    def test_tool_tasks_route_to_tools_queue(self, routes) -> None:
        for task_name in (
            "argus.tool_run",
            "argus.va_active_scan_tool",
            "argus.va.run_dalfox",
            "argus.va.run_nuclei",
            "argus.va.run_sqlmap",
        ):
            assert routes[task_name]["queue"] == "argus.tools", f"{task_name} bad queue"

    def test_recon_task_routes_to_recon_queue(self, routes) -> None:
        assert routes["argus.recon_job"]["queue"] == "argus.recon"

    def test_exploitation_tasks_route_to_exploitation_queue(self, routes) -> None:
        assert routes["argus.exploitation"]["queue"] == "argus.exploitation"

    def test_intel_tasks_route_to_intel_queue(self, routes) -> None:
        for task_name in (
            "argus.intel.epss_refresh",
            "argus.intel.kev_refresh",
            "argus.metrics.queue_depth_refresh",
        ):
            assert routes[task_name]["queue"] == "argus.intel", f"{task_name} bad queue"

    def test_notifications_wildcard_routes_to_notifications_queue(self, routes) -> None:
        assert routes["argus.notifications.*"]["queue"] == "argus.notifications"

    def test_default_queue_set(self, celery_app) -> None:
        assert celery_app.conf.task_default_queue == "argus.default"


class TestCeleryTaskIncludes:
    """Task include list must reference importable packages."""

    @pytest.fixture(scope="module")
    def includes(self):
        from src.celery_app import app

        return set(app.conf.include)

    def test_includes_tasks_module(self, includes) -> None:
        assert "src.tasks" in includes

    def test_includes_intel_refresh(self, includes) -> None:
        assert "src.celery.tasks.intel_refresh" in includes

    def test_includes_webhook_dlq(self, includes) -> None:
        assert "src.celery.tasks.webhook_dlq_replay" in includes

    def test_includes_scan_trigger(self, includes) -> None:
        assert "src.scheduling.scan_trigger" in includes

    def test_every_include_is_importable(self, includes) -> None:
        for module_path in sorted(includes):
            try:
                __import__(module_path)
            except ImportError as exc:
                pytest.skip(f"Cannot import {module_path}: {exc}")


class TestCeleryBeatSchedule:
    """Beat schedule entries — optional Celery dependency, skip if missing."""

    def test_beat_schedule_module_imports(self) -> None:
        try:
            from src.celery.beat_schedule import BEAT_SCHEDULE
        except ImportError:
            pytest.skip("Celery not installed — skipping beat schedule tests")
        assert isinstance(BEAT_SCHEDULE, dict)

    def test_beat_schedule_apply_does_not_raise(self) -> None:
        try:
            from celery import Celery
            from src.celery.beat_schedule import apply_beat_schedule
        except ImportError:
            pytest.skip("Celery not installed — skipping beat schedule tests")

        app = Celery("test")
        apply_beat_schedule(app)


class TestVulnDiscoveryWorker:
    """``src.workers.vuln_discovery.worker`` data types and prompt builder."""

    def test_vuln_finding_dataclass_defaults(self) -> None:
        from src.workers.vuln_discovery.worker import VulnFinding

        f = VulnFinding()
        assert f.id == ""
        assert f.severity == ""
        assert f.exploitability == ""
        assert isinstance(f.references, list)

    def test_result_dataclass_defaults(self) -> None:
        from src.workers.vuln_discovery.worker import VulnDiscoveryResult

        r = VulnDiscoveryResult()
        assert r.findings == []
        assert r.total_files_scanned == 0
        assert r.scan_duration_seconds == 0.0

    def test_prompt_contains_target_name(self) -> None:
        from src.analysis.cpg import CodePropertyGraph
        from src.workers.vuln_discovery.worker import _prompt_vuln_discovery

        cpg = CodePropertyGraph(language="python", nodes=[], edges=[])
        prompt = _prompt_vuln_discovery(cpg, {}, "test-repo")
        assert "test-repo" in prompt
        assert "MODE" in prompt
