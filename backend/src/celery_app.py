"""Celery app — Redis broker, tasks for scan phases and tool runs (Phase 5)."""

from celery import Celery

from src.core.config import settings

app = Celery(
    "argus",
    broker=settings.celery_broker,
    backend=settings.redis_url,
    include=["src.tasks", "src.recon.jobs.runner"],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    worker_prefetch_multiplier=1,
    task_routes={
        "argus.scan_phase": {"queue": "argus.scans"},
        "argus.generate_report": {"queue": "argus.reports"},
        "argus.generate_all_reports": {"queue": "argus.reports"},
        "argus.report_generation": {"queue": "argus.reports"},
        "argus.ai_text_generation": {"queue": "argus.reports"},
        "argus.tool_run": {"queue": "argus.tools"},
        "argus.va_active_scan_tool": {"queue": "argus.tools"},
        "argus.va.run_dalfox": {"queue": "argus.tools"},
        "argus.va.run_xsstrike": {"queue": "argus.tools"},
        "argus.va.run_ffuf": {"queue": "argus.tools"},
        "argus.va.run_sqlmap": {"queue": "argus.tools"},
        "argus.va.run_nuclei": {"queue": "argus.tools"},
        "argus.recon_job": {"queue": "argus.recon"},
        "argus.exploitation": {"queue": "argus.exploitation"},
    },
    task_default_queue="argus.default",
)
