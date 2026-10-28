"""T1/T2 triggers — gated enqueue, never raises."""

from __future__ import annotations

import pytest

from src.intel.dark_web import triggers


class _ReconOut:
    tool_results = {
        "theharvester": {"stdout": "contact alice@acme.com and bob@acme.com here"},
    }


class _VulnOut:
    findings = [{"id": "f1", "host": "acme.com", "category": "known_cve", "cve": "CVE-2021-1"}]


def test_t1_skipped_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", False, raising=False)
    calls: list = []
    monkeypatch.setattr(
        "src.celery.tasks.darkweb_tasks.darkweb_sweep_task",
        type("T", (), {"delay": staticmethod(lambda *a, **k: calls.append(a))}),
    )
    res = triggers.trigger_recon_sweep(
        scan_id="s", tenant_id="t", target="https://acme.com", options={"dark_web": {"enabled": True}},
        recon_out=_ReconOut(),
    )
    assert res["enqueued"] is False
    assert res["status"] == "disabled"
    assert calls == []


def test_t1_enqueues_when_all_gates_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", True, raising=False)
    calls: list = []
    monkeypatch.setattr(
        "src.celery.tasks.darkweb_tasks.darkweb_sweep_task",
        type("T", (), {"delay": staticmethod(lambda *a, **k: calls.append(a))}),
    )
    res = triggers.trigger_recon_sweep(
        scan_id="s", tenant_id="t", target="https://acme.com",
        options={"dark_web": {"enabled": True}}, recon_out=_ReconOut(),
    )
    assert res["enqueued"] is True
    assert res["domain"] == "acme.com"
    assert res["emails"] == 2
    assert len(calls) == 1


def test_t2_enqueues_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", True, raising=False)
    calls: list = []
    monkeypatch.setattr(
        "src.celery.tasks.darkweb_tasks.darkweb_correlate_task",
        type("T", (), {"delay": staticmethod(lambda *a, **k: calls.append(a))}),
    )
    res = triggers.trigger_finding_correlation(
        scan_id="s", tenant_id="t", target="acme.com",
        options={"dark_web": {"enabled": True}}, vuln_out=_VulnOut(),
    )
    assert res["enqueued"] is True
    assert res["findings"] == 1
    assert len(calls) == 1


def test_t2_skipped_when_include_findings_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", True, raising=False)
    res = triggers.trigger_finding_correlation(
        scan_id="s", tenant_id="t", target="acme.com",
        options={"dark_web": {"enabled": True, "include_findings": False}}, vuln_out=_VulnOut(),
    )
    assert res["enqueued"] is False
