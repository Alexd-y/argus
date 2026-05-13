"""Tests for Incident Enrichment."""

import pytest

from src.workers.incidents.enricher import (
    EnrichedAlert,
    enrich_incident,
    generate_remediation_playbook,
    _prompt_incident_enrichment,
)


class TestEnrichedAlert:
    def test_default_values(self):
        alert = EnrichedAlert()
        assert alert.title == ""
        assert alert.severity == ""
        assert alert.confidence == 0.0

    def test_with_data(self):
        alert = EnrichedAlert(
            id="e1", incident_id="inc1", title="SQLi detected",
            severity="high", iocs=[{"type": "ip", "value": "10.0.0.1"}],
        )
        assert alert.incident_id == "inc1"
        assert len(alert.iocs) == 1


class TestPromptBuilding:
    def test_builds_prompt_with_iocs(self):
        alert = {
            "title": "Suspicious login", "severity": "high",
            "iocs": [{"type": "ip", "value": "1.2.3.4"}],
            "stack_traces": ["File app.py line 42 in login"],
            "affected_services": ["auth-service"],
        }
        prompt = _prompt_incident_enrichment(alert, None)
        assert "Suspicious login" in prompt
        assert "1.2.3.4" in prompt
        assert "app.py" in prompt

    def test_builds_prompt_minimal(self):
        alert = {"title": "Test", "severity": "low"}
        prompt = _prompt_incident_enrichment(alert, None)
        assert "Test" in prompt


class TestPlaybook:
    def test_generates_tasks(self):
        alert = EnrichedAlert(
            incident_id="inc1", title="RCE detected",
            remediation_tasks=[
                {"title": "Patch RCE", "assignee": "backend", "priority": "p1_critical"},
                {"title": "Review logs", "assignee": "soc", "priority": "p2_high"},
            ],
        )
        tasks = generate_remediation_playbook(alert)
        assert len(tasks) == 2
        assert tasks[0]["assignee"] == "backend"
        assert tasks[0]["priority"] == "p1_critical"

    def test_generates_default_task(self):
        alert = EnrichedAlert(incident_id="inc1", title="Unknown issue")
        tasks = generate_remediation_playbook(alert)
        assert len(tasks) == 1
        assert "investigate" in tasks[0]["title"].lower()
