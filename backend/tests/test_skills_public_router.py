"""Tests for public GET /api/v1/skills (skills_public router)."""

from __future__ import annotations

from starlette.testclient import TestClient


def test_get_skills_returns_200_and_shape(client: TestClient) -> None:
    response = client.get("/api/v1/skills")
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    skills = data.get("skills")
    assert isinstance(skills, dict)
    for category in ("vulnerabilities", "technologies", "recon"):
        assert category in skills
        assert isinstance(skills[category], list)
        assert len(skills[category]) > 0
