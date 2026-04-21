"""INFRA-005: Validate infra/backend/Dockerfile for ARGUS infrastructure.

Validates:
- Multi-stage build (builder + runtime)
- gunicorn in CMD
- Non-root user
- Builder installs deps from pyproject.toml (single source of truth, PEP 621)
- requirements.txt is kept as auto-generated mirror for legacy CI/SCA tooling
"""

from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE_PATH = ARGUS_ROOT / "infra" / "backend" / "Dockerfile"
BACKEND_ROOT = ARGUS_ROOT / "backend"
PYPROJECT_PATH = BACKEND_ROOT / "pyproject.toml"
REQUIREMENTS_PATH = BACKEND_ROOT / "requirements.txt"


@pytest.fixture(scope="module")
def dockerfile_content() -> str:
    """Load Dockerfile content."""
    return DOCKERFILE_PATH.read_text(encoding="utf-8")


class TestInfra005BackendDockerfileExists:
    """INFRA-005: infra/backend/Dockerfile file existence."""

    def test_dockerfile_exists(self) -> None:
        """infra/backend/Dockerfile must exist."""
        assert DOCKERFILE_PATH.exists(), f"Not found: {DOCKERFILE_PATH}"
        assert DOCKERFILE_PATH.is_file()


class TestInfra005BackendDockerfileContent:
    """INFRA-005: Dockerfile must meet security and build requirements."""

    def test_multi_stage_build(self, dockerfile_content: str) -> None:
        """Must use multi-stage build (AS builder, AS runtime or similar)."""
        content_upper = dockerfile_content.upper()
        assert " AS " in content_upper or "AS BUILDER" in content_upper or "AS RUNTIME" in content_upper, (
            "INFRA-005: Dockerfile must use multi-stage build (FROM ... AS builder/runtime)"
        )
        # At least two FROM statements
        from_count = dockerfile_content.upper().count("FROM ")
        assert from_count >= 2, (
            "INFRA-005: Dockerfile must have at least 2 stages (builder + runtime)"
        )

    def test_gunicorn_in_cmd(self, dockerfile_content: str) -> None:
        """CMD must use gunicorn."""
        assert "gunicorn" in dockerfile_content.lower(), (
            "INFRA-005: CMD must use gunicorn"
        )
        assert "CMD" in dockerfile_content.upper(), (
            "INFRA-005: Dockerfile must have CMD"
        )

    def test_non_root_user(self, dockerfile_content: str) -> None:
        """Must run as non-root user (USER directive)."""
        content_upper = dockerfile_content.upper()
        assert "USER " in content_upper, (
            "INFRA-005: Dockerfile must have USER directive (non-root)"
        )
        assert "USER ROOT" not in content_upper and "USER 0" not in content_upper, (
            "INFRA-005: Must not run as root (USER root or USER 0)"
        )

    def test_pyproject_is_dependency_source(self, dockerfile_content: str) -> None:
        """Builder must install runtime deps from pyproject.toml (single source of truth)."""
        assert "COPY pyproject.toml" in dockerfile_content, (
            "INFRA-005: Dockerfile builder must COPY pyproject.toml as dependency source"
        )
        assert "pip install" in dockerfile_content, (
            "INFRA-005: Dockerfile must install Python dependencies in the builder stage"
        )

    def test_pyproject_exists_in_backend(self) -> None:
        """pyproject.toml must exist in backend (build context)."""
        assert PYPROJECT_PATH.exists(), (
            f"INFRA-005: pyproject.toml must exist at {PYPROJECT_PATH} "
            "(backend is build context, [project.dependencies] drives the image build)"
        )

    def test_requirements_txt_kept_as_mirror(self) -> None:
        """requirements.txt is auto-generated from pyproject.toml — must stay present for CI/SCA."""
        assert REQUIREMENTS_PATH.exists(), (
            f"INFRA-005: requirements.txt must exist at {REQUIREMENTS_PATH} "
            "(legacy CI/SCA mirror; regenerate with backend/scripts/sync_requirements.py)"
        )
