"""Docker build verification — Dockerfile structure and docker-compose config.

Ensures:
- Backend Dockerfile copies app/, src/, main.py, alembic
- docker-compose defines backend and worker with build sections
- Required directories exist in backend for COPY instructions
"""

from pathlib import Path

import pytest
import yaml

# ARGUS root: backend/tests/ -> parent=backend, parent.parent=ARGUS
ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = ARGUS_ROOT / "backend"
INFRA_DIR = ARGUS_ROOT / "infra"
BACKEND_DOCKERFILE = INFRA_DIR / "backend" / "Dockerfile"
WORKER_DOCKERFILE = INFRA_DIR / "worker" / "Dockerfile"
DOCKER_COMPOSE_PATH = INFRA_DIR / "docker-compose.yml"


@pytest.fixture(scope="module")
def backend_dockerfile_content() -> str:
    """Read backend Dockerfile."""
    return BACKEND_DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def worker_dockerfile_content() -> str:
    """Read worker Dockerfile."""
    return WORKER_DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Load and parse docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)


class TestBackendDockerfile:
    """Backend Dockerfile structure and required COPY instructions."""

    def test_dockerfile_exists(self) -> None:
        """Backend Dockerfile exists at infra/backend/Dockerfile."""
        assert BACKEND_DOCKERFILE.exists(), f"Not found: {BACKEND_DOCKERFILE}"
        assert BACKEND_DOCKERFILE.is_file()

    def test_copy_main_py(self, backend_dockerfile_content: str) -> None:
        """Dockerfile copies main.py."""
        assert "COPY main.py" in backend_dockerfile_content, (
            "Backend Dockerfile must COPY main.py"
        )

    def test_copy_src(self, backend_dockerfile_content: str) -> None:
        """Dockerfile copies src/ directory."""
        assert "COPY src/" in backend_dockerfile_content, (
            "Backend Dockerfile must COPY src/"
        )

    def test_copy_app(self, backend_dockerfile_content: str) -> None:
        """Dockerfile copies app/ (schemas, prompts)."""
        assert "COPY app/" in backend_dockerfile_content, (
            "Backend Dockerfile must COPY app/ (schemas, prompts)"
        )

    def test_copy_alembic(self, backend_dockerfile_content: str) -> None:
        """Dockerfile copies alembic for migrations."""
        assert "COPY alembic" in backend_dockerfile_content, (
            "Backend Dockerfile must COPY alembic"
        )

    def test_copy_requirements(self, backend_dockerfile_content: str) -> None:
        """Dockerfile copies requirements.txt in builder stage."""
        assert "COPY requirements.txt" in backend_dockerfile_content, (
            "Backend Dockerfile must COPY requirements.txt"
        )

    def test_backend_app_dir_exists(self) -> None:
        """backend/app/ exists (required for COPY app/)."""
        app_dir = BACKEND_DIR / "app"
        assert app_dir.exists(), f"backend/app/ must exist for Docker build: {app_dir}"
        assert app_dir.is_dir()

    def test_backend_src_dir_exists(self) -> None:
        """backend/src/ exists (required for COPY src/)."""
        src_dir = BACKEND_DIR / "src"
        assert src_dir.exists(), f"backend/src/ must exist for Docker build: {src_dir}"
        assert src_dir.is_dir()

    def test_backend_main_py_exists(self) -> None:
        """backend/main.py exists."""
        main_py = BACKEND_DIR / "main.py"
        assert main_py.exists(), f"backend/main.py must exist: {main_py}"

    def test_backend_requirements_exists(self) -> None:
        """backend/requirements.txt exists."""
        req = BACKEND_DIR / "requirements.txt"
        assert req.exists(), f"backend/requirements.txt must exist: {req}"


class TestWorkerDockerfile:
    """Worker Dockerfile inherits from backend image."""

    def test_worker_dockerfile_exists(self) -> None:
        """Worker Dockerfile exists at infra/worker/Dockerfile."""
        assert WORKER_DOCKERFILE.exists(), f"Not found: {WORKER_DOCKERFILE}"
        assert WORKER_DOCKERFILE.is_file()

    def test_worker_from_backend_image(
        self, worker_dockerfile_content: str
    ) -> None:
        """Worker uses backend image as base."""
        assert "argus-backend" in worker_dockerfile_content or "BACKEND_IMAGE" in worker_dockerfile_content, (
            "Worker Dockerfile must FROM argus-backend (or ARG BACKEND_IMAGE)"
        )

    def test_worker_celery_cmd(self, worker_dockerfile_content: str) -> None:
        """Worker runs celery."""
        assert "celery" in worker_dockerfile_content.lower(), (
            "Worker Dockerfile must run celery"
        )


class TestDockerComposeBuild:
    """docker-compose.yml build configuration."""

    def test_compose_exists(self) -> None:
        """docker-compose.yml exists."""
        assert DOCKER_COMPOSE_PATH.exists(), f"Not found: {DOCKER_COMPOSE_PATH}"
        assert DOCKER_COMPOSE_PATH.is_file()

    def test_compose_valid_yaml(self, compose_config: dict) -> None:
        """docker-compose.yml is valid YAML."""
        assert compose_config is not None
        assert isinstance(compose_config, dict)
        assert "services" in compose_config

    def test_backend_has_build_section(self, compose_config: dict) -> None:
        """Backend service has build section."""
        services = compose_config.get("services", {})
        assert "backend" in services, "backend service must be defined"
        build = services["backend"].get("build")
        assert build is not None, "backend must have build section"
        assert "context" in build or isinstance(build, dict), (
            "backend.build must specify context"
        )

    def test_backend_build_context_points_to_backend(
        self, compose_config: dict
    ) -> None:
        """Backend build context is ../backend (from infra)."""
        services = compose_config.get("services", {})
        build = services.get("backend", {}).get("build", {})
        if isinstance(build, dict):
            ctx = build.get("context", "")
            assert "backend" in ctx, (
                f"backend build context must point to backend dir, got: {ctx}"
            )

    def test_worker_has_build_section(self, compose_config: dict) -> None:
        """Worker service has build section."""
        services = compose_config.get("services", {})
        assert "worker" in services, "worker service must be defined"
        build = services["worker"].get("build")
        assert build is not None, "worker must have build section"

    def test_backend_and_worker_images_defined(
        self, compose_config: dict
    ) -> None:
        """Backend and worker have image names for tagging."""
        services = compose_config.get("services", {})
        backend_img = services.get("backend", {}).get("image")
        worker_img = services.get("worker", {}).get("image")
        assert backend_img, "backend must have image name"
        assert worker_img, "worker must have image name"
        assert "argus-backend" in str(backend_img)
        assert "argus-worker" in str(worker_img)
