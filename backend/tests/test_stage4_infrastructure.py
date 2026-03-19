"""Stage 4 (Exploitation) infrastructure validation tests.

Validates Docker/infra configuration files that were added or modified
for the exploitation pipeline:
- Settings class fields and defaults
- Celery task route and registration
- ENV templates (backend/.env.example, infra/.env.example)
- docker-compose.yml: sandbox service, minio-init, resource limits
- sandbox/Dockerfile: exploitation tools installed
- plugins/exploit_scripts/ directory structure
- Alembic migration 008 (exploitation_runs, exploitation_approvals)

All tests are deterministic — no Docker or running services required.
"""

import re
from pathlib import Path

import pytest
import yaml

# ARGUS root: backend/tests/ -> parent=backend, parent.parent=ARGUS
ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = ARGUS_ROOT / "backend"
INFRA_DIR = ARGUS_ROOT / "infra"
SANDBOX_DIR = ARGUS_ROOT / "sandbox"
PLUGINS_DIR = ARGUS_ROOT / "plugins" / "exploit_scripts"
DOCKER_COMPOSE_PATH = INFRA_DIR / "docker-compose.yml"
WORKER_DOCKERFILE = INFRA_DIR / "worker" / "Dockerfile"
SANDBOX_DOCKERFILE = SANDBOX_DIR / "Dockerfile"
BACKEND_ENV_EXAMPLE = BACKEND_DIR / ".env.example"
INFRA_ENV_EXAMPLE = INFRA_DIR / ".env.example"
ALEMBIC_VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"
MIGRATION_008 = ALEMBIC_VERSIONS_DIR / "008_add_exploitation_models.py"

STAGE4_ENV_VARS = [
    "STAGE4_ARTIFACTS_BUCKET",
    "EXPLOITATION_TIMEOUT_MINUTES",
    "EXPLOITATION_MAX_CONCURRENT",
    "EXPLOITATION_APPROVAL_TIMEOUT_MINUTES",
]

SANDBOX_REQUIRED_TOOLS = ["sqlmap", "hydra", "nuclei", "python3"]


def _parse_env_keys(content: str) -> set[str]:
    """Extract KEY names from env file content, ignoring comments and blanks."""
    keys: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, _ = line.partition("=")
            keys.add(key.strip())
    return keys


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Load and parse infra/docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)


@pytest.fixture(scope="module")
def sandbox_dockerfile_content() -> str:
    """Read sandbox/Dockerfile."""
    return SANDBOX_DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def worker_dockerfile_content() -> str:
    """Read infra/worker/Dockerfile."""
    return WORKER_DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def backend_env_example_keys() -> set[str]:
    """Parse backend/.env.example into a set of key names."""
    content = BACKEND_ENV_EXAMPLE.read_text(encoding="utf-8")
    return _parse_env_keys(content)


@pytest.fixture(scope="module")
def infra_env_example_keys() -> set[str]:
    """Parse infra/.env.example into a set of key names."""
    content = INFRA_ENV_EXAMPLE.read_text(encoding="utf-8")
    return _parse_env_keys(content)


@pytest.fixture(scope="module")
def migration_008_content() -> str:
    """Read alembic migration 008."""
    return MIGRATION_008.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Settings class tests
# ---------------------------------------------------------------------------

class TestStage4SettingsFields:
    """Settings class has all Stage 4 fields with correct defaults."""

    @pytest.fixture(autouse=True)
    def _load_settings_class(self):
        from src.core.config import Settings
        self.settings_cls = Settings

    def test_stage4_artifacts_bucket_field_exists(self) -> None:
        """Settings has stage4_artifacts_bucket field."""
        fields = self.settings_cls.model_fields
        assert "stage4_artifacts_bucket" in fields

    def test_stage4_artifacts_bucket_default(self) -> None:
        """stage4_artifacts_bucket defaults to 'stage4-artifacts'."""
        default = self.settings_cls.model_fields["stage4_artifacts_bucket"].default
        assert default == "stage4-artifacts"

    def test_exploitation_timeout_minutes_field_exists(self) -> None:
        """Settings has exploitation_timeout_minutes field."""
        fields = self.settings_cls.model_fields
        assert "exploitation_timeout_minutes" in fields

    def test_exploitation_timeout_minutes_default_positive(self) -> None:
        """exploitation_timeout_minutes default is positive integer."""
        default = self.settings_cls.model_fields["exploitation_timeout_minutes"].default
        assert isinstance(default, int)
        assert default > 0, f"Timeout must be > 0, got {default}"

    def test_exploitation_max_concurrent_field_exists(self) -> None:
        """Settings has exploitation_max_concurrent field."""
        fields = self.settings_cls.model_fields
        assert "exploitation_max_concurrent" in fields

    def test_exploitation_max_concurrent_default_positive(self) -> None:
        """exploitation_max_concurrent default is positive integer."""
        default = self.settings_cls.model_fields["exploitation_max_concurrent"].default
        assert isinstance(default, int)
        assert default > 0, f"Max concurrent must be > 0, got {default}"

    def test_exploitation_approval_timeout_minutes_field_exists(self) -> None:
        """Settings has exploitation_approval_timeout_minutes field."""
        fields = self.settings_cls.model_fields
        assert "exploitation_approval_timeout_minutes" in fields

    def test_exploitation_approval_timeout_minutes_default_positive(self) -> None:
        """exploitation_approval_timeout_minutes default is positive integer."""
        default = self.settings_cls.model_fields["exploitation_approval_timeout_minutes"].default
        assert isinstance(default, int)
        assert default > 0, f"Approval timeout must be > 0, got {default}"

    def test_exploitation_timeout_reasonable_range(self) -> None:
        """exploitation_timeout_minutes within reasonable range (1-120)."""
        default = self.settings_cls.model_fields["exploitation_timeout_minutes"].default
        assert 1 <= default <= 120, (
            f"Timeout {default}m outside reasonable 1-120 range"
        )

    def test_exploitation_approval_timeout_reasonable_range(self) -> None:
        """exploitation_approval_timeout_minutes within reasonable range (5-1440)."""
        default = self.settings_cls.model_fields["exploitation_approval_timeout_minutes"].default
        assert 5 <= default <= 1440, (
            f"Approval timeout {default}m outside reasonable 5-1440 range"
        )


# ---------------------------------------------------------------------------
# Celery config tests
# ---------------------------------------------------------------------------

class TestStage4CeleryConfig:
    """Celery task routes and registration include exploitation."""

    def test_exploitation_route_exists(self) -> None:
        """argus.exploitation route exists in celery task_routes."""
        from src.celery_app import app as celery_app

        routes = celery_app.conf.task_routes or {}
        assert "argus.exploitation" in routes, (
            "Celery task_routes must include 'argus.exploitation'"
        )

    def test_exploitation_route_queue(self) -> None:
        """argus.exploitation routes to argus.exploitation queue."""
        from src.celery_app import app as celery_app

        routes = celery_app.conf.task_routes or {}
        route = routes.get("argus.exploitation", {})
        assert route.get("queue") == "argus.exploitation", (
            f"Exploitation route must target 'argus.exploitation' queue, got {route}"
        )

    def test_tasks_module_included(self) -> None:
        """src.tasks module is in celery include list (contains run_exploitation)."""
        from src.celery_app import app as celery_app

        include = celery_app.conf.get("include") or getattr(celery_app, "_include", []) or []
        if not include:
            include = celery_app.loader._conf.get("include", [])
        assert any("src.tasks" in mod for mod in include), (
            "Celery include must contain 'src.tasks' (run_exploitation task module)"
        )


# ---------------------------------------------------------------------------
# ENV template tests
# ---------------------------------------------------------------------------

class TestStage4BackendEnvExample:
    """backend/.env.example contains all Stage 4 variables."""

    def test_backend_env_example_exists(self) -> None:
        """backend/.env.example file exists."""
        assert BACKEND_ENV_EXAMPLE.exists(), f"Not found: {BACKEND_ENV_EXAMPLE}"

    @pytest.mark.parametrize("var", STAGE4_ENV_VARS)
    def test_stage4_var_present(
        self, backend_env_example_keys: set[str], var: str
    ) -> None:
        """Each Stage 4 env var must be defined in backend/.env.example."""
        assert var in backend_env_example_keys, (
            f"Missing Stage 4 var '{var}' in backend/.env.example"
        )


class TestStage4InfraEnvExample:
    """infra/.env.example contains all Stage 4 variables."""

    def test_infra_env_example_exists(self) -> None:
        """infra/.env.example file exists."""
        assert INFRA_ENV_EXAMPLE.exists(), f"Not found: {INFRA_ENV_EXAMPLE}"

    @pytest.mark.parametrize("var", STAGE4_ENV_VARS)
    def test_stage4_var_present(
        self, infra_env_example_keys: set[str], var: str
    ) -> None:
        """Each Stage 4 env var must be defined in infra/.env.example."""
        assert var in infra_env_example_keys, (
            f"Missing Stage 4 var '{var}' in infra/.env.example"
        )


# ---------------------------------------------------------------------------
# Docker Compose validation tests
# ---------------------------------------------------------------------------

class TestStage4DockerComposeSandbox:
    """docker-compose.yml sandbox service configuration."""

    def test_sandbox_service_defined(self, compose_config: dict) -> None:
        """sandbox service must exist in docker-compose.yml."""
        services = compose_config.get("services", {})
        assert "sandbox" in services, (
            "docker-compose.yml must define 'sandbox' service"
        )

    def test_sandbox_has_build_section(self, compose_config: dict) -> None:
        """sandbox service must have build section."""
        sandbox = compose_config["services"]["sandbox"]
        assert "build" in sandbox, "sandbox must have build section"

    def test_sandbox_has_resource_limits(self, compose_config: dict) -> None:
        """sandbox service must have deploy.resources.limits (CPU + memory)."""
        sandbox = compose_config["services"]["sandbox"]
        deploy = sandbox.get("deploy", {})
        resources = deploy.get("resources", {})
        limits = resources.get("limits", {})
        assert limits, "sandbox must have deploy.resources.limits"
        assert "cpus" in limits, "sandbox resource limits must include cpus"
        assert "memory" in limits, "sandbox resource limits must include memory"

    def test_sandbox_cpu_limit_reasonable(self, compose_config: dict) -> None:
        """sandbox CPU limit should be between 0.5 and 8.0 cores."""
        limits = (
            compose_config["services"]["sandbox"]
            .get("deploy", {})
            .get("resources", {})
            .get("limits", {})
        )
        cpus = float(limits.get("cpus", "0"))
        assert 0.5 <= cpus <= 8.0, f"sandbox CPU limit {cpus} outside 0.5-8.0 range"

    def test_sandbox_memory_limit_reasonable(self, compose_config: dict) -> None:
        """sandbox memory limit should be between 256M and 8192M."""
        limits = (
            compose_config["services"]["sandbox"]
            .get("deploy", {})
            .get("resources", {})
            .get("limits", {})
        )
        mem = limits.get("memory", "0M")
        mem_mb = int(re.sub(r"[^0-9]", "", str(mem)))
        assert 256 <= mem_mb <= 8192, (
            f"sandbox memory limit {mem} outside 256M-8192M range"
        )

    def test_sandbox_exploit_scripts_volume(self, compose_config: dict) -> None:
        """sandbox volumes must include exploit_scripts mount."""
        sandbox = compose_config["services"]["sandbox"]
        volumes = sandbox.get("volumes", [])
        volume_strs = [str(v) for v in volumes]
        assert any("exploit_scripts" in v for v in volume_strs), (
            f"sandbox must mount exploit_scripts, got volumes: {volume_strs}"
        )

    def test_sandbox_exploit_scripts_readonly(self, compose_config: dict) -> None:
        """exploit_scripts volume should be mounted read-only (:ro)."""
        sandbox = compose_config["services"]["sandbox"]
        volumes = sandbox.get("volumes", [])
        exploit_vol = [str(v) for v in volumes if "exploit_scripts" in str(v)]
        assert any(":ro" in v for v in exploit_vol), (
            "exploit_scripts mount should be read-only (:ro)"
        )

    def test_sandbox_on_data_network(self, compose_config: dict) -> None:
        """sandbox must be on 'data' network (needs MinIO access)."""
        sandbox = compose_config["services"]["sandbox"]
        networks = sandbox.get("networks", [])
        assert "data" in networks, (
            f"sandbox must be on 'data' network, got: {networks}"
        )

    def test_sandbox_depends_on_minio(self, compose_config: dict) -> None:
        """sandbox must depend on minio."""
        sandbox = compose_config["services"]["sandbox"]
        depends = sandbox.get("depends_on", {})
        if isinstance(depends, list):
            assert "minio" in depends
        else:
            assert "minio" in depends, (
                f"sandbox must depend on minio, got: {list(depends.keys())}"
            )

    def test_sandbox_has_healthcheck(self, compose_config: dict) -> None:
        """sandbox service must have healthcheck."""
        sandbox = compose_config["services"]["sandbox"]
        assert "healthcheck" in sandbox, "sandbox must have healthcheck"
        hc = sandbox["healthcheck"]
        assert "test" in hc, "sandbox healthcheck must have 'test'"


class TestStage4DockerComposeMinioInit:
    """docker-compose.yml minio-init service."""

    def test_minio_init_service_defined(self, compose_config: dict) -> None:
        """minio-init service must exist in docker-compose.yml."""
        services = compose_config.get("services", {})
        assert "minio-init" in services, (
            "docker-compose.yml must define 'minio-init' service"
        )

    def test_minio_init_depends_on_minio(self, compose_config: dict) -> None:
        """minio-init must depend on minio."""
        minio_init = compose_config["services"]["minio-init"]
        depends = minio_init.get("depends_on", {})
        if isinstance(depends, list):
            assert "minio" in depends
        else:
            assert "minio" in depends

    def test_minio_init_creates_stage4_bucket(self, compose_config: dict) -> None:
        """minio-init entrypoint should create stage4-artifacts bucket."""
        minio_init = compose_config["services"]["minio-init"]
        entrypoint = str(minio_init.get("entrypoint", ""))
        assert "stage4-artifacts" in entrypoint, (
            "minio-init must create 'stage4-artifacts' bucket"
        )


class TestStage4DockerComposeVolumes:
    """docker-compose.yml has sandbox_tmp volume."""

    def test_sandbox_tmp_volume_defined(self, compose_config: dict) -> None:
        """sandbox_tmp volume must be defined."""
        volumes = compose_config.get("volumes", {})
        assert "sandbox_tmp" in volumes, (
            "docker-compose.yml must define 'sandbox_tmp' volume"
        )


# ---------------------------------------------------------------------------
# Worker Dockerfile tests
# ---------------------------------------------------------------------------

class TestStage4WorkerDockerfile:
    """Worker Dockerfile includes exploitation queue."""

    def test_worker_dockerfile_exists(self) -> None:
        """infra/worker/Dockerfile exists."""
        assert WORKER_DOCKERFILE.exists(), f"Not found: {WORKER_DOCKERFILE}"

    def test_exploitation_queue_in_worker(
        self, worker_dockerfile_content: str
    ) -> None:
        """Worker CMD must include argus.exploitation queue."""
        assert "argus.exploitation" in worker_dockerfile_content, (
            "Worker Dockerfile must include 'argus.exploitation' in -Q queue list"
        )


# ---------------------------------------------------------------------------
# Sandbox Dockerfile tests
# ---------------------------------------------------------------------------

class TestStage4SandboxDockerfile:
    """sandbox/Dockerfile installs required exploitation tools."""

    def test_sandbox_dockerfile_exists(self) -> None:
        """sandbox/Dockerfile exists."""
        assert SANDBOX_DOCKERFILE.exists(), f"Not found: {SANDBOX_DOCKERFILE}"

    @pytest.mark.parametrize("tool", SANDBOX_REQUIRED_TOOLS)
    def test_tool_installed(
        self, sandbox_dockerfile_content: str, tool: str
    ) -> None:
        """Each required tool must appear in sandbox Dockerfile (apt-get or binary install)."""
        assert tool in sandbox_dockerfile_content, (
            f"sandbox/Dockerfile must install '{tool}'"
        )

    def test_nuclei_binary_install(self, sandbox_dockerfile_content: str) -> None:
        """Nuclei installed from GitHub release (binary, not apt)."""
        assert "nuclei" in sandbox_dockerfile_content
        assert "projectdiscovery/nuclei" in sandbox_dockerfile_content, (
            "Nuclei should be installed from projectdiscovery GitHub release"
        )

    def test_nuclei_template_update(self, sandbox_dockerfile_content: str) -> None:
        """Nuclei template update step exists in Dockerfile."""
        assert "nuclei" in sandbox_dockerfile_content
        assert "update-templates" in sandbox_dockerfile_content or "-update-templates" in sandbox_dockerfile_content, (
            "Dockerfile must include nuclei template update step"
        )

    def test_metasploit_optional_build_arg(
        self, sandbox_dockerfile_content: str
    ) -> None:
        """Metasploit is optional via INSTALL_MSF build arg."""
        assert "INSTALL_MSF" in sandbox_dockerfile_content, (
            "Metasploit must be optional via INSTALL_MSF build arg"
        )

    def test_exploit_scripts_mount_point(
        self, sandbox_dockerfile_content: str
    ) -> None:
        """Dockerfile creates /opt/exploit_scripts mount point."""
        assert "/opt/exploit_scripts" in sandbox_dockerfile_content, (
            "Dockerfile must create /opt/exploit_scripts directory"
        )

    def test_runs_as_non_root(self, sandbox_dockerfile_content: str) -> None:
        """Dockerfile switches to non-root user before CMD."""
        assert "USER" in sandbox_dockerfile_content, (
            "Dockerfile must switch to non-root USER"
        )
        lines = sandbox_dockerfile_content.strip().splitlines()
        user_lines = [
            i for i, line in enumerate(lines) if line.strip().startswith("USER")
        ]
        cmd_lines = [
            i for i, line in enumerate(lines) if line.strip().startswith("CMD")
        ]
        if user_lines and cmd_lines:
            assert max(user_lines) < min(cmd_lines), (
                "USER directive must appear before CMD (run as non-root)"
            )


# ---------------------------------------------------------------------------
# Plugin directory tests
# ---------------------------------------------------------------------------

class TestStage4PluginDirectory:
    """plugins/exploit_scripts/ directory structure."""

    def test_exploit_scripts_dir_exists(self) -> None:
        """plugins/exploit_scripts/ directory exists."""
        assert PLUGINS_DIR.exists(), f"Not found: {PLUGINS_DIR}"
        assert PLUGINS_DIR.is_dir()

    def test_gitkeep_exists(self) -> None:
        """.gitkeep exists in plugins/exploit_scripts/."""
        gitkeep = PLUGINS_DIR / ".gitkeep"
        assert gitkeep.exists(), f"Not found: {gitkeep}"

    def test_readme_exists(self) -> None:
        """README.md exists in plugins/exploit_scripts/."""
        readme = PLUGINS_DIR / "README.md"
        assert readme.exists(), f"Not found: {readme}"
        assert readme.stat().st_size > 0, "README.md must not be empty"


# ---------------------------------------------------------------------------
# Migration file tests
# ---------------------------------------------------------------------------

class TestStage4Migration:
    """Alembic migration 008 — exploitation_runs and exploitation_approvals."""

    def test_migration_file_exists(self) -> None:
        """008_add_exploitation_models.py exists in alembic/versions/."""
        assert MIGRATION_008.exists(), f"Not found: {MIGRATION_008}"

    def test_migration_creates_exploitation_runs(
        self, migration_008_content: str
    ) -> None:
        """Migration creates exploitation_runs table."""
        assert "exploitation_runs" in migration_008_content, (
            "Migration 008 must create 'exploitation_runs' table"
        )

    def test_migration_creates_exploitation_approvals(
        self, migration_008_content: str
    ) -> None:
        """Migration creates exploitation_approvals table."""
        assert "exploitation_approvals" in migration_008_content, (
            "Migration 008 must create 'exploitation_approvals' table"
        )

    def test_migration_has_upgrade(self, migration_008_content: str) -> None:
        """Migration has upgrade() function."""
        assert "def upgrade" in migration_008_content

    def test_migration_has_downgrade(self, migration_008_content: str) -> None:
        """Migration has downgrade() function."""
        assert "def downgrade" in migration_008_content

    def test_migration_revision_is_008(self, migration_008_content: str) -> None:
        """Migration revision ID is '008'."""
        assert re.search(r'revision.*=.*"008"', migration_008_content), (
            "Migration revision must be '008'"
        )

    def test_migration_enables_rls(self, migration_008_content: str) -> None:
        """Migration enables Row Level Security on exploitation tables."""
        assert "ROW LEVEL SECURITY" in migration_008_content.upper() or "row level security" in migration_008_content.lower(), (
            "Migration must enable RLS on exploitation tables"
        )

    def test_migration_has_tenant_id_columns(
        self, migration_008_content: str
    ) -> None:
        """Both tables must have tenant_id column for multi-tenancy."""
        assert migration_008_content.count("tenant_id") >= 2, (
            "Both exploitation_runs and exploitation_approvals must have tenant_id"
        )
