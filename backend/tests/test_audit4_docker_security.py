"""H-2, H-3: Docker compose security checks."""

from __future__ import annotations

from pathlib import Path

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "infra" / "docker-compose.yml"


class TestDockerSecurity:
    """Worker must not run as root; docker.sock must be read-only."""

    def test_compose_file_exists(self) -> None:
        assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"

    def test_worker_not_root(self) -> None:
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        assert 'user: "0:0"' not in content, "Worker must not run as root (user 0:0)"
        assert 'user: "0"' not in content, "Worker must not run as root (user 0)"

    def test_docker_sock_has_ro(self) -> None:
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        lines = [line for line in content.splitlines() if "docker.sock" in line]
        assert len(lines) > 0, "docker.sock mount not found in compose file"
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if stripped.startswith("-"):
                assert ":ro" in line, f"docker.sock mount must be read-only: {stripped}"

    def test_worker_has_non_root_user(self) -> None:
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        assert 'user: "1000:' in content, "Worker should run as non-root user (UID 1000)"
