# Docker Build Verification Suite

**Type:** Testing Component  
**Location:** `backend/tests/test_docker_build.py`  
**Last Updated:** 2026-03-19  
**Status:** ✅ 19/19 tests passing

---

## Purpose

Автоматическая верификация Docker-конфигурации ARGUS:
- ✅ Dockerfile структура (builder + runtime stages)
- ✅ Обязательные `COPY` инструкции (main.py, src/, **app/**, alembic, requirements)
- ✅ Существование необходимых директорий в backend/
- ✅ docker-compose.yml валидность и конфигурация
- ✅ Build контекст корректен
- ✅ Worker наследует backend image

---

## Test Structure

### Class: `TestBackendDockerfile`

Проверяет backend Dockerfile и структуру приложения.

| Test | Purpose | Result |
|------|---------|--------|
| `test_dockerfile_exists` | Dockerfile exists at `infra/backend/Dockerfile` | ✅ Pass |
| `test_copy_main_py` | Dockerfile copies `main.py` | ✅ Pass |
| `test_copy_src` | Dockerfile copies `src/` directory | ✅ Pass |
| `test_copy_app` | **Dockerfile copies `app/` (schemas, prompts)** | ✅ Pass |
| `test_copy_alembic` | Dockerfile copies `alembic/` for migrations | ✅ Pass |
| `test_copy_requirements` | Dockerfile copies `requirements.txt` in builder | ✅ Pass |
| `test_backend_app_dir_exists` | `backend/app/` directory exists | ✅ Pass |
| `test_backend_src_dir_exists` | `backend/src/` directory exists | ✅ Pass |
| `test_backend_main_py_exists` | `backend/main.py` exists | ✅ Pass |
| `test_backend_requirements_exists` | `backend/requirements.txt` exists | ✅ Pass |

**Critical:** `test_copy_app` проверяет наличие `COPY app/ ./app/` для поддержки schemas и prompts.

### Class: `TestWorkerDockerfile`

Проверяет worker Dockerfile.

| Test | Purpose | Result |
|------|---------|--------|
| `test_worker_dockerfile_exists` | Worker Dockerfile exists | ✅ Pass |
| `test_worker_from_backend_image` | Worker uses `argus-backend` as base image | ✅ Pass |
| `test_worker_celery_cmd` | Worker Dockerfile runs `celery` | ✅ Pass |

### Class: `TestDockerComposeBuild`

Проверяет docker-compose.yml конфигурацию.

| Test | Purpose | Result |
|------|---------|--------|
| `test_compose_exists` | docker-compose.yml exists | ✅ Pass |
| `test_compose_valid_yaml` | docker-compose.yml is valid YAML | ✅ Pass |
| `test_backend_has_build_section` | Backend service has `build` section | ✅ Pass |
| `test_backend_build_context_points_to_backend` | Build context points to `backend/` dir | ✅ Pass |
| `test_worker_has_build_section` | Worker service has `build` section | ✅ Pass |
| `test_backend_and_worker_images_defined` | Both services have image names (`argus-*`) | ✅ Pass |

**Total: 19 tests** ✅ All passing

---

## Usage

### Run All Docker Build Tests

```bash
cd ARGUS/backend
pytest tests/test_docker_build.py -v
```

### Run Specific Test Class

```bash
# Backend Dockerfile tests only
pytest tests/test_docker_build.py::TestBackendDockerfile -v

# Worker tests only
pytest tests/test_docker_build.py::TestWorkerDockerfile -v

# Docker Compose tests only
pytest tests/test_docker_build.py::TestDockerComposeBuild -v
```

### Run Specific Test

```bash
# Check app/ COPY instruction
pytest tests/test_docker_build.py::TestBackendDockerfile::test_copy_app -v
```

### With Coverage

```bash
pytest tests/test_docker_build.py --cov=backend --cov-report=html
```

---

## Implementation Details

### Fixtures

```python
@pytest.fixture(scope="module")
def backend_dockerfile_content() -> str:
    """Read backend Dockerfile content."""
    return BACKEND_DOCKERFILE.read_text(encoding="utf-8")

@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Load and parse docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)
```

### Key Test Examples

#### Test: `test_copy_app`

```python
def test_copy_app(self, backend_dockerfile_content: str) -> None:
    """Dockerfile copies app/ (schemas, prompts)."""
    assert "COPY app/" in backend_dockerfile_content, (
        "Backend Dockerfile must COPY app/ (schemas, prompts)"
    )
```

**What it checks:**
- Literal string `"COPY app/"` present in Dockerfile
- Ensures schemas and prompts are copied to container

#### Test: `test_backend_app_dir_exists`

```python
def test_backend_app_dir_exists(self) -> None:
    """backend/app/ exists (required for COPY app/)."""
    app_dir = BACKEND_DIR / "app"
    assert app_dir.exists(), f"backend/app/ must exist: {app_dir}"
    assert app_dir.is_dir()
```

**What it checks:**
- `backend/app/` directory physically exists
- Is a directory (not a file)
- Required for docker build COPY instruction

#### Test: `test_backend_build_context_points_to_backend`

```python
def test_backend_build_context_points_to_backend(self, compose_config: dict) -> None:
    """Backend build context is ../backend (from infra)."""
    services = compose_config.get("services", {})
    build = services.get("backend", {}).get("build", {})
    if isinstance(build, dict):
        ctx = build.get("context", "")
        assert "backend" in ctx, (
            f"backend build context must point to backend dir, got: {ctx}"
        )
```

**What it checks:**
- docker-compose backend build context contains "backend"
- Typically: `context: ../backend`
- Ensures COPY instructions resolve correctly

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Docker Build Verification

on: [push, pull_request]

jobs:
  docker-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: "3.12"
      
      - name: Install dependencies
        run: |
          pip install pytest pyyaml
      
      - name: Run Docker build tests
        run: |
          cd ARGUS/backend
          pytest tests/test_docker_build.py -v
      
      - name: Build Docker images
        run: |
          cd ARGUS
          docker compose -f infra/docker-compose.yml build backend worker
      
      - name: Verify images
        run: |
          docker images | grep argus
          docker history argus-backend:latest | head -10
```

---

## Related Files

| File | Purpose |
|------|---------|
| `infra/backend/Dockerfile` | Backend multi-stage build (contains `COPY app/` line 37) |
| `infra/worker/Dockerfile` | Worker Dockerfile (FROM argus-backend) |
| `infra/docker-compose.yml` | Compose config with build sections |
| `backend/app/` | Directory with schemas & prompts (verified by tests) |
| `backend/tests/test_docker_build.py` | This test suite |

---

## Troubleshooting

### ❌ Test: `test_copy_app` Fails

**Error:** `Backend Dockerfile must COPY app/ (schemas, prompts)`

**Cause:** Line `COPY app/ ./app/` missing from Dockerfile

**Fix:**

```dockerfile
# Add to infra/backend/Dockerfile (after line 36)
COPY app/ ./app/
```

### ❌ Test: `test_backend_app_dir_exists` Fails

**Error:** `backend/app/ must exist for Docker build`

**Cause:** `backend/app/` directory doesn't exist

**Fix:**

```bash
# Verify directory structure
ls -la ARGUS/backend/app/

# If missing, create it
mkdir -p ARGUS/backend/app/schemas
mkdir -p ARGUS/backend/app/prompts
```

### ❌ Test: `test_compose_valid_yaml` Fails

**Error:** `docker-compose.yml is not valid YAML`

**Cause:** YAML syntax error

**Fix:**

```bash
# Validate compose file
docker compose -f infra/docker-compose.yml config
```

---

## Performance

- **Execution time:** ~50-100ms (all 19 tests)
- **Memory overhead:** Minimal (just file reads + YAML parsing)
- **CI/CD impact:** +5 seconds per run

---

## Future Enhancements

- [ ] Test Dockerfile `EXPOSE` port correctness
- [ ] Test multi-stage layer cache hits
- [ ] Test image size (< 500 MB target)
- [ ] Integration test: build → run → health check
- [ ] Security scanning (Trivy/Snyk integration)

---

**Test Suite Created:** 2026-03-19  
**Verified by:** Test-Writer + Test-Runner  
**CI Integration:** github-actions

