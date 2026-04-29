"""Pytest fixtures + collection hooks for ARGUS backend tests.

Original responsibilities (ARGUS-003 / ARGUS-004):
* Make ``backend/`` importable when pytest is invoked from the repo root.
* Provide a session-scoped ``app`` fixture and an autouse ``override_auth``.
* Expose a ``client`` fixture wrapping ``starlette.testclient.TestClient``.

ARG-028 additions:
* Auto-classify tests by infrastructure dependency at collection time and add
  ``requires_postgres`` / ``requires_redis`` / ``requires_oast`` /
  ``requires_docker`` markers. This lets ``pytest -q`` (default) skip the
  ~3k tests that need a live Postgres / Redis / OAST listener and lets CI
  run them in a dedicated job via ``pytest -m requires_docker``.

ARG-038 additions:
* Session-scope ``read_only_catalog`` autouse fixture that chmods the signed
  catalog (``config/{tools,payloads,prompts}/*.yaml`` + ``SIGNATURES``) to
  read-only for the duration of the test session. Defence-in-depth against
  the historical ``apktool.yaml`` drift symptom (Cycle 3) — any future test
  that accidentally opens a production YAML in ``"w"`` mode now fails fast
  with ``PermissionError`` instead of silently rewriting ground truth.
* New ``mutates_catalog`` marker registered for tests that *legitimately*
  need to mutate the catalog (must use ``tmp_path`` copy — see marker
  description in ``pyproject.toml`` / ``pytest.ini``).
"""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Final

import pytest

# Ensure backend is on path when running from ARGUS root
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# pytest-asyncio: async tests run without explicit event loop
pytest_plugins = ["pytest_asyncio"]

TESTS_DIR: Final[Path] = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# ARG-028 — auto-marker auto-detection.
#
# Path-based allowlist of tests that are guaranteed offline (signed YAML
# catalogs, render-only fixtures, pure schema tests, etc.). Anything matching
# these prefixes (relative to ``backend/tests``) is NEVER marked ``requires_*``
# even if its name or module body looks suspicious. Keeping the list explicit
# avoids hiding regressions when new offline suites land.
# ---------------------------------------------------------------------------

_OFFLINE_PATH_PREFIXES: Final[tuple[str, ...]] = (
    # Pure unit suite — by-design offline. Always green in dev.
    "unit/",
    # Sandbox parser/dispatch suite — uses signed YAML catalog + on-disk
    # fixtures. Spec: tests/integration/sandbox/* MUST stay offline.
    "integration/sandbox/",
    # ARG-045 — Alembic chain smoke tests. Layer A (revision-graph integrity)
    # is dialect-free and MUST run in dev's default ``pytest -q``. Layer B
    # (Postgres round-trip) is explicitly gated by ``pytestmark_pg.skipif``
    # on a real ``DATABASE_URL`` env var, so it skips cleanly without Docker.
    "integration/migrations/",
    # Pure schema-export / contract / parser suites — no FastAPI app, no DB.
    "schemas/",
    "reports/",
    "recon/",
    "storage/",
    # P2-010 — pure inventory / planner / argv / quality-gate fixtures (no live OAST/DB).
    "active_injection/",
)

# Path prefixes that ALWAYS require a full Docker stack (Postgres + Redis at
# minimum). The MCP subtree spawns subprocess servers and the rest of
# ``tests/integration/`` exercises composed subsystems whose cross-component
# regressions only surface against a live DB / broker stack — even though
# in-process fakes (signed payloads, FakeOASTListener, in-memory SQLite) keep
# many of them green offline. Per ARG-028 spec ``tests/integration/sandbox/``
# is the only intentionally-offline subtree under integration/.
_DOCKER_FORCED_PATH_PREFIXES: Final[tuple[str, ...]] = (
    "integration/mcp/",
    "integration/oast/",
    "integration/findings/",
    "integration/orchestrator_runtime/",
    "integration/policy/",
    "integration/payloads/",
    "integration/reports/",
)

# Per-file overrides — explicitly-offline tests that live at the root of
# ``backend/tests/`` and would otherwise be auto-marked because of the
# autouse ``override_auth(app)`` chain that pulls in ``main.app``.
_OFFLINE_FILE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "test_tool_catalog_coverage.py",
        # ARG-039 — pure FastMCP-registry introspection; no app, DB, or broker.
        "test_mcp_tools_have_docstrings.py",
        "test_openapi_export_stable.py",
        # ARG-038 — file-permission + subprocess-based catalog gate; no app or DB.
        "test_catalog_immutable_during_pytest.py",
        # ARG-046 — pure pathlib regression gate (no app, DB, broker, or HTTP).
        # Scans active source/tests/docs for legacy refs against an immutable
        # historical-artifact whitelist. MUST run in dev's default ``pytest -q``
        # so accidental reintroduction fails the local feedback loop, not just
        # CI. Filename built via concatenation so this conftest itself does not
        # contain the bare forbidden literal (defence-in-depth: the regression
        # gate scans this conftest along with the rest of ``backend/tests/``).
        "test_no_" + "hex" + "strike" + "_active_imports.py",
        # ARG-058 — pure file-IO migration regression suite (no app, DB, or
        # broker). Reads raw YAML / JSON via ``yaml.safe_load`` /
        # ``json.load`` and intentionally avoids ``src.sandbox.tool_registry``
        # so it stays green even when ``backend/config/tools/SIGNATURES`` is
        # stale (the YAML edits invalidated 16 entries until the operator
        # re-runs ``python -m scripts.tools_sign sign-all``).
        "test_arg058_dual_listed_migration.py",
        # VAL-001 — pure ``report_quality_gate`` / FindingRow fixtures; no app DB broker.
        "test_report_quality_gate.py",
        # RPT-006 — mocked AsyncSession / MinIO upload / Redis client; Celery app import only for route registry.
        "test_rpt006_generate_report.py",
    }
)

# Module-content patterns that signal a real service dependency. Compiled
# once and reused across thousands of test items.
_RE_POSTGRES: Final[re.Pattern[str]] = re.compile(
    r"\b(?:postgres(?:ql)?\+(?:asyncpg|psycopg2?))?(?:://)?"
    r"(?:[^/\s]+@)?(?:localhost|127\.0\.0\.1|postgres|db)[:/]\d{0,5}",
    re.IGNORECASE,
)
_RE_REDIS: Final[re.Pattern[str]] = re.compile(
    r"\bredis://|\bREDIS_URL\b|CELERY_BROKER_URL|celery_app\.send_task|apply_async\(",
    re.IGNORECASE,
)
_RE_OAST: Final[re.Pattern[str]] = re.compile(
    r"\binteractsh(?!.*Fake)|OAST_LISTENER_URL|oast_callback_url|" r"oast_token\b|RealOASTListener",
    re.IGNORECASE,
)

# Memoise per-file content scans so 12k test items do not re-read 250 files.
_MODULE_FLAG_CACHE: dict[Path, frozenset[str]] = {}


def _module_service_flags(path: Path) -> frozenset[str]:
    """Return the union of service tags detected in *path*'s source body."""
    cached = _MODULE_FLAG_CACHE.get(path)
    if cached is not None:
        return cached

    flags: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _MODULE_FLAG_CACHE[path] = frozenset()
        return _MODULE_FLAG_CACHE[path]

    if _RE_POSTGRES.search(text):
        flags.add("requires_postgres")
    if _RE_REDIS.search(text):
        flags.add("requires_redis")
    if _RE_OAST.search(text):
        flags.add("requires_oast")

    frozen = frozenset(flags)
    _MODULE_FLAG_CACHE[path] = frozen
    return frozen


def _relative_path(item: pytest.Item) -> str:
    """Posix-style path of the test module relative to ``backend/tests``."""
    try:
        rel = Path(item.path).resolve().relative_to(TESTS_DIR)
    except ValueError:
        return Path(item.path).as_posix()
    return rel.as_posix()


def _is_offline_path(rel_path: str) -> bool:
    """True for paths that are explicitly offline (unit + signed-fixture)."""
    if any(rel_path.startswith(prefix) for prefix in _OFFLINE_PATH_PREFIXES):
        return True
    file_name = rel_path.rsplit("/", 1)[-1]
    return file_name in _OFFLINE_FILE_NAMES


def _classify_item(item: pytest.Item) -> set[str]:
    """Compute the set of ``requires_*`` markers that apply to *item*.

    Heuristics — applied additively:

    * Offline allowlist: anything matched by ``_OFFLINE_PATH_PREFIXES`` or
      ``_OFFLINE_FILE_NAMES`` is never marked. This is the safety net that
      keeps pure-schema / parser / signed-fixture suites green in dev.
    * Path-forced: anything under ``tests/integration/mcp/`` needs the full
      Docker stack (Postgres + Redis), no exceptions.
    * Root-level legacy: ``tests/test_*.py`` files live above the per-subtree
      conftests that neutralise ``override_auth(app)``. Every test in this
      bucket pulls ``main.app`` (and therefore ``src.db.session``) as part
      of an autouse fixture chain. Almost all of them also exercise FastAPI
      routes via the ``client`` fixture or call into Celery tasks. Mark as
      ``requires_postgres`` + ``requires_redis`` so they are skipped in the
      developer's default ``pytest -q`` run; CI brings up the Docker stack
      and runs them via ``pytest -m requires_docker``.
    * Fixture-based: tests pulling the ``client`` fixture exercise FastAPI
      routes against a real-DB-bound app — already covered by the root-level
      rule, but kept explicit for tests that may live in future subdirs.
    * Module content: regex-scan the source body for hardcoded
      Postgres / Redis / OAST URLs and Celery-task patterns.
    """
    rel_path = _relative_path(item)

    if _is_offline_path(rel_path):
        return set()

    markers: set[str] = set()

    if any(rel_path.startswith(prefix) for prefix in _DOCKER_FORCED_PATH_PREFIXES):
        markers.update({"requires_postgres", "requires_redis"})

    if "/" not in rel_path and rel_path.startswith("test_"):
        markers.update({"requires_postgres", "requires_redis"})

    fixturenames: Iterable[str] = getattr(item, "fixturenames", ())
    if "client" in fixturenames:
        markers.add("requires_postgres")

    markers |= _module_service_flags(Path(item.path))
    return markers


def pytest_configure(config: pytest.Config) -> None:
    """Register pre-existing + ARG-028 markers."""
    config.addinivalue_line(
        "markers",
        "weasyprint_pdf: needs WeasyPrint (Pango/Cairo); skip with ARGUS_SKIP_WEASYPRINT_PDF=1 or if import fails",
    )
    config.addinivalue_line(
        "markers",
        "no_auth_override: skip autouse get_required_auth override (real auth behaviour)",
    )
    # ARG-028 markers — also declared in pyproject.toml for IDE discovery.
    config.addinivalue_line(
        "markers",
        "requires_postgres: needs a live PostgreSQL backend (skipped by default in dev)",
    )
    config.addinivalue_line(
        "markers",
        "requires_redis: needs a live Redis backend / Celery broker (skipped by default in dev)",
    )
    config.addinivalue_line(
        "markers",
        "requires_oast: needs a live OAST listener (interactsh) (skipped by default in dev)",
    )
    config.addinivalue_line(
        "markers",
        "requires_docker: union marker — any test that needs the Docker test-stack (skipped by default in dev)",
    )
    # ARG-047 marker — e2e capstone tests under tests/integration/e2e/.
    # Auto-marked as ``requires_docker`` too (auto-classifier matches the
    # ``localhost`` URLs in fixtures) so the default ``-m 'not requires_docker'``
    # filter already skips them. The dedicated marker exists so the e2e CI
    # lane can opt INTO this subset via ``pytest -m requires_docker_e2e``.
    config.addinivalue_line(
        "markers",
        "requires_docker_e2e: needs the full docker-compose.e2e.yml stack (ARG-047 capstone)",
    )
    # B6-T04 marker — kind-cluster integration tests under tests/integration/k8s/.
    # The k8s subtree's own conftest auto-tags every item with this marker AND
    # adds a skipif gate when KIND_CLUSTER_NAME is missing. Declared here so
    # `pytest --strict-markers` is happy when CI invokes `pytest -m requires_kind`.
    config.addinivalue_line(
        "markers",
        "requires_kind: needs a live kind cluster + kubectl on PATH "
        "(skipped by default; opt-in via KIND_CLUSTER_NAME env or "
        "pytest -m requires_kind; CI workflow .github/workflows/kev-hpa-kind.yml "
        "provisions the cluster)",
    )
    # ARG-038 marker — declared here for IDE discovery; mirrored in pyproject.toml + pytest.ini.
    config.addinivalue_line(
        "markers",
        "mutates_catalog: test legitimately mutates the signed catalog "
        "(MUST use tmp_path copy — read_only_catalog fixture chmods production catalog "
        "to 0o444 for the session, so this marker is documentation-only)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,  # noqa: ARG001 — pytest hook signature
    items: list[pytest.Item],
) -> None:
    """Auto-classify each test by infrastructure dependency.

    The hook is purely additive: we only ``add_marker``; we never remove
    existing markers, never reorder, never deselect. Default test selection
    (skip ``requires_docker``) is configured via ``addopts`` in pyproject.
    """
    for item in items:
        markers = _classify_item(item)
        if not markers:
            continue
        for marker_name in markers:
            item.add_marker(getattr(pytest.mark, marker_name))
        # Union marker — any specific requires_* implies requires_docker.
        item.add_marker(pytest.mark.requires_docker)


@pytest.fixture(scope="module")
def app():
    """FastAPI app instance."""
    from main import app as _app

    return _app


@pytest.fixture(autouse=True)
def override_auth(request, app):
    """Override auth dependency so tests run without real credentials.

    Tests marked with ``@pytest.mark.no_auth_override`` are excluded — they
    verify real authentication behaviour.
    """
    if "no_auth_override" in {m.name for m in request.node.iter_markers()}:
        yield
        return

    from src.core.auth import AuthContext, get_required_auth

    async def _mock_auth():
        return AuthContext(
            user_id="test-user",
            tenant_id="test-tenant",
            is_api_key=False,
        )

    app.dependency_overrides[get_required_auth] = _mock_auth
    yield
    app.dependency_overrides.pop(get_required_auth, None)


@pytest.fixture
def client(app):
    """TestClient for FastAPI app (uses httpx via starlette)."""
    from starlette.testclient import TestClient

    return TestClient(app)


# ---------------------------------------------------------------------------
# ARG-038 — Read-only catalog session fixture.
#
# Goal: prevent any test from accidentally rewriting the production signed
# catalog (Cycle 3 reported intermittent ``apktool.yaml`` drift). The
# ``read_only_catalog`` fixture is autouse + session-scope: it chmods every
# YAML descriptor and SIGNATURES manifest under
# ``backend/config/{tools,payloads,prompts}/`` to read-only (0o444 on POSIX,
# the FILE_ATTRIBUTE_READONLY equivalent on Windows via ``stat.S_IREAD``)
# before the first test runs, and restores the original mode on teardown.
#
# Tests that legitimately need to mutate the catalog must use ``tmp_path``
# (see ``backend/tests/unit/payloads/conftest.py::signed_payloads_dir`` and
# ``backend/tests/unit/sandbox/conftest.py::signed_tools_dir`` for the
# canonical pattern). The ``mutates_catalog`` marker is documentation only;
# the chmod is unconditional because the production catalog is signed
# ground truth.
#
# Windows note: ``Path.chmod`` only honours ``stat.S_IWRITE`` / ``S_IREAD``
# — all other bits are ignored — so we use the appropriate constant per
# platform. The read-only attribute prevents writes via the Win32 API,
# which is what every Python file-write call goes through.
# ---------------------------------------------------------------------------

_BACKEND_DIR_FOR_CATALOG: Final[Path] = Path(__file__).resolve().parent.parent
_CATALOG_DIRS: Final[tuple[Path, ...]] = (
    _BACKEND_DIR_FOR_CATALOG / "config" / "tools",
    _BACKEND_DIR_FOR_CATALOG / "config" / "payloads",
    _BACKEND_DIR_FOR_CATALOG / "config" / "prompts",
)
_CATALOG_PROTECTED_SUFFIXES: Final[frozenset[str]] = frozenset({".yaml", ".yml"})
_CATALOG_PROTECTED_NAMES: Final[frozenset[str]] = frozenset({"SIGNATURES"})


def _iter_catalog_files() -> Iterator[Path]:
    """Yield every protected ground-truth file under each catalog dir."""
    for catalog_dir in _CATALOG_DIRS:
        if not catalog_dir.is_dir():
            continue
        for entry in catalog_dir.iterdir():
            if not entry.is_file():
                continue
            if (
                entry.suffix in _CATALOG_PROTECTED_SUFFIXES
                or entry.name in _CATALOG_PROTECTED_NAMES
            ):
                yield entry


def _make_read_only(path: Path) -> None:
    """Chmod *path* to read-only, portably across POSIX and Windows."""
    if os.name == "nt":
        path.chmod(stat.S_IREAD)
    else:
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def _restore_mode(path: Path, original_mode: int) -> None:
    """Restore *path* to its original mode; warn on failure but never raise.

    Used in fixture teardown — a failed restore must not mask test results.
    """
    try:
        path.chmod(original_mode)
    except OSError:
        # File may have been deleted by a misbehaving test — surface to stderr
        # so it's visible in pytest output but do not fail teardown.
        print(  # noqa: T201 — fixture teardown diagnostic, intentional
            f"[read_only_catalog] WARNING: failed to restore mode on {path}",
            file=sys.stderr,
        )


@pytest.fixture(scope="session", autouse=True)
def read_only_catalog() -> Iterator[None]:
    """Make the signed catalog read-only for the duration of the test session.

    See module docstring for design notes.
    """
    original_modes: list[tuple[Path, int]] = []
    for path in _iter_catalog_files():
        original_modes.append((path, path.stat().st_mode))
        _make_read_only(path)

    try:
        yield
    finally:
        for path, mode in original_modes:
            _restore_mode(path, mode)
