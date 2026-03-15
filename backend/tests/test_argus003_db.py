"""DB tests for ARGUS-003 (Phase 2: Core Backend).

Models structure, migration files. No real DB required.
"""

import uuid
from pathlib import Path

import pytest
from src.db.models import (
    AuditLog,
    Base,
    Finding,
    Report,
    Scan,
    ScanEvent,
    ScanStep,
    Target,
    Tenant,
    User,
    gen_uuid,
)


class TestGenUuid:
    """gen_uuid helper."""

    def test_returns_valid_uuid_string(self) -> None:
        """gen_uuid returns valid UUID string."""
        uid = gen_uuid()
        uuid.UUID(uid)
        assert isinstance(uid, str)

    def test_unique_per_call(self) -> None:
        """Each call returns different UUID."""
        u1, u2 = gen_uuid(), gen_uuid()
        assert u1 != u2


class TestModelsStructure:
    """Model class structure and metadata."""

    def test_base_exists(self) -> None:
        """Base declarative base exists."""
        assert Base is not None
        assert hasattr(Base, "metadata")

    def test_tenant_table_name(self) -> None:
        """Tenant has correct __tablename__."""
        assert Tenant.__tablename__ == "tenants"

    def test_user_table_name(self) -> None:
        """User has correct __tablename__."""
        assert User.__tablename__ == "users"

    def test_target_table_name(self) -> None:
        """Target has correct __tablename__."""
        assert Target.__tablename__ == "targets"

    def test_scan_table_name(self) -> None:
        """Scan has correct __tablename__."""
        assert Scan.__tablename__ == "scans"

    def test_scan_step_table_name(self) -> None:
        """ScanStep has correct __tablename__."""
        assert ScanStep.__tablename__ == "scan_steps"

    def test_scan_event_table_name(self) -> None:
        """ScanEvent has correct __tablename__."""
        assert ScanEvent.__tablename__ == "scan_events"

    def test_report_table_name(self) -> None:
        """Report has correct __tablename__."""
        assert Report.__tablename__ == "reports"

    def test_finding_table_name(self) -> None:
        """Finding has correct __tablename__."""
        assert Finding.__tablename__ == "findings"

    def test_audit_log_table_name(self) -> None:
        """AuditLog has correct __tablename__."""
        assert AuditLog.__tablename__ == "audit_logs"

    def test_all_tables_in_metadata(self) -> None:
        """All models registered in Base.metadata."""
        tables = {t.name for t in Base.metadata.tables.values()}
        expected = {
            "tenants",
            "users",
            "targets",
            "scans",
            "scan_steps",
            "scan_events",
            "reports",
            "findings",
            "audit_logs",
        }
        assert expected.issubset(tables)


class TestMigrationFiles:
    """Alembic migration files exist and are valid."""

    @pytest.fixture
    def migrations_dir(self) -> Path:
        """Path to alembic versions."""
        return Path(__file__).resolve().parent.parent / "alembic" / "versions"

    def test_migrations_dir_exists(self, migrations_dir: Path) -> None:
        """alembic/versions exists."""
        assert migrations_dir.exists()
        assert migrations_dir.is_dir()

    def test_initial_migration_exists(self, migrations_dir: Path) -> None:
        """001_initial_schema migration exists."""
        files = list(migrations_dir.glob("001*.py"))
        assert len(files) >= 1

    def test_initial_migration_has_upgrade_downgrade(
        self, migrations_dir: Path
    ) -> None:
        """001 migration defines upgrade and downgrade."""
        content = (migrations_dir / "001_initial_schema.py").read_text()
        assert "def upgrade(" in content
        assert "def downgrade(" in content

    def test_rls_migration_exists(self, migrations_dir: Path) -> None:
        """002_rls migration exists."""
        files = list(migrations_dir.glob("002*.py"))
        assert len(files) >= 1
