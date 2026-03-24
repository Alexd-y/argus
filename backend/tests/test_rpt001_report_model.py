"""RPT-001 — Report tier / generation metadata (model + Alembic 009).

No database connection: mapper metadata, table defaults, migration file smoke.
"""

from pathlib import Path

import pytest
from sqlalchemy import inspect as orm_inspect
from sqlalchemy.sql.schema import ScalarElementColumnDefault
from src.db.models import Report, gen_uuid


class TestReportRpt001Columns:
    """Report ORM exposes RPT-001 columns and index names."""

    def test_mapper_has_new_columns(self) -> None:
        keys = set(orm_inspect(Report).columns.keys())
        assert {
            "tier",
            "generation_status",
            "template_version",
            "prompt_version",
            "last_error_message",
            "requested_formats",
            "report_metadata",
        }.issubset(keys)

    def test_tier_and_generation_status_not_null(self) -> None:
        cols = {c.name: c for c in Report.__table__.columns}
        assert cols["tier"].nullable is False
        assert cols["generation_status"].nullable is False

    def test_optional_string_and_jsonb_nullable(self) -> None:
        cols = {c.name: c for c in Report.__table__.columns}
        for name in (
            "template_version",
            "prompt_version",
            "last_error_message",
            "requested_formats",
            "report_metadata",
        ):
            assert cols[name].nullable is True, f"{name} should be nullable"

    def test_python_column_defaults_midgard_ready(self) -> None:
        """INSERT-time defaults from mapped_column(default=...)."""
        tier_def = Report.__table__.c.tier.default
        gen_def = Report.__table__.c.generation_status.default
        assert isinstance(tier_def, ScalarElementColumnDefault)
        assert isinstance(gen_def, ScalarElementColumnDefault)
        assert tier_def.arg == "midgard"
        assert gen_def.arg == "ready"

    def test_indexes_match_migration(self) -> None:
        names = {ix.name for ix in Report.__table__.indexes}
        assert "ix_reports_tenant_target_created" in names
        assert "ix_reports_scan_tier" in names


class TestReportRpt001Instantiation:
    """Model accepts explicit values for new fields (no DB)."""

    def test_instantiate_with_metadata_fields(self) -> None:
        tid = gen_uuid()
        r = Report(
            tenant_id=tid,
            target="https://report.example.com",
            tier="asgard",
            generation_status="pending",
            template_version="tpl-2",
            prompt_version="prm-3",
            last_error_message="timeout",
            requested_formats=["json", "pdf"],
            report_metadata={"run": "e2e"},
        )
        assert r.tenant_id == tid
        assert r.tier == "asgard"
        assert r.generation_status == "pending"
        assert r.template_version == "tpl-2"
        assert r.prompt_version == "prm-3"
        assert r.last_error_message == "timeout"
        assert r.requested_formats == ["json", "pdf"]
        assert r.report_metadata == {"run": "e2e"}


class TestReportRpt001Migration009:
    """Alembic 009 file present and structurally valid."""

    @pytest.fixture
    def migrations_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent / "alembic" / "versions"

    def test_migration_file_exists(self, migrations_dir: Path) -> None:
        path = migrations_dir / "009_reports_tier_generation_metadata.py"
        assert path.is_file()

    def test_migration_defines_revision_and_hooks(self, migrations_dir: Path) -> None:
        content = (migrations_dir / "009_reports_tier_generation_metadata.py").read_text(
            encoding="utf-8"
        )
        assert 'revision: str = "009"' in content
        assert 'down_revision: str | None = "008"' in content
        assert "def upgrade(" in content
        assert "def downgrade(" in content
        assert "tier" in content
        assert "generation_status" in content
        assert "ix_reports_scan_tier" in content
        assert "ix_reports_tenant_target_created" in content
        assert "report_metadata" in content
        assert "requested_formats" in content
        assert 'server_default="midgard"' in content
        assert 'server_default="ready"' in content
        assert (
            'op.alter_column(REPORTS_TABLE, "tier", server_default=None)' not in content
        )
        assert (
            'op.alter_column(REPORTS_TABLE, "generation_status", server_default=None)'
            not in content
        )
