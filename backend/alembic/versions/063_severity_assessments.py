"""063 — finding taxonomy axes + severity_assessments provenance table.

Revision ID: 063
Revises: 062
Create Date: 2026-09-09

Two additive, idempotent changes backing the canonical severity/provenance
model (docs/finding-severity-and-counting.md):

1. Four nullable taxonomy columns on ``findings`` — ``record_kind``,
   ``validation``, ``lifecycle``, ``remediation_priority`` — so the four
   orthogonal axes stop sharing the overloaded ``confidence`` / ``status`` /
   ``false_positive`` fields.
2. A ``severity_assessments`` table recording every severity opinion (method,
   source, policy version, rationale, evidence, supersedes, conflicts, and the
   manual-override audit trail). The effective severity is selected
   deterministically from these rows, so identical data always yields the same
   band regardless of write order.

All changes are additive/nullable; existing rows keep their semantics.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "063"
down_revision: str | None = "062"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_FINDING_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("record_kind", sa.String(20)),
    ("validation", sa.String(20)),
    ("lifecycle", sa.String(20)),
    ("remediation_priority", sa.String(4)),
)


def _json_type() -> sa.types.TypeEngine:
    bind = op.get_bind()
    return postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def _existing_columns(table: str) -> set[str]:
    bind = op.get_bind()
    return {col["name"] for col in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    existing = _existing_columns("findings")
    for name, col_type in _FINDING_COLUMNS:
        if name not in existing:
            op.add_column("findings", sa.Column(name, col_type, nullable=True))

    if not _has_table("severity_assessments"):
        json_type = _json_type()
        op.create_table(
            "severity_assessments",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "finding_id",
                sa.String(length=36),
                sa.ForeignKey("findings.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("method", sa.String(length=32), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("cvss_score", sa.Float(), nullable=True),
            sa.Column("cvss_vector", sa.String(length=100), nullable=True),
            sa.Column("source_ref", sa.String(length=255), nullable=True),
            sa.Column("policy_version", sa.String(length=32), nullable=True),
            sa.Column("rationale", sa.Text(), nullable=True),
            sa.Column("evidence_ref", json_type, nullable=True),
            sa.Column("supersedes", sa.String(length=36), nullable=True),
            sa.Column("conflicts_with", json_type, nullable=True),
            sa.Column(
                "is_manual_override",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("override_author", sa.String(length=120), nullable=True),
            sa.Column("override_reason", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
            ),
        )
        op.create_index(
            "ix_severity_assessments_finding_id",
            "severity_assessments",
            ["finding_id"],
        )
        op.create_index(
            "ix_severity_assessments_tenant_id",
            "severity_assessments",
            ["tenant_id"],
        )

        # Tenant isolation via RLS on Postgres (matches 045-051). Skipped on
        # SQLite (smoke tests) so upgrade/downgrade still round-trips.
        if op.get_bind().dialect.name == "postgresql":
            table = "severity_assessments"
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f"""
                CREATE POLICY tenant_isolation ON "{table}"
                    USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
                """)


def downgrade() -> None:
    if _has_table("severity_assessments"):
        if op.get_bind().dialect.name == "postgresql":
            op.execute(
                'DROP POLICY IF EXISTS tenant_isolation ON "severity_assessments"'
            )
            op.execute(
                'ALTER TABLE "severity_assessments" NO FORCE ROW LEVEL SECURITY'
            )
            op.execute(
                'ALTER TABLE "severity_assessments" DISABLE ROW LEVEL SECURITY'
            )
        op.drop_index(
            "ix_severity_assessments_tenant_id", table_name="severity_assessments"
        )
        op.drop_index(
            "ix_severity_assessments_finding_id", table_name="severity_assessments"
        )
        op.drop_table("severity_assessments")

    existing = _existing_columns("findings")
    for name, _col_type in reversed(_FINDING_COLUMNS):
        if name in existing:
            op.drop_column("findings", name)
