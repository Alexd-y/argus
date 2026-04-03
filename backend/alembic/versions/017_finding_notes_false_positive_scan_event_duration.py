"""Finding notes table, findings false-positive flags, scan_events.duration_sec.

Revision ID: 017
Revises: 016
"""

from alembic import op

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS finding_notes (
            id VARCHAR(36) PRIMARY KEY,
            finding_id VARCHAR(36) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            author VARCHAR(255) NOT NULL DEFAULT 'system',
            note TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_finding_notes_finding_id ON finding_notes(finding_id)")

    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS false_positive BOOLEAN NOT NULL DEFAULT false"
    )
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS false_positive_reason TEXT"
    )

    op.execute(
        "ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS duration_sec DOUBLE PRECISION"
    )

    op.execute("ALTER TABLE finding_notes ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_notes")
    op.execute("""
        CREATE POLICY tenant_isolation ON finding_notes
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
    """)


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON finding_notes")
    op.execute("ALTER TABLE finding_notes DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TABLE IF EXISTS finding_notes")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS false_positive")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS false_positive_reason")
    op.execute("ALTER TABLE scan_events DROP COLUMN IF EXISTS duration_sec")
