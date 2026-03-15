"""RLS on tenant-scoped tables + audit_logs immutable (no UPDATE/DELETE).

Revision ID: 002
Revises: 001
Create Date: 2026-03-08

"""

from typing import Sequence, Union

from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TENANT_SCOPED_TABLES = [
    "users",
    "targets",
    "scans",
    "scan_steps",
    "scan_events",
    "findings",
    "reports",
    "audit_logs",
]


def upgrade() -> None:
    # Enable RLS on tenant-scoped tables
    for table in TENANT_SCOPED_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')

    # Policy: rows visible only when app.current_tenant_id matches tenant_id
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"""
            CREATE POLICY tenant_isolation ON "{table}"
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
        """)

    # audit_logs: append-only — block UPDATE and DELETE
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_logs_immutable()
        RETURNS TRIGGER AS $$
        BEGIN
            IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'audit_logs is append-only: UPDATE and DELETE are not allowed';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER audit_logs_immutable_trigger
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE PROCEDURE audit_logs_immutable();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_immutable()")

    for table in reversed(TENANT_SCOPED_TABLES):
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
