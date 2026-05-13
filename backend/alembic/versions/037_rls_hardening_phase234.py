"""037 — RLS hardening for Phase 2/3/4 tables + fix patche_proposals typo

Revision ID: 037
Revises: 036_phase4_gateway_benchmarks_release
Create Date: 2026-05-13

Adds RLS isolation to 10 tenant-scoped tables that were created in 034/035/036
without row-level security. Also renames patche_proposals → patch_proposals.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "037"
down_revision: Union[str, None] = "036"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = [
    # Phase 2 (034)
    "sandbox_artifacts",
    "risk_scores",
    "abac_policies",
    # Phase 3 (035)
    "binary_dynamic_runs",
    "binary_custody",
    "incident_enrichments",
    "integration_logs",
    "compliance_evidence",
    "safety_alerts",
    # Phase 4 (036)
    "gateway_invocations",
    "research_artifacts",
]


def upgrade() -> None:
    for table in _TABLES:
        op.execute(
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"
        )
        op.execute(
            f"CREATE POLICY {table}_tenant_isolation ON {table} "
            "USING (tenant_id = current_setting('app.current_tenant_id'))"
        )

    op.execute("ALTER TABLE patche_proposals RENAME TO patch_proposals")
    op.execute("ALTER POLICY patches_tenant_isolation ON patch_proposals RENAME TO patch_proposals_tenant_isolation")


def downgrade() -> None:
    op.execute("ALTER TABLE patch_proposals RENAME TO patche_proposals")
    op.execute("ALTER POLICY patch_proposals_tenant_isolation ON patche_proposals RENAME TO patches_tenant_isolation")

    for table in reversed(_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
