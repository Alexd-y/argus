"""052 — FORCE ROW LEVEL SECURITY on core tenant-scoped tables (SEC-002).

Revision ID: 052
Revises: 051
Create Date: 2026-07-24

SEC-002 remediation. Migrations 002/003/005/006/007/008/017/019/020/021/033/034/
035/036/037 created tenant-scoped tables with ``ENABLE ROW LEVEL SECURITY`` only.
The application connects to PostgreSQL as the *table owner* (``argus``), and a
table owner **bypasses** RLS unless ``FORCE ROW LEVEL SECURITY`` is set. That
left tenant isolation on the hot-path tables (scans, findings, reports, …)
dependent solely on app-layer ``WHERE tenant_id`` filters — defense-in-depth was
absent. Newer tables (026/027/045/046/048–051) already ``FORCE``; this migration
brings the older core tables up to the same standard.

The upgrade is deliberately guarded and idempotent: a table is forced only when
it (a) exists, (b) already has RLS enabled, and (c) has at least one policy.
Guard (c) is critical — forcing RLS on a table with no policy would deny *all*
access, including the owner, and break the application.

OPERATIONAL PRECONDITION (why this migration is written but not auto-applied):
Under FORCE, every read/write against these tables — including background Celery
workers, beat schedulers, and future data migrations — MUST set
``app.current_tenant_id`` (via ``set_session_tenant`` / ``SET LOCAL``) or rows
become invisible and INSERTs fail the WITH CHECK. Validate on staging that no
system/worker path writes without a tenant context before applying to prod.

On SQLite (smoke round-trip tests) RLS is unsupported, so upgrade/downgrade are
no-ops and the migration round-trips cleanly (matches the 045 pattern).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "052"
down_revision: str | None = "051"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Evidence-based list of tenant-scoped tables that had ENABLE-only RLS prior to
# this migration (see module docstring for the source migration per group).
_CORE_ENABLE_ONLY_TABLES: tuple[str, ...] = (
    # 002_rls_and_audit_immutable
    # ``users`` IS forced — this is the reviewed SEC-002 decision
    # (docs/rls-force-052-checklist.md §3.1: "Exempt users from the FORCE set" was
    # rejected; "add a policy allowing lookup without a tenant context" was chosen).
    # The pre-auth login lookup in src/api/routers/auth.py reads ``users`` with no
    # tenant context, which FORCE would hide. Migration 053 adds the SELECT-only
    # ``users_auth_bootstrap`` policy (satisfied only when the GUC is unset) so login
    # keeps working, while tenant-scoped sessions and all writes stay isolated by the
    # 002 ``tenant_isolation`` policy. Ordering is safe: 052 forces ``users`` (guard
    # (c) is met by ``tenant_isolation`` from 002), then 053 installs the bootstrap
    # policy in the following revision.
    "users",
    "targets",
    "scans",
    "scan_steps",
    "scan_events",
    "findings",
    "reports",
    "audit_logs",
    # 003_backend_core_tables_rls
    "subscriptions",
    "scan_timeline",
    "assets",
    "tool_runs",
    "evidence",
    "policies",
    "usage_metering",
    "provider_configs",
    "provider_health",
    "phase_inputs",
    "phase_outputs",
    "report_objects",
    "screenshots",
    # 005_recon_models
    "engagements",
    "recon_targets",
    "scan_jobs",
    "artifacts",
    "normalized_findings",
    "hypotheses",
    # 006 / 007 / 008
    "threat_model_runs",
    "vulnerability_analysis_runs",
    "exploitation_runs",
    "exploitation_approvals",
    # 017 / 019 / 020 / 021
    "finding_notes",
    "report_bundles",
    "mcp_audit",
    "notification_dispatch_log",
    # 033_phase1_ingestion_knowledge_graph
    "repos",
    "repo_artifacts",
    "knowledge_nodes",
    "knowledge_edges",
    "threat_models",
    # 034_phase2_sandbox_patches_rbac (patche_proposals renamed to patch_proposals in 037)
    "sandbox_runs",
    "patch_proposals",
    "access_audit_log",
    "approval_workflows",
    # 035 / 036
    "binary_analyses",
    "gateway_providers",
    # 037_rls_hardening_phase234
    "sandbox_artifacts",
    "risk_scores",
    "abac_policies",
    "binary_dynamic_runs",
    "binary_custody",
    "incident_enrichments",
    "integration_logs",
    "compliance_evidence",
    "safety_alerts",
    "gateway_invocations",
    "research_artifacts",
)


def _table_array_literal() -> str:
    # Table names are static module constants (no external input) — safe to inline.
    joined = ", ".join(f"'{name}'" for name in _CORE_ENABLE_ONLY_TABLES)
    return f"ARRAY[{joined}]::text[]"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(
        f"""
        DO $$
        DECLARE
            r record;
        BEGIN
            FOR r IN
                SELECT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = current_schema()
                  AND c.relkind = 'r'
                  AND c.relname = ANY ({_table_array_literal()})
                  AND c.relrowsecurity = true
                  AND c.relforcerowsecurity = false
                  AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
            LOOP
                EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', r.relname);
                RAISE NOTICE 'SEC-002: FORCED RLS on %', r.relname;
            END LOOP;
        END
        $$;
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(
        f"""
        DO $$
        DECLARE
            r record;
        BEGIN
            FOR r IN
                SELECT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = current_schema()
                  AND c.relkind = 'r'
                  AND c.relname = ANY ({_table_array_literal()})
                  AND c.relforcerowsecurity = true
            LOOP
                EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', r.relname);
            END LOOP;
        END
        $$;
        """
    )
