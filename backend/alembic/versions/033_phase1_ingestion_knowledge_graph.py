"""Phase1 — ingestion & knowledge graph tables

Revision ID: 033
Revises: 032_admin_mfa_columns
Create Date: 2026-05-11

Tables:
  - repos: connected repositories
  - repo_artifacts: per-file provenance tracks
  - knowledge_nodes: code property graph nodes
  - knowledge_edges: code property graph edges
  - threat_models: STRIDE results
  - threat_model_versions: per-commit snapshots
  - scan_targets: what to scan (full_repo, PR, binary)
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "033"
down_revision: Union[str, None] = "032"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # repos
    op.create_table(
        "repos",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("provider", sa.String(20), nullable=False),  # github | gitlab | bitbucket
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(512), nullable=False),
        sa.Column("default_branch", sa.String(255), server_default="main"),
        sa.Column("clone_url", sa.String(1024)),
        sa.Column("web_url", sa.String(1024)),
        sa.Column("language", sa.String(64)),
        sa.Column("description", sa.Text),
        sa.Column("private", sa.Boolean, server_default=sa.text("false")),
        sa.Column("archived", sa.Boolean, server_default=sa.text("false")),
        sa.Column("webhook_secret", sa.String(255)),
        sa.Column("size_kb", sa.Integer, server_default=sa.text("0")),
        sa.Column("last_synced_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "full_name", name="uq_repos_tenant_fullname"),
    )
    op.execute("ALTER TABLE repos ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY repos_tenant_isolation ON repos USING (tenant_id = current_setting('app.current_tenant_id'))")

    # repo_artifacts
    op.create_table(
        "repo_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("repo_id", sa.String(36), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("artifact_type", sa.String(32), server_default="source_code"),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("source", sa.String(32), server_default="webhook"),
        sa.Column("size_bytes", sa.Integer, server_default=sa.text("0")),
        sa.Column("parsed_info", JSONB),
        sa.Column("synced_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("repo_id", "path", "commit_sha", name="uq_repo_artifacts_path_commit"),
    )
    op.execute("ALTER TABLE repo_artifacts ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY repo_artifacts_tenant_isolation ON repo_artifacts USING (tenant_id = current_setting('app.current_tenant_id'))")

    # knowledge_nodes
    op.create_table(
        "knowledge_nodes",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("repo_id", sa.String(36), nullable=False),
        sa.Column("node_type", sa.String(32), nullable=False),
        sa.Column("name", sa.String(512)),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("line_start", sa.Integer),
        sa.Column("line_end", sa.Integer),
        sa.Column("language", sa.String(32)),
        sa.Column("metadata", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_knowledge_nodes_repo_type", "knowledge_nodes", ["repo_id", "node_type"])
    op.execute("ALTER TABLE knowledge_nodes ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY knowledge_nodes_tenant_isolation ON knowledge_nodes USING (tenant_id = current_setting('app.current_tenant_id'))")

    # knowledge_edges
    op.create_table(
        "knowledge_edges",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("repo_id", sa.String(36), nullable=False),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("edge_type", sa.String(32), nullable=False),
        sa.Column("metadata", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_knowledge_edges_source", "knowledge_edges", ["source_id"])
    op.create_index("ix_knowledge_edges_target", "knowledge_edges", ["target_id"])
    op.execute("ALTER TABLE knowledge_edges ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY knowledge_edges_tenant_isolation ON knowledge_edges USING (tenant_id = current_setting('app.current_tenant_id'))")

    # threat_models
    op.create_table(
        "threat_models",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("repo_id", sa.String(36), nullable=False),
        sa.Column("version", sa.String(16), server_default="1.0"),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("model_json", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_threat_models_repo_version", "threat_models", ["repo_id", "version"])
    op.execute("ALTER TABLE threat_models ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY threat_models_tenant_isolation ON threat_models USING (tenant_id = current_setting('app.current_tenant_id'))")

    # threat_model_versions
    op.create_table(
        "threat_model_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("threat_model_id", sa.String(36), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=False),
        sa.Column("diff_json", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["threat_model_id"], ["threat_models.id"], ondelete="CASCADE"),
    )

    # scan_targets
    op.create_table(
        "scan_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("repo_id", sa.String(36), nullable=False),
        sa.Column("target_type", sa.String(32), server_default="full_repo"),
        sa.Column("target_ref", sa.String(64)),
        sa.Column("paths", JSONB),
        sa.Column("scan_options", JSONB),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("scan_targets")
    op.drop_table("threat_model_versions")
    op.drop_table("threat_models")
    op.drop_table("knowledge_edges")
    op.drop_table("knowledge_nodes")
    op.drop_table("repo_artifacts")
    op.drop_table("repos")
