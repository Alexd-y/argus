"""070 — add llm_model_aliases (per-tenant LLM alias overrides).

Backs ``AliasRegistry.load_from_db``: one row per ``(tenant_id, alias)`` whose
``providers`` JSON overrides the env/config alias defaults at startup. Additive and
backward compatible — deployments with no rows keep the env/config defaults.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "070"
down_revision: str | None = "069"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "llm_model_aliases"


def _has_table(table: str) -> bool:
    bind = op.get_bind()
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    if _has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("alias", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False, server_default="planner"),
        sa.Column("providers", JSONB(), nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_llm_model_aliases_tenant_alias",
        _TABLE,
        ["tenant_id", "alias"],
        unique=True,
    )


def downgrade() -> None:
    if not _has_table(_TABLE):
        return
    op.drop_index("ix_llm_model_aliases_tenant_alias", table_name=_TABLE)
    op.drop_table(_TABLE)
