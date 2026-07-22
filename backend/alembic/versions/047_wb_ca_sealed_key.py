"""047 — Web Workbench proxy CA sealed-key column (WB-P2b-1).

Revision ID: 047
Revises: 046
Create Date: 2026-07-22

Adds ``wb_proxy_listeners.ca_sealed_key`` (BYTEA / BLOB, nullable) to hold the
proxy MITM CA private key SEALED (Fernet ciphertext) with an external KEK. The
plaintext key is never stored; ``ca_secrets_ref`` records which KEK sealed it.
Purely additive — no RLS change (the table already enforces tenant isolation).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "047"
down_revision: str | None = "046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "wb_proxy_listeners"
_COLUMN = "ca_sealed_key"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column(_COLUMN, sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column(_TABLE, _COLUMN)
