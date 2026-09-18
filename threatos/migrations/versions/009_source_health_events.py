"""source health events (URL Scanner dependency monitoring)

Revision ID: 009
Revises: 008
Create Date: 2026-09-18
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "009"
down_revision: Union[str, None]               = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS source_health_events (
            id          VARCHAR(36)  NOT NULL PRIMARY KEY,
            source      VARCHAR(30)  NOT NULL,
            outcome     VARCHAR(20)  NOT NULL,
            message     VARCHAR(500),
            occurred_at TIMESTAMPTZ  NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_source_health_source_occurred "
               "ON source_health_events (source, occurred_at)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS source_health_events CASCADE")
