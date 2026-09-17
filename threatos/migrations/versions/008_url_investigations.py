"""url investigation history

Revision ID: 008
Revises: 007
Create Date: 2026-09-17
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "008"
down_revision: Union[str, None]               = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS url_investigations (
            id              VARCHAR(36)  NOT NULL PRIMARY KEY,
            url             TEXT         NOT NULL,
            domain          VARCHAR(255) NOT NULL,
            overall_verdict VARCHAR(20)  NOT NULL,
            report_text     TEXT         NOT NULL,
            investigated_by VARCHAR(100),
            investigated_at TIMESTAMPTZ  NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_url_investigations_domain "
               "ON url_investigations (domain)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_url_investigations_investigated_at "
               "ON url_investigations (investigated_at)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS url_investigations CASCADE")
