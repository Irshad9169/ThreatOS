"""threat intelligence enrichment

Revision ID: 007
Revises: 006
Create Date: 2026-04-27
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "007"
down_revision: Union[str, None]               = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS ti_enrichments (
            id           VARCHAR(36)  NOT NULL PRIMARY KEY,
            ioc_type     VARCHAR(20)  NOT NULL,
            ioc_value    VARCHAR(500) NOT NULL,
            source       VARCHAR(30)  NOT NULL,
            verdict      VARCHAR(20)  NOT NULL DEFAULT 'unknown',
            score        INTEGER,
            country      VARCHAR(100),
            asn          VARCHAR(200),
            tags         JSONB        NOT NULL DEFAULT '[]',
            raw_response JSONB,
            enriched_at  TIMESTAMPTZ  NOT NULL,
            expires_at   TIMESTAMPTZ  NOT NULL,
            UNIQUE (ioc_type, ioc_value, source)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_ti_ioc     ON ti_enrichments (ioc_type, ioc_value)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ti_verdict ON ti_enrichments (verdict)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_ti_expires ON ti_enrichments (expires_at)")

    # Add enrichment summary to alerts table
    op.execute("""
        ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS ti_enriched   BOOLEAN     DEFAULT false,
        ADD COLUMN IF NOT EXISTS ti_verdict    VARCHAR(20),
        ADD COLUMN IF NOT EXISTS ti_summary    TEXT
    """)

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ti_enrichments CASCADE")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS ti_enriched")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS ti_verdict")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS ti_summary")
