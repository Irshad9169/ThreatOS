"""audit chain sequence — deterministic ordering for hash-chain verification

Revision ID: 010
Revises: 009
Create Date: 2026-09-18

The hash chain in compliance_service.py ordered entries by `timestamp`
alone. Two audit entries written within the same wall-clock tick (possible
under back-to-back writes, e.g. a bulk session-revoke) would tie on that
ordering, which is not a well-defined total order — the "latest hash"
lookup used at stamp time and the ascending replay used at verify time
could then disagree about entry order, risking a false "COMPROMISED"
tamper finding for entries nobody touched. `seq` is a strictly increasing,
application-assigned counter used purely for chain ordering so that
ambiguity can no longer arise, regardless of clock resolution.
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "010"
down_revision: Union[str, None]               = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS seq BIGINT")
    # Backfill existing rows in timestamp order so the pre-existing history
    # gets a consistent (if approximate) sequence rather than all-NULL.
    op.execute("""
        WITH ordered AS (
            SELECT id, ROW_NUMBER() OVER (ORDER BY timestamp ASC) AS rn
            FROM audit_logs
        )
        UPDATE audit_logs
        SET seq = ordered.rn
        FROM ordered
        WHERE audit_logs.id = ordered.id AND audit_logs.seq IS NULL
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_seq ON audit_logs (seq)")

def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_seq")
    op.execute("ALTER TABLE audit_logs DROP COLUMN IF EXISTS seq")
