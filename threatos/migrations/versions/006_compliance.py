"""compliance — sessions, audit protection, rule approval

Revision ID: 006
Revises: 005
Create Date: 2026-04-24
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "006"
down_revision: Union[str, None]               = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Active sessions table
    op.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id           VARCHAR(36)  NOT NULL PRIMARY KEY,
            user_id      VARCHAR(36)  NOT NULL,
            jti          VARCHAR(64)  NOT NULL UNIQUE,
            ip_address   VARCHAR(45),
            user_agent   VARCHAR(255),
            created_at   TIMESTAMPTZ  NOT NULL,
            last_seen_at TIMESTAMPTZ  NOT NULL,
            expires_at   TIMESTAMPTZ  NOT NULL,
            is_active    BOOLEAN      NOT NULL DEFAULT true
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_sessions_user    ON user_sessions (user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_sessions_jti     ON user_sessions (jti)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_sessions_expires ON user_sessions (expires_at)")

    # Rule approval workflow
    op.execute("""
        CREATE TABLE IF NOT EXISTS rule_change_requests (
            id           VARCHAR(36)  NOT NULL PRIMARY KEY,
            rule_id      VARCHAR(36),
            requested_by VARCHAR(100) NOT NULL,
            requested_at TIMESTAMPTZ  NOT NULL,
            change_type  VARCHAR(20)  NOT NULL,
            proposed_ast JSONB,
            reason       VARCHAR(1000),
            status       VARCHAR(20)  NOT NULL DEFAULT 'pending',
            reviewed_by  VARCHAR(100),
            reviewed_at  TIMESTAMPTZ,
            review_note  VARCHAR(1000)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_rule_cr_status ON rule_change_requests (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_rule_cr_rule   ON rule_change_requests (rule_id)")

    # Protect audit_logs — add hash chain for tamper detection
    op.execute("""
        ALTER TABLE audit_logs
        ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64),
        ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(64)
    """)

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_sessions CASCADE")
    op.execute("DROP TABLE IF EXISTS rule_change_requests CASCADE")
    op.execute("ALTER TABLE audit_logs DROP COLUMN IF EXISTS prev_hash")
    op.execute("ALTER TABLE audit_logs DROP COLUMN IF EXISTS entry_hash")
