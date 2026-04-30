"""add audit_logs table

Revision ID: 003
Revises: 002
Create Date: 2026-04-24
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "003"
down_revision: Union[str, None]               = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id          VARCHAR(36)   NOT NULL PRIMARY KEY,
            timestamp   TIMESTAMPTZ   NOT NULL,
            user_id     VARCHAR(36),
            username    VARCHAR(100),
            role        VARCHAR(20),
            action      VARCHAR(100)  NOT NULL,
            resource    VARCHAR(50)   NOT NULL,
            resource_id VARCHAR(100),
            detail      TEXT,
            ip_address  VARCHAR(45),
            user_agent  VARCHAR(255),
            result      VARCHAR(20)   NOT NULL DEFAULT 'success',
            changes     JSONB
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_timestamp ON audit_logs (timestamp DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_username  ON audit_logs (username)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_action    ON audit_logs (action)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_resource  ON audit_logs (resource)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_result    ON audit_logs (result)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_logs CASCADE")
