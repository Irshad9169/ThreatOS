"""security hardening — token blacklist, rate limit tracking

Revision ID: 004
Revises: 003
Create Date: 2026-04-24
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "004"
down_revision: Union[str, None]               = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Token blacklist — revoked JWTs before expiry
    op.execute("""
        CREATE TABLE IF NOT EXISTS token_blacklist (
            jti        VARCHAR(64)  NOT NULL PRIMARY KEY,
            user_id    VARCHAR(36)  NOT NULL,
            revoked_at TIMESTAMPTZ  NOT NULL,
            expires_at TIMESTAMPTZ  NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_token_blacklist_expires ON token_blacklist (expires_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_token_blacklist_user    ON token_blacklist (user_id)")

    # Login attempts — for rate limiting
    op.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id         VARCHAR(36)  NOT NULL PRIMARY KEY,
            ip_address VARCHAR(45)  NOT NULL,
            username   VARCHAR(100),
            success    BOOLEAN      NOT NULL DEFAULT false,
            attempted_at TIMESTAMPTZ NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_login_attempts_ip  ON login_attempts (ip_address)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_login_attempts_at  ON login_attempts (attempted_at)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS token_blacklist CASCADE")
    op.execute("DROP TABLE IF EXISTS login_attempts CASCADE")
