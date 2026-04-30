"""add users table

Revision ID: 002
Revises: 001
Create Date: 2026-04-23
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision:       str                          = "002"
down_revision:  Union[str, None]             = "001"
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            VARCHAR(36)  NOT NULL PRIMARY KEY,
            username      VARCHAR(100) NOT NULL UNIQUE,
            email         VARCHAR(255) NOT NULL UNIQUE,
            full_name     VARCHAR(200),
            password_hash VARCHAR(255) NOT NULL,
            role          VARCHAR(20)  NOT NULL DEFAULT 'analyst',
            is_active     BOOLEAN      NOT NULL DEFAULT true,
            created_at    TIMESTAMPTZ  NOT NULL,
            last_login    TIMESTAMPTZ,
            api_key       VARCHAR(64)  UNIQUE
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_username ON users (username)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_email    ON users (email)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_api_key  ON users (api_key)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS users CASCADE")
