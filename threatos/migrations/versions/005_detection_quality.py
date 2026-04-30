"""detection quality — rule metrics, fp tracking, rule versions

Revision ID: 005
Revises: 004
Create Date: 2026-04-24
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision:      str                             = "005"
down_revision: Union[str, None]               = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Rule performance metrics
    op.execute("""
        CREATE TABLE IF NOT EXISTS rule_metrics (
            rule_id          VARCHAR(36)  NOT NULL PRIMARY KEY,
            rule_name        VARCHAR(200),
            total_evals      BIGINT       NOT NULL DEFAULT 0,
            total_matches    BIGINT       NOT NULL DEFAULT 0,
            total_fp         BIGINT       NOT NULL DEFAULT 0,
            avg_eval_ms      FLOAT        NOT NULL DEFAULT 0.0,
            last_eval_at     TIMESTAMPTZ,
            last_match_at    TIMESTAMPTZ,
            fp_rate          FLOAT        NOT NULL DEFAULT 0.0,
            suggested_disable BOOLEAN     NOT NULL DEFAULT false
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_rule_metrics_fp ON rule_metrics (fp_rate DESC)")

    # Rule version history
    op.execute("""
        CREATE TABLE IF NOT EXISTS rule_versions (
            id           VARCHAR(36)  NOT NULL PRIMARY KEY,
            rule_id      VARCHAR(36)  NOT NULL,
            version      INTEGER      NOT NULL DEFAULT 1,
            changed_by   VARCHAR(100),
            changed_at   TIMESTAMPTZ  NOT NULL,
            change_type  VARCHAR(20)  NOT NULL,
            snapshot     JSONB        NOT NULL DEFAULT '{}'
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_rule_versions_rule ON rule_versions (rule_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_rule_versions_at  ON rule_versions (changed_at DESC)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS rule_metrics  CASCADE")
    op.execute("DROP TABLE IF EXISTS rule_versions CASCADE")
