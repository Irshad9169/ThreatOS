"""initial schema

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS raw_events (
            id           VARCHAR(36)  NOT NULL,
            received_at  TIMESTAMPTZ  NOT NULL,
            log_source   VARCHAR(30)  NOT NULL,
            raw_payload  JSONB        NOT NULL DEFAULT '{}',
            normalized   JSONB,
            hash         VARCHAR(64)  UNIQUE,
            PRIMARY KEY (id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_raw_events_received_at ON raw_events (received_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_raw_events_log_source  ON raw_events (log_source)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            id             VARCHAR(36)   NOT NULL PRIMARY KEY,
            name           VARCHAR(200)  NOT NULL UNIQUE,
            description    VARCHAR(1000),
            author         VARCHAR(100),
            technique_id   VARCHAR(20)   NOT NULL,
            tactic         VARCHAR(60)   NOT NULL,
            log_sources    JSONB         NOT NULL DEFAULT '[]',
            platforms      JSONB         NOT NULL DEFAULT '[]',
            sigma_yaml     VARCHAR(10000),
            detection_ast  JSONB         NOT NULL DEFAULT '{}',
            severity       INTEGER       NOT NULL DEFAULT 5,
            confidence     FLOAT         NOT NULL DEFAULT 0.7,
            tags           JSONB         NOT NULL DEFAULT '[]',
            enabled        BOOLEAN       NOT NULL DEFAULT true,
            last_triggered TIMESTAMPTZ,
            trigger_count  BIGINT        NOT NULL DEFAULT 0
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_detection_rules_technique_id ON detection_rules (technique_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_detection_rules_enabled      ON detection_rules (enabled)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                VARCHAR(36)  NOT NULL PRIMARY KEY,
            rule_id           VARCHAR(100),
            rule_name         VARCHAR(200),
            event_id          VARCHAR(100),
            technique_id      VARCHAR(20)  NOT NULL,
            tactic            VARCHAR(60)  NOT NULL,
            severity          INTEGER      NOT NULL,
            confidence        FLOAT        NOT NULL,
            asset_criticality INTEGER      NOT NULL DEFAULT 2,
            risk_score        FLOAT        NOT NULL,
            entity_host       VARCHAR(255),
            entity_user       VARCHAR(255),
            entity_process    VARCHAR(255),
            entity_ip         VARCHAR(45),
            status            VARCHAR(20)  NOT NULL DEFAULT 'open'
                              CONSTRAINT ck_alerts_status
                              CHECK (status IN ('open','investigating','escalated','closed','false_positive')),
            created_at        TIMESTAMPTZ  NOT NULL,
            updated_at        TIMESTAMPTZ  NOT NULL,
            closed_at         TIMESTAMPTZ,
            description       VARCHAR(500),
            raw_match         JSONB
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_technique_id ON alerts (technique_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_status       ON alerts (status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_risk_score   ON alerts (risk_score)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_entity_host  ON alerts (entity_host)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alerts_created_at   ON alerts (created_at)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS coverage_matrix (
            technique_id   VARCHAR(20)  NOT NULL PRIMARY KEY,
            technique_name VARCHAR(200),
            tactic         VARCHAR(60),
            rule_count     INTEGER      NOT NULL DEFAULT 0,
            confidence_avg FLOAT        NOT NULL DEFAULT 0.0,
            covered        BOOLEAN      NOT NULL DEFAULT false,
            last_triggered TIMESTAMPTZ,
            platforms      JSONB        NOT NULL DEFAULT '[]',
            priority_gap   BOOLEAN      NOT NULL DEFAULT false,
            refreshed_at   TIMESTAMPTZ
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id           VARCHAR(36)  NOT NULL PRIMARY KEY,
            hostname     VARCHAR(255) NOT NULL UNIQUE,
            ip_addresses JSONB        NOT NULL DEFAULT '[]',
            criticality  INTEGER      NOT NULL DEFAULT 2
                         CONSTRAINT ck_assets_criticality CHECK (criticality BETWEEN 1 AND 4),
            owner_team   VARCHAR(100),
            environment  VARCHAR(30)  NOT NULL DEFAULT 'unknown',
            os_type      VARCHAR(30)  NOT NULL DEFAULT 'unknown',
            tags         JSONB        NOT NULL DEFAULT '[]',
            extra        JSONB        NOT NULL DEFAULT '{}'
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_criticality ON assets (criticality)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS attack_chains (
            id               VARCHAR(36)  NOT NULL PRIMARY KEY,
            host             VARCHAR(255) NOT NULL,
            chain_hash       VARCHAR(64)  NOT NULL UNIQUE,
            alert_ids        JSONB        NOT NULL DEFAULT '[]',
            technique_ids    JSONB        NOT NULL DEFAULT '[]',
            tactics_observed JSONB        NOT NULL DEFAULT '[]',
            tactic_count     INTEGER      NOT NULL DEFAULT 1,
            risk_score       FLOAT        NOT NULL DEFAULT 0.0,
            first_seen       TIMESTAMPTZ  NOT NULL,
            last_seen        TIMESTAMPTZ  NOT NULL,
            duration_seconds INTEGER      NOT NULL DEFAULT 0,
            status           VARCHAR(20)  NOT NULL DEFAULT 'open'
                             CONSTRAINT ck_attack_chains_status
                             CHECK (status IN ('open','investigating','closed')),
            is_multi_stage   BOOLEAN      NOT NULL DEFAULT false
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_attack_chains_host         ON attack_chains (host)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_attack_chains_risk_score   ON attack_chains (risk_score)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_attack_chains_is_multi_stage ON attack_chains (is_multi_stage)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS purple_team_runs (
            id             VARCHAR(36)   NOT NULL PRIMARY KEY,
            technique_id   VARCHAR(20)   NOT NULL,
            chain_id       VARCHAR(36),
            emulated_event JSONB         NOT NULL DEFAULT '{}',
            rules_expected JSONB         NOT NULL DEFAULT '[]',
            rules_fired    JSONB         NOT NULL DEFAULT '[]',
            rules_missed   JSONB         NOT NULL DEFAULT '[]',
            detection_rate FLOAT         NOT NULL DEFAULT 0.0,
            verdict        VARCHAR(10)   NOT NULL DEFAULT 'unknown',
            run_by         VARCHAR(100),
            notes          VARCHAR(1000),
            run_at         TIMESTAMPTZ   NOT NULL
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id           VARCHAR(36)   NOT NULL PRIMARY KEY,
            target       VARCHAR(255)  NOT NULL,
            scan_type    VARCHAR(30)   NOT NULL DEFAULT 'quick',
            status       VARCHAR(20)   NOT NULL DEFAULT 'pending',
            started_at   TIMESTAMPTZ,
            finished_at  TIMESTAMPTZ,
            duration_s   FLOAT,
            hosts_up     INTEGER       NOT NULL DEFAULT 0,
            hosts_down   INTEGER       NOT NULL DEFAULT 0,
            open_ports   JSONB         NOT NULL DEFAULT '[]',
            os_guesses   JSONB         NOT NULL DEFAULT '[]',
            scan_data    JSONB         NOT NULL DEFAULT '{}',
            error_detail VARCHAR(1000),
            requested_by VARCHAR(100)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_results_target  ON scan_results (target)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_results_status  ON scan_results (status)")

def downgrade() -> None:
    for t in ["scan_results","purple_team_runs","attack_chains",
              "assets","coverage_matrix","alerts","detection_rules","raw_events"]:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
