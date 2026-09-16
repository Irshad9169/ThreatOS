"""
models/attack_chain.py
───────────────────────
AttackChain — a correlated sequence of alerts on a single host
that span multiple ATT&CK tactics in kill-chain order.

Design decisions:
  - natural key: (host, chain_hash) — same attack on the same host
    should extend an existing chain rather than create a duplicate.
  - chain_hash is sha256(sorted_technique_ids + host) so re-running
    correlation on the same alert set is idempotent.
  - tactics_observed stores the kill-chain phases seen so far, ordered.
  - alert_ids is a JSON array of alert UUIDs that form this chain.
  - risk_score is the MAX risk_score among member alerts — the chain
    is as dangerous as its most dangerous individual hit.
  - status mirrors the Alert lifecycle: open/investigating/closed.
  - duration_seconds is derived (last_seen - first_seen); stored for
    fast sorting without re-joining alerts.

Phase 1 correlation window: 24 hours (configurable).
Phase 2: add actor attribution via threat intel feeds.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, Float,
    Index, Integer, String,
)
from sqlalchemy.orm import Mapped, mapped_column

from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat


CHAIN_STATUSES = ("open", "investigating", "closed")


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    # Canonical join key: the host this chain was observed on
    host: Mapped[str] = mapped_column(String(255), nullable=False)

    # Deduplication fingerprint
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # ── Composition ───────────────────────────────────────────────────────────
    # UUIDs of the alerts that make up this chain (insertion order = time order)
    alert_ids: Mapped[list] = mapped_column(
        JSONBCompat, nullable=False, default=list
    )

    # ATT&CK technique IDs observed, deduplicated, kill-chain ordered
    technique_ids: Mapped[list] = mapped_column(
        JSONBCompat, nullable=False, default=list
    )

    # Tactic shortnames observed (kill-chain order)
    tactics_observed: Mapped[list] = mapped_column(
        JSONBCompat, nullable=False, default=list
    )

    # How many distinct tactics have been observed
    tactic_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # ── Scoring ───────────────────────────────────────────────────────────────
    # Max risk_score among member alerts
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # ── Timeline ──────────────────────────────────────────────────────────────
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Cached: (last_seen - first_seen).total_seconds()
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # ── Status ────────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open"
    )

    # True when the chain spans 3+ distinct tactics (high-confidence attack)
    is_multi_stage: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    __table_args__ = (
        Index("ix_attack_chains_host",           "host"),
        Index("ix_attack_chains_status",         "status"),
        Index("ix_attack_chains_risk_score",     "risk_score"),
        Index("ix_attack_chains_first_seen",     "first_seen"),
        Index("ix_attack_chains_is_multi_stage", "is_multi_stage"),
        CheckConstraint(
            f"status IN {CHAIN_STATUSES}",
            name="ck_attack_chains_status",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<AttackChain host={self.host!r} "
            f"tactics={self.tactic_count} "
            f"score={self.risk_score:.1f} "
            f"status={self.status!r}>"
        )
