"""
models/asset.py
────────────────
Asset — an enriched host record used for business-context risk scoring.

Criticality tiers (1-4):
  1 = development / sandbox     → low business impact if compromised
  2 = internal workstation      → medium impact
  3 = internal server           → high impact
  4 = production / critical     → critical (PCI, HIPAA, OT, crown jewels)

The criticality value flows directly into compute_risk_score() in
rule_engine.py as the asset_criticality multiplier. A tier-4 asset
hit by the same rule as a tier-1 asset will score 4× higher.

Design decisions:
  - hostname is the canonical join key against Alert.entity_host
  - ip_addresses stored as JSON array (SQLite compat; INET[] on PG)
  - tags allows free-form classification ("pci-scope", "dmz", "ot")
  - extra stores arbitrary k/v metadata without schema migrations
"""
from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat


VALID_ENVIRONMENTS = ("production", "staging", "development", "dmz", "ot", "cloud", "unknown")
VALID_OS_TYPES     = ("windows", "linux", "macos", "network", "cloud", "unknown")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    # hostname is the join key: Alert.entity_host == Asset.hostname
    hostname: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )

    # IP addresses stored as JSON list for cross-dialect compat
    ip_addresses: Mapped[list] = mapped_column(
        JSONBCompat, nullable=False, default=list
    )

    # ── Risk context ──────────────────────────────────────────────────────────
    criticality: Mapped[int] = mapped_column(
        Integer, nullable=False, default=2
    )
    # 1=dev, 2=workstation, 3=server, 4=critical

    # ── Classification ────────────────────────────────────────────────────────
    owner_team: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    environment: Mapped[str] = mapped_column(
        String(30), nullable=False, default="unknown"
    )
    os_type: Mapped[str] = mapped_column(
        String(30), nullable=False, default="unknown"
    )

    # ── Free-form metadata ────────────────────────────────────────────────────
    tags: Mapped[list] = mapped_column(
        JSONBCompat, nullable=False, default=list
    )
    extra: Mapped[dict] = mapped_column(
        JSONBCompat, nullable=False, default=dict
    )

    __table_args__ = (
        Index("ix_assets_hostname",    "hostname",    unique=True),
        Index("ix_assets_criticality", "criticality"),
        Index("ix_assets_environment", "environment"),
        UniqueConstraint("hostname", name="uq_assets_hostname"),
        CheckConstraint(
            "criticality BETWEEN 1 AND 4",
            name="ck_assets_criticality",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Asset hostname={self.hostname!r} "
            f"criticality={self.criticality} "
            f"env={self.environment!r}>"
        )
