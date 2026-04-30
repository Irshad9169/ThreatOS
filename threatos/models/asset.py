from __future__ import annotations
import uuid
from sqlalchemy import CheckConstraint, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

VALID_ENVIRONMENTS = ("production","staging","development","dmz","ot","cloud","unknown")

class Asset(Base):
    __tablename__ = "assets"
    id:           Mapped[str]      = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname:     Mapped[str]      = mapped_column(String(255), nullable=False, unique=True)
    ip_addresses: Mapped[list]     = mapped_column(JSONBCompat, nullable=False, default=list)
    criticality:  Mapped[int]      = mapped_column(Integer, nullable=False, default=2)
    owner_team:   Mapped[str|None] = mapped_column(String(100), nullable=True)
    environment:  Mapped[str]      = mapped_column(String(30),  nullable=False, default="unknown")
    os_type:      Mapped[str]      = mapped_column(String(30),  nullable=False, default="unknown")
    tags:         Mapped[list]     = mapped_column(JSONBCompat, nullable=False, default=list)
    extra:        Mapped[dict]     = mapped_column(JSONBCompat, nullable=False, default=dict)
    __table_args__ = (
        Index("ix_assets_hostname",    "hostname", unique=True),
        Index("ix_assets_criticality", "criticality"),
        UniqueConstraint("hostname", name="uq_assets_hostname"),
        CheckConstraint("criticality BETWEEN 1 AND 4", name="ck_assets_criticality"),
    )
