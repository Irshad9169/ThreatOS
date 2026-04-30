from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Index, Integer, String, Boolean, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class TIEnrichment(Base):
    __tablename__ = "ti_enrichments"
    id:           Mapped[str]           = mapped_column(String(36),  primary_key=True,
                                              default=lambda: str(uuid.uuid4()))
    ioc_type:     Mapped[str]           = mapped_column(String(20),  nullable=False)
    ioc_value:    Mapped[str]           = mapped_column(String(500), nullable=False)
    source:       Mapped[str]           = mapped_column(String(30),  nullable=False)
    verdict:      Mapped[str]           = mapped_column(String(20),  nullable=False, default="unknown")
    score:        Mapped[int|None]      = mapped_column(Integer,     nullable=True)
    country:      Mapped[str|None]      = mapped_column(String(100), nullable=True)
    asn:          Mapped[str|None]      = mapped_column(String(200), nullable=True)
    tags:         Mapped[list]          = mapped_column(JSONBCompat, nullable=False, default=list)
    raw_response: Mapped[dict|None]     = mapped_column(JSONBCompat, nullable=True)
    enriched_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at:   Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        UniqueConstraint("ioc_type", "ioc_value", "source", name="uq_ti_ioc_source"),
        Index("ix_ti_ioc",     "ioc_type", "ioc_value"),
        Index("ix_ti_verdict", "verdict"),
        Index("ix_ti_expires", "expires_at"),
    )
