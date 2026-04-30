from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class RuleVersion(Base):
    __tablename__ = "rule_versions"
    id:          Mapped[str]      = mapped_column(String(36), primary_key=True,
                                       default=lambda: str(uuid.uuid4()))
    rule_id:     Mapped[str]      = mapped_column(String(36),  nullable=False)
    version:     Mapped[int]      = mapped_column(Integer,     nullable=False, default=1)
    changed_by:  Mapped[str|None] = mapped_column(String(100), nullable=True)
    changed_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_type: Mapped[str]      = mapped_column(String(20),  nullable=False)
    snapshot:    Mapped[dict]     = mapped_column(JSONBCompat, nullable=False, default=dict)
    __table_args__ = (
        Index("ix_rule_versions_rule", "rule_id"),
        Index("ix_rule_versions_at",   "changed_at"),
    )
