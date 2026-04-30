from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class RuleChangeRequest(Base):
    __tablename__ = "rule_change_requests"
    id:           Mapped[str]           = mapped_column(String(36), primary_key=True,
                                              default=lambda: str(uuid.uuid4()))
    rule_id:      Mapped[str|None]      = mapped_column(String(36),   nullable=True)
    requested_by: Mapped[str]           = mapped_column(String(100),  nullable=False)
    requested_at: Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=False)
    change_type:  Mapped[str]           = mapped_column(String(20),   nullable=False)
    proposed_ast: Mapped[dict|None]     = mapped_column(JSONBCompat,  nullable=True)
    reason:       Mapped[str|None]      = mapped_column(String(1000), nullable=True)
    status:       Mapped[str]           = mapped_column(String(20),   nullable=False, default="pending")
    reviewed_by:  Mapped[str|None]      = mapped_column(String(100),  nullable=True)
    reviewed_at:  Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note:  Mapped[str|None]      = mapped_column(String(1000), nullable=True)
    __table_args__ = (
        Index("ix_rule_cr_status", "status"),
        Index("ix_rule_cr_rule",   "rule_id"),
    )
