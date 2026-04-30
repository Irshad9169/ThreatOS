from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id:           Mapped[str]      = mapped_column(String(36),  primary_key=True)
    ip_address:   Mapped[str]      = mapped_column(String(45),  nullable=False)
    username:     Mapped[str|None] = mapped_column(String(100), nullable=True)
    success:      Mapped[bool]     = mapped_column(Boolean,     nullable=False, default=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        Index("ix_login_attempts_ip",  "ip_address"),
        Index("ix_login_attempts_at",  "attempted_at"),
    )
