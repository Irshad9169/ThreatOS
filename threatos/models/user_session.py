from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

class UserSession(Base):
    __tablename__ = "user_sessions"
    id:           Mapped[str]      = mapped_column(String(36), primary_key=True,
                                        default=lambda: str(uuid.uuid4()))
    user_id:      Mapped[str]      = mapped_column(String(36),  nullable=False)
    jti:          Mapped[str]      = mapped_column(String(64),  nullable=False, unique=True)
    ip_address:   Mapped[str|None] = mapped_column(String(45),  nullable=True)
    user_agent:   Mapped[str|None] = mapped_column(String(255), nullable=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active:    Mapped[bool]     = mapped_column(Boolean, nullable=False, default=True)
    __table_args__ = (
        Index("ix_sessions_user",    "user_id"),
        Index("ix_sessions_jti",     "jti",    unique=True),
        Index("ix_sessions_expires", "expires_at"),
    )
