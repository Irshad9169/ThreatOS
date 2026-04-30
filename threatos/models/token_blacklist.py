from __future__ import annotations
from datetime import datetime
from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"
    jti:        Mapped[str]      = mapped_column(String(64),  primary_key=True)
    user_id:    Mapped[str]      = mapped_column(String(36),  nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        Index("ix_token_blacklist_expires", "expires_at"),
        Index("ix_token_blacklist_user",    "user_id"),
    )
