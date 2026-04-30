from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

VALID_ROLES = ("analyst", "engineer", "admin", "ingest")

class User(Base):
    __tablename__ = "users"
    id:            Mapped[str]           = mapped_column(String(36),  primary_key=True, default=lambda: str(uuid.uuid4()))
    username:      Mapped[str]           = mapped_column(String(100), nullable=False, unique=True)
    email:         Mapped[str]           = mapped_column(String(255), nullable=False, unique=True)
    full_name:     Mapped[str|None]      = mapped_column(String(200), nullable=True)
    password_hash: Mapped[str]           = mapped_column(String(255), nullable=False)
    role:          Mapped[str]           = mapped_column(String(20),  nullable=False, default="analyst")
    is_active:     Mapped[bool]          = mapped_column(Boolean,     nullable=False, default=True)
    created_at:    Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=False)
    last_login:    Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key:       Mapped[str|None]      = mapped_column(String(64),  nullable=True, unique=True)
    __table_args__ = (
        Index("ix_users_username", "username", unique=True),
        Index("ix_users_email",    "email",    unique=True),
        Index("ix_users_api_key",  "api_key"),
    )
