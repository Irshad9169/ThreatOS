from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base

class UrlInvestigation(Base):
    __tablename__ = "url_investigations"
    id:              Mapped[str]           = mapped_column(String(36), primary_key=True,
                                                  default=lambda: str(uuid.uuid4()))
    url:             Mapped[str]           = mapped_column(Text, nullable=False)
    domain:          Mapped[str]           = mapped_column(String(255), nullable=False)
    overall_verdict: Mapped[str]           = mapped_column(String(20), nullable=False)
    report_text:     Mapped[str]           = mapped_column(Text, nullable=False)
    investigated_by: Mapped[str | None]    = mapped_column(String(100), nullable=True)
    investigated_at: Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        Index("ix_url_investigations_domain",          "domain"),
        Index("ix_url_investigations_investigated_at",  "investigated_at"),
    )
