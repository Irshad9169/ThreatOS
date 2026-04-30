from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

SCAN_STATUSES = ("pending","running","completed","failed","cancelled")

class ScanResult(Base):
    __tablename__ = "scan_results"
    id:           Mapped[str]          = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target:       Mapped[str]          = mapped_column(String(255), nullable=False)
    scan_type:    Mapped[str]          = mapped_column(String(30),  nullable=False, default="quick")
    status:       Mapped[str]          = mapped_column(String(20),  nullable=False, default="pending")
    started_at:   Mapped[datetime|None]= mapped_column(DateTime(timezone=True), nullable=True)
    finished_at:  Mapped[datetime|None]= mapped_column(DateTime(timezone=True), nullable=True)
    duration_s:   Mapped[float|None]   = mapped_column(Float, nullable=True)
    hosts_up:     Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    hosts_down:   Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    open_ports:   Mapped[list]         = mapped_column(JSONBCompat, nullable=False, default=list)
    os_guesses:   Mapped[list]         = mapped_column(JSONBCompat, nullable=False, default=list)
    scan_data:    Mapped[dict]         = mapped_column(JSONBCompat, nullable=False, default=dict)
    error_detail: Mapped[str|None]     = mapped_column(String(1000), nullable=True)
    requested_by: Mapped[str|None]     = mapped_column(String(100),  nullable=True)
    __table_args__ = (
        Index("ix_scan_results_target",  "target"),
        Index("ix_scan_results_status",  "status"),
        Index("ix_scan_results_started", "started_at"),
    )
