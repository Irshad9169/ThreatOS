"""
models/scan_result.py
──────────────────────
ScanResult — persisted Nmap scan output.

One row per scan job. The full Nmap output is stored in scan_data
(JSONB) so nothing is discarded. Derived summary fields (open_ports,
os_guess, hosts_up) are extracted for fast querying without JSON parsing.

Oracle Linux 8 install:
    sudo dnf install nmap
    # binary at /usr/bin/nmap — same path as Ubuntu
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat


SCAN_STATUSES = ("pending", "running", "completed", "failed", "cancelled")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # ── Target ────────────────────────────────────────────────────────────────
    target:      Mapped[str] = mapped_column(String(255), nullable=False)
    # IP, CIDR, hostname or range: "10.0.0.1", "10.0.0.0/24", "host.corp"
    scan_type:   Mapped[str] = mapped_column(String(30),  nullable=False, default="quick")
    # quick | full | stealth | udp | vuln

    # ── Status ────────────────────────────────────────────────────────────────
    status:      Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    started_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_s:  Mapped[float | None]    = mapped_column(Float, nullable=True)

    # ── Summary (extracted for fast querying) ─────────────────────────────────
    hosts_up:   Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_down: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # List of {"host": str, "port": int, "protocol": str, "service": str, "state": str}
    open_ports: Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)

    # List of {"host": str, "os_guess": str, "accuracy": int}
    os_guesses: Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)

    # ── Full output ───────────────────────────────────────────────────────────
    scan_data:    Mapped[dict] = mapped_column(JSONBCompat, nullable=False, default=dict)
    error_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # ── Audit ─────────────────────────────────────────────────────────────────
    requested_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

    __table_args__ = (
        Index("ix_scan_results_target",  "target"),
        Index("ix_scan_results_status",  "status"),
        Index("ix_scan_results_started", "started_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanResult target={self.target!r} "
            f"status={self.status!r} "
            f"hosts_up={self.hosts_up}>"
        )
