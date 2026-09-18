from __future__ import annotations
import uuid
from datetime import datetime
from sqlalchemy import BigInteger, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id:          Mapped[str]           = mapped_column(String(36), primary_key=True,
                                           default=lambda: str(uuid.uuid4()))
    timestamp:   Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=False)
    user_id:     Mapped[str|None]      = mapped_column(String(36),  nullable=True)
    username:    Mapped[str|None]      = mapped_column(String(100), nullable=True)
    role:        Mapped[str|None]      = mapped_column(String(20),  nullable=True)
    action:      Mapped[str]           = mapped_column(String(100), nullable=False)
    resource:    Mapped[str]           = mapped_column(String(50),  nullable=False)
    resource_id: Mapped[str|None]      = mapped_column(String(100), nullable=True)
    detail:      Mapped[str|None]      = mapped_column(Text,        nullable=True)
    ip_address:  Mapped[str|None]      = mapped_column(String(45),  nullable=True)
    user_agent:  Mapped[str|None]      = mapped_column(String(255), nullable=True)
    result:      Mapped[str]           = mapped_column(String(20),  nullable=False, default="success")
    changes:     Mapped[dict|None]     = mapped_column(JSONBCompat, nullable=True)
    # Added by migration 006 (ALTER TABLE) — declared here so the hash
    # chain tamper-detection in compliance_service.py actually persists;
    # previously missing, so entry.prev_hash/entry_hash writes were
    # silently dropped and any query referencing AuditLog.entry_hash
    # raised AttributeError.
    prev_hash:   Mapped[str|None]      = mapped_column(String(64),  nullable=True)
    entry_hash:  Mapped[str|None]      = mapped_column(String(64),  nullable=True)
    # Added by migration 010. `timestamp` alone is not a safe hash-chain
    # ordering key — two entries can share the same wall-clock tick under
    # back-to-back writes, and SQL doesn't break such ties consistently
    # between the "latest hash" lookup (stamp time) and the full replay
    # (verify time). `seq` is assigned once, strictly increasing, and used
    # only for chain ordering.
    seq:         Mapped[int|None]      = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        Index("ix_audit_timestamp",   "timestamp"),
        Index("ix_audit_username",    "username"),
        Index("ix_audit_action",      "action"),
        Index("ix_audit_resource",    "resource"),
        Index("ix_audit_result",      "result"),
        Index("ix_audit_seq",         "seq"),
    )
