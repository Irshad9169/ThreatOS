"""
models/coverage_matrix.py
──────────────────────────
CoverageMatrix — one row per ATT&CK technique.

Tracks whether each technique is covered by at least one enabled
detection rule. Updated by the coverage_service on demand.
The SOC dashboard renders this as an ATT&CK heatmap.

Coverage status bands (derived, not stored):
  covered=True,  confidence_avg >= 0.8  → strong
  covered=True,  confidence_avg <  0.8  → weak
  covered=False, priority_gap=True      → priority gap
  covered=False, priority_gap=False     → gap
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat


class CoverageMatrix(Base):
    __tablename__ = "coverage_matrix"

    # technique_id is the natural primary key: "T1059.001"
    technique_id: Mapped[str] = mapped_column(
        String(20), primary_key=True, nullable=False
    )

    # Human-readable name from the ATT&CK bundle
    technique_name: Mapped[str | None] = mapped_column(
        String(200), nullable=True
    )

    # ATT&CK tactic shortname, e.g. "execution"
    tactic: Mapped[str | None] = mapped_column(
        String(60), nullable=True
    )

    # ── Rule coverage stats ───────────────────────────────────────────────────
    rule_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    confidence_avg: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    covered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # When the last matching alert fired for this technique
    last_triggered: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Platforms from the ATT&CK bundle: ["windows", "linux", ...]
    platforms: Mapped[list] = mapped_column(
        JSONBCompat, nullable=False, default=list
    )

    # True when no rule covers this technique AND it is actively
    # used by tracked threat actors (Phase 3 adds actor tracking;
    # Phase 1 sets this to False for all uncovered techniques)
    priority_gap: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # Timestamp of last coverage recomputation
    refreshed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_coverage_tactic",   "tactic"),
        Index("ix_coverage_covered",  "covered"),
        Index("ix_coverage_priority", "priority_gap"),
    )

    def __repr__(self) -> str:
        return (
            f"<CoverageMatrix {self.technique_id} "
            f"covered={self.covered} "
            f"rules={self.rule_count}>"
        )
