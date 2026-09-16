"""
models/purple_team_run.py
──────────────────────────
PurpleTeamRun — one validation exercise.

A purple team run takes a target ATT&CK technique (or a full chain),
emulates a detection event, and checks whether the detection rules
fire as expected. The result tells the SOC team:
  - Which rules covered the technique
  - Which rules were expected but missed
  - The detection gap percentage for that technique

Fields:
  technique_id    → the technique being validated
  chain_id        → optional: validate all techniques in a chain
  emulated_event  → the NormalizedEvent fields used for emulation
  rules_expected  → rule IDs that should have fired
  rules_fired     → rule IDs that actually fired
  rules_missed    → rules_expected - rules_fired
  detection_rate  → len(rules_fired) / len(rules_expected) * 100
  verdict         → pass / partial / fail
  run_by          → analyst who triggered the run
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from threatos.models.base import Base
from threatos.models.raw_event import JSONBCompat


VERDICTS = ("pass", "partial", "fail", "unknown")


class PurpleTeamRun(Base):
    __tablename__ = "purple_team_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # What was tested
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    chain_id:     Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Emulation inputs
    emulated_event: Mapped[dict] = mapped_column(JSONBCompat, nullable=False, default=dict)

    # Results
    rules_expected: Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)
    rules_fired:    Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)
    rules_missed:   Mapped[list] = mapped_column(JSONBCompat, nullable=False, default=list)
    detection_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verdict:        Mapped[str]   = mapped_column(String(10), nullable=False, default="unknown")

    # Context
    run_by:    Mapped[str | None]  = mapped_column(String(100), nullable=True)
    notes:     Mapped[str | None]  = mapped_column(String(1000), nullable=True)
    run_at:    Mapped[datetime]    = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<PurpleTeamRun technique={self.technique_id} "
            f"verdict={self.verdict!r} "
            f"detection={self.detection_rate:.0f}%>"
        )
