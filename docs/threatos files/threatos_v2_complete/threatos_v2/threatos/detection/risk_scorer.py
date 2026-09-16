"""
detection/risk_scorer.py
─────────────────────────
Risk Scoring Engine v2.

v1 formula (in rule_engine.py, kept for backward compat):
    score = min((severity × confidence × asset_criticality) / 40 × 100, 100)

v2 formula adds two chain-context multipliers:
    base        = (severity × confidence × asset_criticality) / 40 × 100
    chain_boost = 1.0 + (tactic_count - 1) × 0.15   if part of chain
    stage_boost = 1.25                                if chain is multi-stage
    score_v2    = min(base × chain_boost × stage_boost, 100)

Rationale:
    An isolated credential-dump scores 35.
    The same dump as step 3 of a 5-tactic chain scores 35 × 1.6 × 1.25 = 70.
    Context lifts score; context never lowers it (chain_boost ≥ 1.0).

All inputs validated; all edge cases return sensible defaults.

Pure functions only — no DB, no I/O, no side effects.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ── Score components (stored individually on every alert) ─────────────────────

@dataclass(frozen=True)
class ScoreComponents:
    """
    All values used to compute a risk score — stored on the Alert row
    so analysts can understand exactly why a score is what it is.
    """
    severity:          int    # 1–10
    confidence:        float  # 0.0–1.0
    asset_criticality: int    # 1–4
    chain_tactic_count:int    # 1 if standalone, N if part of chain
    is_multi_stage:    bool   # True if chain has 3+ tactics
    base_score:        float  # v1 score before chain boosts
    chain_boost:       float  # multiplier from tactic_count
    stage_boost:       float  # multiplier for multi-stage chains
    final_score:       float  # 0.0–100.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity":          self.severity,
            "confidence":        self.confidence,
            "asset_criticality": self.asset_criticality,
            "chain_tactic_count":self.chain_tactic_count,
            "is_multi_stage":    self.is_multi_stage,
            "base_score":        self.base_score,
            "chain_boost":       self.chain_boost,
            "stage_boost":       self.stage_boost,
            "final_score":       self.final_score,
        }


# ── v1 formula (kept for backward compat) ────────────────────────────────────

def compute_score_v1(
    severity:          int,
    confidence:        float,
    asset_criticality: int = 2,
) -> float:
    """
    Original Phase 1 formula. Still used for standalone alerts
    (no chain context). Identical to rule_engine.compute_risk_score.
    """
    raw     = float(severity) * float(confidence) * float(asset_criticality)
    MAX_RAW = 40.0
    return round(min(raw / MAX_RAW * 100.0, 100.0), 2)


# ── v2 formula (chain-aware) ──────────────────────────────────────────────────

def compute_score_v2(
    severity:           int,
    confidence:         float,
    asset_criticality:  int  = 2,
    chain_tactic_count: int  = 1,
    is_multi_stage:     bool = False,
) -> ScoreComponents:
    """
    Chain-aware risk scoring.

    chain_boost = 1.0 + (tactic_count - 1) × TACTIC_STEP
        Each additional tactic in the chain raises the score by TACTIC_STEP.
        A 5-tactic chain gets a 1.6× boost. Capped at MAX_CHAIN_BOOST.

    stage_boost = MULTI_STAGE_BOOST if is_multi_stage else 1.0
        Multi-stage chains get an additional 25% lift on top of chain_boost.

    Returns a ScoreComponents dataclass with all values for audit trail.
    """
    TACTIC_STEP       = 0.15
    MAX_CHAIN_BOOST   = 2.0
    MULTI_STAGE_BOOST = 1.25

    # Clamp inputs to valid ranges
    sev  = max(1, min(10, int(severity)))
    conf = max(0.0, min(1.0, float(confidence)))
    crit = max(1, min(4, int(asset_criticality)))
    tc   = max(1, int(chain_tactic_count))

    base_score  = compute_score_v1(sev, conf, crit)

    chain_boost = round(
        min(1.0 + (tc - 1) * TACTIC_STEP, MAX_CHAIN_BOOST), 4
    )
    stage_boost = MULTI_STAGE_BOOST if is_multi_stage else 1.0

    final = round(min(base_score * chain_boost * stage_boost, 100.0), 2)

    return ScoreComponents(
        severity=sev,
        confidence=conf,
        asset_criticality=crit,
        chain_tactic_count=tc,
        is_multi_stage=is_multi_stage,
        base_score=base_score,
        chain_boost=chain_boost,
        stage_boost=stage_boost,
        final_score=final,
    )


def score_alert_in_context(
    severity:          int,
    confidence:        float,
    asset_criticality: int,
    chain_tactic_count: int  = 1,
    is_multi_stage:    bool  = False,
) -> float:
    """
    Convenience wrapper — returns just the final float score.
    Use compute_score_v2 when you need the full audit trail.
    """
    return compute_score_v2(
        severity, confidence, asset_criticality,
        chain_tactic_count, is_multi_stage,
    ).final_score


def rescore_alert_for_chain(
    current_score: float,
    chain_tactic_count: int,
    is_multi_stage: bool,
) -> float:
    """
    Re-score an existing alert when it gets linked to a chain.
    Called by the correlation engine when a new chain is formed.

    Since we don't store severity/confidence/criticality on the chain
    itself, we work backwards from the current score to apply the
    chain multipliers incrementally.

    current_score is the v1 base score.
    Returns the new chain-boosted score, capped at 100.
    """
    TACTIC_STEP       = 0.15
    MAX_CHAIN_BOOST   = 2.0
    MULTI_STAGE_BOOST = 1.25

    tc          = max(1, int(chain_tactic_count))
    chain_boost = min(1.0 + (tc - 1) * TACTIC_STEP, MAX_CHAIN_BOOST)
    stage_boost = MULTI_STAGE_BOOST if is_multi_stage else 1.0

    return round(min(current_score * chain_boost * stage_boost, 100.0), 2)
