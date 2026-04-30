from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class ScoreComponents:
    severity: int; confidence: float; asset_criticality: int
    chain_tactic_count: int; is_multi_stage: bool
    base_score: float; chain_boost: float; stage_boost: float; final_score: float
    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity, "confidence": self.confidence,
            "asset_criticality": self.asset_criticality,
            "chain_tactic_count": self.chain_tactic_count,
            "is_multi_stage": self.is_multi_stage,
            "base_score": self.base_score, "chain_boost": self.chain_boost,
            "stage_boost": self.stage_boost, "final_score": self.final_score,
        }

def compute_score_v1(severity: int, confidence: float, asset_criticality: int = 2) -> float:
    return round(min(float(severity)*float(confidence)*float(asset_criticality)/40.0*100.0, 100.0), 2)

def compute_score_v2(severity: int, confidence: float, asset_criticality: int = 2,
                     chain_tactic_count: int = 1, is_multi_stage: bool = False) -> ScoreComponents:
    sev  = max(1, min(10, int(severity)))
    conf = max(0.0, min(1.0, float(confidence)))
    crit = max(1, min(4, int(asset_criticality)))
    tc   = max(1, int(chain_tactic_count))
    base = compute_score_v1(sev, conf, crit)
    chain_boost = round(min(1.0 + (tc-1)*0.15, 2.0), 4)
    stage_boost = 1.25 if is_multi_stage else 1.0
    final = round(min(base * chain_boost * stage_boost, 100.0), 2)
    return ScoreComponents(severity=sev, confidence=conf, asset_criticality=crit,
        chain_tactic_count=tc, is_multi_stage=is_multi_stage,
        base_score=base, chain_boost=chain_boost, stage_boost=stage_boost, final_score=final)

def score_alert_in_context(severity: int, confidence: float, asset_criticality: int,
                            chain_tactic_count: int = 1, is_multi_stage: bool = False) -> float:
    return compute_score_v2(severity, confidence, asset_criticality,
                             chain_tactic_count, is_multi_stage).final_score

def rescore_alert_for_chain(current_score: float, chain_tactic_count: int, is_multi_stage: bool) -> float:
    tc = max(1, int(chain_tactic_count))
    chain_boost = min(1.0 + (tc-1)*0.15, 2.0)
    stage_boost = 1.25 if is_multi_stage else 1.0
    return round(min(current_score * chain_boost * stage_boost, 100.0), 2)
