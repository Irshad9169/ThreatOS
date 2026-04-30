from __future__ import annotations
import logging, uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from threatos.detection.rule_ast import evaluate_ast, node_from_dict
from threatos.ingestion.normalizer import NormalizedEvent

log = logging.getLogger(__name__)

@dataclass
class CompiledRule:
    id: str; name: str; technique_id: str; tactic: str
    log_sources: list[str]; severity: int; confidence: float
    ast: Any; tags: list[str]

_RULES: list[CompiledRule] = []

def load_rules_into_engine(rows: list[dict]) -> int:
    global _RULES
    compiled = []
    for r in rows:
        try:
            compiled.append(CompiledRule(
                id=str(r["id"]), name=r["name"],
                technique_id=r["technique_id"], tactic=r["tactic"],
                log_sources=r.get("log_sources") or [],
                severity=int(r["severity"]), confidence=float(r["confidence"]),
                ast=node_from_dict(r["detection_ast"]),
                tags=r.get("tags") or [],
            ))
        except Exception as exc:
            log.warning("Failed to compile rule %s: %s", r.get("name"), exc)
    _RULES = compiled
    return len(_RULES)

def clear_rules() -> None:
    global _RULES; _RULES = []

def get_loaded_rule_count() -> int:
    return len(_RULES)

def compute_risk_score(severity: int, confidence: float, asset_criticality: int = 2) -> float:
    raw = float(severity) * float(confidence) * float(asset_criticality)
    return round(min(raw / 40.0 * 100.0, 100.0), 2)

def evaluate_event(event: NormalizedEvent, asset_criticality: int = 2) -> list[dict]:
    fields  = event.to_flat_dict()
    matches = []
    for rule in _RULES:
        if rule.log_sources and event.log_source not in rule.log_sources:
            continue
        try:
            if evaluate_ast(rule.ast, fields):
                matches.append(build_alert_dict(event, rule, asset_criticality))
        except Exception as exc:
            log.warning("Rule %s eval error: %s", rule.name, exc)
    return matches

def build_alert_dict(event: NormalizedEvent, rule: CompiledRule, asset_criticality: int = 2) -> dict:
    now = datetime.now(UTC)
    return {
        "id":               str(uuid.uuid4()),
        "rule_id":          rule.id,
        "rule_name":        rule.name,
        "event_id":         event.event_id,
        "technique_id":     rule.technique_id,
        "tactic":           rule.tactic,
        "severity":         rule.severity,
        "confidence":       rule.confidence,
        "asset_criticality":asset_criticality,
        "risk_score":       compute_risk_score(rule.severity, rule.confidence, asset_criticality),
        "entity_host":      event.host,
        "entity_user":      event.user,
        "entity_process":   event.process,
        "entity_ip":        event.src_ip,
        "status":           "open",
        "created_at":       now,
        "updated_at":       now,
        "raw_match":        {"event_id": event.event_id, "log_source": event.log_source},
    }
