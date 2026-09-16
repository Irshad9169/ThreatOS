"""
detection/rule_engine.py
─────────────────────────
Core detection service. Pure functions only — no DB, no I/O.

Responsibilities:
  1. Maintain an in-memory cache of compiled rules (load_rules_into_engine)
  2. Flatten a NormalizedEvent to a field dict  (_event_to_fields)
  3. Evaluate every loaded rule against the field dict (evaluate_event)
  4. Compute a risk score for each match (compute_risk_score)
  5. Build an alert dict ready for DB insertion (build_alert_dict)

The engine is intentionally synchronous so it can be called from
asyncio code OR from a ProcessPoolExecutor without threading concerns.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threatos.detection.rule_ast import RuleNode, evaluate_ast, node_from_dict
from threatos.ingestion.normalizer import NormalizedEvent


# ── Compiled rule (in-memory representation) ──────────────────────────────────

@dataclass
class CompiledRule:
    """
    A detection rule loaded into memory.
    Created once at startup; never modified after loading.
    """
    id:           str
    name:         str
    technique_id: str
    tactic:       str
    log_sources:  list[str]   # empty = matches all sources
    severity:     int         # 1–10
    confidence:   float       # 0.0–1.0
    ast:          RuleNode
    tags:         list[str] = field(default_factory=list)


@dataclass
class RuleMatch:
    """Result of a rule firing against one event."""
    rule:           CompiledRule
    matched_fields: dict[str, Any]  # fields that contributed to the match
    risk_score:     float


# ── Module-level rule cache ────────────────────────────────────────────────────
# Populated once at startup by load_rules_into_engine().
# Intentionally module-level so workers can share it without DB re-reads.

_RULES: list[CompiledRule] = []


def load_rules_into_engine(rules_data: list[dict[str, Any]]) -> int:
    """
    Compile rule dicts (from DB rows) into CompiledRule objects.
    Stores them in the module-level cache.
    Returns the count of successfully compiled rules.

    Called once at startup by rule_loader.py.
    Thread-safe for reads; only called from a single startup coroutine.
    """
    global _RULES
    compiled: list[CompiledRule] = []
    errors = 0

    for row in rules_data:
        try:
            ast = node_from_dict(row["detection_ast"])
            compiled.append(CompiledRule(
                id=str(row["id"]),
                name=row["name"],
                technique_id=row["technique_id"],
                tactic=row["tactic"],
                log_sources=[s.lower() for s in (row.get("log_sources") or [])],
                severity=int(row["severity"]),
                confidence=float(row["confidence"]),
                ast=ast,
                tags=row.get("tags") or [],
            ))
        except Exception:
            errors += 1

    _RULES = compiled
    return len(compiled)


def get_loaded_rule_count() -> int:
    """Return the number of rules currently in the engine cache."""
    return len(_RULES)


def clear_rules() -> None:
    """Reset the engine cache. Used in tests to ensure isolation."""
    global _RULES
    _RULES = []


# ── Core evaluation logic ─────────────────────────────────────────────────────

def _event_to_fields(event: NormalizedEvent) -> dict[str, Any]:
    """
    Flatten a NormalizedEvent into a plain dict for AST evaluation.

    Merge order: raw_fields first (lower priority), typed fields second.
    Typed fields win on collision so rules written against known field
    names always get the canonical normalised value.
    """
    base = {k: v for k, v in event.raw_fields.items() if v is not None}
    typed = {
        "host":           event.host,
        "user":           event.user,
        "process":        event.process,
        "command_line":   event.command_line,
        "parent_process": event.parent_process,
        "src_ip":         event.src_ip,
        "dst_ip":         event.dst_ip,
        "dst_port":       event.dst_port,
        "file_path":      event.file_path,
        "file_hash":      event.file_hash,
        "logon_type":     event.logon_type,
        "auth_result":    event.auth_result,
        "log_source":     event.log_source,
    }
    base.update({k: v for k, v in typed.items() if v is not None})
    return base


def compute_risk_score(
    severity: int,
    confidence: float,
    asset_criticality: int = 2,
) -> float:
    """
    Phase 1 risk scoring formula:
        raw   = severity * confidence * asset_criticality
        score = min(raw / MAX_RAW * 100, 100)

    Component ranges:
        severity          1–10
        confidence        0.0–1.0
        asset_criticality 1–4   (1=dev, 2=internal, 3=server, 4=critical)

    MAX_RAW = 10 * 1.0 * 4 = 40 → maps to score 100.

    All component values are stored on the Alert row so analysts can see
    which factor drove the score — never store only the final number.
    """
    raw = float(severity) * float(confidence) * float(asset_criticality)
    MAX_RAW = 40.0
    return round(min(raw / MAX_RAW * 100.0, 100.0), 2)


def evaluate_event(
    event: NormalizedEvent,
    asset_criticality: int = 2,
) -> list[RuleMatch]:
    """
    Evaluate a NormalizedEvent against every loaded rule.
    Returns one RuleMatch per rule that fires.

    Properties:
      - Synchronous (no async) → safe in ProcessPoolExecutor
      - Pure (no DB / Redis calls) → callers handle persistence
      - O(rules) → iterates every enabled rule once per event
    """
    if not _RULES:
        return []

    fields  = _event_to_fields(event)
    matches: list[RuleMatch] = []

    for rule in _RULES:
        # Skip rules scoped to specific log sources if this event is different
        if rule.log_sources and event.log_source not in rule.log_sources:
            continue

        try:
            fired = evaluate_ast(rule.ast, fields)
        except Exception:
            # A broken rule must never crash the pipeline
            continue

        if fired:
            # Collect a minimal snapshot of matched fields for analyst context
            matched = {
                k: v for k, v in fields.items()
                if k in ("process", "command_line", "file_path",
                         "src_ip", "dst_ip", "dst_port", "auth_result")
                and v is not None
            }
            risk = compute_risk_score(
                rule.severity, rule.confidence, asset_criticality
            )
            matches.append(RuleMatch(
                rule=rule,
                matched_fields=matched,
                risk_score=risk,
            ))

    return matches


def build_alert_dict(
    event: NormalizedEvent,
    match: RuleMatch,
    asset_criticality: int = 2,
) -> dict[str, Any]:
    """
    Convert a RuleMatch into a plain dict ready for INSERT into alerts table.
    Called by the ingest worker after evaluate_event().
    """
    now = datetime.now(UTC).isoformat()
    return {
        "id":               str(uuid.uuid4()),
        "rule_id":          match.rule.id,
        "event_id":         event.event_id,
        "technique_id":     match.rule.technique_id,
        "tactic":           match.rule.tactic,
        "severity":         match.rule.severity,
        "confidence":       match.rule.confidence,
        "risk_score":       match.risk_score,
        "asset_criticality":asset_criticality,
        "entity_host":      event.host,
        "entity_user":      event.user,
        "entity_process":   event.process,
        "entity_ip":        event.src_ip or event.dst_ip,
        "status":           "open",
        "description":      f"Rule '{match.rule.name}' matched on {event.log_source}",
        "raw_match": {
            "rule_name":     match.rule.name,
            "tags":          match.rule.tags,
            "matched_fields":match.matched_fields,
        },
        "created_at":  now,
        "updated_at":  now,
    }
