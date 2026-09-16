"""
detection/rule_ast.py
──────────────────────
Pure evaluation functions. No database. No I/O. No side effects.

Node types:
  FieldMatch   — leaf: compare one event field to a value
  AndNode      — all children must match
  OrNode       — any child must match
  NotNode      — child must NOT match
"""
from __future__ import annotations

import re
from typing import Any, Literal, Union

from pydantic import BaseModel


class FieldMatch(BaseModel):
    type: Literal["field_match"] = "field_match"
    field: str
    operator: Literal[
        "eq","neq","contains","not_contains",
        "startswith","endswith","regex",
        "in","not_in","gt","lt","exists",
    ]
    value: str | int | float | list[str | int | float] | None = None
    case_sensitive: bool = False

    def evaluate(self, fields: dict[str, Any]) -> bool:
        raw = fields.get(self.field)

        if self.operator == "exists":
            return raw is not None and raw != ""
        if raw is None:
            return False

        val = str(raw)
        if not self.case_sensitive:
            val = val.lower()

        def _n(v: Any) -> str:
            s = str(v)
            return s.lower() if not self.case_sensitive else s

        match self.operator:
            case "eq":           return val == _n(self.value)
            case "neq":          return val != _n(self.value)
            case "contains":     return _n(self.value) in val
            case "not_contains": return _n(self.value) not in val
            case "startswith":   return val.startswith(_n(self.value))
            case "endswith":     return val.endswith(_n(self.value))
            case "regex":
                flags = 0 if self.case_sensitive else re.IGNORECASE
                try:    return bool(re.search(str(self.value), val, flags))
                except re.error: return False
            case "in":     return val in [_n(i) for i in (self.value or [])]
            case "not_in": return val not in [_n(i) for i in (self.value or [])]
            case "gt":
                try:    return float(raw) > float(self.value)  # type: ignore
                except (TypeError, ValueError): return False
            case "lt":
                try:    return float(raw) < float(self.value)  # type: ignore
                except (TypeError, ValueError): return False
            case _: return False


class AndNode(BaseModel):
    type: Literal["and"] = "and"
    children: list["RuleNode"]
    def evaluate(self, fields: dict[str, Any]) -> bool:
        return all(c.evaluate(fields) for c in self.children)


class OrNode(BaseModel):
    type: Literal["or"] = "or"
    children: list["RuleNode"]
    def evaluate(self, fields: dict[str, Any]) -> bool:
        return any(c.evaluate(fields) for c in self.children)


class NotNode(BaseModel):
    type: Literal["not"] = "not"
    child: "RuleNode"
    def evaluate(self, fields: dict[str, Any]) -> bool:
        return not self.child.evaluate(fields)


RuleNode = Union[FieldMatch, AndNode, OrNode, NotNode]

AndNode.model_rebuild()
OrNode.model_rebuild()
NotNode.model_rebuild()


def node_from_dict(d: dict[str, Any]) -> RuleNode:
    """Reconstruct a RuleNode tree from a plain dict (loaded from JSONB)."""
    t = d.get("type")
    match t:
        case "field_match":
            return FieldMatch(**d)
        case "and":
            return AndNode(type="and",
                children=[node_from_dict(c) for c in d.get("children", [])])
        case "or":
            return OrNode(type="or",
                children=[node_from_dict(c) for c in d.get("children", [])])
        case "not":
            return NotNode(type="not", child=node_from_dict(d["child"]))
        case _:
            raise ValueError(f"Unknown AST node type: {t!r}")


def evaluate_ast(root: RuleNode, event_fields: dict[str, Any]) -> bool:
    """Top-level: evaluate a compiled tree against a flat field dict."""
    return root.evaluate(event_fields)
