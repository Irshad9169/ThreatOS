from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class FieldMatch:
    field:    str
    operator: str
    value:    Any = None

@dataclass
class AndNode:
    children: list = field(default_factory=list)

@dataclass
class OrNode:
    children: list = field(default_factory=list)

@dataclass
class NotNode:
    child: Any = None

def node_from_dict(d: dict) -> Any:
    t = d.get("type","")
    if t == "field_match":
        return FieldMatch(field=d["field"], operator=d["operator"], value=d.get("value"))
    if t == "and":
        return AndNode(children=[node_from_dict(c) for c in d.get("children",[])])
    if t == "or":
        return OrNode(children=[node_from_dict(c) for c in d.get("children",[])])
    if t == "not":
        return NotNode(child=node_from_dict(d["child"]))
    raise ValueError(f"Unknown node type: {t!r}")

def evaluate_ast(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, AndNode):
        return all(evaluate_ast(c, event) for c in node.children)
    if isinstance(node, OrNode):
        return any(evaluate_ast(c, event) for c in node.children)
    if isinstance(node, NotNode):
        return not evaluate_ast(node.child, event)
    if isinstance(node, FieldMatch):
        return _eval_field(node, event)
    return False

def _eval_field(node: FieldMatch, event: dict) -> bool:
    val = event.get(node.field)
    if val is None:
        return node.operator in ("not_exists", "is_null")
    val_s = str(val).lower()
    cmp_s = str(node.value).lower() if node.value is not None else ""
    op = node.operator
    if op == "equals":          return val_s == cmp_s
    if op == "not_equals":      return val_s != cmp_s
    if op == "contains":        return cmp_s in val_s
    if op == "not_contains":    return cmp_s not in val_s
    if op == "starts_with":     return val_s.startswith(cmp_s)
    if op == "ends_with":       return val_s.endswith(cmp_s)
    if op == "regex":
        import re
        return bool(re.search(node.value, str(val), re.IGNORECASE))
    if op == "exists":          return True
    if op == "not_exists":      return False
    if op == "gt":              return float(val) > float(node.value)
    if op == "lt":              return float(val) < float(node.value)
    if op == "is_null":         return False
    return False
