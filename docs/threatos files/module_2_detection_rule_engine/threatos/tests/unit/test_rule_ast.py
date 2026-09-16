"""
tests/unit/test_rule_ast.py
────────────────────────────
Unit tests for every operator and node type in rule_ast.py.
Pure function tests — zero I/O, zero DB, zero network.
"""
import pytest
from threatos.detection.rule_ast import (
    AndNode, FieldMatch, NotNode, OrNode,
    evaluate_ast, node_from_dict,
)


# ── FieldMatch: eq / neq ──────────────────────────────────────────────────────

def test_eq_exact_match():
    n = FieldMatch(field="process", operator="eq", value="powershell.exe")
    assert n.evaluate({"process": "powershell.exe"}) is True

def test_eq_case_insensitive_by_default():
    n = FieldMatch(field="process", operator="eq", value="PowerShell.exe")
    assert n.evaluate({"process": "powershell.exe"}) is True

def test_eq_case_sensitive_mode():
    n = FieldMatch(field="process", operator="eq", value="PowerShell.exe",
                   case_sensitive=True)
    assert n.evaluate({"process": "powershell.exe"}) is False
    assert n.evaluate({"process": "PowerShell.exe"}) is True

def test_neq_returns_true_when_different():
    n = FieldMatch(field="process", operator="neq", value="svchost.exe")
    assert n.evaluate({"process": "malware.exe"}) is True

def test_neq_returns_false_when_same():
    n = FieldMatch(field="process", operator="neq", value="svchost.exe")
    assert n.evaluate({"process": "svchost.exe"}) is False


# ── FieldMatch: contains / not_contains ───────────────────────────────────────

def test_contains_substring_present():
    n = FieldMatch(field="command_line", operator="contains",
                   value="-EncodedCommand")
    assert n.evaluate({"command_line": "powershell -EncodedCommand abc"}) is True

def test_contains_substring_absent():
    n = FieldMatch(field="command_line", operator="contains",
                   value="-EncodedCommand")
    assert n.evaluate({"command_line": "powershell -NoProfile"}) is False

def test_not_contains():
    n = FieldMatch(field="command_line", operator="not_contains",
                   value="malicious")
    assert n.evaluate({"command_line": "normal command"}) is True
    assert n.evaluate({"command_line": "malicious payload"}) is False


# ── FieldMatch: startswith / endswith ─────────────────────────────────────────

def test_startswith():
    n = FieldMatch(field="file_path", operator="startswith",
                   value="c:\\windows\\temp")
    assert n.evaluate({"file_path": "C:\\Windows\\Temp\\payload.exe"}) is True
    assert n.evaluate({"file_path": "C:\\Program Files\\app.exe"}) is False

def test_endswith():
    n = FieldMatch(field="file_path", operator="endswith", value=".exe")
    assert n.evaluate({"file_path": "malware.exe"}) is True
    assert n.evaluate({"file_path": "document.docx"}) is False


# ── FieldMatch: regex ─────────────────────────────────────────────────────────

def test_regex_match():
    n = FieldMatch(field="file_path", operator="regex",
                   value=r"\\Temp\\[a-z0-9]+\.exe")
    assert n.evaluate({"file_path": "C:\\Temp\\abc123.exe"}) is True
    assert n.evaluate({"file_path": "C:\\Windows\\system32\\svchost.exe"}) is False

def test_regex_invalid_pattern_returns_false():
    n = FieldMatch(field="process", operator="regex", value="[invalid(")
    assert n.evaluate({"process": "anything"}) is False

def test_regex_case_insensitive_by_default():
    n = FieldMatch(field="process", operator="regex", value="MIMIKATZ")
    assert n.evaluate({"process": "mimikatz.exe"}) is True


# ── FieldMatch: in / not_in ───────────────────────────────────────────────────

def test_in_value_present():
    n = FieldMatch(field="dst_port", operator="in", value=[4444, 4445, 9001])
    assert n.evaluate({"dst_port": "4444"}) is True

def test_in_value_absent():
    n = FieldMatch(field="dst_port", operator="in", value=[4444, 4445])
    assert n.evaluate({"dst_port": "80"}) is False

def test_not_in():
    n = FieldMatch(field="process", operator="not_in",
                   value=["svchost.exe", "explorer.exe"])
    assert n.evaluate({"process": "malware.exe"}) is True
    assert n.evaluate({"process": "svchost.exe"}) is False


# ── FieldMatch: gt / lt ───────────────────────────────────────────────────────

def test_gt_numeric():
    n = FieldMatch(field="dst_port", operator="gt", value=1024)
    assert n.evaluate({"dst_port": "4444"}) is True
    assert n.evaluate({"dst_port": "80"}) is False

def test_lt_numeric():
    n = FieldMatch(field="dst_port", operator="lt", value=1024)
    assert n.evaluate({"dst_port": "80"}) is True
    assert n.evaluate({"dst_port": "8080"}) is False

def test_gt_non_numeric_returns_false():
    n = FieldMatch(field="process", operator="gt", value=5)
    assert n.evaluate({"process": "not-a-number"}) is False


# ── FieldMatch: exists ────────────────────────────────────────────────────────

def test_exists_field_present():
    n = FieldMatch(field="process", operator="exists")
    assert n.evaluate({"process": "bash"}) is True

def test_exists_field_absent():
    n = FieldMatch(field="process", operator="exists")
    assert n.evaluate({"command_line": "something"}) is False

def test_exists_empty_string_is_not_present():
    n = FieldMatch(field="process", operator="exists")
    assert n.evaluate({"process": ""}) is False

def test_missing_field_returns_false_for_non_exists():
    n = FieldMatch(field="command_line", operator="contains", value="malware")
    assert n.evaluate({"process": "explorer.exe"}) is False


# ── AndNode ───────────────────────────────────────────────────────────────────

def test_and_all_children_match():
    n = AndNode(children=[
        FieldMatch(field="process", operator="contains", value="powershell"),
        FieldMatch(field="command_line", operator="contains", value="-enc"),
    ])
    assert n.evaluate({
        "process": "powershell.exe",
        "command_line": "powershell -enc abc",
    }) is True

def test_and_one_child_fails():
    n = AndNode(children=[
        FieldMatch(field="process", operator="contains", value="powershell"),
        FieldMatch(field="command_line", operator="contains", value="-enc"),
    ])
    assert n.evaluate({
        "process": "powershell.exe",
        "command_line": "powershell -help",  # no -enc
    }) is False

def test_and_empty_children_returns_true():
    # vacuous truth — all() of empty is True
    n = AndNode(children=[])
    assert n.evaluate({}) is True


# ── OrNode ────────────────────────────────────────────────────────────────────

def test_or_first_child_matches():
    n = OrNode(children=[
        FieldMatch(field="process", operator="eq", value="mimikatz.exe"),
        FieldMatch(field="command_line", operator="contains", value="sekurlsa"),
    ])
    assert n.evaluate({"process": "mimikatz.exe", "command_line": "normal"}) is True

def test_or_second_child_matches():
    n = OrNode(children=[
        FieldMatch(field="process", operator="eq", value="mimikatz.exe"),
        FieldMatch(field="command_line", operator="contains", value="sekurlsa"),
    ])
    assert n.evaluate({"process": "cmd.exe",
                        "command_line": "sekurlsa::logonpasswords"}) is True

def test_or_no_child_matches():
    n = OrNode(children=[
        FieldMatch(field="process", operator="eq", value="mimikatz.exe"),
        FieldMatch(field="command_line", operator="contains", value="sekurlsa"),
    ])
    assert n.evaluate({"process": "notepad.exe", "command_line": "normal"}) is False

def test_or_empty_children_returns_false():
    n = OrNode(children=[])
    assert n.evaluate({}) is False


# ── NotNode ───────────────────────────────────────────────────────────────────

def test_not_inverts_match():
    n = NotNode(child=FieldMatch(field="process", operator="eq",
                                  value="svchost.exe"))
    assert n.evaluate({"process": "malware.exe"}) is True
    assert n.evaluate({"process": "svchost.exe"}) is False

def test_not_nested_in_and():
    """AND(process=powershell, NOT(host=safe-host))"""
    n = AndNode(children=[
        FieldMatch(field="process", operator="contains", value="powershell"),
        NotNode(child=FieldMatch(field="host", operator="eq",
                                  value="safe-host")),
    ])
    assert n.evaluate({"process": "powershell.exe",
                        "host": "attacker-pc"}) is True
    assert n.evaluate({"process": "powershell.exe",
                        "host": "safe-host"}) is False


# ── node_from_dict / evaluate_ast ─────────────────────────────────────────────

def test_node_from_dict_field_match():
    d = {"type": "field_match", "field": "process",
         "operator": "contains", "value": "powershell"}
    node = node_from_dict(d)
    assert isinstance(node, FieldMatch)
    assert node.evaluate({"process": "powershell.exe"}) is True

def test_node_from_dict_and():
    d = {
        "type": "and",
        "children": [
            {"type": "field_match", "field": "process",
             "operator": "contains", "value": "powershell"},
            {"type": "field_match", "field": "command_line",
             "operator": "contains", "value": "-enc"},
        ],
    }
    node = node_from_dict(d)
    assert isinstance(node, AndNode)
    assert node.evaluate({"process": "powershell.exe",
                           "command_line": "-enc abc"}) is True

def test_node_from_dict_nested_not_in_and():
    d = {
        "type": "and",
        "children": [
            {"type": "field_match", "field": "process",
             "operator": "contains", "value": "powershell"},
            {"type": "not",
             "child": {"type": "field_match", "field": "host",
                       "operator": "eq", "value": "safe-host"}},
        ],
    }
    node = node_from_dict(d)
    assert node.evaluate({"process": "powershell.exe",
                           "host": "attacker"}) is True
    assert node.evaluate({"process": "powershell.exe",
                           "host": "safe-host"}) is False

def test_node_from_dict_unknown_type_raises():
    with pytest.raises(ValueError, match="Unknown AST node type"):
        node_from_dict({"type": "magic_node"})

def test_evaluate_ast_top_level():
    node = node_from_dict({
        "type": "or",
        "children": [
            {"type": "field_match", "field": "process",
             "operator": "eq", "value": "mimikatz.exe"},
            {"type": "field_match", "field": "command_line",
             "operator": "contains", "value": "sekurlsa"},
        ],
    })
    assert evaluate_ast(node, {"process": "mimikatz.exe"}) is True
    assert evaluate_ast(node, {"command_line": "sekurlsa::logon"}) is True
    assert evaluate_ast(node, {"process": "notepad.exe"}) is False
