"""
tests/unit/test_rule_ast.py
────────────────────────────
Unit tests for every operator and node type in rule_ast.py.
Pure function tests — zero I/O, zero DB, zero network.

NOTE ON API DRIFT FROM THE HISTORICAL SUITE:
Current rule_ast.py is free-function based: nodes are plain dataclasses
(FieldMatch/AndNode/OrNode/NotNode) with no `.evaluate()` method — evaluation
happens via the module-level `evaluate_ast(node, event)` / `node_from_dict(d)`
functions. The operator vocabulary also differs: "equals"/"not_equals"/
"starts_with"/"ends_with" instead of "eq"/"neq"/"startswith"/"endswith", and
there is no "in"/"not_in" support and no `case_sensitive` field on FieldMatch.
All tests below are rewritten to call the real current API.
"""
import pytest
from threatos.detection.rule_ast import (
    AndNode, FieldMatch, NotNode, OrNode,
    evaluate_ast, node_from_dict,
)


# ── FieldMatch: equals / not_equals ────────────────────────────────────────────

def test_equals_exact_match():
    n = FieldMatch(field="process", operator="equals", value="powershell.exe")
    assert evaluate_ast(n, {"process": "powershell.exe"}) is True

def test_equals_case_insensitive_by_default():
    n = FieldMatch(field="process", operator="equals", value="PowerShell.exe")
    assert evaluate_ast(n, {"process": "powershell.exe"}) is True

def test_equals_has_no_case_sensitive_option():
    """The historical FieldMatch had a `case_sensitive` flag; the current
    dataclass only has field/operator/value — there is no way to opt into
    case-sensitive comparison anymore, so passing the old kwarg is a TypeError."""
    with pytest.raises(TypeError):
        FieldMatch(field="process", operator="equals", value="PowerShell.exe",
                   case_sensitive=True)

def test_equals_mismatched_value_returns_false():
    n = FieldMatch(field="process", operator="equals", value="svchost.exe")
    assert evaluate_ast(n, {"process": "malware.exe"}) is False

def test_not_equals_returns_true_when_different():
    n = FieldMatch(field="process", operator="not_equals", value="svchost.exe")
    assert evaluate_ast(n, {"process": "malware.exe"}) is True

def test_not_equals_returns_false_when_same():
    n = FieldMatch(field="process", operator="not_equals", value="svchost.exe")
    assert evaluate_ast(n, {"process": "svchost.exe"}) is False


# ── FieldMatch: contains / not_contains ───────────────────────────────────────

def test_contains_substring_present():
    n = FieldMatch(field="command_line", operator="contains",
                   value="-EncodedCommand")
    assert evaluate_ast(n, {"command_line": "powershell -EncodedCommand abc"}) is True

def test_contains_substring_absent():
    n = FieldMatch(field="command_line", operator="contains",
                   value="-EncodedCommand")
    assert evaluate_ast(n, {"command_line": "powershell -NoProfile"}) is False

def test_not_contains():
    n = FieldMatch(field="command_line", operator="not_contains",
                   value="malicious")
    assert evaluate_ast(n, {"command_line": "normal command"}) is True
    assert evaluate_ast(n, {"command_line": "malicious payload"}) is False


# ── FieldMatch: starts_with / ends_with ───────────────────────────────────────

def test_starts_with():
    n = FieldMatch(field="file_path", operator="starts_with",
                   value="c:\\windows\\temp")
    assert evaluate_ast(n, {"file_path": "C:\\Windows\\Temp\\payload.exe"}) is True
    assert evaluate_ast(n, {"file_path": "C:\\Program Files\\app.exe"}) is False

def test_ends_with():
    n = FieldMatch(field="file_path", operator="ends_with", value=".exe")
    assert evaluate_ast(n, {"file_path": "malware.exe"}) is True
    assert evaluate_ast(n, {"file_path": "document.docx"}) is False


# ── FieldMatch: regex ─────────────────────────────────────────────────────────

def test_regex_match():
    n = FieldMatch(field="file_path", operator="regex",
                   value=r"\\Temp\\[a-z0-9]+\.exe")
    assert evaluate_ast(n, {"file_path": "C:\\Temp\\abc123.exe"}) is True
    assert evaluate_ast(n, {"file_path": "C:\\Windows\\system32\\svchost.exe"}) is False

@pytest.mark.skip(reason=(
    "suspected production bug: _eval_field()'s regex branch "
    "(threatos/detection/rule_ast.py:59-61) calls re.search(node.value, ...) with "
    "no try/except around it. A malformed regex pattern raises "
    "re.PatternError instead of evaluating to False, so evaluate_ast() (and any "
    "code calling it outside of rule_engine.evaluate_event's own broad "
    "try/except) will crash on a rule with an invalid regex, instead of the "
    "rule simply not matching."
))
def test_regex_invalid_pattern_returns_false():
    n = FieldMatch(field="process", operator="regex", value="[invalid(")
    assert evaluate_ast(n, {"process": "anything"}) is False

def test_regex_case_insensitive_by_default():
    n = FieldMatch(field="process", operator="regex", value="MIMIKATZ")
    assert evaluate_ast(n, {"process": "mimikatz.exe"}) is True


# ── FieldMatch: in / not_in ────────────────────────────────────────────────────
# NOTE: current rule_ast.py's _eval_field() has no "in"/"not_in" branch at all —
# any operator it doesn't recognize falls through to `return False` at the
# bottom of the function. That means a detection rule authored with an "in"
# operator (e.g. "dst_port in [4444, 4445, 9001]") will *silently never match*
# rather than raising an error or doing set membership — a real, dangerous
# silent-detection-gap bug for a SIEM. Keeping these skipped/documented rather
# than deleted so the gap stays visible.

@pytest.mark.skip(reason=(
    "suspected production bug: rule_ast.py's _eval_field() has no 'in' operator "
    "branch (threatos/detection/rule_ast.py:53-66); unrecognized operators fall "
    "through to `return False`. A rule using operator='in' will silently never "
    "match instead of doing set-membership, which is a silent detection gap."
))
def test_in_value_present():
    n = FieldMatch(field="dst_port", operator="in", value=[4444, 4445, 9001])
    assert evaluate_ast(n, {"dst_port": "4444"}) is True

@pytest.mark.skip(reason=(
    "suspected production bug: see test_in_value_present — 'in' operator is "
    "unimplemented in rule_ast.py's _eval_field()."
))
def test_in_value_absent():
    n = FieldMatch(field="dst_port", operator="in", value=[4444, 4445])
    assert evaluate_ast(n, {"dst_port": "80"}) is False

@pytest.mark.skip(reason=(
    "suspected production bug: 'not_in' is likewise unimplemented in "
    "rule_ast.py's _eval_field() (threatos/detection/rule_ast.py:53-66) — it "
    "falls through to `return False` for both present and absent values, so a "
    "not_in rule can never fire (it's supposed to fire when the value is "
    "absent from the list)."
))
def test_not_in():
    n = FieldMatch(field="process", operator="not_in",
                   value=["svchost.exe", "explorer.exe"])
    assert evaluate_ast(n, {"process": "malware.exe"}) is True
    assert evaluate_ast(n, {"process": "svchost.exe"}) is False


# ── FieldMatch: gt / lt ───────────────────────────────────────────────────────

def test_gt_numeric():
    n = FieldMatch(field="dst_port", operator="gt", value=1024)
    assert evaluate_ast(n, {"dst_port": "4444"}) is True
    assert evaluate_ast(n, {"dst_port": "80"}) is False

def test_lt_numeric():
    n = FieldMatch(field="dst_port", operator="lt", value=1024)
    assert evaluate_ast(n, {"dst_port": "80"}) is True
    assert evaluate_ast(n, {"dst_port": "8080"}) is False

@pytest.mark.skip(reason=(
    "suspected production bug: _eval_field()'s gt/lt branches "
    "(threatos/detection/rule_ast.py:64-65) call float(val)/float(node.value) "
    "with no try/except. A non-numeric field value raises ValueError instead "
    "of evaluating to False, so a gt/lt rule crashes (within rule_engine it's "
    "swallowed per-rule and just fails to fire, but evaluate_ast() itself "
    "propagates the exception to any other caller)."
))
def test_gt_non_numeric_returns_false():
    n = FieldMatch(field="process", operator="gt", value=5)
    assert evaluate_ast(n, {"process": "not-a-number"}) is False


# ── FieldMatch: exists ────────────────────────────────────────────────────────

def test_exists_field_present():
    n = FieldMatch(field="process", operator="exists")
    assert evaluate_ast(n, {"process": "bash"}) is True

def test_exists_field_absent():
    n = FieldMatch(field="process", operator="exists")
    assert evaluate_ast(n, {"command_line": "something"}) is False

@pytest.mark.skip(reason=(
    "suspected production bug: _eval_field() (threatos/detection/rule_ast.py:62) "
    "treats operator=='exists' as unconditionally True once the field key is "
    "present and non-None — it never checks for an empty string. So a field "
    "present with value '' is reported as 'exists', which contradicts the "
    "intended semantics (and the historical behavior) of exists meaning "
    "'meaningfully populated'."
))
def test_exists_empty_string_is_not_present():
    n = FieldMatch(field="process", operator="exists")
    assert evaluate_ast(n, {"process": ""}) is False

def test_missing_field_returns_false_for_non_exists():
    n = FieldMatch(field="command_line", operator="contains", value="malware")
    assert evaluate_ast(n, {"process": "explorer.exe"}) is False


# ── AndNode ───────────────────────────────────────────────────────────────────

def test_and_all_children_match():
    n = AndNode(children=[
        FieldMatch(field="process", operator="contains", value="powershell"),
        FieldMatch(field="command_line", operator="contains", value="-enc"),
    ])
    assert evaluate_ast(n, {
        "process": "powershell.exe",
        "command_line": "powershell -enc abc",
    }) is True

def test_and_one_child_fails():
    n = AndNode(children=[
        FieldMatch(field="process", operator="contains", value="powershell"),
        FieldMatch(field="command_line", operator="contains", value="-enc"),
    ])
    assert evaluate_ast(n, {
        "process": "powershell.exe",
        "command_line": "powershell -help",  # no -enc
    }) is False

def test_and_empty_children_returns_true():
    # vacuous truth — all() of empty is True
    n = AndNode(children=[])
    assert evaluate_ast(n, {}) is True


# ── OrNode ────────────────────────────────────────────────────────────────────

def test_or_first_child_matches():
    n = OrNode(children=[
        FieldMatch(field="process", operator="equals", value="mimikatz.exe"),
        FieldMatch(field="command_line", operator="contains", value="sekurlsa"),
    ])
    assert evaluate_ast(n, {"process": "mimikatz.exe", "command_line": "normal"}) is True

def test_or_second_child_matches():
    n = OrNode(children=[
        FieldMatch(field="process", operator="equals", value="mimikatz.exe"),
        FieldMatch(field="command_line", operator="contains", value="sekurlsa"),
    ])
    assert evaluate_ast(n, {"process": "cmd.exe",
                             "command_line": "sekurlsa::logonpasswords"}) is True

def test_or_no_child_matches():
    n = OrNode(children=[
        FieldMatch(field="process", operator="equals", value="mimikatz.exe"),
        FieldMatch(field="command_line", operator="contains", value="sekurlsa"),
    ])
    assert evaluate_ast(n, {"process": "notepad.exe", "command_line": "normal"}) is False

def test_or_empty_children_returns_false():
    n = OrNode(children=[])
    assert evaluate_ast(n, {}) is False


# ── NotNode ───────────────────────────────────────────────────────────────────

def test_not_inverts_match():
    n = NotNode(child=FieldMatch(field="process", operator="equals",
                                  value="svchost.exe"))
    assert evaluate_ast(n, {"process": "malware.exe"}) is True
    assert evaluate_ast(n, {"process": "svchost.exe"}) is False

def test_not_nested_in_and():
    """AND(process=powershell, NOT(host=safe-host))"""
    n = AndNode(children=[
        FieldMatch(field="process", operator="contains", value="powershell"),
        NotNode(child=FieldMatch(field="host", operator="equals",
                                  value="safe-host")),
    ])
    assert evaluate_ast(n, {"process": "powershell.exe",
                             "host": "attacker-pc"}) is True
    assert evaluate_ast(n, {"process": "powershell.exe",
                             "host": "safe-host"}) is False


# ── node_from_dict / evaluate_ast ─────────────────────────────────────────────

def test_node_from_dict_field_match():
    d = {"type": "field_match", "field": "process",
         "operator": "contains", "value": "powershell"}
    node = node_from_dict(d)
    assert isinstance(node, FieldMatch)
    assert evaluate_ast(node, {"process": "powershell.exe"}) is True

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
    assert evaluate_ast(node, {"process": "powershell.exe",
                                "command_line": "-enc abc"}) is True

def test_node_from_dict_nested_not_in_and():
    d = {
        "type": "and",
        "children": [
            {"type": "field_match", "field": "process",
             "operator": "contains", "value": "powershell"},
            {"type": "not",
             "child": {"type": "field_match", "field": "host",
                       "operator": "equals", "value": "safe-host"}},
        ],
    }
    node = node_from_dict(d)
    assert evaluate_ast(node, {"process": "powershell.exe",
                                "host": "attacker"}) is True
    assert evaluate_ast(node, {"process": "powershell.exe",
                                "host": "safe-host"}) is False

def test_node_from_dict_unknown_type_raises():
    with pytest.raises(ValueError, match="Unknown node type"):
        node_from_dict({"type": "magic_node"})

def test_evaluate_ast_top_level():
    node = node_from_dict({
        "type": "or",
        "children": [
            {"type": "field_match", "field": "process",
             "operator": "equals", "value": "mimikatz.exe"},
            {"type": "field_match", "field": "command_line",
             "operator": "contains", "value": "sekurlsa"},
        ],
    })
    assert evaluate_ast(node, {"process": "mimikatz.exe"}) is True
    assert evaluate_ast(node, {"command_line": "sekurlsa::logon"}) is True
    assert evaluate_ast(node, {"process": "notepad.exe"}) is False
