"""
tests/unit/test_normalizer.py
──────────────────────────────
Unit tests for the normalizer service.
No database, no Redis, no HTTP — pure function tests.
Every test is a single input → expected output assertion.
"""
import pytest
from threatos.ingestion.normalizer import normalize_event, NormalizedEvent


# ── JSON format ────────────────────────────────────────────────────────────────

def test_json_flat_hostname():
    event = normalize_event("json", {"hostname": "srv01", "message": "test"})
    assert event.host == "srv01"

def test_json_ecs_nested_host():
    event = normalize_event("json", {"host": {"hostname": "ecs-host"}})
    assert event.host == "ecs-host"

def test_json_ecs_nested_process():
    event = normalize_event("json", {
        "process": {"name": "bash", "command_line": "bash -c id"}
    })
    assert event.process == "bash"
    assert event.command_line == "bash -c id"

def test_json_ecs_nested_user():
    event = normalize_event("json", {"user": {"name": "ubuntu"}})
    assert event.user == "ubuntu"

def test_json_ecs_nested_network():
    event = normalize_event("json", {
        "source":      {"ip": "10.0.0.1"},
        "destination": {"ip": "8.8.8.8", "port": 443},
    })
    assert event.src_ip  == "10.0.0.1"
    assert event.dst_ip  == "8.8.8.8"
    assert event.dst_port == 443

def test_json_port_as_string_coerced_to_int():
    event = normalize_event("json", {"dst_port": "8080"})
    assert event.dst_port == 8080

def test_json_invalid_port_returns_none():
    event = normalize_event("json", {"dst_port": "not-a-port"})
    assert event.dst_port is None

def test_json_empty_payload_returns_all_none_fields():
    event = normalize_event("json", {})
    assert event.host        is None
    assert event.user        is None
    assert event.process     is None
    assert event.command_line is None
    assert event.src_ip      is None

def test_json_raw_fields_preserved():
    payload = {"hostname": "h1", "custom_key": "custom_value", "count": 42}
    event = normalize_event("json", payload)
    assert event.raw_fields["custom_key"] == "custom_value"
    assert event.raw_fields["count"] == 42


# ── Syslog format ─────────────────────────────────────────────────────────────

def test_syslog_hostname_extraction():
    event = normalize_event("syslog", {
        "hostname": "mail-server",
        "app_name": "postfix",
        "msg": "connect from unknown[192.168.1.50]",
    })
    assert event.host    == "mail-server"
    assert event.process == "postfix"
    assert "192.168.1.50" in event.command_line

def test_syslog_auth_result_preserved():
    event = normalize_event("syslog", {
        "hostname": "auth-srv",
        "msg": "Failed password for root",
        "auth_result": "failed",
    })
    assert event.auth_result == "failed"


# ── CEF format ────────────────────────────────────────────────────────────────

def test_cef_standard_fields():
    event = normalize_event("cef", {
        "src":   "192.168.1.1",
        "dst":   "10.0.0.5",
        "dpt":   "4444",
        "suser": "attacker",
        "dhost": "victim-pc",
        "sproc": "nc.exe",
    })
    assert event.src_ip   == "192.168.1.1"
    assert event.dst_ip   == "10.0.0.5"
    assert event.dst_port == 4444
    assert event.user     == "attacker"
    assert event.host     == "victim-pc"
    assert event.process  == "nc.exe"

def test_cef_file_fields():
    event = normalize_event("cef", {
        "filePath": "/tmp/malware.sh",
        "fileHash": "abc123",
    })
    assert event.file_path == "/tmp/malware.sh"
    assert event.file_hash == "abc123"


# ── Windows Event Log format ──────────────────────────────────────────────────

def test_winlog_flat_fields():
    event = normalize_event("winlog", {
        "Computer": "WIN-DC01",
        "EventData": {
            "SubjectUserName": "SYSTEM",
            "Image":           "C:\\Windows\\System32\\cmd.exe",
            "CommandLine":     "cmd.exe /c whoami",
            "ParentImage":     "explorer.exe",
        },
    })
    assert event.host           == "WIN-DC01"
    assert event.user           == "SYSTEM"
    assert "cmd.exe" in event.process
    assert "whoami"  in event.command_line
    assert "explorer.exe" in event.parent_process

def test_winlog_network_fields():
    event = normalize_event("winlog", {
        "Computer": "WORKSTATION-01",
        "EventData": {
            "IpAddress":       "10.0.0.100",
            "DestinationIp":   "185.220.101.1",
            "DestinationPort": "443",
        },
    })
    assert event.src_ip   == "10.0.0.100"
    assert event.dst_ip   == "185.220.101.1"
    assert event.dst_port == 443

def test_winlog_logon_type_as_string():
    event = normalize_event("winlog", {
        "EventData": {"LogonType": 3}
    })
    assert event.logon_type == "3"

def test_winlog_flat_payload_no_eventdata_key():
    """Payloads without an EventData key should still work."""
    event = normalize_event("winlog", {
        "Computer":   "HOST-01",
        "Image":      "powershell.exe",
        "CommandLine":"powershell -enc abc",
    })
    assert event.host    == "HOST-01"
    assert event.process == "powershell.exe"


# ── Common behaviour across all formats ───────────────────────────────────────

def test_unknown_log_source_raises_value_error():
    with pytest.raises(ValueError, match="Unsupported log_source"):
        normalize_event("unknown_format", {"key": "value"})

def test_log_source_case_insensitive():
    e1 = normalize_event("JSON",   {"hostname": "h1"})
    e2 = normalize_event("json",   {"hostname": "h1"})
    e3 = normalize_event("Json",   {"hostname": "h1"})
    assert e1.log_source == e2.log_source == e3.log_source == "json"

def test_event_id_is_a_valid_uuid():
    import uuid
    event = normalize_event("json", {})
    # Should not raise
    parsed = uuid.UUID(event.event_id)
    assert str(parsed) == event.event_id

def test_received_at_is_iso8601_with_timezone():
    from datetime import datetime, timezone
    event = normalize_event("json", {})
    dt = datetime.fromisoformat(event.received_at)
    assert dt.tzinfo is not None

def test_fingerprint_is_deterministic():
    payload = {"hostname": "h1", "process": {"name": "bash"}}
    e1 = normalize_event("json", payload)
    e2 = normalize_event("json", payload)
    assert e1.hash == e2.hash

def test_fingerprint_differs_for_different_events():
    e1 = normalize_event("json", {"hostname": "host-a"})
    e2 = normalize_event("json", {"hostname": "host-b"})
    assert e1.hash != e2.hash

def test_fingerprint_is_16_chars():
    event = normalize_event("json", {"hostname": "h1"})
    assert len(event.hash) == 16

def test_empty_payload_produces_hash_not_none():
    """Even an empty payload must produce a fingerprint — not None."""
    event = normalize_event("json", {})
    assert event.hash is not None
    assert len(event.hash) == 16
