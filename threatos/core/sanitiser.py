from __future__ import annotations
import re
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_FIELD_LENGTH    = 2048    # max chars per string field
MAX_PAYLOAD_FIELDS  = 100     # max fields in a single event payload
MAX_PAYLOAD_BYTES   = 65536   # 64KB max payload size
MAX_BATCH_SIZE      = 500     # max events per batch request
ALLOWED_LOG_SOURCES = {
    "json","winlog","syslog","cef","network","cloud","linux",
    "firewall","proxy","dns","dhcp","vpn","edr","custom",
}

# Fields that should never contain HTML or script content
SANITISE_FIELDS = {
    "host","hostname","user","username","process","command_line",
    "parent_process","file_path","message","description",
}

_SCRIPT_PATTERN  = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
_HTML_PATTERN    = re.compile(r'<[^>]+>')
_NULL_BYTES      = re.compile(r'\x00')

def sanitise_string(value: str, field_name: str = "") -> str:
    """Clean a single string value."""
    if not isinstance(value, str):
        return str(value)[:MAX_FIELD_LENGTH]
    # Remove null bytes
    value = _NULL_BYTES.sub('', value)
    # Remove script tags from known text fields
    if field_name in SANITISE_FIELDS:
        value = _SCRIPT_PATTERN.sub('', value)
        value = _HTML_PATTERN.sub('', value)
    # Truncate
    return value[:MAX_FIELD_LENGTH]

def sanitise_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitise an ingest event payload.
    - Truncates oversized strings
    - Removes null bytes
    - Strips script injection from text fields
    - Caps number of fields
    - Returns cleaned copy
    """
    if not isinstance(payload, dict):
        return {}

    # Cap field count
    if len(payload) > MAX_PAYLOAD_FIELDS:
        payload = dict(list(payload.items())[:MAX_PAYLOAD_FIELDS])

    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        # Sanitise key
        clean_key = sanitise_string(str(key))[:64]
        # Sanitise value
        if isinstance(value, str):
            cleaned[clean_key] = sanitise_string(value, field_name=clean_key)
        elif isinstance(value, (int, float, bool)):
            cleaned[clean_key] = value
        elif isinstance(value, dict):
            cleaned[clean_key] = sanitise_payload(value)
        elif isinstance(value, list):
            cleaned[clean_key] = [
                sanitise_string(str(v)) if isinstance(v, str) else v
                for v in value[:50]  # cap list length
            ]
        elif value is None:
            cleaned[clean_key] = None
        else:
            cleaned[clean_key] = sanitise_string(str(value))

    return cleaned

def validate_log_source(log_source: str) -> str:
    """Normalise and validate log_source field."""
    if not log_source:
        return "unknown"
    normalised = log_source.lower().strip()[:30]
    if normalised not in ALLOWED_LOG_SOURCES:
        return "custom"
    return normalised

def check_payload_size(payload: dict) -> tuple[bool, str]:
    """
    Returns (ok, error_message).
    Checks payload is within size limits.
    """
    import json
    try:
        size = len(json.dumps(payload).encode('utf-8'))
        if size > MAX_PAYLOAD_BYTES:
            return False, f"Payload too large: {size} bytes (max {MAX_PAYLOAD_BYTES})"
    except Exception:
        return False, "Payload could not be serialised"
    return True, ""
