"""
ingestion/normalizer.py
────────────────────────
Pure service functions — no database calls, no FastAPI, no Redis.
Takes raw log payload dicts, returns NormalizedEvent objects.

This is the ONLY place where log-format-specific field names are known.
Everything downstream works with NormalizedEvent exclusively.

Supported log_source values:
  "json"    — generic JSON (ECS-style nested or flat)
  "syslog"  — RFC 5424 or BSD syslog fields already parsed to dict
  "cef"     — ArcSight CEF extension fields already parsed to dict
  "winlog"  — Windows Event Log (flat or nested EventData)
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Output schema ─────────────────────────────────────────────────────────────

class NormalizedEvent(BaseModel):
    """
    The canonical event representation used by every downstream module.
    All rule-engine matchers operate exclusively on these fields.
    """
    # Identity
    event_id:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    log_source:  str = ""
    received_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    # Entity context
    host:           str | None = None
    user:           str | None = None
    process:        str | None = None
    command_line:   str | None = None
    parent_process: str | None = None

    # Network
    src_ip:   str | None = None
    dst_ip:   str | None = None
    dst_port: int | None = None
    protocol: str | None = None

    # File system
    file_path: str | None = None
    file_hash: str | None = None

    # Auth
    logon_type:  str | None = None
    auth_result: str | None = None

    # Raw fields preserved for matching arbitrary keys
    raw_fields: dict[str, Any] = Field(default_factory=dict)

    # Deduplication fingerprint
    hash: str | None = None


# ── Public entry point ────────────────────────────────────────────────────────

def normalize_event(log_source: str, payload: dict[str, Any]) -> NormalizedEvent:
    """
    Route to the correct normalizer based on log_source.
    Returns a fully populated NormalizedEvent.
    Raises ValueError for unknown log_source values.
    """
    source = log_source.strip().lower()

    _normalizers = {
        "json":   _from_json,
        "syslog": _from_syslog,
        "cef":    _from_cef,
        "winlog": _from_winlog,
    }

    fn = _normalizers.get(source)
    if fn is None:
        raise ValueError(
            f"Unsupported log_source: {source!r}. "
            f"Supported: {sorted(_normalizers)}"
        )

    event = fn(payload)
    event.log_source  = source
    event.received_at = datetime.now(UTC).isoformat()
    event.hash        = _fingerprint(event)
    return event


# ── Format-specific extractors ────────────────────────────────────────────────

def _from_json(p: dict[str, Any]) -> NormalizedEvent:
    """
    Handles both flat JSON logs and ECS-style nested objects.

    ECS nested example:
      {"host": {"hostname": "srv01"}, "process": {"name": "bash",
       "command_line": "bash -c id"}, "user": {"name": "ubuntu"},
       "source": {"ip": "10.0.0.1"}, "destination": {"ip": "8.8.8.8", "port": 443}}

    Flat example:
      {"hostname": "srv01", "process_name": "bash", "username": "ubuntu"}
    """
    def _get(obj: dict, *keys: str) -> Any:
        """Try multiple key names, return first match."""
        for k in keys:
            if k in obj:
                return obj[k]
        return None

    def _nested(obj: dict, outer: str, inner: str) -> Any:
        v = obj.get(outer)
        if isinstance(v, dict):
            return v.get(inner)
        return None

    return NormalizedEvent(
        host=(
            _nested(p, "host", "hostname")
            or _nested(p, "host", "name")
            or _get(p, "hostname", "host")
        ),
        user=(
            _nested(p, "user", "name")
            or _get(p, "username", "user")
        ),
        process=(
            _nested(p, "process", "name")
            or _get(p, "process_name", "process")
        ),
        command_line=(
            _nested(p, "process", "command_line")
            or _get(p, "command_line", "cmdline", "cmd")
        ),
        parent_process=(
            _nested(p, "process", "parent", )
            or _get(p, "parent_process", "parent_image")
        ),
        src_ip=(
            _nested(p, "source", "ip")
            or _get(p, "src_ip", "source_ip", "src")
        ),
        dst_ip=(
            _nested(p, "destination", "ip")
            or _get(p, "dst_ip", "dest_ip", "dst")
        ),
        dst_port=_to_int(
            _nested(p, "destination", "port")
            or _get(p, "dst_port", "dest_port", "dport")
        ),
        file_path=(
            _nested(p, "file", "path")
            or _get(p, "file_path", "filepath")
        ),
        file_hash=_get(p, "file_hash", "hash", "sha256", "md5"),
        auth_result=_get(p, "auth_result", "result", "outcome"),
        raw_fields=p,
    )


def _from_syslog(p: dict[str, Any]) -> NormalizedEvent:
    """
    Maps RFC 5424 / BSD syslog fields produced by syslog_parser.py.
    Expected keys: hostname, app_name, procid, msg, auth_result
    """
    return NormalizedEvent(
        host=p.get("hostname") or p.get("host"),
        user=p.get("procid"),
        process=p.get("app_name"),
        command_line=p.get("msg") or p.get("message"),
        auth_result=p.get("auth_result"),
        raw_fields=p,
    )


def _from_cef(p: dict[str, Any]) -> NormalizedEvent:
    """
    Maps ArcSight CEF extension fields produced by cef_parser.py.
    Standard CEF field names: src, dst, dpt, suser, duser, sproc, dproc, etc.
    """
    return NormalizedEvent(
        host=p.get("dhost") or p.get("shost"),
        user=p.get("suser") or p.get("duser"),
        process=p.get("sproc") or p.get("dproc"),
        command_line=p.get("request") or p.get("msg"),
        src_ip=p.get("src"),
        dst_ip=p.get("dst"),
        dst_port=_to_int(p.get("dpt")),
        file_path=p.get("filePath") or p.get("fname"),
        file_hash=p.get("fileHash"),
        raw_fields=p,
    )


def _from_winlog(p: dict[str, Any]) -> NormalizedEvent:
    """
    Maps Windows Event Log fields.
    Handles both flat dicts and nested {"EventData": {...}} structure.
    """
    # EventData may be nested or the payload may be flat
    ed: dict[str, Any] = p.get("EventData", p)
    if not isinstance(ed, dict):
        ed = p

    return NormalizedEvent(
        host=p.get("Computer") or p.get("Hostname") or p.get("hostname"),
        user=(
            ed.get("SubjectUserName")
            or ed.get("TargetUserName")
            or ed.get("User")
        ),
        process=(
            ed.get("Image")
            or ed.get("ProcessName")
            or ed.get("NewProcessName")
        ),
        command_line=ed.get("CommandLine"),
        parent_process=ed.get("ParentImage") or ed.get("ParentProcessName"),
        src_ip=ed.get("IpAddress") or ed.get("SourceAddress"),
        dst_ip=ed.get("DestinationIp") or ed.get("DestinationAddress"),
        dst_port=_to_int(
            ed.get("DestinationPort") or ed.get("TargetPort")
        ),
        file_path=(
            ed.get("TargetFilename")
            or ed.get("FilePath")
            or ed.get("ObjectName")
        ),
        file_hash=ed.get("Hashes"),
        logon_type=str(ed["LogonType"]) if "LogonType" in ed else None,
        auth_result=ed.get("AuthResult"),
        raw_fields=p,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_int(value: Any) -> int | None:
    """Safely cast to int. Returns None if conversion fails."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _fingerprint(event: NormalizedEvent) -> str:
    """
    Compute a 16-char deduplication fingerprint.
    Same log line from the same source always produces the same hash.
    Used to deduplicate repeated identical events before DB insert.
    """
    parts = "|".join(filter(None, [
        event.log_source,
        event.host or "",
        event.user or "",
        event.process or "",
        event.command_line or "",
        event.src_ip or "",
        event.dst_ip or "",
        str(event.dst_port or ""),
    ]))
    return hashlib.sha256(parts.encode()).hexdigest()[:16]
