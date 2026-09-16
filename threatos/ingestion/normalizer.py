from __future__ import annotations
import hashlib, json, re, uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

@dataclass
class NormalizedEvent:
    event_id:      str
    log_source:    str
    host:          str | None = None
    user:          str | None = None
    process:       str | None = None
    command_line:  str | None = None
    parent_process:str | None = None
    src_ip:        str | None = None
    dst_ip:        str | None = None
    dst_port:      int | None = None
    file_path:     str | None = None
    file_hash:     str | None = None
    logon_type:    str | None = None
    auth_result:   str | None = None
    raw_fields:    dict       = field(default_factory=dict)
    hash:          str | None = None

    def to_flat_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if v is not None and k != "hash"}
        d.update(self.raw_fields)
        return d

def _fingerprint(data: dict) -> str:
    stable = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(stable.encode()).hexdigest()

def _coerce_port(v: Any) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None

def normalize_json(raw: dict) -> NormalizedEvent:
    event_id = raw.get("event_id") or raw.get("id") or str(uuid.uuid4())
    e = NormalizedEvent(
        event_id=event_id,
        log_source=raw.get("log_source","json"),
        host=raw.get("host") or raw.get("hostname"),
        user=raw.get("user") or raw.get("username"),
        process=raw.get("process") or raw.get("process_name"),
        command_line=raw.get("command_line") or raw.get("cmdline"),
        parent_process=raw.get("parent_process"),
        src_ip=raw.get("src_ip") or raw.get("source_ip"),
        dst_ip=raw.get("dst_ip") or raw.get("dest_ip"),
        dst_port=_coerce_port(raw.get("dst_port") or raw.get("dest_port")),
        file_path=raw.get("file_path"),
        file_hash=raw.get("file_hash") or raw.get("md5") or raw.get("sha256"),
        logon_type=raw.get("logon_type"),
        auth_result=raw.get("auth_result") or raw.get("result"),
        raw_fields=raw,
    )
    e.hash = _fingerprint(raw)
    return e

def normalize_cef(raw_line: str) -> NormalizedEvent:
    parts = raw_line.split("|", 7)
    ext   = {}
    if len(parts) == 8:
        for kv in parts[7].split(" "):
            if "=" in kv:
                k, _, v = kv.partition("=")
                ext[k] = v
    e = NormalizedEvent(
        event_id=ext.get("externalId") or str(uuid.uuid4()),
        log_source="cef",
        host=ext.get("dhost") or ext.get("shost"),
        user=ext.get("duser") or ext.get("suser"),
        process=ext.get("sproc") or ext.get("dproc"),
        src_ip=ext.get("src"),
        dst_ip=ext.get("dst"),
        dst_port=int(ext["dpt"]) if ext.get("dpt","").isdigit() else None,
        file_path=ext.get("filePath"),
        file_hash=ext.get("fileHash") or ext.get("md5") or ext.get("sha256"),
        raw_fields=ext,
    )
    e.hash = _fingerprint(ext)
    return e

def normalize_winlog(raw: dict) -> NormalizedEvent:
    evt  = raw.get("winlog", raw)
    data = evt.get("event_data", {})
    e = NormalizedEvent(
        event_id=str(evt.get("event_id") or uuid.uuid4()),
        log_source="winlog",
        host=raw.get("host") or raw.get("computer_name"),
        user=data.get("SubjectUserName") or data.get("TargetUserName"),
        process=data.get("NewProcessName") or data.get("ProcessName") or raw.get("Image"),
        command_line=data.get("CommandLine") or raw.get("CommandLine"),
        parent_process=data.get("ParentProcessName") or raw.get("ParentImage"),
        src_ip=data.get("IpAddress"),
        dst_ip=data.get("DestinationIp"),
        dst_port=_coerce_port(data.get("DestinationPort")),
        logon_type=str(data["LogonType"]) if data.get("LogonType") else None,
        raw_fields=raw,
    )
    e.hash = _fingerprint(raw)
    return e

def normalize_event(raw: dict | str, fmt: str = "json") -> NormalizedEvent:
    if fmt == "cef":
        return normalize_cef(raw if isinstance(raw, str) else json.dumps(raw))
    if fmt == "winlog":
        return normalize_winlog(raw if isinstance(raw, dict) else json.loads(raw))
    if fmt == "syslog":
        from threatos.ingestion.syslog_parser import parse_syslog
        parsed = parse_syslog(raw if isinstance(raw, str) else raw.get("message",""))
        return normalize_json({**parsed, "log_source":"syslog"})
    return normalize_json(raw if isinstance(raw, dict) else json.loads(raw))
