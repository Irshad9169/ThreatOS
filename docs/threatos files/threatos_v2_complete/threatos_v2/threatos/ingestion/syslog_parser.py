"""
ingestion/syslog_parser.py
───────────────────────────
Parses RFC 5424 and BSD Syslog lines into flat dicts
that the normalizer maps to NormalizedEvent fields.
"""
from __future__ import annotations

import re
from typing import Any

_RFC5424 = re.compile(
    r"<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<structured_data>\[.*?\]|-)\s*"
    r"(?P<msg>.*)",
    re.DOTALL,
)

_BSD = re.compile(
    r"<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+(?P<tag>[^\s:]+):\s*(?P<msg>.*)",
    re.DOTALL,
)


def parse_syslog(line: str) -> dict[str, Any]:
    """Parse a Syslog line into a flat dict. Raises ValueError if unparseable."""
    line = line.strip()

    m = _RFC5424.match(line)
    if m:
        d   = m.groupdict()
        pri = int(d["pri"])
        return {
            "facility": pri >> 3,
            "severity": pri & 7,
            "hostname": d["hostname"] if d["hostname"] != "-" else None,
            "app_name": d["app_name"] if d["app_name"] != "-" else None,
            "procid":   d["procid"]   if d["procid"]   != "-" else None,
            "timestamp":d["timestamp"],
            "msg":      d["msg"],
            "raw":      line,
            "format":   "rfc5424",
        }

    m = _BSD.match(line)
    if m:
        d   = m.groupdict()
        pri = int(d["pri"])
        return {
            "facility": pri >> 3,
            "severity": pri & 7,
            "hostname": d["hostname"],
            "app_name": d["tag"],
            "timestamp":d["timestamp"],
            "msg":      d["msg"],
            "raw":      line,
            "format":   "bsd",
        }

    # Last resort — treat entire line as message body
    return {"msg": line, "raw": line, "format": "unknown"}
