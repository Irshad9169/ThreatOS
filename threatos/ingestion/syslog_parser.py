from __future__ import annotations
import re
from typing import Any

_RFC5424 = re.compile(
    r"<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\S+)\s*(?P<msg>.*)"
)
_BSD = re.compile(
    r"<(?P<pri>\d+)>(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:]+):\s*(?P<msg>.*)"
)

def parse_syslog(line: str) -> dict[str, Any]:
    m = _RFC5424.match(line)
    if m:
        d = m.groupdict()
        return {"host": d["host"], "process": d["app"],
                "message": d["msg"], "timestamp": d["ts"],
                "raw_message": line}
    m = _BSD.match(line)
    if m:
        d = m.groupdict()
        return {"host": d["host"], "process": d["tag"].strip(),
                "message": d["msg"],
                "timestamp": f"{d['month']} {d['day']} {d['time']}",
                "raw_message": line}
    return {"message": line, "raw_message": line}
