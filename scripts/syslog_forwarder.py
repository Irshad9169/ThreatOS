#!/usr/bin/env python3
"""
syslog_forwarder.py
────────────────────
Reads /var/log/messages and /var/log/secure in real-time
and forwards events to ThreatOS via /api/ingest/event.

Designed for Oracle Linux 8 / RHEL 8.
Runs as a systemd service.

Usage:
    python syslog_forwarder.py
    python syslog_forwarder.py --dry-run   # print without sending
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, signal, sys, time, uuid
from datetime import UTC, datetime
from pathlib import Path
import urllib.request, urllib.error

# ── Config ────────────────────────────────────────────────────────────────────
THREATOS_URL  = os.environ.get("THREATOS_URL",  "http://localhost:8001")
API_KEY       = os.environ.get("THREATOS_API_KEY", "")
HOSTNAME      = os.popen("hostname").read().strip()
BATCH_SIZE    = int(os.environ.get("FORWARDER_BATCH_SIZE", "20"))
FLUSH_SECONDS = float(os.environ.get("FORWARDER_FLUSH_SECONDS", "5"))

LOG_FILES = [
    "/var/log/authlog",       # SSH, sudo, su, PAM — auth events (OL8 custom)
    "/var/log/secure",        # SSH auth (standard RHEL — may be empty)
    "/var/log/messages",      # General system events
    "/var/log/cron",          # Cron job execution
    "/var/log/daemon",        # Daemon events
    "/var/log/audit/audit.log",     # Auditd events
    "/var/log/nginx/access.log",    # Web access logs
]

# State file — tracks read position per log file
STATE_FILE = "/var/lib/threatos-forwarder/state.json"

# ── Syslog patterns ───────────────────────────────────────────────────────────
# Apr 28 07:22:24 test06 sshd[1234]: ...
SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
    r'(\S+)\s+'                                   # hostname
    r'(\S+?)(?:\[(\d+)\])?:\s*'                  # process[pid]
    r'(.*)$'                                      # message
)

# ── Event normalisation ───────────────────────────────────────────────────────
def parse_nginx_line(line: str) -> dict | None:
    """Parse nginx access log: 1.2.3.4 - - [28/Apr/2026:10:00:00 +0000] "GET /api/alerts HTTP/1.1" 200 1234"""
    nginx_re = re.compile(
        r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
    )
    m = nginx_re.match(line.strip())
    if not m:
        return None
    src_ip, timestamp, method, path, status, size = m.groups()
    return {
        "event_id":    str(uuid.uuid4()),
        "log_source":  "nginx",
        "host":        HOSTNAME,
        "user":        "",
        "process":     "nginx",
        "command_line":f"{method} {path} {status}",
        "src_ip":      src_ip,
        "message":     line.strip()[:500],
        "pid":         "",
        "log_file":    "nginx",
        "raw_fields":  json.dumps({
            "method": method, "path": path,
            "status": status, "src_ip": src_ip,
            "timestamp": timestamp,
        }),
    }

def normalise(line: str, log_file: str) -> dict | None:
    """Parse a syslog line into a ThreatOS normalized event."""
    line = line.strip()
    if not line:
        return None

    # Route nginx logs to dedicated parser
    if "nginx" in log_file:
        return parse_nginx_line(line)

    m = SYSLOG_RE.match(line)
    if not m:
        return None

    timestamp, host, process, pid, message = m.groups()
    process = process.lower()

    # Extract user from common patterns
    user = None
    user_match = re.search(r'(?:user|for)\s+(\w+)', message, re.IGNORECASE)
    if user_match:
        user = user_match.group(1)

    # Extract IP addresses
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
    src_ip = ip_match.group(1) if ip_match else None

    # Build command_line from message (what actually happened)
    command_line = message[:500]

    # Determine log source type
    if "authlog" in log_file or "secure" in log_file or process in ("sshd","sudo","su","passwd","pam","login"):
        log_source = "syslog-auth"
    elif "audit" in log_file:
        log_source = "syslog-audit"
    elif "cron" in log_file or process in ("crond","cron"):
        log_source = "syslog-cron"
    else:
        log_source = "syslog"

    return {
        "event_id":    str(uuid.uuid4()),
        "log_source":  log_source,
        "host":        host or HOSTNAME,
        "user":        user or "",
        "process":     process or "",
        "command_line":command_line,
        "src_ip":      src_ip or "",
        "message":     message[:500],
        "pid":         pid or "",
        "log_file":    log_file,
        "raw_fields":  json.dumps({
            "timestamp": timestamp,
            "host":      host,
            "process":   process,
            "pid":       pid,
            "message":   message[:500],
            "log_file":  log_file,
        }),
    }

# ── State management ──────────────────────────────────────────────────────────
def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as exc:
        print(f"WARN: Could not save state: {exc}", file=sys.stderr)

# ── HTTP send ─────────────────────────────────────────────────────────────────
def send_event(event: dict, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"  DRY-RUN: {event['log_source']} | {event['process']} | {event['command_line'][:60]}")
        return True
    if not API_KEY:
        print("ERROR: THREATOS_API_KEY not set", file=sys.stderr)
        return False
    try:
        payload = json.dumps({"payload": event, "fmt": event["log_source"]}).encode()
        req = urllib.request.Request(
            f"{THREATOS_URL}/api/ingest/event",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": API_KEY,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status in (200, 201)
    except Exception as exc:
        print(f"WARN: Send failed: {exc}", file=sys.stderr)
        return False

def send_batch(events: list[dict], dry_run: bool = False) -> int:
    """Send up to BATCH_SIZE events in one request."""
    if not events:
        return 0
    if dry_run:
        for e in events:
            print(f"  DRY: {e['log_source']:15} {e['process']:15} {e['command_line'][:50]}")
        return len(events)
    if not API_KEY:
        print("ERROR: THREATOS_API_KEY not set", file=sys.stderr)
        return 0
    try:
        items = [{"payload": e, "fmt": e["log_source"]} for e in events]
        payload = json.dumps(items).encode()
        req = urllib.request.Request(
            f"{THREATOS_URL}/api/ingest/batch",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": API_KEY,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
            return resp.get("accepted", 0)
    except Exception as exc:
        print(f"WARN: Batch send failed: {exc}", file=sys.stderr)
        return 0

# ── File tail ─────────────────────────────────────────────────────────────────
class LogTailer:
    def __init__(self, path: str, state: dict):
        self.path   = path
        self.pos    = state.get(path, 0)
        self._inode = None

    def _check_rotation(self) -> bool:
        """Detect log rotation — file recreated with new inode."""
        try:
            inode = os.stat(self.path).st_ino
            if self._inode and inode != self._inode:
                self.pos    = 0
                self._inode = inode
                return True
            self._inode = inode
        except FileNotFoundError:
            pass
        return False

    def read_new_lines(self) -> list[str]:
        self._check_rotation()
        lines = []
        try:
            size = os.path.getsize(self.path)
            if size < self.pos:
                self.pos = 0  # truncated
            if size == self.pos:
                return []
            with open(self.path, errors="replace") as f:
                f.seek(self.pos)
                for line in f:
                    lines.append(line)
                self.pos = f.tell()
        except (FileNotFoundError, PermissionError):
            pass
        return lines

# ── Main loop ─────────────────────────────────────────────────────────────────
_RUNNING = True

def _stop(sig, _frame):
    global _RUNNING
    print(f"\nSignal {sig} — stopping forwarder")
    _RUNNING = False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Print events without sending")
    parser.add_argument("--tail-lines", type=int, default=0,
                        help="Start from last N lines (0 = continue from saved position)")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    print(f"ThreatOS syslog forwarder starting")
    print(f"  Target:    {THREATOS_URL}")
    print(f"  Hostname:  {HOSTNAME}")
    print(f"  Batch:     {BATCH_SIZE} events / {FLUSH_SECONDS}s")
    print(f"  Dry run:   {args.dry_run}")
    print(f"  Log files: {LOG_FILES}")

    state   = load_state()
    tailers = {}

    for path in LOG_FILES:
        if not os.path.exists(path):
            print(f"  SKIP (not found): {path}")
            continue
        if args.tail_lines > 0:
            # Start from last N lines
            try:
                with open(path, errors="replace") as f:
                    lines_all = f.readlines()
                    state[path] = sum(len(l) for l in lines_all[:-args.tail_lines])
            except Exception:
                state[path] = 0
        tailers[path] = LogTailer(path, state)
        print(f"  Watching: {path}  (pos={state.get(path,0)})")

    if not tailers:
        print("ERROR: No log files found to watch")
        sys.exit(1)

    total_sent = 0
    batch: list[dict] = []
    last_flush = time.time()

    print("\nForwarder running — press Ctrl+C to stop\n")

    while _RUNNING:
        for path, tailer in tailers.items():
            for line in tailer.read_new_lines():
                event = normalise(line, path)
                if event:
                    batch.append(event)

        # Flush when batch is full or time elapsed
        now = time.time()
        if batch and (len(batch) >= BATCH_SIZE or now - last_flush >= FLUSH_SECONDS):
            sent = send_batch(batch, dry_run=args.dry_run)
            total_sent += sent
            if sent > 0:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Sent {sent} events  (total: {total_sent})")
            batch = []
            last_flush = now

            # Save position state
            new_state = {p: t.pos for p, t in tailers.items()}
            save_state(new_state)

        time.sleep(0.5)

    # Final flush
    if batch:
        send_batch(batch, dry_run=args.dry_run)
        save_state({p: t.pos for p, t in tailers.items()})

    print(f"Forwarder stopped — total events sent: {total_sent}")

if __name__ == "__main__":
    main()
