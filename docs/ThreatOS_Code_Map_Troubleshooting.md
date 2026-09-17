		# ThreatOS — Code Map & Troubleshooting Guide

		**Purpose:** Know exactly which file does what, where to look when something breaks,
		and which script to run for every common task.

		---

		## Quick Lookup — "I need to..."

		| I need to... | File / Command |
		|---|---|
		| Change API port | `.env` → `threatos-api.service` ExecStart |
		| Add a detection rule | UI Rules page OR `POST /api/rules` |
		| Import Sigma rules | `scripts/import_sigma_rules.py` |
		| Fix a rule that's too noisy | `GET /api/detection/noisy-rules` → toggle in UI |
		| Add a log source | `scripts/syslog_forwarder.py` → `LOG_FILES` list |
		| Change retention period | `.env` → `RAW_EVENTS_RETENTION_DAYS` |
		| Change JWT expiry | `.env` → `JWT_ACCESS_EXPIRE_MINUTES` |
		| Add TI API keys | `.env` → `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` |
		| Register a new server | UI Assets page OR `POST /api/assets` |
		| Fix "no alerts appearing" | Check `threatos-worker` logs |
		| Fix "login failed" | Check `postgresql-15` is running |
		| Fix "rules not loading" | Restart `threatos-api` |
		| Fix "ATT&CK shows 0" | `POST /api/coverage/refresh` |
		| Run a backup | `bash /opt/threatos/scripts/backup_threatos.sh` |
		| Simulate an attack | `python scripts/simulate_threats.py --list` |
		| Validate a detection | UI Purple Team page |
		| Download weekly report | UI Reports page → Download PDF |
		| Check audit integrity | `GET /api/compliance/audit-integrity` |

		---

		## Directory Structure — Every Folder Explained

		```
		/opt/threatos/
		│
		├── .env                          ← ALL configuration lives here
		├── .venv/                        ← Python virtualenv (never edit manually)
		├── alembic.ini                   ← Database migration config
		├── pyproject.toml                ← Python package + dependencies
		│
		├── scripts/                      ← Standalone utility scripts
		│   ├── syslog_forwarder.py       ← Reads system logs → sends to API
		│   ├── simulate_threats.py       ← Attack simulation for testing
		│   ├── import_sigma_rules.py     ← Downloads + imports SigmaHQ rules
		│   ├── backup_threatos.sh        ← Full backup (DB + code + configs)
		│   └── create_custom_rules.py    ← Bulk rule creation helper
		│
		└── threatos/                     ← Main application package
			├── main.py                   ← FastAPI app entry point
			│
			├── api/
			│   └── routers/              ← One file per API group (18 files)
			│       ├── auth_router.py    ← Login, logout, users, API keys
			│       ├── alerts_router.py  ← Alert CRUD + status updates
			│       ├── rules_router.py   ← Detection rule management
			│       ├── assets_router.py  ← Host registry
			│       ├── chains_router.py  ← Attack chain correlation
			│       ├── coverage_router.py← ATT&CK coverage matrix
			│       ├── purple_router.py  ← Purple team validation
			│       ├── scans_router.py   ← Nmap scan management
			│       ├── audit_router.py   ← Audit log access
			│       ├── events_router.py  ← Raw event search
			│       ├── report_router.py  ← PDF + JSON report generation
			│       ├── retention_router.py← Data retention management
			│       ├── detection_router.py← Detection quality metrics
			│       ├── compliance_router.py← Sessions, hash chain, approvals
			│       ├── health_router.py  ← Health check endpoints
			│       ├── metrics_router.py ← Prometheus /metrics endpoint
			│       ├── ingest_router.py  ← Event ingestion (API key auth)
			│       ├── ti_router.py      ← Threat intelligence enrichment
			│       └── ws_router.py      ← WebSocket real-time alerts
			│
			├── core/                     ← Shared infrastructure
			│   ├── auth.py               ← JWT encode/decode, bcrypt, blacklist
			│   ├── database.py           ← SQLAlchemy engine + session factory
			│   ├── dependencies.py       ← FastAPI auth dependencies (get_current_user)
			│   ├── logging_config.py     ← structlog JSON configuration
			│   ├── metrics.py            ← Prometheus metrics definitions
			│   ├── redis_client.py       ← Redis connection factory
			│   ├── sanitiser.py          ← Input validation + sanitisation
			│   ├── settings.py           ← Pydantic settings loaded from .env
			│   └── attck_kb.py           ← ATT&CK knowledge base in-memory cache
			│
			├── models/                   ← Database table definitions (17 files)
			│   ├── base.py               ← SQLAlchemy declarative base
			│   ├── alert.py              ← alerts table
			│   ├── detection_rule.py     ← detection_rules table
			│   ├── coverage_matrix.py    ← coverage_matrix table
			│   ├── asset.py              ← assets table
			│   ├── attack_chain.py       ← attack_chains table
			│   ├── raw_event.py          ← raw_events table + JSONBCompat type
			│   ├── user.py               ← users table
			│   ├── audit_log.py          ← audit_logs table
			│   ├── token_blacklist.py    ← token_blacklist table
			│   ├── login_attempt.py      ← login_attempts table
			│   ├── rule_metrics.py       ← rule_metrics table
			│   ├── rule_version.py       ← rule_versions table
			│   ├── user_session.py       ← user_sessions table
			│   ├── rule_change_request.py← rule_change_requests table
			│   ├── ti_enrichment.py      ← ti_enrichments table
			│   ├── purple_team_run.py    ← purple_team_runs table
			│   └── scan_result.py        ← scan_results table
			│
			├── migrations/
			│   └── versions/             ← Alembic migration files
			│       ├── 001_initial.py    ← Core tables
			│       ├── 002_assets.py     ← Assets table
			│       ├── 003_audit_chain.py← Audit hash chain
			│       ├── 004_rule_quality.py← Rule metrics + versions
			│       ├── 005_auth_hardening.py← Sessions, blacklist, login_attempts
			│       ├── 006_compliance.py ← Rule change requests
			│       └── 007_threat_intel.py← TI enrichments + alert TI fields
			│
			├── detection/                ← Rule evaluation engine
			│   ├── rule_engine.py        ← Main AST evaluator — matches events to rules
			│   ├── rule_ast.py           ← AST node types (FieldMatch, And, Or, Not)
			│   ├── rule_loader.py        ← Loads rules from DB into in-memory engine
			│   └── risk_scorer.py        ← Risk score formula v2
			│
			├── ingestion/
			│   └── normalizer.py         ← Parses raw events → NormalizedEvent object
			│
			├── services/                 ← Business logic (one file per domain)
			│   ├── alert_service.py      ← Alert CRUD operations
			│   ├── asset_service.py      ← Asset CRUD operations
			│   ├── audit_service.py      ← Write audit log entries + hash chain
			│   ├── chain_service.py      ← Attack chain correlation logic
			│   ├── compliance_service.py ← Sessions, audit integrity, rule approvals
			│   ├── coverage_service.py   ← ATT&CK coverage computation
			│   ├── detection_quality_service.py ← FP tracking, rule metrics, dedup
			│   ├── event_search_service.py      ← Raw event search + stats
			│   ├── health_alert_service.py      ← Platform health checks
			│   ├── nmap_service.py       ← Nmap scan execution
			│   ├── purple_service.py     ← Purple team validation logic
			│   ├── report_service.py     ← Data gathering + PDF generation
			│   ├── retention_service.py  ← Data cleanup + table size estimation
			│   ├── suppression_service.py← Alert deduplication logic
			│   └── ti_service.py         ← VirusTotal + AbuseIPDB enrichment
			│
			├── workers/                  ← Background processes
			│   ├── ingest_worker.py      ← Main detection loop (Redis → rules → alerts)
			│   ├── coverage_worker.py    ← Hourly ATT&CK bundle refresh
			│   └── retention_worker.py   ← Daily data cleanup
			│
			└── frontend/
				├── src/
				│   ├── App.tsx           ← Root component + auth gate + routing
				│   ├── lib/
				│   │   ├── auth.ts       ← JWT storage + session management
				│   │   └── api.ts        ← axios client + all API functions
				│   ├── components/       ← Shared UI components
				│   │   ├── Sidebar.tsx   ← Navigation sidebar
				│   │   ├── Badge.tsx     ← Status/verdict badge
				│   │   └── Table.tsx     ← Reusable data table
				│   └── pages/            ← One file per UI page (14 files)
				│       ├── Login.tsx         ← Login form
				│       ├── Dashboard.tsx     ← KPI cards + summary
				│       ├── Alerts.tsx        ← Alert list + status updates
				│       ├── Rules.tsx         ← Rule list + create + toggle
				│       ├── Assets.tsx        ← Host registry
				│       ├── Chains.tsx        ← Attack chain list
				│       ├── Coverage.tsx      ← ATT&CK heatmap
				│       ├── Purple.tsx        ← Purple team validation
				│       ├── Scans.tsx         ← Nmap scans
				│       ├── Users.tsx         ← User management [admin]
				│       ├── AuditLog.tsx      ← Audit log viewer
				│       ├── EventSearch.tsx   ← Raw event search
				│       ├── Reports.tsx       ← Security report + PDF download
				│       ├── HealthDashboard.tsx← System health + Grafana links
				│       └── ThreatIntel.tsx   ← IOC lookup + TI cache
				└── dist/                 ← Built files (served by nginx — don't edit)
		```

		---

		## File-by-File Reference

		---

		### `/opt/threatos/.env`
		**What it does:** Master configuration file. Every setting, secret, and credential.

		**When to edit:**
		- Change database password
		- Add TI API keys (VirusTotal, AbuseIPDB)
		- Change retention periods
		- Change JWT expiry times
		- Change rate limiting thresholds

		**Key variables:**
		```bash
		DATABASE_URL          # PostgreSQL connection
		REDIS_URL             # Redis connection
		JWT_SECRET_KEY        # Access token signing (never share)
		JWT_REFRESH_SECRET_KEY# Refresh token signing (never share)
		VIRUSTOTAL_API_KEY    # TI enrichment
		ABUSEIPDB_API_KEY     # TI enrichment
		RAW_EVENTS_RETENTION_DAYS  # How long to keep raw logs
		THREATOS_API_KEY      # Used by syslog_forwarder.py
		```

		**After editing:** Always restart affected service
		```bash
		systemctl restart threatos-api threatos-worker
		```

		---

		### `threatos/main.py`
		**What it does:** FastAPI application entry point. Registers all routers, sets up middleware, runs startup tasks.

		**Startup tasks (lifespan function):**
		1. Loads all detection rules into engine memory
		2. Creates admin user if none exists
		3. Loads ATT&CK bundle into cache

		**When to edit:**
		- Add a new router
		- Change startup behaviour
		- Add new middleware

		**Common issue:** After editing, always restart:
		```bash
		systemctl restart threatos-api
		```

		---

		### `threatos/core/settings.py`
		**What it does:** Reads `.env` file and exposes all settings as a Python object via Pydantic.

		**When to edit:** When adding a new configuration variable.

		**Pattern:**
		```python
		# In settings.py — add new field
		my_new_setting: str = "default_value"

		# In .env — add the value
		MY_NEW_SETTING=actual_value

		# In code — use it
		from threatos.core.settings import settings
		print(settings.my_new_setting)
		```

		---

		### `threatos/core/auth.py`
		**What it does:** All authentication logic.

		**Functions:**
		- `create_access_token()` — generates JWT
		- `verify_token()` — decodes + validates JWT, checks blacklist
		- `hash_password()` / `verify_password()` — bcrypt
		- `check_rate_limit()` — tracks failed logins per IP
		- `ensure_admin_exists()` — creates admin on first startup

		**When to edit:**
		- Change token expiry logic
		- Change rate limiting behaviour
		- Change password complexity requirements

		---

		### `threatos/core/database.py`
		**What it does:** Creates the SQLAlchemy async engine and session factory.

		**Key objects:**
		- `engine` — database connection pool
		- `AsyncSessionLocal` — session factory
		- `get_db()` — FastAPI dependency for DB sessions
		- `get_db_context()` — async context manager for workers

		**When to edit:**
		- Change pool size (but prefer `.env` settings)
		- Add connection retry logic

		---

		### `threatos/core/metrics.py`
		**What it does:** Defines all 18 Prometheus metrics. Exposes `/metrics` endpoint.

		**When to edit:** When adding a new metric to track.

		**Pattern:**
		```python
		# Add new counter
		my_counter = Counter('threatos_my_metric', 'Description', ['label1'])

		# Use in code
		from threatos.core.metrics import my_counter
		my_counter.labels(label1='value').inc()
		```

		---

		### `threatos/detection/rule_engine.py`
		**What it does:** Core detection logic. Evaluates a NormalizedEvent against a rule's AST.

		**Main function:** `evaluate_rule(event, rule_ast) → bool`

		**How it works:**
		```
		Rule AST (JSON tree)
			│
			▼
		RuleEngine.evaluate()
			│
			├── If type="field_match" → compare event field to value using operator
			├── If type="and"         → ALL children must match
			├── If type="or"          → ANY child must match
			└── If type="not"         → child must NOT match
		```

		**When to edit:**
		- Add a new operator (e.g. "between", "in_list")
		- Fix evaluation logic bug
		- Improve performance

		---

		### `threatos/detection/rule_loader.py`
		**What it does:** Loads all enabled rules from PostgreSQL into the in-memory RuleEngine on startup.

		**When rules are reloaded:**
		- API startup
		- After `systemctl restart threatos-api`
		- NOT automatically after adding rules via API (engine reloads on next restart)

		**Common issue:** Added rules via API but they're not firing?
		```bash
		systemctl restart threatos-api threatos-worker
		# Wait 8 seconds for startup
		curl -s http://localhost:8001/health | grep rules_loaded
		```

		---

		### `threatos/detection/risk_scorer.py`
		**What it does:** Calculates the risk score for an alert.

		**Formula:**
		```
		base  = (severity × confidence × asset_criticality) / 40 × 100
		boost = 1 + (tactic_count - 1) × 0.15  (chain boost)
		stage = 1.25  (if 3+ tactics = multi-stage)
		final = min(base × boost × stage, 100)
		```

		**When to edit:** Change risk scoring weights.

		---

		### `threatos/ingestion/normalizer.py`
		**What it does:** Parses raw event JSON into a `NormalizedEvent` dataclass.

		**Input:** Raw JSON from `/api/ingest/event`
		**Output:** `NormalizedEvent` with fields: host, user, process, command_line, src_ip, etc.

		**When to edit:**
		- Add a new event format (e.g. Windows Event Log format)
		- Add a new field to extract
		- Fix parsing bug for a specific log source

		---

		### `threatos/workers/ingest_worker.py`
		**What it does:** The detection engine's main loop. Reads events from Redis stream, evaluates rules, creates alerts.

		**Loop:**
		```
		Every 200ms:
		  1. XREADGROUP — read batch of events from Redis
		  2. For each event:
			 a. Parse NormalizedEvent
			 b. Resolve asset criticality
			 c. Evaluate against all rules
			 d. For each match: check suppression → create alert
		  3. XACK — acknowledge processed messages
		  4. Idle: XAUTOCLAIM — reclaim stuck messages (Redis 6.2+)
		```

		**When something is wrong:**
		```bash
		# Check worker logs
		journalctl -u threatos-worker -f --no-pager

		# Check Redis stream backlog
		redis-cli xlen threatos:events:normalized

		# Check pending (unprocessed) messages
		redis-cli xpending threatos:events:normalized detection-workers - + 10
		```

		**Common issue: XAUTOCLAIM warning**
		```
		WARNING XAUTOCLAIM failed: unknown command XAUTOCLAIM
		```
		This is normal on Redis 5. Worker continues without crash recovery. Safe to ignore.

		---

		### `threatos/workers/coverage_worker.py`
		**What it does:** Downloads the MITRE ATT&CK STIX bundle every hour and refreshes coverage matrix.

		**What it does each cycle:**
		1. Downloads bundle from GitHub (enterprise-attack.json)
		2. Parses all technique IDs
		3. Updates coverage_matrix table
		4. Updates in-memory cache

		**When coverage shows 0 after restart:**
		```bash
		# Manual refresh
		TOKEN=$(...)
		curl -s -X POST -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/coverage/refresh
		```

		**When to edit:**
		- Change refresh interval (default: 3600s)
		- Change ATT&CK bundle URL

		---

		### `threatos/workers/retention_worker.py`
		**What it does:** Runs once on startup then every 24 hours. Deletes old data.

		**What it deletes:**
		- raw_events older than 90 days
		- closed alerts older than 365 days
		- audit_logs older than 365 days
		- scan_results older than 180 days
		- expired login_attempts
		- expired token_blacklist entries

		**Manual run:**
		```bash
		curl -s -X POST -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/retention/run
		```

		**Check table sizes:**
		```bash
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/retention/sizes
		```

		---

		### `threatos/services/audit_service.py`
		**What it does:** Writes entries to the audit_logs table with SHA256 hash chain.

		**Used by:** Every router that performs a significant action.

		**Hash chain mechanism:**
		```
		entry_hash = SHA256(id + timestamp + action + username + result + prev_hash)
		```
		This makes audit entries tamper-evident — modifying any entry breaks the chain.

		**Verify integrity:**
		```bash
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/compliance/audit-integrity
		# Returns: {"integrity":"ok"} or {"integrity":"COMPROMISED","broken_entries":[...]}
		```

		---

		### `threatos/services/report_service.py`
		**What it does:** Two functions:
		1. `gather_report_data(db, days)` — runs all DB queries, returns data dict
		2. `generate_pdf_report(data)` — builds PDF from data dict using ReportLab

		**When to edit:**
		- Add a new section to the report
		- Fix a report query error
		- Change PDF styling

		**Common error pattern:**
		```
		AttributeError: 'X' object has no attribute 'Y'
		```
		Means a model field name is wrong. Check the model file for correct field names.

		---

		### `threatos/services/ti_service.py`
		**What it does:** Threat intelligence enrichment via VirusTotal and AbuseIPDB.

		**Key functions:**
		- `detect_ioc_type(value)` — auto-detects if value is IP/hash/domain
		- `enrich_virustotal(db, ioc_type, ioc_value)` — VT API call + cache
		- `enrich_abuseipdb(db, ip_address)` — AbuseIPDB API call + cache
		- `enrich_ioc(db, ioc_type, ioc_value)` — combined enrichment
		- `enrich_alert(db, alert_data)` — extracts + enriches all IOCs from alert

		**Cache behaviour:**
		- Results cached 24h in `ti_enrichments` table
		- Cached results returned without API call
		- Private IPs (10.x, 192.168.x, 127.x) skipped automatically

		**When API keys not working:**
		```bash
		# Check keys are loaded by running process
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/ti/stats
		# Should show: "virustotal_key": true, "abuseipdb_key": true

		# If false — keys not loaded into process
		systemctl restart threatos-api
		```

		---

		### `threatos/services/suppression_service.py`
		**What it does:** Prevents alert storms by deduplicating alerts.

		**Logic:** Is there an alert for this `rule_id + entity_host` created in the last 15 minutes?
		- Yes → suppress (don't create duplicate alert)
		- No → create alert

		**Change suppression window:**
		```bash
		# In .env
		SUPPRESSION_WINDOW_MINUTES=15   # change to 5 for more alerts, 30 for fewer
		```

		**Check suppression stats:**
		```bash
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/events/suppression-stats
		```

		---

		### `scripts/syslog_forwarder.py`
		**What it does:** Runs on monitored servers. Reads log files, parses syslog format, sends batches to ThreatOS ingest API.

		**Configuration (environment variables):**
		```bash
		THREATOS_URL=http://test06:8001       # ThreatOS server
		THREATOS_API_KEY=<key>               # Ingest API key
		FORWARDER_BATCH_SIZE=20              # Events per batch
		FORWARDER_FLUSH_SECONDS=5           # Send interval
		```

		**State file:** `/var/lib/threatos-forwarder/state.json`
		- Stores file read position for each log file
		- If deleted, forwarder re-reads from beginning

		**Log files watched:**
		```python
		LOG_FILES = [
			"/var/log/authlog",           # Auth events (OL8/custom)
			"/var/log/secure",            # Auth events (standard RHEL)
			"/var/log/messages",          # System events
			"/var/log/cron",              # Cron jobs
			"/var/log/daemon",            # Daemon events
			"/var/log/audit/audit.log",   # Auditd
			"/var/log/nginx/access.log",  # Web access
		]
		```

		**Dry run (test without sending):**
		```bash
		THREATOS_API_KEY=xxx python scripts/syslog_forwarder.py --dry-run --tail-lines 20
		```

		**When logs stop flowing:**
		```bash
		# Check service
		systemctl status threatos-forwarder
		journalctl -u threatos-forwarder -n 20

		# Check state file
		cat /var/lib/threatos-forwarder/state.json

		# Reset state (re-read from last 100 lines)
		systemctl stop threatos-forwarder
		python scripts/syslog_forwarder.py --tail-lines 100 &
		# Or delete state to re-read everything
		rm /var/lib/threatos-forwarder/state.json
		systemctl start threatos-forwarder
		```

		---

		### `scripts/simulate_threats.py`
		**What it does:** Pushes fake attack events directly to Redis stream. Used for testing detection and training.

		**How it works:** Bypasses the HTTP API — writes directly to Redis XADD. Events are picked up by the worker and processed through the rule engine.

		**Usage:**
		```bash
		# List all scenarios
		python scripts/simulate_threats.py --list

		# Run one scenario
		python scripts/simulate_threats.py --scenario ssh_bruteforce --host test06

		# Run full kill chain
		python scripts/simulate_threats.py --scenario full_linux_attack --host test06

		# Run all scenarios
		python scripts/simulate_threats.py --host test06

		# Slow down (default 0.1s between events)
		python scripts/simulate_threats.py --scenario linux_recon --delay 1.0
		```

		**When simulated alerts don't appear:**
		```bash
		# Check worker is consuming from Redis
		redis-cli xlen threatos:events:normalized
		# If growing → worker is stuck

		systemctl restart threatos-worker
		```

		---

		### `scripts/import_sigma_rules.py`
		**What it does:** Downloads Sigma rules from SigmaHQ GitHub repository and imports them into the detection_rules table.

		**What it does:**
		1. Downloads YAML rule files from SigmaHQ
		2. Converts Sigma detection logic to ThreatOS AST format
		3. Deduplicates by content hash
		4. Bulk inserts into detection_rules table

		**Run manually:**
		```bash
		cd /opt/threatos && source .venv/bin/activate
		python scripts/import_sigma_rules.py
		```

		**Runs automatically:** Daily at 02:00 via `threatos-sigma-import.timer`

		**Check timer:**
		```bash
		systemctl list-timers threatos-sigma-import.timer
		journalctl -u threatos-sigma-import --no-pager -n 20
		```

		---

		### `scripts/backup_threatos.sh`
		**What it does:** Complete backup of ThreatOS — database, code, configs, frontend dist.

		**What it backs up:**
		1. PostgreSQL → `threatos_db_YYYYMMDD_HHMM.sql.gz`
		2. Code (no .venv/.env) → `threatos_code_YYYYMMDD.zip`
		3. Configs (.env + nginx + systemd) → `threatos_configs_YYYYMMDD.zip`
		4. Frontend dist → `threatos_frontend_dist_YYYYMMDD.zip`

		**Output:** `/backup/threatos/`
		**Retention:** 7 days (auto-cleanup)
		**Log:** `/var/log/backup-threatos.log`

		**Run manually:**
		```bash
		bash /opt/threatos/scripts/backup_threatos.sh
		```

		---

		## Troubleshooting Guide

		---

		### Problem: API not responding / login fails

		**Symptoms:** Browser shows "Cannot connect" or login returns empty response.

		**Check:**
		```bash
		# 1. Is the API process running?
		systemctl is-active threatos-api

		# 2. Is PostgreSQL running? (most common cause)
		systemctl is-active postgresql-15

		# 3. API startup errors?
		journalctl -u threatos-api --no-pager -n 20

		# Fix:
		systemctl start postgresql-15
		sleep 3
		systemctl restart threatos-api
		sleep 8
		curl -s http://localhost:8001/health
		```

		---

		### Problem: No alerts appearing after events ingested

		**Symptoms:** Events show in /api/events/stats but no alerts created.

		**Check:**
		```bash
		# 1. Is worker running?
		systemctl is-active threatos-worker

		# 2. Is Redis stream being consumed?
		redis-cli xlen threatos:events:normalized
		# If this number keeps growing → worker not consuming

		# 3. Worker errors?
		journalctl -u threatos-worker --no-pager -n 20

		# 4. How many rules are in the engine?
		curl -s http://localhost:8001/health | grep rules_loaded
		# If 0 → rules not loaded

		# Fix:
		systemctl restart threatos-worker
		# Or if rules are 0:
		systemctl restart threatos-api threatos-worker
		```

		---

		### Problem: ATT&CK coverage shows 0% or drops suddenly

		**Symptoms:** Coverage page shows 0 or much lower than expected.

		**Cause:** ATT&CK cache is in-memory. It empties after API restart. Coverage worker reloads it hourly, but there's a gap right after restart.

		**Fix:**
		```bash
		TOKEN=$(...)
		curl -s -X POST -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/coverage/refresh
		# Should return coverage_pct: 100.0 within 5 seconds
		```

		**Permanent fix:** The `main.py` lifespan function loads ATT&CK on startup — verify:
		```bash
		journalctl -u threatos-api --no-pager | grep "ATT&CK bundle loaded"
		# Should appear ~5 seconds after each startup
		```

		---

		### Problem: Rules loaded count is less than expected

		**Symptoms:** Health shows `rules_loaded: 2662` but DB has `3044`.

		**Cause:** Rules added via API after last startup are in DB but not in engine memory.

		**Fix:**
		```bash
		systemctl restart threatos-api threatos-worker
		sleep 8
		curl -s http://localhost:8001/health | grep rules_loaded
		```

		---

		### Problem: TI enrichment shows no_api_key

		**Symptoms:** All TI verdicts return `no_api_key`.

		**Check:**
		```bash
		# Are keys in .env?
		grep -E "VIRUSTOTAL|ABUSEIPDB" /opt/threatos/.env

		# Are they loaded by running process?
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/ti/stats
		# Shows: "virustotal_key": false → keys not in process environment
		```

		**Fix:**
		```bash
		# After adding keys to .env:
		systemctl restart threatos-api
		sleep 5
		# Re-check stats
		```

		---

		### Problem: Syslog forwarder not sending events

		**Symptoms:** `events_ingested` count not growing, but log files have new entries.

		**Check:**
		```bash
		# Is service running?
		systemctl status threatos-forwarder

		# Any errors?
		journalctl -u threatos-forwarder --no-pager -n 20

		# Can it reach ThreatOS?
		curl -s -X POST http://localhost:8001/api/ingest/event \
		  -H "X-API-Key: $(grep THREATOS_API_KEY /opt/threatos/.env | cut -d= -f2)" \
		  -H "Content-Type: application/json" \
		  -d '{"payload":{"event_id":"test","log_source":"syslog","host":"test","message":"test"},"fmt":"syslog"}'
		# Should return {"accepted":1}

		# Is state file position past end of file?
		cat /var/lib/threatos-forwarder/state.json
		ls -la /var/log/authlog  # compare sizes
		```

		**Fix — reset state to resume from near end:**
		```bash
		systemctl stop threatos-forwarder
		python /opt/threatos/scripts/syslog_forwarder.py --tail-lines 50 &
		sleep 10 && kill %1
		systemctl start threatos-forwarder
		```

		---

		### Problem: PDF report is only 21 bytes / "Internal Server Error"

		**Symptoms:** PDF download returns tiny file with "Internal Server Error".

		**Check:**
		```bash
		journalctl -u threatos-api --no-pager -n 10 | grep -i "error\|report\|pdf"
		```

		**Common causes and fixes:**

		| Error | Fix |
		|---|---|
		| `AttributeError: 'X' has no attribute 'Y'` | Field name wrong in report_service.py — check model |
		| `NameError: name 'X' is not defined` | Variable used before defined — check report_service.py |
		| `coroutine object has no attribute 'encode'` | Missing `await` — add await to generate_pdf_report call |
		| `'dict' has no attribute 'execute'` | Wrong argument passed to function — check router |

		---

		### Problem: Prometheus shows "No data" for rate() panels

		**Symptoms:** Alert Creation Rate, Event Ingestion Rate panels show "No data".

		**Cause:** Normal. `rate()` needs at least 2 scrape intervals of history. After a restart, it takes 15–30 minutes to accumulate.

		**Not a bug.** Stat panels (Rules Loaded, Coverage %, Open Alerts) show data immediately. Rate panels need time history.

		**Speed it up:**
		```bash
		# Push some events to generate activity
		python scripts/simulate_threats.py --scenario ssh_bruteforce --host test06
		# Wait 15 minutes then check Grafana
		```

		---

		### Problem: Grafana terminal output in PuTTY

		**Symptoms:** Every UI refresh prints log lines to terminal.

		**Cause:** Grafana is running in foreground.

		**Fix:**
		```bash
		# On test05
		pkill -f "grafana server"
		sleep 2
		nohup ./grafana/bin/grafana server \
		  --homepath ./grafana \
		  --config ./grafana/conf/defaults.ini \
		  > /fs/untd-1/threatos-monitoring/grafana.log 2>&1 &
		```

		---

		### Problem: Disk space running low

		**Check:**
		```bash
		df -h /
		du -sh /opt/threatos/
		du -sh /backup/threatos/

		# Check largest DB tables
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/retention/sizes

		# Estimate when disk fills
		curl -s -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/retention/estimate
		```

		**Fix — run retention manually:**
		```bash
		curl -s -X POST -H "Authorization: Bearer $TOKEN" \
		  http://localhost:8001/api/retention/run
		```

		**Fix — clean old backups:**
		```bash
		ls -lht /backup/threatos/ | head -20
		find /backup/threatos -mtime +7 -delete
		```

		---

		## Service Dependencies

		Understanding which service needs what — important for restart order:

		```
		postgresql-15 ──► threatos-api       (API needs DB to start)
		postgresql-15 ──► threatos-worker    (Worker needs DB for alerts)
		redis         ──► threatos-api       (API needs Redis for stream)
		redis         ──► threatos-worker    (Worker reads from Redis stream)
		threatos-api  ──► threatos-forwarder (Forwarder sends to API)
		nginx         ──► (serves UI only, independent)
		```

		**Correct restart order after full server reboot:**
		```bash
		systemctl start postgresql-15
		sleep 3
		systemctl start redis
		sleep 1
		systemctl start threatos-api
		sleep 8     # wait for rules to load
		systemctl start threatos-worker threatos-coverage threatos-retention
		sleep 2
		systemctl start threatos-forwarder
		systemctl start nginx
		```

		**Or simply — all enabled services auto-start on boot via systemd.**

		---

		## Database Quick Reference

		```bash
		# Connect to DB
		psql -h localhost -U threatos -d threatos

		# Row counts for all tables
		SELECT relname, n_live_tup
		FROM pg_stat_user_tables
		ORDER BY n_live_tup DESC;

		# Check active connections
		SELECT count(*) FROM pg_stat_activity WHERE datname='threatos';

		# Check DB size
		SELECT pg_size_pretty(pg_database_size('threatos'));

		# Check table sizes
		SELECT
		  tablename,
		  pg_size_pretty(pg_total_relation_size(tablename::text)) AS size
		FROM pg_tables
		WHERE schemaname='public'
		ORDER BY pg_total_relation_size(tablename::text) DESC;

		# Recent alerts
		SELECT technique_id, tactic, risk_score, entity_host, status, created_at
		FROM alerts ORDER BY created_at DESC LIMIT 10;

		# Recent raw events
		SELECT log_source, normalized->>'host' as host,
			   normalized->>'process' as process, received_at
		FROM raw_events ORDER BY received_at DESC LIMIT 10;

		# Rules by tactic
		SELECT tactic, count(*) FROM detection_rules
		WHERE enabled=true GROUP BY tactic ORDER BY count DESC;
		```

		---

		## Environment Variables — Full Reference

		| Variable | Default | Used By | What it controls |
		|---|---|---|---|
		| `APP_ENV` | `production` | API | Log format (JSON vs coloured) |
		| `DATABASE_URL` | — | API, workers | PostgreSQL connection string |
		| `DATABASE_POOL_SIZE` | `10` | API | Persistent DB connections |
		| `DATABASE_MAX_OVERFLOW` | `20` | API | Extra connections under load |
		| `REDIS_URL` | `redis://localhost:6379/0` | All | Redis connection |
		| `REDIS_STREAM_NAME` | `threatos:events:normalized` | API, worker | Event stream key |
		| `REDIS_CONSUMER_GROUP` | `detection-workers` | Worker | Consumer group name |
		| `REDIS_CONSUMER_NAME` | `worker-1` | Worker | Consumer instance name |
		| `WORKER_BATCH_SIZE` | `500` | Worker | Events per batch |
		| `WORKER_BLOCK_MS` | `200` | Worker | Poll interval |
		| `JWT_SECRET_KEY` | — | API | Access token signing |
		| `JWT_REFRESH_SECRET_KEY` | — | API | Refresh token signing |
		| `JWT_ACCESS_EXPIRE_MINUTES` | `480` | API | Access token lifetime (8h) |
		| `JWT_REFRESH_EXPIRE_DAYS` | `30` | API | Refresh token lifetime |
		| `MAX_LOGIN_ATTEMPTS` | `5` | API | Before lockout |
		| `LOGIN_LOCKOUT_MINUTES` | `15` | API | Lockout duration |
		| `THREATOS_ADMIN_PASSWORD` | — | API | Bootstrap admin (first run) |
		| `ASSET_CRITICALITY_TTL` | `300` | Worker | Redis cache TTL (seconds) |
		| `ATTCK_BUNDLE_URL` | GitHub URL | Coverage worker | STIX bundle source |
		| `COVERAGE_REFRESH_INTERVAL_SECONDS` | `3600` | Coverage worker | How often to refresh |
		| `NMAP_BINARY_PATH` | `/usr/bin/nmap` | API | Nmap location |
		| `VIRUSTOTAL_API_KEY` | — | API | VT enrichment |
		| `ABUSEIPDB_API_KEY` | — | API | AbuseIPDB enrichment |
		| `TI_CACHE_HOURS` | `24` | API | TI result cache lifetime |
		| `TI_TIMEOUT_SECONDS` | `10` | API | TI API call timeout |
		| `RAW_EVENTS_RETENTION_DAYS` | `90` | Retention worker | Raw event lifetime |
		| `AUDIT_LOG_RETENTION_DAYS` | `365` | Retention worker | Audit log lifetime |
		| `CLOSED_ALERTS_RETENTION_DAYS` | `365` | Retention worker | Closed alert lifetime |
		| `SCAN_RESULTS_RETENTION_DAYS` | `180` | Retention worker | Scan result lifetime |
		| `ALERT_WORKER_LAG` | `1000` | Health service | Lag threshold before warning |
		| `ALERT_NO_EVENTS_HOURS` | `2` | Health service | Idle time before warning |
		| `ALERT_MIN_RULES` | `100` | Health service | Min rules before critical |
		| `MAX_SESSIONS_PER_USER` | `5` | API | Concurrent sessions per user |
		| `THREATOS_API_KEY` | — | Forwarder | Ingest authentication |
		| `THREATOS_URL` | `http://localhost:8001` | Forwarder | API endpoint |
		| `FORWARDER_BATCH_SIZE` | `20` | Forwarder | Events per batch |
		| `FORWARDER_FLUSH_SECONDS` | `5` | Forwarder | Send interval |

		---

		## Logs Reference

		| What you want to see | Command |
		|---|---|
		| API startup + errors | `journalctl -u threatos-api -f` |
		| Detection + alert creation | `journalctl -u threatos-worker -f` |
		| ATT&CK refresh | `journalctl -u threatos-coverage -f` |
		| Retention runs | `journalctl -u threatos-retention --no-pager -n 20` |
		| Forwarder activity | `journalctl -u threatos-forwarder -f` |
		| Sigma import | `journalctl -u threatos-sigma-import --no-pager -n 30` |
		| nginx access | `tail -f /var/log/nginx/access.log` |
		| nginx errors | `tail -f /var/log/nginx/error.log` |
		| Backup log | `tail -f /var/log/backup-threatos.log` |
		| Grafana (test05) | `tail -f /fs/untd-1/threatos-monitoring/grafana.log` |
		| Prometheus (test05) | `tail -f /fs/untd-1/threatos-monitoring/prometheus.log` |

		---

		*ThreatOS Code Map — Naveen, IT Infrastructure, April 2026*
