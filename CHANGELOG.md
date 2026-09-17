# Changelog

All notable changes to ThreatOS are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/), grouped by date rather than
semantic version since this project doesn't yet cut versioned releases.

## 2026-09-17 — URL Scanner

### Added
- **URL Scanner**: standalone URL/domain investigation tool with 11 sources
  (VirusTotal, urlscan.io, Spamhaus DBL, SURBL, URIBL, SEM-URI, URLhaus, RDAP
  domain age, Google Safe Browsing, PhishTank, SPF/DMARC/DKIM), mounted at
  `/api/url-intel`. Each investigation generates a plain-text report meant
  to be copied straight into an email reply.
- **Investigation history**: every scan persists to a new `url_investigations`
  table (migration 008); a "View Report" action re-displays a past report
  instantly, without re-querying any external source.
- **Admin-managed API keys**: `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
  `URLSCAN_API_KEY`, `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, and
  `PHISHTANK_APP_KEY` can be added/changed from the UI (admin role) instead
  of hand-editing `.env` — applies immediately across all worker processes,
  also persists to `.env` for future restarts.
- Audit logging for URL Scanner investigations (previously missing — scans
  weren't showing up in the centralized Audit Log).

### Fixed
- API-key status card showing stale/incorrect state after a key was added,
  caused by a router holding a copy of the key imported at process-startup
  time instead of reading it live.
- Newly-added API keys sometimes appearing to "not take" — caused by the
  API running multiple `uvicorn` worker processes (separate memory per
  process); added a re-sync step so a stale worker picks up a key written
  by another worker via the shared `.env` file, without needing a restart.

## 2026-09-16 — Repo cleanup and test suite

### Added
- Ported the historical (pre-monorepo) test suite into `threatos/tests/`,
  rewritten against the current API rather than copied as-is — 436 passing
  tests where none ran before.
- `deploy/systemd/` and `deploy/nginx/` — the systemd unit files and nginx
  config the README's install steps already referenced but that didn't
  exist in the repo.
- Real dependency list in `pyproject.toml` (was empty — `pip install -e .`
  previously installed nothing).

### Fixed
- Detection engine: `in`/`not_in` operators were completely unimplemented in
  `rule_ast.py` (rules using them would silently never fire); `regex`/`gt`/
  `lt` crashed on invalid input instead of failing safe; `exists` didn't
  treat an empty string as "not present".
- Ingestion: JSON-sourced `dst_port` wasn't coerced to int; CEF events never
  captured `file_hash`; winlog events never captured destination IP/port and
  had no flat-payload fallback.
- Alerts: `closed_at` was never set when an alert closed, despite the column
  existing specifically for that.
- Rules API: no `GET /api/rules/{id}` route existed; `technique_id` and
  `detection_ast` had no validation on create, so malformed rules were
  silently accepted and then silently dropped by the live detection engine.
- Redis client forced RESP2 — a fresh `redis` package install (no version
  ceiling was pinned) defaults to negotiating RESP3 via `HELLO` on connect,
  which this deployment's Redis (predates 6.0) doesn't understand.
- Untracked `.venv` and `.egg-info` from git (were never meant to be
  version-controlled build artifacts).
- Deduplicated `Scripts/`/`scripts/` — same physical folder tracked twice
  under two cases on a case-insensitive filesystem.

## 2026-04-30 — Initial commit

- First commit of ThreatOS: FastAPI backend, React frontend, detection rule
  engine, ATT&CK coverage mapping, alerting, asset registry, purple team
  validation, nmap scanning, threat intelligence enrichment.
