# Changelog

All notable changes to ThreatOS are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/), grouped by date rather than
semantic version since this project doesn't yet cut versioned releases.

## 2026-09-18 — URL Scanner source health monitoring

### Added
- Per-source health tracking for the URL Scanner (`source_health_events`
  table, migration 009): every investigation logs each source's outcome
  (ok / no key configured / error). `GET /api/url-intel/health` reports,
  per source over the last 7 days, total checks and error rate, flagging
  a source "degraded" once it has 5+ checks and a ≥50% error rate.
- Source Health panel on the URL Scanner page — a status dot per source,
  refreshing automatically, so a provider silently tightening its policy
  (as PhishTank did) shows up as a red indicator instead of only being
  noticed via bad investigation results.

## 2026-09-18 — CI pipeline

### Added
- `.github/workflows/ci.yml` — runs the backend test suite (Python, no
  external services needed since tests run against SQLite in-memory) and
  the frontend typecheck + production build on every push/PR to `main`.
  `ruff` and `eslint` run too but are informational only (`|| true`) —
  the codebase currently has ~480 pre-existing `ruff` findings and a
  handful of `eslint` ones that predate this pipeline and haven't been
  cleaned up, so making lint a hard gate now would block unrelated work.
- CI status badge in `README.md`.

## 2026-09-17 — Docs cleanup

### Changed
- Moved every loose documentation file (`.txt`/`.docx`/`.md` notes) that
  was sitting at the repo root into `docs/`, where the rest of the
  project's documentation already lives.
- Removed `docs/README.md`, a stale duplicate of the root `README.md`
  (still referenced the old internal hostname and pre-fix rule counts —
  superseded by the real README, not a second source of truth).
- Resolved one filename collision between a root-level and a `docs/`
  copy of the same troubleshooting note by keeping the newer content.

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
- Spamhaus DBL report line duplicating an unrecognized listing code (e.g.
  "listed (unrecognized code 127.0.1.255) (127.0.1.255)"), found in a live
  investigation report.
- PhishTank returning a raw "HTTP 403" message with no explanation — their
  auth policy appears to have tightened to require `app_key` on every
  request; now reported as a clear, actionable message.
- Stray extra whitespace in two of the report's recommendation lines,
  caused by a Python string-continuation formatting slip
  ("...scan    the affected endpoint.").

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
