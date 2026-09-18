# Redis 5.x → 6.2+ Upgrade Guide

## Why

This deployment currently runs Redis 5.x on Oracle Linux 8. Two workarounds
in the ThreatOS codebase exist specifically because of that:

1. **`HELLO` / RESP3 incompatibility** — `HELLO` was added in Redis 6.0.
   Newer versions of the `redis` Python package negotiate RESP3 via `HELLO`
   on connect by default; against a pre-6.0 server this crash-loops the
   worker with `unknown command 'HELLO'`. Worked around in code by forcing
   `protocol=2` in `threatos/core/redis_client.py` and
   `threatos/workers/ingest_worker.py`.
2. **`XAUTOCLAIM` unsupported** — added in Redis 6.2. This is what the
   ingest worker uses for crash recovery (reclaiming stream messages left
   pending by a worker that died mid-processing). On Redis 5.x this fails
   every time with a logged warning, and crash-recovery reclaim is
   effectively disabled — a message from a crashed worker just sits
   pending forever instead of being picked back up.

Upgrading to **Redis 6.2 or newer** removes the root cause of both. No
code changes are required for either — connecting with `protocol=2` still
works fine against a newer server (RESP2 is still fully supported), and
`_reclaim_pending()` in `ingest_worker.py` calls `xautoclaim` inside a
plain `try/except` with no version check — it will simply stop raising
and start working the moment the server supports it.

## Before you start

- This requires briefly stopping Redis — do it in a maintenance window.
- Stream data in `threatos:events:normalized` is transient (events already
  ingested and evaluated); a short Redis restart during the upgrade is not
  a data-loss concern for the pipeline itself. If Redis has RDB/AOF
  persistence enabled and you want to be extra safe, take a manual backup
  first: `redis-cli SAVE` (writes `dump.rdb` to the configured `dir`).
- Confirm current version and install method before choosing an upgrade
  path:
  ```bash
  redis-server --version
  rpm -qa | grep -i redis
  dnf module list redis    # shows which module streams are available/enabled
  ```

## Option A — DNF module stream (recommended for Oracle Linux 8)

OL8's AppStream repo ships Redis via DNF module streams. If a `redis:6`
(or newer) stream is available, this is the simplest path and stays on
distro-supported packages:

```bash
sudo systemctl stop threatos-worker threatos-api threatos-coverage threatos-retention
sudo systemctl stop redis

sudo dnf module list redis                 # confirm redis:6 (or higher) exists
sudo dnf module reset redis
sudo dnf module enable redis:6             # pick the highest available >= 6.2
sudo dnf update redis

sudo systemctl start redis
redis-cli ping                              # expect PONG
redis-cli INFO server | grep redis_version  # confirm >= 6.2.0

sudo systemctl start threatos-api threatos-worker threatos-coverage threatos-retention
```

## Option B — Redis's official YUM repo (if you want 7.x specifically)

If OL8's module stream doesn't go past 6.2 and you want a newer release:

```bash
sudo systemctl stop threatos-worker threatos-api threatos-coverage threatos-retention
sudo systemctl stop redis

sudo rpm --import https://packages.redis.io/gpg
sudo tee /etc/yum.repos.d/redis.repo > /dev/null <<'EOF'
[redis]
name=Redis
baseurl=https://packages.redis.io/rpm/rhel8
enabled=1
gpgcheck=1
EOF
sudo dnf install -y redis

sudo systemctl start redis
redis-cli ping
redis-cli INFO server | grep redis_version

sudo systemctl start threatos-api threatos-worker threatos-coverage threatos-retention
```

## After upgrading

1. Confirm the version: `redis-cli INFO server | grep redis_version` → `6.2.0` or higher.
2. Restart the ThreatOS services if they weren't already restarted above (`threatos-api`, `threatos-worker`, `threatos-coverage`, `threatos-retention`) so they reconnect.
3. Watch the worker log for the warning to disappear:
   ```bash
   journalctl -u threatos-worker -n 50 --no-pager
   ```
   You should no longer see `XAUTOCLAIM failed (Redis may not support it): ...` at startup.
4. Update the README's "Known Limitations" section (already noted there — remove the line once confirmed, or leave it with a note that it's resolved as of this deployment).

## Optional cleanup (not required)

The `protocol=2` forcing in `redis_client.py`/`ingest_worker.py` can stay
as-is indefinitely — RESP2 works identically well against Redis 6.2+/7.x,
so there's no functional reason to remove it. If you'd rather move to
RESP3 to match the redis-py default going forward, that's a separate,
purely optional cleanup with no urgency attached to this upgrade.
