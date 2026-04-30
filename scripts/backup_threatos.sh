#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# backup_threatos.sh — ThreatOS complete backup
# Run:  bash /opt/threatos/scripts/backup_threatos.sh
# Cron: 0 1 * * * bash /opt/threatos/scripts/backup_threatos.sh >> /var/log/backup-threatos.log 2>&1
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

BACKUP_DIR="/backup/threatos"
DATE=$(date +%Y%m%d_%H%M)
LOG="/var/log/backup-threatos.log"
KEEP_DAYS=7

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "══════════════════════════════════════════════"
log "ThreatOS Backup Started — $DATE"
log "══════════════════════════════════════════════"

mkdir -p "$BACKUP_DIR"

# ── 1. Database ───────────────────────────────────────────────────
log "[1/5] Database backup..."
if PGPASSWORD=threatos_secret pg_dump \
    -h localhost -U threatos threatos 2>/dev/null | \
    gzip > "$BACKUP_DIR/threatos_db_${DATE}.sql.gz"; then
    SIZE=$(du -sh "$BACKUP_DIR/threatos_db_${DATE}.sql.gz" | cut -f1)
    log "      OK  threatos_db_${DATE}.sql.gz  ($SIZE)"
else
    log "      ERROR: Database backup failed — is PostgreSQL running?"
    exit 1
fi

# ── 2. Code ───────────────────────────────────────────────────────
log "[2/5] Code backup..."
cd /opt
zip -qr "$BACKUP_DIR/threatos_code_${DATE}.zip" threatos/ \
    --exclude "threatos/.venv/*" \
    --exclude "threatos/threatos/frontend/node_modules/*" \
    --exclude "threatos/threatos/frontend/dist/*" \
    --exclude "threatos/__pycache__/*" \
    --exclude "threatos/threatos/__pycache__/*" \
    --exclude "threatos/.env"
SIZE=$(du -sh "$BACKUP_DIR/threatos_code_${DATE}.zip" | cut -f1)
log "      OK  threatos_code_${DATE}.zip  ($SIZE)"

# ── 3. Secrets & configs ──────────────────────────────────────────
log "[3/5] Secrets and configs..."
mkdir -p /tmp/threatos_cfg_${DATE}

cp /opt/threatos/.env             /tmp/threatos_cfg_${DATE}/threatos.env
cp /etc/nginx/conf.d/threatos.conf /tmp/threatos_cfg_${DATE}/nginx_threatos.conf 2>/dev/null || true
cp /etc/systemd/system/threatos-*.service /tmp/threatos_cfg_${DATE}/ 2>/dev/null || true
cp /etc/systemd/system/threatos-*.timer   /tmp/threatos_cfg_${DATE}/ 2>/dev/null || true

[ -f /var/lib/threatos-forwarder/state.json ] && \
    cp /var/lib/threatos-forwarder/state.json \
       /tmp/threatos_cfg_${DATE}/forwarder_state.json

zip -qj "$BACKUP_DIR/threatos_configs_${DATE}.zip" \
    /tmp/threatos_cfg_${DATE}/*
chmod 600 "$BACKUP_DIR/threatos_configs_${DATE}.zip"
rm -rf /tmp/threatos_cfg_${DATE}
log "      OK  threatos_configs_${DATE}.zip  (permissions: 600)"

# ── 4. Frontend dist ──────────────────────────────────────────────
log "[4/5] Frontend dist..."
cd /opt/threatos/threatos/frontend
zip -qr "$BACKUP_DIR/threatos_frontend_dist_${DATE}.zip" dist/
SIZE=$(du -sh "$BACKUP_DIR/threatos_frontend_dist_${DATE}.zip" | cut -f1)
log "      OK  threatos_frontend_dist_${DATE}.zip  ($SIZE)"

# ── 5. Cleanup ────────────────────────────────────────────────────
log "[5/5] Cleaning backups older than ${KEEP_DAYS} days..."
find "$BACKUP_DIR" -name "threatos_*" -mtime +${KEEP_DAYS} -delete
REMAINING=$(ls "$BACKUP_DIR"/threatos_* 2>/dev/null | wc -l)
log "      Remaining backup files: $REMAINING"

# ── Summary ───────────────────────────────────────────────────────
log ""
log "══ ThreatOS Backup Summary ══════════════════"
ls -lh "$BACKUP_DIR"/threatos_*${DATE}* 2>/dev/null | \
    awk '{print "  " $5 "\t" $9}' | tee -a "$LOG"
TOTAL=$(du -sh "$BACKUP_DIR" | cut -f1)
log "Backup dir total size: $TOTAL"
log "ThreatOS backup DONE — $DATE"
log ""
