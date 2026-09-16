# ThreatOS — Oracle Linux 8 Setup Guide

## 1. System prerequisites

```bash
# Enable EPEL and CodeReady Linux Builder repositories
sudo dnf install -y epel-release
sudo dnf config-manager --set-enabled ol8_codeready_builder

# Core system packages
sudo dnf install -y \
    python3.11 \
    python3.11-pip \
    python3.11-devel \
    gcc \
    gcc-c++ \
    make \
    git \
    curl \
    wget \
    nmap \
    postgresql-devel \   # asyncpg needs libpq headers
    openssl-devel \
    libffi-devel

# Verify Python version
python3.11 --version   # should print Python 3.11.x
```

## 2. Docker & Docker Compose (for PostgreSQL + Redis)

```bash
# Remove old Docker if present
sudo dnf remove -y docker docker-client docker-client-latest \
    docker-common docker-latest docker-latest-logrotate \
    docker-logrotate docker-engine

# Add Docker CE repo (Oracle Linux 8 uses RHEL 8 repo)
sudo dnf config-manager --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo

sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker

# Add your user to docker group (avoids sudo on every command)
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

## 3. SELinux configuration

Oracle Linux 8 runs SELinux in enforcing mode by default. Docker handles
most cases automatically, but if you see permission-denied errors on
mounted volumes, run:

```bash
# Check SELinux status
getenforce   # should print "Enforcing"

# Allow Docker containers to access host files via bind mounts
# (required if you mount source code into containers)
sudo setsebool -P container_manage_cgroup 1

# If volume mount errors persist, relabel the project directory:
sudo chcon -Rt svirt_sandbox_file_t /opt/threatos

# For PostgreSQL data volume, ensure the directory is labelled:
sudo mkdir -p /var/lib/threatos/pgdata
sudo chcon -Rt svirt_sandbox_file_t /var/lib/threatos/pgdata
```

## 4. firewalld — open required ports

```bash
# Open API port (internal only — do NOT expose 8000 publicly)
sudo firewall-cmd --permanent --add-port=8000/tcp --zone=internal
sudo firewall-cmd --permanent --add-port=5432/tcp --zone=internal   # PostgreSQL
sudo firewall-cmd --permanent --add-port=6379/tcp --zone=internal   # Redis
sudo firewall-cmd --reload

# For the React frontend dev server (development only)
sudo firewall-cmd --permanent --add-port=5173/tcp --zone=internal
sudo firewall-cmd --reload
```

## 5. Project install

```bash
# Clone / copy project to /opt
sudo mkdir -p /opt/threatos
sudo chown $USER:$USER /opt/threatos
cp -r threatos_v2/* /opt/threatos/
cd /opt/threatos

# Install Python dependencies using python3.11 explicitly
python3.11 -m pip install --user -e ".[dev]"

# Or use a virtual environment (recommended for production)
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 6. Environment file

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL and REDIS_URL to match docker-compose.yml
```

## 7. Start the stack

```bash
cd /opt/threatos

# Start PostgreSQL and Redis
docker compose up -d db redis

# Wait for healthy status
docker compose ps   # both should show "healthy"

# Run DB migrations
python3.11 -m alembic upgrade head

# Seed ATT&CK bundle and detection rules
python3.11 -m threatos.scripts.load_attck_bundle
python3.11 -m threatos.scripts.seed_rules

# Start API
python3.11 -m uvicorn threatos.main:app --host 0.0.0.0 --port 8000 &

# Start ingest worker
python3.11 -m threatos.workers.ingest_worker &

# Start coverage worker
python3.11 -m threatos.workers.coverage_worker &
```

## 8. systemd service units (production)

Create `/etc/systemd/system/threatos-api.service`:

```ini
[Unit]
Description=ThreatOS FastAPI service
After=network.target docker.service
Requires=docker.service

[Service]
Type=exec
User=threatos
WorkingDirectory=/opt/threatos
Environment="PATH=/opt/threatos/.venv/bin:/usr/local/bin:/usr/bin"
ExecStart=/opt/threatos/.venv/bin/uvicorn threatos.main:app \
    --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/threatos-worker.service`:

```ini
[Unit]
Description=ThreatOS ingest worker
After=network.target threatos-api.service

[Service]
Type=exec
User=threatos
WorkingDirectory=/opt/threatos
Environment="PATH=/opt/threatos/.venv/bin:/usr/local/bin:/usr/bin"
ExecStart=/opt/threatos/.venv/bin/python -m threatos.workers.ingest_worker
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threatos-api threatos-worker
sudo systemctl status threatos-api
```

## 9. Run tests on Oracle Linux 8

```bash
cd /opt/threatos
source .venv/bin/activate
python3.11 -m pytest threatos/tests/ -v
```

## 10. Key differences from Ubuntu that affect daily use

| Task | Ubuntu | Oracle Linux 8 |
|------|--------|----------------|
| Install package | `apt install pkg` | `dnf install pkg` |
| Python command | `python3` | `python3.11` |
| pip command | `pip3` | `pip3.11` or venv pip |
| Service logs | `journalctl -u svc` | Same |
| Firewall | `ufw allow port` | `firewall-cmd --add-port` |
| SELinux | not enforced | enforced — check `audit.log` |
| Nmap binary | `/usr/bin/nmap` | `/usr/bin/nmap` (same) |
