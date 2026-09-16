# ── Base stage ─────────────────────────────────────────────────────────────────
# Builds on Python 3.11-slim (Debian-based) for the container image.
# The HOST machine can be Oracle Linux 8, Ubuntu, or anything else —
# the container is self-contained.
FROM python:3.11-slim AS base

# System deps: nmap for scan engine, libpq-dev for asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpq-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .

# ── Development stage ──────────────────────────────────────────────────────────
FROM base AS development
RUN uv pip install --system -e ".[dev]"
COPY . .
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ── Production stage ───────────────────────────────────────────────────────────
FROM base AS production
RUN uv pip install --system -e "."
COPY . .
RUN adduser --disabled-password --gecos "" threatos \
    && chown -R threatos:threatos /app
USER threatos
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["uvicorn", "threatos.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
