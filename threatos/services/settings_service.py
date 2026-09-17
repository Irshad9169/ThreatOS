from __future__ import annotations
import importlib
import os
import re
from pathlib import Path

# Only these TI/URL-intel API keys are manageable from the UI. Deliberately
# excludes secrets like JWT signing keys, DB credentials, or the admin
# password — those stay .env-only, edited by hand.
_MANAGED_KEYS: dict[str, list[tuple[str, str]]] = {
    "VIRUSTOTAL_API_KEY": [
        ("threatos.services.ti_service", "VT_API_KEY"),
        ("threatos.services.url_intel_service", "VT_API_KEY"),
    ],
    "ABUSEIPDB_API_KEY": [
        ("threatos.services.ti_service", "ABUSEIPDB_KEY"),
    ],
    "URLSCAN_API_KEY": [
        ("threatos.services.url_intel_service", "URLSCAN_API_KEY"),
    ],
    "URLHAUS_AUTH_KEY": [
        ("threatos.services.url_intel_service", "URLHAUS_AUTH_KEY"),
    ],
    "GOOGLE_SAFE_BROWSING_API_KEY": [
        ("threatos.services.url_intel_service", "GSB_API_KEY"),
    ],
    "PHISHTANK_APP_KEY": [
        ("threatos.services.url_intel_service", "PHISHTANK_APP_KEY"),
    ],
}

_ENV_PATH = Path(".env")
_NO_NEWLINES_RE = re.compile(r"^[^\r\n]*$")


def get_api_key_status() -> dict[str, bool]:
    """Whether each managed key currently has a non-empty value. Never
    returns the actual value."""
    refresh_from_env_file()
    return {name: bool(os.environ.get(name)) for name in _MANAGED_KEYS}


def set_api_key(key_name: str, value: str) -> None:
    """Update a managed API key: apply in-memory immediately, persist to
    .env for future restarts. Raises ValueError on bad input."""
    if key_name not in _MANAGED_KEYS:
        raise ValueError(f"Unknown or unmanaged key: {key_name!r}")

    value = value.strip()
    if not value:
        raise ValueError("Value cannot be empty")
    if not _NO_NEWLINES_RE.match(value):
        raise ValueError("Value cannot contain newlines")

    os.environ[key_name] = value
    _apply_in_memory(key_name, value)
    _persist_to_env_file(key_name, value)


def _apply_in_memory(key_name: str, value: str) -> None:
    for module_path, attr in _MANAGED_KEYS[key_name]:
        module = importlib.import_module(module_path)
        setattr(module, attr, value)


def refresh_from_env_file() -> None:
    """
    Re-sync this process's copy of each managed key from the .env file on
    disk. Needed because the API runs as multiple uvicorn worker processes
    (see deploy/systemd/threatos-api.service, --workers 2) — each is a
    separate process with its own memory, so a key saved via the UI only
    updates in-memory state on whichever worker handled that request. The
    .env file is the one thing every worker actually shares, so re-reading
    it here (called at the start of each enrichment/status lookup) lets a
    stale worker catch up without needing a restart.
    """
    if not _ENV_PATH.exists():
        return
    for line in _ENV_PATH.read_text().splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key_name, _, value = line.partition("=")
        if key_name in _MANAGED_KEYS and value and os.environ.get(key_name) != value:
            os.environ[key_name] = value
            _apply_in_memory(key_name, value)


def _persist_to_env_file(key_name: str, value: str) -> None:
    lines = _ENV_PATH.read_text().splitlines() if _ENV_PATH.exists() else []
    prefix = f"{key_name}="
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = f"{key_name}={value}"
            break
    else:
        lines.append(f"{key_name}={value}")
    _ENV_PATH.write_text("\n".join(lines) + "\n")
