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
}

_ENV_PATH = Path(".env")
_NO_NEWLINES_RE = re.compile(r"^[^\r\n]*$")


def get_api_key_status() -> dict[str, bool]:
    """Whether each managed key currently has a non-empty value. Never
    returns the actual value."""
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
