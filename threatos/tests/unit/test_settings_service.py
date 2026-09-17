"""
tests/unit/test_settings_service.py
──────────────────────────────────────
Unit tests for services/settings_service.py.
Never touches the real .env — _ENV_PATH is always redirected to a tmp file,
and every module attribute this test changes is captured via monkeypatch
first so pytest reliably restores the true original at teardown.
"""
from __future__ import annotations

import pytest

from threatos.services import settings_service, ti_service, url_intel_service
from threatos.services.settings_service import get_api_key_status, set_api_key


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    # Redirect .env writes to a scratch file for every test in this module.
    monkeypatch.setattr(settings_service, "_ENV_PATH", tmp_path / ".env")
    # Capture originals so monkeypatch restores them at teardown, no matter
    # what set_api_key's plain setattr() does to them in between.
    monkeypatch.setattr(ti_service, "VT_API_KEY", ti_service.VT_API_KEY)
    monkeypatch.setattr(ti_service, "ABUSEIPDB_KEY", ti_service.ABUSEIPDB_KEY)
    monkeypatch.setattr(url_intel_service, "VT_API_KEY", url_intel_service.VT_API_KEY)
    monkeypatch.setattr(url_intel_service, "URLSCAN_API_KEY", url_intel_service.URLSCAN_API_KEY)
    monkeypatch.setattr(url_intel_service, "URLHAUS_AUTH_KEY", url_intel_service.URLHAUS_AUTH_KEY)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)


def test_rejects_unmanaged_key():
    with pytest.raises(ValueError):
        set_api_key("JWT_SECRET_KEY", "whatever")

def test_rejects_empty_value():
    with pytest.raises(ValueError):
        set_api_key("URLSCAN_API_KEY", "   ")

def test_rejects_newline_injection():
    with pytest.raises(ValueError):
        set_api_key("URLSCAN_API_KEY", "abc\nTHREATOS_ADMIN_PASSWORD=hacked")

def test_set_api_key_updates_in_memory_immediately():
    set_api_key("URLSCAN_API_KEY", "test-scan-key")
    assert url_intel_service.URLSCAN_API_KEY == "test-scan-key"

def test_set_api_key_updates_all_modules_sharing_a_key(tmp_path):
    set_api_key("VIRUSTOTAL_API_KEY", "shared-vt-key")
    assert ti_service.VT_API_KEY == "shared-vt-key"
    assert url_intel_service.VT_API_KEY == "shared-vt-key"

def test_set_api_key_persists_to_env_file(tmp_path):
    set_api_key("URLHAUS_AUTH_KEY", "uh-key-1")
    content = (tmp_path / ".env").read_text()
    assert "URLHAUS_AUTH_KEY=uh-key-1" in content

def test_set_api_key_updates_existing_env_line_in_place(tmp_path):
    (tmp_path / ".env").write_text("SOMETHING_ELSE=1\nURLHAUS_AUTH_KEY=old\nOTHER=2\n")
    set_api_key("URLHAUS_AUTH_KEY", "new-value")
    lines = (tmp_path / ".env").read_text().splitlines()
    assert lines.count("URLHAUS_AUTH_KEY=new-value") == 1
    assert "SOMETHING_ELSE=1" in lines
    assert "OTHER=2" in lines

def test_get_api_key_status_reflects_current_state():
    assert get_api_key_status()["URLSCAN_API_KEY"] is False
    set_api_key("URLSCAN_API_KEY", "abc")
    assert get_api_key_status()["URLSCAN_API_KEY"] is True
