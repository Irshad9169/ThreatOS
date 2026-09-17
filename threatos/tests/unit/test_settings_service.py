"""
tests/unit/test_settings_service.py
──────────────────────────────────────
Unit tests for services/settings_service.py.
Never touches the real .env — _ENV_PATH is always redirected to a tmp file,
and every module attribute this test changes is captured via monkeypatch
first so pytest reliably restores the true original at teardown.
"""
from __future__ import annotations

import os

import pytest

from threatos.services import settings_service, ti_service, url_intel_service
from threatos.services.settings_service import (
    get_api_key_status, refresh_from_env_file, set_api_key,
)


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
    monkeypatch.setattr(url_intel_service, "GSB_API_KEY", url_intel_service.GSB_API_KEY)
    monkeypatch.setattr(url_intel_service, "PHISHTANK_APP_KEY", url_intel_service.PHISHTANK_APP_KEY)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("PHISHTANK_APP_KEY", raising=False)


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


# ── Cross-worker consistency ──────────────────────────────────────────────────
# Regression tests for: with `uvicorn --workers 2` (deploy/systemd/threatos-
# api.service), each worker is a separate process with its own memory. A key
# saved via set_api_key() in one worker's process only updates *that*
# process's in-memory state directly — other workers only find out by
# re-reading the shared .env file. These tests simulate "another worker wrote
# this" by writing straight to the .env file, bypassing set_api_key() (which
# would also update this process's own memory and mask the bug).

def test_refresh_picks_up_a_key_written_by_another_process(tmp_path):
    (tmp_path / ".env").write_text("URLSCAN_API_KEY=written-by-other-worker\n")
    assert url_intel_service.URLSCAN_API_KEY != "written-by-other-worker"

    refresh_from_env_file()

    assert url_intel_service.URLSCAN_API_KEY == "written-by-other-worker"
    assert os.environ["URLSCAN_API_KEY"] == "written-by-other-worker"

def test_get_api_key_status_reflects_file_without_local_set_api_key_call(tmp_path):
    (tmp_path / ".env").write_text("URLHAUS_AUTH_KEY=from-file\n")
    assert get_api_key_status()["URLHAUS_AUTH_KEY"] is True

def test_url_intel_get_key_status_reflects_file_directly(tmp_path):
    (tmp_path / ".env").write_text("URLSCAN_API_KEY=from-file\nURLHAUS_AUTH_KEY=also-from-file\n")
    status = url_intel_service.get_key_status()
    assert status == {"urlscan_key": True, "urlhaus_key": True,
                       "safe_browsing_key": False, "phishtank_key": False}

def test_refresh_does_not_overwrite_with_blank_env_lines(tmp_path):
    set_api_key("URLSCAN_API_KEY", "keep-me")
    (tmp_path / ".env").write_text(
        (tmp_path / ".env").read_text().replace("keep-me", "keep-me") + "URLHAUS_AUTH_KEY=\n"
    )
    refresh_from_env_file()
    assert url_intel_service.URLSCAN_API_KEY == "keep-me"

def test_refresh_missing_env_file_is_a_noop(tmp_path):
    assert not (tmp_path / ".env").exists()
    refresh_from_env_file()  # must not raise
