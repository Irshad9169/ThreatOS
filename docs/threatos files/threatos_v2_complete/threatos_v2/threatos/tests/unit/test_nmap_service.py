"""
tests/unit/test_nmap_service.py
─────────────────────────────────
Unit tests for services/nmap_service.py.
No real Nmap needed — run_scan is mocked; _parse_nmap_xml is tested directly.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text

from threatos.services.nmap_service import (
    SCAN_FLAGS,
    _parse_nmap_xml,
    create_scan,
    get_scan,
    list_scans,
    run_scan,
)


# ── Sample Nmap XML ───────────────────────────────────────────────────────────

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.x" accuracy="95"/>
      <osmatch name="Linux 5.x" accuracy="90"/>
    </os>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>"""

EMPTY_XML = """<?xml version="1.0"?><nmaprun></nmaprun>"""


# ── _parse_nmap_xml ───────────────────────────────────────────────────────────

def test_parse_counts_hosts_up():
    result = _parse_nmap_xml(SAMPLE_XML)
    assert result["hosts_up"] == 1

def test_parse_counts_hosts_down():
    result = _parse_nmap_xml(SAMPLE_XML)
    assert result["hosts_down"] == 1

def test_parse_only_open_ports():
    result = _parse_nmap_xml(SAMPLE_XML)
    ports = [p["port"] for p in result["open_ports"]]
    assert 22  in ports
    assert 80  in ports
    assert 443 not in ports   # closed, must be excluded

def test_parse_port_has_required_fields():
    result = _parse_nmap_xml(SAMPLE_XML)
    port   = result["open_ports"][0]
    assert "host" in port
    assert "port" in port
    assert "protocol" in port
    assert "service"  in port
    assert "state"    in port

def test_parse_extracts_service_names():
    result   = _parse_nmap_xml(SAMPLE_XML)
    services = {p["service"] for p in result["open_ports"]}
    assert "ssh"  in services
    assert "http" in services

def test_parse_os_guesses():
    result = _parse_nmap_xml(SAMPLE_XML)
    assert len(result["os_guesses"]) >= 1
    assert result["os_guesses"][0]["accuracy"] == 95

def test_parse_empty_xml():
    result = _parse_nmap_xml(EMPTY_XML)
    assert result["hosts_up"]   == 0
    assert result["open_ports"] == []

def test_parse_invalid_xml_returns_error():
    result = _parse_nmap_xml("NOT XML AT ALL")
    assert "error" in result

def test_parse_host_ip_extracted():
    result = _parse_nmap_xml(SAMPLE_XML)
    hosts = {p["host"] for p in result["open_ports"]}
    assert "10.0.0.1" in hosts


# ── SCAN_FLAGS ────────────────────────────────────────────────────────────────

def test_all_scan_types_defined():
    for t in ("quick", "full", "stealth", "udp", "vuln"):
        assert t in SCAN_FLAGS
        assert isinstance(SCAN_FLAGS[t], list)
        assert len(SCAN_FLAGS[t]) > 0

def test_quick_scan_uses_fast_flag():
    assert "-F" in SCAN_FLAGS["quick"]

def test_full_scan_scans_all_ports():
    assert "-p-" in SCAN_FLAGS["full"]

def test_udp_scan_uses_su_flag():
    assert "-sU" in SCAN_FLAGS["udp"]


# ── create_scan ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_scan_inserts_row(db_session):
    scan = await create_scan(db_session, "10.0.0.1", scan_type="quick")
    count = (await db_session.execute(text("SELECT COUNT(*) FROM scan_results"))).scalar()
    assert count == 1
    assert scan.target == "10.0.0.1"
    assert scan.status == "pending"

@pytest.mark.asyncio
async def test_create_scan_strips_target_whitespace(db_session):
    scan = await create_scan(db_session, "  10.0.0.1  ")
    assert scan.target == "10.0.0.1"

@pytest.mark.asyncio
async def test_create_scan_invalid_type_raises(db_session):
    with pytest.raises(ValueError, match="Unknown scan_type"):
        await create_scan(db_session, "10.0.0.1", scan_type="INVALID")

@pytest.mark.asyncio
async def test_create_scan_stores_requested_by(db_session):
    scan = await create_scan(db_session, "10.0.0.1", requested_by="analyst1")
    assert scan.requested_by == "analyst1"


# ── run_scan ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_scan_updates_status_to_completed(db_session):
    scan = await create_scan(db_session, "10.0.0.1")
    await db_session.commit()

    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=(SAMPLE_XML, None)):
        result = await run_scan(db_session, scan.id)

    assert result.status    == "completed"
    assert result.hosts_up  == 1
    assert result.hosts_down == 1
    assert len(result.open_ports) == 2

@pytest.mark.asyncio
async def test_run_scan_failed_on_nmap_error(db_session):
    scan = await create_scan(db_session, "10.0.0.1")
    await db_session.commit()

    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=("", "Nmap binary not found")):
        result = await run_scan(db_session, scan.id)

    assert result.status       == "failed"
    assert result.error_detail is not None

@pytest.mark.asyncio
async def test_run_scan_sets_timestamps(db_session):
    scan = await create_scan(db_session, "10.0.0.1")
    await db_session.commit()

    with patch("threatos.services.nmap_service._run_nmap",
               new_callable=AsyncMock, return_value=(SAMPLE_XML, None)):
        result = await run_scan(db_session, scan.id)

    assert result.started_at  is not None
    assert result.finished_at is not None
    assert result.duration_s  is not None
    assert result.duration_s  >= 0

@pytest.mark.asyncio
async def test_run_scan_missing_id_raises(db_session):
    with pytest.raises(ValueError, match="not found"):
        await run_scan(db_session, "nonexistent-id")

@pytest.mark.asyncio
async def test_run_scan_non_pending_raises(db_session):
    scan = await create_scan(db_session, "10.0.0.1")
    scan.status = "completed"
    await db_session.flush()

    with pytest.raises(ValueError, match="cannot run"):
        await run_scan(db_session, scan.id)


# ── get_scan / list_scans ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_scan_returns_scan(db_session):
    scan = await create_scan(db_session, "10.0.0.1")
    fetched = await get_scan(db_session, scan.id)
    assert fetched is not None
    assert fetched.id == scan.id

@pytest.mark.asyncio
async def test_get_scan_returns_none_for_missing(db_session):
    result = await get_scan(db_session, "nonexistent")
    assert result is None

@pytest.mark.asyncio
async def test_list_scans_returns_all(db_session):
    for target in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        await create_scan(db_session, target)
    scans = await list_scans(db_session)
    assert len(scans) == 3

@pytest.mark.asyncio
async def test_list_scans_filter_by_target(db_session):
    await create_scan(db_session, "10.0.0.1")
    await create_scan(db_session, "10.0.0.2")
    scans = await list_scans(db_session, target="10.0.0.1")
    assert len(scans) == 1
    assert scans[0].target == "10.0.0.1"

@pytest.mark.asyncio
async def test_list_scans_filter_by_status(db_session):
    s1 = await create_scan(db_session, "10.0.0.1")
    s2 = await create_scan(db_session, "10.0.0.2")
    s1.status = "completed"
    await db_session.flush()

    scans = await list_scans(db_session, status="completed")
    assert len(scans) == 1

@pytest.mark.asyncio
async def test_list_scans_empty_returns_empty(db_session):
    scans = await list_scans(db_session)
    assert scans == []
