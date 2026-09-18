"""
tests/unit/test_ti_service.py
──────────────────────────────
Unit tests for services/ti_service.py — the original IP/hash/domain threat
intel enrichment (VirusTotal + AbuseIPDB), reused internally by
url_intel_service.py but never directly tested itself until now.
All DB operations run against SQLite in-memory via the db_session fixture.
All HTTP calls are intercepted with httpx.MockTransport — no live network.
"""
from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from threatos.services.ti_service import (
    VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_NO_KEY, VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN, cleanup_expired_enrichments, detect_ioc_type,
    enrich_abuseipdb, enrich_alert, enrich_ioc, enrich_virustotal,
    extract_iocs_from_alert, get_cached_enrichment, get_enrichment_stats,
    save_enrichment,
)

_RealAsyncClient = httpx.AsyncClient

def _mock_client_factory(handler):
    def factory(*args, **kwargs):
        return _RealAsyncClient(transport=httpx.MockTransport(handler))
    return factory


# ── detect_ioc_type ─────────────────────────────────────────────────────────────

def test_detect_ioc_type_public_ip():
    assert detect_ioc_type("8.8.8.8") == "ip"

def test_detect_ioc_type_private_ip_returns_none():
    assert detect_ioc_type("192.168.1.1") is None
    assert detect_ioc_type("10.0.0.5") is None

def test_detect_ioc_type_loopback_returns_none():
    assert detect_ioc_type("127.0.0.1") is None

def test_detect_ioc_type_sha256():
    assert detect_ioc_type("a" * 64) == "sha256"

def test_detect_ioc_type_md5():
    assert detect_ioc_type("a" * 32) == "md5"

def test_detect_ioc_type_sha1():
    assert detect_ioc_type("a" * 40) == "sha1"

def test_detect_ioc_type_domain():
    assert detect_ioc_type("evil.example.com") == "domain"

def test_detect_ioc_type_invalid_returns_none():
    assert detect_ioc_type("not an ioc!!") is None
    assert detect_ioc_type("") is None
    assert detect_ioc_type(None) is None

def test_detect_ioc_type_too_long_returns_none():
    assert detect_ioc_type("a.com" * 200) is None


# ── extract_iocs_from_alert ──────────────────────────────────────────────────────

def test_extract_iocs_from_alert_finds_direct_fields():
    iocs = extract_iocs_from_alert({
        "entity_host": "evil.example.com",
        "src_ip": "1.2.3.4",
        "dst_ip": "192.168.1.1",  # private, should be skipped
        "file_hash": "a" * 64,
    })
    assert ("domain", "evil.example.com") in iocs
    assert ("ip", "1.2.3.4") in iocs
    assert ("sha256", "a" * 64) in iocs
    assert not any(v == "192.168.1.1" for _, v in iocs)

def test_extract_iocs_from_alert_checks_raw_fields():
    iocs = extract_iocs_from_alert({
        "raw_fields": {"md5": "b" * 32, "domain": "raw.example.com"},
    })
    assert ("md5", "b" * 32) in iocs
    assert ("domain", "raw.example.com") in iocs

def test_extract_iocs_from_alert_dedups_identical_values():
    iocs = extract_iocs_from_alert({
        "entity_host": "evil.example.com",
        "raw_fields": {"domain": "evil.example.com"},
    })
    assert len([v for _, v in iocs if v == "evil.example.com"]) == 1

def test_extract_iocs_from_alert_ignores_non_string_and_empty():
    iocs = extract_iocs_from_alert({
        "entity_host": None, "src_ip": "", "raw_fields": "not-a-dict",
    })
    assert iocs == []

def test_extract_iocs_from_alert_empty_alert_returns_empty():
    assert extract_iocs_from_alert({}) == []


# ── Cache ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_save_enrichment_inserts_new_row(db_session):
    entry = await save_enrichment(db_session, "ip", "1.2.3.4", "virustotal",
                                   VERDICT_MALICIOUS, score=90)
    assert entry.verdict == VERDICT_MALICIOUS
    cached = await get_cached_enrichment(db_session, "ip", "1.2.3.4")
    assert len(cached) == 1
    assert cached[0].score == 90

@pytest.mark.asyncio
async def test_save_enrichment_updates_existing_row_for_same_source(db_session):
    await save_enrichment(db_session, "ip", "1.2.3.4", "virustotal", VERDICT_CLEAN, score=0)
    await save_enrichment(db_session, "ip", "1.2.3.4", "virustotal", VERDICT_MALICIOUS, score=95)

    cached = await get_cached_enrichment(db_session, "ip", "1.2.3.4")
    assert len(cached) == 1  # updated in place, not duplicated
    assert cached[0].verdict == VERDICT_MALICIOUS
    assert cached[0].score == 95

@pytest.mark.asyncio
async def test_save_enrichment_different_sources_coexist(db_session):
    await save_enrichment(db_session, "ip", "1.2.3.4", "virustotal", VERDICT_CLEAN)
    await save_enrichment(db_session, "ip", "1.2.3.4", "abuseipdb", VERDICT_MALICIOUS)

    cached = await get_cached_enrichment(db_session, "ip", "1.2.3.4")
    assert len(cached) == 2


# ── VirusTotal ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_virustotal_no_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "")
    result = await enrich_virustotal(db_session, "ip", "1.2.3.4")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_virustotal_malicious_classification(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 80, "undetected": 5},
            "country": "US", "as_owner": "Example ASN", "tags": ["botnet"],
        }}})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_virustotal(db_session, "ip", "1.2.3.4")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["malicious_engines"] == 5
    assert result["country"] == "US"

@pytest.mark.asyncio
async def test_virustotal_suspicious_classification(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 89, "undetected": 0},
        }}})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_virustotal(db_session, "domain", "example.com")
    assert result["verdict"] == VERDICT_SUSPICIOUS

@pytest.mark.asyncio
async def test_virustotal_clean_classification(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 0},
        }}})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_virustotal(db_session, "domain", "example.com")
    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_virustotal_not_found_returns_unknown_and_caches(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_virustotal(db_session, "domain", "neverseen.example")
    assert result["verdict"] == VERDICT_UNKNOWN

    cached = await get_cached_enrichment(db_session, "domain", "neverseen.example")
    assert len(cached) == 1  # 404 is cached too, avoids repeat lookups

@pytest.mark.asyncio
async def test_virustotal_invalid_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "bad-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_virustotal(db_session, "ip", "1.2.3.4")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_virustotal_http_error_returns_unknown(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_virustotal(db_session, "ip", "1.2.3.4")
    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_virustotal_unsupported_ioc_type_returns_unknown(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")
    result = await enrich_virustotal(db_session, "url", "https://example.com")
    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_virustotal_uses_cache_on_second_call(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 0},
        }}})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        await enrich_virustotal(db_session, "ip", "1.2.3.4")
        result2 = await enrich_virustotal(db_session, "ip", "1.2.3.4")

    assert calls["n"] == 1
    assert result2["cached"] is True


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_abuseipdb_no_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "")
    result = await enrich_abuseipdb(db_session, "1.2.3.4")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_abuseipdb_malicious_classification(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": 95, "countryCode": "RU", "isp": "Bad ISP",
            "totalReports": 42, "usageType": "Data Center/Web Hosting",
        }})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_abuseipdb(db_session, "1.2.3.4")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["score"] == 95
    # Regression: `asn` was previously computed from abuseConfidenceScore
    # (nonsensical) and then silently dropped from the fresh-lookup response
    # entirely, while the cached-path response did include an `asn` key
    # (from the DB column) — inconsistent shape depending on cache state.
    assert result["asn"] == "Bad ISP"

@pytest.mark.asyncio
async def test_abuseipdb_suspicious_classification(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 30}})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_abuseipdb(db_session, "1.2.3.4")
    assert result["verdict"] == VERDICT_SUSPICIOUS

@pytest.mark.asyncio
async def test_abuseipdb_clean_classification(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_abuseipdb(db_session, "1.2.3.4")
    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_abuseipdb_cached_response_includes_asn(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": 10, "isp": "Some ISP",
        }})

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        await enrich_abuseipdb(db_session, "5.6.7.8")
        result2 = await enrich_abuseipdb(db_session, "5.6.7.8")

    assert result2["cached"] is True
    assert result2["asn"] == "Some ISP"  # matches the fresh-lookup shape

@pytest.mark.asyncio
async def test_abuseipdb_invalid_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "bad-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_abuseipdb(db_session, "1.2.3.4")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_abuseipdb_http_error_returns_unknown(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with patch("threatos.services.ti_service.httpx.AsyncClient", _mock_client_factory(handler)):
        result = await enrich_abuseipdb(db_session, "1.2.3.4")
    assert result["verdict"] == VERDICT_UNKNOWN


# ── Combined enrichment ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_ioc_ip_checks_both_sources_worst_verdict_wins(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "test-key")

    async def fake_vt(db, ioc_type, ioc_value):
        return {"source": "virustotal", "verdict": VERDICT_CLEAN}
    async def fake_abuse(db, ip):
        return {"source": "abuseipdb", "verdict": VERDICT_MALICIOUS}

    with patch("threatos.services.ti_service.enrich_virustotal", fake_vt), \
         patch("threatos.services.ti_service.enrich_abuseipdb", fake_abuse):
        result = await enrich_ioc(db_session, "ip", "1.2.3.4")

    assert result["overall_verdict"] == VERDICT_MALICIOUS
    assert set(result["sources"]) == {"virustotal", "abuseipdb"}

@pytest.mark.asyncio
async def test_enrich_ioc_hash_only_checks_virustotal(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")
    result = await enrich_ioc(db_session, "sha256", "a" * 64)
    assert set(result["sources"]) == {"virustotal"}

@pytest.mark.asyncio
async def test_enrich_ioc_domain_only_checks_virustotal(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")
    result = await enrich_ioc(db_session, "domain", "example.com")
    assert set(result["sources"]) == {"virustotal"}

@pytest.mark.asyncio
async def test_enrich_alert_aggregates_and_summarizes_malicious(db_session):
    async def fake_ioc(db, ioc_type, ioc_value):
        if ioc_value == "evil.example.com":
            return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                     "overall_verdict": VERDICT_MALICIOUS, "sources": {}}
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                 "overall_verdict": VERDICT_CLEAN, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_ioc):
        result = await enrich_alert(db_session, {
            "entity_host": "evil.example.com", "src_ip": "8.8.8.8",
        })

    assert result["overall_verdict"] == VERDICT_MALICIOUS
    assert "MALICIOUS: evil.example.com" in result["summary"]
    assert result["iocs_found"] == 2

@pytest.mark.asyncio
async def test_enrich_alert_no_iocs_found(db_session):
    result = await enrich_alert(db_session, {"description": "no IOCs here"})
    assert result["iocs_found"] == 0
    assert result["overall_verdict"] == VERDICT_UNKNOWN
    assert result["summary"] == "No enrichable IOCs found"

@pytest.mark.asyncio
async def test_enrich_alert_all_clean_summary(db_session):
    async def fake_ioc(db, ioc_type, ioc_value):
        return {"ioc_type": ioc_type, "ioc_value": ioc_value,
                 "overall_verdict": VERDICT_CLEAN, "sources": {}}

    with patch("threatos.services.ti_service.enrich_ioc", fake_ioc):
        result = await enrich_alert(db_session, {"src_ip": "8.8.8.8"})

    assert result["overall_verdict"] == VERDICT_CLEAN
    assert "clean" in result["summary"]


# ── Cleanup & stats ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cleanup_expired_enrichments_deletes_only_expired(db_session):
    from datetime import UTC, datetime, timedelta
    from threatos.models.ti_enrichment import TIEnrichment
    import uuid

    now = datetime.now(UTC)
    db_session.add(TIEnrichment(id=str(uuid.uuid4()), ioc_type="ip", ioc_value="1.1.1.1",
                                 source="virustotal", verdict=VERDICT_CLEAN,
                                 enriched_at=now - timedelta(hours=48),
                                 expires_at=now - timedelta(hours=24)))  # expired
    db_session.add(TIEnrichment(id=str(uuid.uuid4()), ioc_type="ip", ioc_value="2.2.2.2",
                                 source="virustotal", verdict=VERDICT_CLEAN,
                                 enriched_at=now, expires_at=now + timedelta(hours=24)))  # fresh
    await db_session.flush()

    deleted = await cleanup_expired_enrichments(db_session)
    assert deleted == 1

    remaining = await get_cached_enrichment(db_session, "ip", "2.2.2.2")
    assert len(remaining) == 1

@pytest.mark.asyncio
async def test_get_enrichment_stats_counts_by_verdict(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.ti_service.VT_API_KEY", "test-key")
    monkeypatch.setattr("threatos.services.ti_service.ABUSEIPDB_KEY", "")

    await save_enrichment(db_session, "ip", "1.1.1.1", "virustotal", VERDICT_MALICIOUS)
    await save_enrichment(db_session, "ip", "2.2.2.2", "virustotal", VERDICT_SUSPICIOUS)
    await save_enrichment(db_session, "domain", "clean.example", "virustotal", VERDICT_CLEAN)

    stats = await get_enrichment_stats(db_session)
    assert stats["total_cached"] == 3
    assert stats["malicious"] == 1
    assert stats["suspicious"] == 1
    assert stats["virustotal_key"] is True
    assert stats["abuseipdb_key"] is False
