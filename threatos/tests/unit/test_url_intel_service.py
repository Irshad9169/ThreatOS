"""
tests/unit/test_url_intel_service.py
──────────────────────────────────────
Unit tests for services/url_intel_service.py.
All DB operations run against SQLite in-memory via the db_session fixture.
All HTTP calls are intercepted with httpx.MockTransport — no live network.
DNS calls (Spamhaus) are mocked via unittest.mock.patch on dns.resolver.resolve.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import dns.resolver
import httpx
import pytest

from threatos.services.ti_service import (
    VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_NO_KEY, VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
)
from threatos.services.url_intel_service import (
    enrich_url, enrich_url_domain_age, enrich_url_email_auth,
    enrich_url_phishtank, enrich_url_safe_browsing, enrich_url_sem,
    enrich_url_spamhaus, enrich_url_surbl, enrich_url_uribl,
    enrich_url_urlhaus, enrich_url_urlscan, enrich_url_virustotal,
    generate_investigation_report, get_investigation, list_investigations,
    parse_url,
)


_RealAsyncClient = httpx.AsyncClient

def _mock_client_factory(handler):
    """Returns a callable that stands in for httpx.AsyncClient(...)."""
    def factory(*args, **kwargs):
        return _RealAsyncClient(transport=httpx.MockTransport(handler))
    return factory


# ── parse_url ─────────────────────────────────────────────────────────────────

def test_parse_url_valid():
    url, domain = parse_url("https://sub.example.com/path?x=1")
    assert url == "https://sub.example.com/path?x=1"
    assert domain == "sub.example.com"

def test_parse_url_rejects_missing_scheme():
    with pytest.raises(ValueError):
        parse_url("example.com/path")

def test_parse_url_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        parse_url("ftp://example.com")


# ── VirusTotal ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_virustotal_no_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.VT_API_KEY", "")
    result = await enrich_url_virustotal(db_session, "https://example.com")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_virustotal_existing_analysis_malicious(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.VT_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "test-key"
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 80, "undetected": 5},
            "last_final_url": "https://example.com/",
            "title": "Example", "categories": {"vendorA": "phishing"},
        }}})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_virustotal(db_session, "https://example.com")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["malicious_engines"] == 5
    assert result["cached"] is False

@pytest.mark.asyncio
async def test_virustotal_submit_and_poll_flow(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.VT_API_KEY", "test-key")
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/urls/" in request.url.path and calls["n"] == 0:
            return httpx.Response(404)
        if request.method == "POST" and request.url.path == "/api/v3/urls":
            return httpx.Response(200, json={"data": {"id": "analysis-1"}})
        if request.method == "GET" and "/analyses/" in request.url.path:
            calls["n"] += 1
            return httpx.Response(200, json={"data": {"attributes": {"status": "completed"}}})
        if request.method == "GET" and "/urls/" in request.url.path:
            return httpx.Response(200, json={"data": {"attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 0},
            }}})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)), \
         patch("asyncio.sleep", new=lambda *_a, **_kw: _noop()):
        result = await enrich_url_virustotal(db_session, "https://neverscanned.example")

    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_virustotal_uses_cache_on_second_call(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.VT_API_KEY", "test-key")
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 0},
        }}})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        await enrich_url_virustotal(db_session, "https://cached.example")
        result2 = await enrich_url_virustotal(db_session, "https://cached.example")

    assert hits["n"] == 1
    assert result2["cached"] is True


async def _noop(*_a, **_kw):
    return None


# ── urlscan.io ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_urlscan_finds_existing_scan_via_search(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        if "/search/" in request.url.path:
            return httpx.Response(200, json={"results": [
                {"task": {"uuid": "abc-123", "time": "2026-01-01"}},
            ]})
        if "/result/" in request.url.path:
            return httpx.Response(200, json={
                "page": {"ip": "1.2.3.4", "country": "US", "asn": "AS1234"},
                "task": {"screenshotURL": "https://urlscan.io/screenshots/abc-123.png",
                          "reportURL": "https://urlscan.io/result/abc-123/"},
                "verdicts": {"overall": {"malicious": True, "score": 90}},
            })
        raise AssertionError(f"unexpected request: {request.url}")

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_urlscan(db_session, "https://evil.example/phish", "evil.example")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["screenshot_url"].endswith(".png")

@pytest.mark.asyncio
async def test_urlscan_submits_when_no_existing_scan(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.URLSCAN_API_KEY", "")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/search/" in request.url.path:
            return httpx.Response(200, json={"results": []})
        if request.method == "POST" and "/scan/" in request.url.path:
            body = request.content
            assert b'"visibility":"public"' in body or b'"visibility": "public"' in body \
                or b"public" in body
            return httpx.Response(200, json={"uuid": "new-uuid"})
        if "/result/" in request.url.path:
            return httpx.Response(200, json={
                "page": {}, "task": {"reportURL": "https://urlscan.io/result/new-uuid/"},
                "verdicts": {"overall": {"malicious": False, "score": 0}},
            })
        raise AssertionError(f"unexpected request: {request.url}")

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)), \
         patch("threatos.services.url_intel_service.asyncio.sleep", new=_noop):
        result = await enrich_url_urlscan(db_session, "https://new.example", "new.example")

    assert result["verdict"] == VERDICT_CLEAN
    assert result["public"] is True


# ── Spamhaus DBL ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_spamhaus_not_listed(db_session):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = await enrich_url_spamhaus(db_session, "clean-domain.example")
    assert result["verdict"] == VERDICT_CLEAN
    assert result["reason"] == "not listed"

@pytest.mark.asyncio
async def test_spamhaus_listed_as_phishing(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.1.4"]):
        result = await enrich_url_spamhaus(db_session, "phish-domain.example")
    assert result["verdict"] == VERDICT_MALICIOUS
    assert "phishing" in result["reason"]

@pytest.mark.asyncio
async def test_spamhaus_dns_error_returns_unknown(db_session):
    with patch("dns.resolver.resolve", side_effect=Exception("timeout")):
        result = await enrich_url_spamhaus(db_session, "unreachable-domain.example")
    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_spamhaus_uses_cache_on_second_call(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.1.5"]) as mocked:
        await enrich_url_spamhaus(db_session, "malware-domain.example")
        result2 = await enrich_url_spamhaus(db_session, "malware-domain.example")
    assert mocked.call_count == 1
    assert result2["cached"] is True


# ── URLhaus ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_urlhaus_no_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.URLHAUS_AUTH_KEY", "")
    result = await enrich_url_urlhaus(db_session, "https://example.com")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_urlhaus_found_online_malware(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.URLHAUS_AUTH_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["auth-key"] == "test-key"
        return httpx.Response(200, json={
            "query_status": "ok", "url_status": "online", "threat": "malware_download",
            "tags": ["emotet"], "payloads": [{"file_type": "exe", "signature": "Emotet"}],
        })

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_urlhaus(db_session, "https://malware.example/payload.exe")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["threat"] == "malware_download"

@pytest.mark.asyncio
async def test_urlhaus_not_found(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.URLHAUS_AUTH_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_results"})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_urlhaus(db_session, "https://unknown.example")

    assert result["verdict"] == VERDICT_UNKNOWN


# ── RDAP domain age ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rdap_old_domain_is_clean(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/domain/old-domain.example"
        return httpx.Response(200, json={"events": [
            {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ]})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_domain_age(db_session, "old-domain.example")

    assert result["verdict"] == VERDICT_CLEAN
    assert result["age_days"] > 3000

@pytest.mark.asyncio
async def test_rdap_young_domain_is_suspicious(db_session):
    from datetime import timedelta
    recent = (datetime.now(UTC) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"events": [
            {"eventAction": "registration", "eventDate": recent},
        ]})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_domain_age(db_session, "brand-new-domain.example")

    assert result["verdict"] == VERDICT_SUSPICIOUS
    assert result["age_days"] < 30

@pytest.mark.asyncio
async def test_rdap_not_found_returns_unknown(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_domain_age(db_session, "unregistered.example")

    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_rdap_rate_limited_returns_unknown(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_domain_age(db_session, "throttled.example")

    assert result["verdict"] == VERDICT_UNKNOWN
    assert "rate-limited" in result["message"]

@pytest.mark.asyncio
async def test_rdap_uses_cache_on_second_call(db_session):
    calls = {"n": 0}
    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"events": [
            {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
        ]})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        await enrich_url_domain_age(db_session, "cached-domain.example")
        result2 = await enrich_url_domain_age(db_session, "cached-domain.example")

    assert calls["n"] == 1
    assert result2["cached"] is True


# ── Google Safe Browsing ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_safe_browsing_no_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.GSB_API_KEY", "")
    result = await enrich_url_safe_browsing(db_session, "https://example.com")
    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_safe_browsing_flagged_url_is_malicious(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.GSB_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "test-key"
        return httpx.Response(200, json={"matches": [
            {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM",
             "threat": {"url": "https://phish.example"}, "cacheDuration": "300.000s"},
        ]})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_safe_browsing(db_session, "https://phish.example")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["threat_types"] == ["SOCIAL_ENGINEERING"]

@pytest.mark.asyncio
async def test_safe_browsing_clean_url_returns_empty_object(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.GSB_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_safe_browsing(db_session, "https://clean.example")

    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_safe_browsing_invalid_key_returns_no_api_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.GSB_API_KEY", "bad-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_safe_browsing(db_session, "https://example.com")

    assert result["verdict"] == VERDICT_NO_KEY

@pytest.mark.asyncio
async def test_safe_browsing_uses_cache_on_second_call(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.GSB_API_KEY", "test-key")
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        await enrich_url_safe_browsing(db_session, "https://cached.example")
        result2 = await enrich_url_safe_browsing(db_session, "https://cached.example")

    assert calls["n"] == 1
    assert result2["cached"] is True


# ── SURBL ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_surbl_not_listed(db_session):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = await enrich_url_surbl(db_session, "clean-domain.example")
    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_surbl_listed_is_malicious(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.0.8"]):
        result = await enrich_url_surbl(db_session, "bad-domain.example")
    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["code"] == "127.0.0.8"

@pytest.mark.asyncio
async def test_surbl_dns_error_returns_unknown(db_session):
    with patch("dns.resolver.resolve", side_effect=Exception("timeout")):
        result = await enrich_url_surbl(db_session, "unreachable-domain.example")
    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_surbl_uses_cache_on_second_call(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.0.8"]) as mocked:
        await enrich_url_surbl(db_session, "cached-bad-domain.example")
        result2 = await enrich_url_surbl(db_session, "cached-bad-domain.example")
    assert mocked.call_count == 1
    assert result2["cached"] is True


# ── URIBL ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_uribl_not_listed(db_session):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = await enrich_url_uribl(db_session, "clean-domain.example")
    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_uribl_listed_is_malicious(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.0.4"]):
        result = await enrich_url_uribl(db_session, "bad-domain.example")
    assert result["verdict"] == VERDICT_MALICIOUS

@pytest.mark.asyncio
async def test_uribl_rate_limit_code_is_not_treated_as_malicious(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.0.255"]):
        result = await enrich_url_uribl(db_session, "throttled-domain.example")
    assert result["verdict"] == VERDICT_UNKNOWN


# ── SEM-URI ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sem_not_listed(db_session):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = await enrich_url_sem(db_session, "clean-domain.example")
    assert result["verdict"] == VERDICT_CLEAN

@pytest.mark.asyncio
async def test_sem_listed_is_malicious(db_session):
    with patch("dns.resolver.resolve", return_value=["127.0.0.2"]):
        result = await enrich_url_sem(db_session, "bad-domain.example")
    assert result["verdict"] == VERDICT_MALICIOUS


# ── Email authentication ──────────────────────────────────────────────────────

class _FakeTxtRdata:
    """Mimics the shape of a real dnspython TXT rdata object closely enough
    for _query_txt_sync's getattr(a, "strings", [a.to_text()]) — that default
    expression is evaluated eagerly by Python regardless of whether "strings"
    is present, so to_text() must exist too, just like on the real object."""
    def __init__(self, value: str):
        self.strings = [value.encode()]
    def to_text(self):
        return self.strings[0].decode()

def _txt_handler(records_by_name: dict):
    def _resolve(name, rtype, lifetime=None):
        name_str = str(name).rstrip(".")
        if name_str not in records_by_name:
            raise dns.resolver.NXDOMAIN()
        return [_FakeTxtRdata(r) for r in records_by_name[name_str]]
    return _resolve

@pytest.mark.asyncio
async def test_email_auth_configured_is_clean(db_session):
    handler = _txt_handler({
        "good-domain.example": ["v=spf1 include:_spf.google.com ~all"],
        "_dmarc.good-domain.example": ["v=DMARC1; p=reject"],
    })
    with patch("dns.resolver.resolve", side_effect=handler):
        result = await enrich_url_email_auth(db_session, "good-domain.example")
    assert result["verdict"] == VERDICT_CLEAN
    assert result["spf"] is True
    assert result["dmarc_policy"] == "reject"

@pytest.mark.asyncio
async def test_email_auth_missing_both_is_suspicious(db_session):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = await enrich_url_email_auth(db_session, "no-auth-domain.example")
    assert result["verdict"] == VERDICT_SUSPICIOUS
    assert result["spf"] is False
    assert result["dmarc_policy"] is None

@pytest.mark.asyncio
async def test_email_auth_dmarc_policy_none_is_suspicious(db_session):
    handler = _txt_handler({
        "weak-domain.example": ["v=spf1 ~all"],
        "_dmarc.weak-domain.example": ["v=DMARC1; p=none"],
    })
    with patch("dns.resolver.resolve", side_effect=handler):
        result = await enrich_url_email_auth(db_session, "weak-domain.example")
    assert result["verdict"] == VERDICT_SUSPICIOUS
    assert result["dmarc_policy"] == "none"

@pytest.mark.asyncio
async def test_email_auth_uses_cache_on_second_call(db_session):
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()) as mocked:
        await enrich_url_email_auth(db_session, "cached-domain.example")
        calls_after_first = mocked.call_count
        result2 = await enrich_url_email_auth(db_session, "cached-domain.example")

    assert result2["cached"] is True
    assert mocked.call_count == calls_after_first  # no new DNS lookups on the cached call


# ── PhishTank ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_phishtank_verified_phish_is_malicious(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": {
            "in_database": True, "verified": True, "valid": True,
            "phish_id": "12345", "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=12345",
        }})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_phishtank(db_session, "https://phish.example")

    assert result["verdict"] == VERDICT_MALICIOUS
    assert result["phish_id"] == "12345"

@pytest.mark.asyncio
async def test_phishtank_unverified_report_is_suspicious(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": {
            "in_database": True, "verified": False, "valid": False, "phish_id": "999",
        }})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_phishtank(db_session, "https://maybe-phish.example")

    assert result["verdict"] == VERDICT_SUSPICIOUS

@pytest.mark.asyncio
async def test_phishtank_not_in_database_returns_unknown(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": {"in_database": False}})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_phishtank(db_session, "https://clean.example")

    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_phishtank_rate_limited_returns_unknown(db_session):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(509)

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_phishtank(db_session, "https://throttled.example")

    assert result["verdict"] == VERDICT_UNKNOWN
    assert "rate limit" in result["message"]

@pytest.mark.asyncio
async def test_phishtank_works_without_app_key(db_session, monkeypatch):
    monkeypatch.setattr("threatos.services.url_intel_service.PHISHTANK_APP_KEY", "")

    def handler(request: httpx.Request) -> httpx.Response:
        assert "app_key" not in request.content.decode()
        return httpx.Response(200, json={"results": {"in_database": False}})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        result = await enrich_url_phishtank(db_session, "https://example.com")

    assert result["verdict"] == VERDICT_UNKNOWN

@pytest.mark.asyncio
async def test_phishtank_uses_cache_on_second_call(db_session):
    calls = {"n": 0}
    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"results": {"in_database": False}})

    with patch("threatos.services.url_intel_service.httpx.AsyncClient",
               _mock_client_factory(handler)):
        await enrich_url_phishtank(db_session, "https://cached.example")
        result2 = await enrich_url_phishtank(db_session, "https://cached.example")

    assert calls["n"] == 1
    assert result2["cached"] is True


# ── Combined enrichment ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_url_invalid_url_raises(db_session):
    with pytest.raises(ValueError):
        await enrich_url(db_session, "not-a-url")

@pytest.mark.asyncio
async def test_enrich_url_worst_verdict_wins(db_session):
    async def fake_vt(db, url): return {"source": "virustotal", "verdict": VERDICT_CLEAN}
    async def fake_urlscan(db, url, domain): return {"source": "urlscan", "verdict": VERDICT_MALICIOUS}
    async def fake_spamhaus(db, domain): return {"source": "spamhaus", "verdict": VERDICT_CLEAN, "reason": "not listed"}
    async def fake_urlhaus(db, url): return {"source": "urlhaus", "verdict": VERDICT_NO_KEY, "message": "no key"}
    async def fake_rdap(db, domain): return {"source": "rdap", "verdict": VERDICT_CLEAN,
                                              "age_days": 3650, "registered_at": "2015-01-01T00:00:00Z"}
    async def fake_gsb(db, url): return {"source": "safe_browsing", "verdict": VERDICT_NO_KEY,
                                          "message": "no key"}
    async def fake_surbl(db, domain): return {"source": "surbl", "verdict": VERDICT_CLEAN}
    async def fake_pt(db, url): return {"source": "phishtank", "verdict": VERDICT_UNKNOWN,
                                         "message": "not found"}
    async def fake_uribl(db, domain): return {"source": "uribl", "verdict": VERDICT_CLEAN}
    async def fake_sem(db, domain): return {"source": "sem", "verdict": VERDICT_CLEAN}
    async def fake_email_auth(db, domain): return {"source": "email_auth", "verdict": VERDICT_CLEAN,
                                                    "spf": True, "dmarc_policy": "reject"}

    with patch("threatos.services.url_intel_service.enrich_url_virustotal", fake_vt), \
         patch("threatos.services.url_intel_service.enrich_url_urlscan", fake_urlscan), \
         patch("threatos.services.url_intel_service.enrich_url_spamhaus", fake_spamhaus), \
         patch("threatos.services.url_intel_service.enrich_url_urlhaus", fake_urlhaus), \
         patch("threatos.services.url_intel_service.enrich_url_domain_age", fake_rdap), \
         patch("threatos.services.url_intel_service.enrich_url_safe_browsing", fake_gsb), \
         patch("threatos.services.url_intel_service.enrich_url_surbl", fake_surbl), \
         patch("threatos.services.url_intel_service.enrich_url_phishtank", fake_pt), \
         patch("threatos.services.url_intel_service.enrich_url_uribl", fake_uribl), \
         patch("threatos.services.url_intel_service.enrich_url_sem", fake_sem), \
         patch("threatos.services.url_intel_service.enrich_url_email_auth", fake_email_auth):
        result = await enrich_url(db_session, "https://mixed.example", investigated_by="analyst1")

    assert result["overall_verdict"] == VERDICT_MALICIOUS
    assert "MALICIOUS" in result["report_text"]
    assert "analyst1" in result["report_text"]
    assert "mixed.example" in result["report_text"]


# ── Report generation ─────────────────────────────────────────────────────────

def test_report_contains_expected_sections_for_malicious():
    sources = {
        "urlscan": {"verdict": VERDICT_MALICIOUS, "score": 90, "landing_ip": "1.2.3.4",
                    "asn": "AS1234", "country": "US",
                    "screenshot_url": "https://urlscan.io/s.png",
                    "report_url": "https://urlscan.io/result/x/", "public": True},
        "virustotal": {"verdict": VERDICT_MALICIOUS, "malicious_engines": 10, "total_engines": 90,
                       "final_url": "https://evil.example/", "categories": {"vendorA": "phishing"},
                       "report_url": "https://virustotal.com/gui/url/x"},
        "spamhaus": {"verdict": VERDICT_MALICIOUS, "reason": "phishing domain", "code": "127.0.1.4"},
        "urlhaus": {"verdict": VERDICT_MALICIOUS, "url_status": "online", "threat": "phishing",
                    "tags": ["phish"], "payloads": []},
    }
    report = generate_investigation_report(
        "https://evil.example/phish", "evil.example", sources,
        VERDICT_MALICIOUS, "analyst1", datetime.now(UTC))

    assert "URL / DOMAIN INVESTIGATION REPORT" in report
    assert "VERDICT: MALICIOUS" in report
    assert "TECHNICAL EVIDENCE" in report
    assert "RECOMMENDATION" in report
    assert "Block this URL" in report
    assert "urlscan.io" in report.lower()

def test_report_clean_verdict_has_no_action_recommendation():
    sources = {
        "urlscan": {"verdict": VERDICT_CLEAN, "score": 0},
        "virustotal": {"verdict": VERDICT_CLEAN, "malicious_engines": 0, "total_engines": 90},
        "spamhaus": {"verdict": VERDICT_CLEAN, "reason": "not listed"},
        "urlhaus": {"verdict": VERDICT_UNKNOWN, "message": "Not found in URLhaus database"},
    }
    report = generate_investigation_report(
        "https://clean.example", "clean.example", sources,
        VERDICT_CLEAN, None, datetime.now(UTC))

    assert "VERDICT: CLEAN" in report
    assert "No action required" in report


# ── Investigation history ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_url_persists_investigation_row(db_session):
    async def fake(db, *a, **kw): return {"source": "x", "verdict": VERDICT_CLEAN}
    with patch("threatos.services.url_intel_service.enrich_url_virustotal", fake), \
         patch("threatos.services.url_intel_service.enrich_url_urlscan", fake), \
         patch("threatos.services.url_intel_service.enrich_url_spamhaus", fake), \
         patch("threatos.services.url_intel_service.enrich_url_urlhaus", fake), \
         patch("threatos.services.url_intel_service.enrich_url_domain_age", fake), \
         patch("threatos.services.url_intel_service.enrich_url_safe_browsing", fake), \
         patch("threatos.services.url_intel_service.enrich_url_surbl", fake), \
         patch("threatos.services.url_intel_service.enrich_url_phishtank", fake), \
         patch("threatos.services.url_intel_service.enrich_url_uribl", fake), \
         patch("threatos.services.url_intel_service.enrich_url_sem", fake), \
         patch("threatos.services.url_intel_service.enrich_url_email_auth", fake):
        result = await enrich_url(db_session, "https://persisted.example", investigated_by="analyst1")

    assert result["id"]
    record = await get_investigation(db_session, result["id"])
    assert record is not None
    assert record.url == "https://persisted.example"
    assert record.domain == "persisted.example"
    assert record.investigated_by == "analyst1"
    assert record.report_text == result["report_text"]

@pytest.mark.asyncio
async def test_list_investigations_most_recent_first(db_session):
    async def fake(db, *a, **kw): return {"source": "x", "verdict": VERDICT_CLEAN}
    with patch("threatos.services.url_intel_service.enrich_url_virustotal", fake), \
         patch("threatos.services.url_intel_service.enrich_url_urlscan", fake), \
         patch("threatos.services.url_intel_service.enrich_url_spamhaus", fake), \
         patch("threatos.services.url_intel_service.enrich_url_urlhaus", fake), \
         patch("threatos.services.url_intel_service.enrich_url_domain_age", fake), \
         patch("threatos.services.url_intel_service.enrich_url_safe_browsing", fake), \
         patch("threatos.services.url_intel_service.enrich_url_surbl", fake), \
         patch("threatos.services.url_intel_service.enrich_url_phishtank", fake), \
         patch("threatos.services.url_intel_service.enrich_url_uribl", fake), \
         patch("threatos.services.url_intel_service.enrich_url_sem", fake), \
         patch("threatos.services.url_intel_service.enrich_url_email_auth", fake):
        await enrich_url(db_session, "https://first.example")
        await enrich_url(db_session, "https://second.example")

    records = await list_investigations(db_session)
    assert [r.domain for r in records[:2]] == ["second.example", "first.example"]

@pytest.mark.asyncio
async def test_get_investigation_returns_none_when_missing(db_session):
    assert await get_investigation(db_session, "not-a-real-id") is None
