from __future__ import annotations
import asyncio
import base64
import hashlib
import logging
import os
import re
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.models.url_investigation import UrlInvestigation
from threatos.services.settings_service import refresh_from_env_file
from threatos.services.ti_service import (
    VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_NO_KEY, VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN, get_cached_enrichment, save_enrichment,
)

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
VT_API_KEY          = os.environ.get("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY      = os.environ.get("URLSCAN_API_KEY", "")
URLHAUS_AUTH_KEY     = os.environ.get("URLHAUS_AUTH_KEY", "")
GSB_API_KEY          = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
PHISHTANK_APP_KEY    = os.environ.get("PHISHTANK_APP_KEY", "")
TI_TIMEOUT           = int(os.environ.get("TI_TIMEOUT_SECONDS", "10"))

_URLSCAN_POLL_DELAY_S   = 15   # initial wait before first poll
_URLSCAN_POLL_INTERVAL  = 5    # seconds between polls
_URLSCAN_POLL_ATTEMPTS  = 6    # ~15s + 6*5s = ~45s bounded wait


def _cache_key_for_url(url: str) -> str:
    """TIEnrichment.ioc_value is String(500) — hash anything longer."""
    return url if len(url) <= 500 else hashlib.sha256(url.encode()).hexdigest()


def parse_url(url: str) -> tuple[str, str]:
    """Validate a URL and return (normalized_url, domain). Raises ValueError."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"'{url}' is not a valid http(s) URL (need scheme + host, e.g. https://example.com/path)"
        )
    return url, parsed.hostname.lower()


# ── VirusTotal (URL) ──────────────────────────────────────────────────────────
async def enrich_url_virustotal(db: AsyncSession, url: str) -> dict:
    if not VT_API_KEY:
        return {"source": "virustotal", "verdict": VERDICT_NO_KEY,
                "message": "Set VIRUSTOTAL_API_KEY in .env"}

    cache_key = _cache_key_for_url(url)
    cached = await get_cached_enrichment(db, "url", cache_key)
    vt_cache = [c for c in cached if c.source == "virustotal"]
    if vt_cache:
        c = vt_cache[0]
        rr = c.raw_response or {}
        return {"source": "virustotal", "verdict": c.verdict, "score": c.score,
                "final_url": rr.get("final_url"), "title": rr.get("title"),
                "categories": rr.get("categories"), "report_url": rr.get("report_url"),
                "cached": True}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            resp = await client.get(vt_url, headers=headers)

            if resp.status_code == 404:
                # Never scanned before — submit it, then poll the analysis.
                submit = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    data={"url": url}, headers=headers,
                )
                if submit.status_code == 401:
                    return {"source": "virustotal", "verdict": VERDICT_NO_KEY,
                            "message": "Invalid VirusTotal API key"}
                if submit.status_code not in (200, 201):
                    return {"source": "virustotal", "verdict": VERDICT_UNKNOWN,
                            "message": f"VT submit error: HTTP {submit.status_code}"}
                analysis_id = submit.json().get("data", {}).get("id")

                completed = False
                for _ in range(6):
                    await asyncio.sleep(3)
                    a = await client.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                    )
                    if a.status_code == 200 and \
                       a.json().get("data", {}).get("attributes", {}).get("status") == "completed":
                        completed = True
                        break
                if not completed:
                    return {"source": "virustotal", "verdict": VERDICT_UNKNOWN,
                            "message": "VirusTotal scan submitted but not completed in time — check back shortly"}

                resp = await client.get(vt_url, headers=headers)

            if resp.status_code == 401:
                return {"source": "virustotal", "verdict": VERDICT_NO_KEY,
                        "message": "Invalid VirusTotal API key"}
            if resp.status_code != 200:
                return {"source": "virustotal", "verdict": VERDICT_UNKNOWN,
                        "message": f"VT API error: HTTP {resp.status_code}"}

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1

        if malicious >= 3:
            verdict = VERDICT_MALICIOUS
        elif malicious >= 1 or suspicious >= 3:
            verdict = VERDICT_SUSPICIOUS
        elif total > 0:
            verdict = VERDICT_CLEAN
        else:
            verdict = VERDICT_UNKNOWN

        score       = int(malicious / total * 100) if total else 0
        final_url   = attrs.get("last_final_url") or url
        title       = attrs.get("title")
        categories  = attrs.get("categories") or {}
        report_url  = f"https://www.virustotal.com/gui/url/{url_id}"

        await save_enrichment(db, "url", cache_key, "virustotal", verdict, score=score,
                               raw_response={"final_url": final_url, "title": title,
                                             "categories": categories, "report_url": report_url,
                                             "stats": stats, "total": total})

        return {"source": "virustotal", "verdict": verdict, "score": score,
                "malicious_engines": malicious, "total_engines": total,
                "final_url": final_url, "title": title, "categories": categories,
                "report_url": report_url, "cached": False}

    except httpx.TimeoutException:
        return {"source": "virustotal", "verdict": VERDICT_UNKNOWN,
                "message": "VirusTotal request timed out"}
    except Exception as exc:
        log.error("VirusTotal URL enrichment failed: %s", exc)
        return {"source": "virustotal", "verdict": VERDICT_UNKNOWN, "message": str(exc)}


# ── urlscan.io ────────────────────────────────────────────────────────────────
async def enrich_url_urlscan(db: AsyncSession, url: str, domain: str) -> dict:
    cache_key = _cache_key_for_url(url)
    cached = await get_cached_enrichment(db, "url", cache_key)
    us_cache = [c for c in cached if c.source == "urlscan"]
    if us_cache:
        c = us_cache[0]
        rr = c.raw_response or {}
        return {"source": "urlscan", "verdict": c.verdict, "score": c.score,
                "country": c.country, "asn": c.asn,
                "screenshot_url": rr.get("screenshot_url"),
                "report_url": rr.get("report_url"), "public": rr.get("public"),
                "cached": True}

    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
    is_public = not bool(URLSCAN_API_KEY)

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            # Search first — avoids submitting a duplicate scan if one exists already.
            search = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f'page.url:"{url}"'}, headers=headers,
            )
            result_uuid = None
            if search.status_code == 200:
                hits = search.json().get("results", [])
                if hits:
                    result_uuid = hits[0].get("task", {}).get("uuid")

            if not result_uuid:
                visibility = "public" if is_public else "unlisted"
                submit = await client.post(
                    "https://urlscan.io/api/v1/scan/",
                    json={"url": url, "visibility": visibility}, headers=headers,
                )
                if submit.status_code == 401:
                    return {"source": "urlscan", "verdict": VERDICT_UNKNOWN,
                            "message": "Invalid urlscan.io API key"}
                if submit.status_code == 429:
                    return {"source": "urlscan", "verdict": VERDICT_UNKNOWN,
                            "message": "urlscan.io daily quota exceeded"}
                if submit.status_code not in (200, 201):
                    return {"source": "urlscan", "verdict": VERDICT_UNKNOWN,
                            "message": f"urlscan.io submit error: HTTP {submit.status_code}"}
                result_uuid = submit.json().get("uuid")
                is_public = visibility == "public"

                await asyncio.sleep(_URLSCAN_POLL_DELAY_S)
                result = None
                for _ in range(_URLSCAN_POLL_ATTEMPTS):
                    r = await client.get(f"https://urlscan.io/api/v1/result/{result_uuid}/",
                                          headers=headers)
                    if r.status_code == 200:
                        result = r
                        break
                    await asyncio.sleep(_URLSCAN_POLL_INTERVAL)
                if result is None:
                    return {"source": "urlscan", "verdict": VERDICT_UNKNOWN,
                            "message": f"Scan submitted but not completed in time — "
                                       f"check https://urlscan.io/result/{result_uuid}/ shortly"}
            else:
                result = await client.get(f"https://urlscan.io/api/v1/result/{result_uuid}/",
                                           headers=headers)

        data     = result.json()
        page     = data.get("page", {})
        task     = data.get("task", {})
        verdicts = data.get("verdicts", {}).get("overall", {})
        is_malicious = bool(verdicts.get("malicious"))
        score        = verdicts.get("score", 0) or 0

        if is_malicious:
            verdict = VERDICT_MALICIOUS
        elif score > 0:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        screenshot_url = task.get("screenshotURL")
        report_url     = task.get("reportURL") or f"https://urlscan.io/result/{result_uuid}/"
        country        = page.get("country")
        asn            = page.get("asn")

        await save_enrichment(db, "url", cache_key, "urlscan", verdict, score=score,
                               country=country, asn=asn,
                               raw_response={"screenshot_url": screenshot_url,
                                             "report_url": report_url,
                                             "landing_ip": page.get("ip"),
                                             "public": is_public})

        return {"source": "urlscan", "verdict": verdict, "score": score,
                "country": country, "asn": asn, "landing_ip": page.get("ip"),
                "screenshot_url": screenshot_url, "report_url": report_url,
                "public": is_public, "cached": False}

    except httpx.TimeoutException:
        return {"source": "urlscan", "verdict": VERDICT_UNKNOWN,
                "message": "urlscan.io request timed out"}
    except Exception as exc:
        log.error("urlscan.io enrichment failed: %s", exc)
        return {"source": "urlscan", "verdict": VERDICT_UNKNOWN, "message": str(exc)}


# ── Spamhaus DBL (free DNS-based lookup) ─────────────────────────────────────
_SPAMHAUS_CODES = {
    "127.0.1.2":   ("spam domain",                    VERDICT_MALICIOUS),
    "127.0.1.4":   ("phishing domain",                 VERDICT_MALICIOUS),
    "127.0.1.5":   ("malware domain",                  VERDICT_MALICIOUS),
    "127.0.1.6":   ("botnet C2 domain",                VERDICT_MALICIOUS),
    "127.0.1.102": ("compromised legitimate — spam",    VERDICT_SUSPICIOUS),
    "127.0.1.103": ("compromised legitimate — phishing",VERDICT_SUSPICIOUS),
    "127.0.1.104": ("compromised legitimate — malware",  VERDICT_SUSPICIOUS),
    "127.0.1.105": ("compromised legitimate — botnet C2",VERDICT_SUSPICIOUS),
}

def _query_dnsbl_sync(domain: str, zone: str) -> tuple[str | None, str | None]:
    """Blocking DNSBL A-record lookup against `<domain>.<zone>`. Returns
    (code, error_message); code is None (no error) when NXDOMAIN (not listed)."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(f"{domain}.{zone}", "A", lifetime=TI_TIMEOUT)
        return str(answers[0]), None
    except dns.resolver.NXDOMAIN:
        return None, None
    except Exception as exc:
        return None, str(exc)

async def enrich_url_spamhaus(db: AsyncSession, domain: str) -> dict:
    cached = await get_cached_enrichment(db, "domain", domain)
    sh_cache = [c for c in cached if c.source == "spamhaus"]
    if sh_cache:
        c = sh_cache[0]
        rr = c.raw_response or {}
        return {"source": "spamhaus", "verdict": c.verdict,
                "reason": rr.get("reason"), "code": rr.get("code"), "cached": True}

    code, error = await asyncio.to_thread(_query_dnsbl_sync, domain, "dbl.spamhaus.org")

    if error:
        return {"source": "spamhaus", "verdict": VERDICT_UNKNOWN,
                "message": f"Spamhaus DNS lookup failed: {error}"}

    if code is None:
        verdict, reason = VERDICT_CLEAN, "not listed"
    else:
        reason, verdict = _SPAMHAUS_CODES.get(code, (f"listed (unrecognized code {code})",
                                                        VERDICT_SUSPICIOUS))

    await save_enrichment(db, "domain", domain, "spamhaus", verdict,
                           raw_response={"code": code, "reason": reason})

    return {"source": "spamhaus", "verdict": verdict, "reason": reason,
            "code": code, "cached": False}


# ── SURBL (free DNS-based lookup) ─────────────────────────────────────────────
# multi.surbl.org returns a bitmask-encoded 127.0.0.x response combining
# several sub-lists (phishing, malware, abuse, etc). Public secondary sources
# disagree on the exact current bit->category mapping, so rather than risk
# mis-categorizing, this only reports listed vs not-listed — still a useful
# independent signal, just without a category breakdown.
async def enrich_url_surbl(db: AsyncSession, domain: str) -> dict:
    cached = await get_cached_enrichment(db, "domain", domain)
    surbl_cache = [c for c in cached if c.source == "surbl"]
    if surbl_cache:
        c = surbl_cache[0]
        rr = c.raw_response or {}
        return {"source": "surbl", "verdict": c.verdict, "code": rr.get("code"), "cached": True}

    code, error = await asyncio.to_thread(_query_dnsbl_sync, domain, "multi.surbl.org")

    if error:
        return {"source": "surbl", "verdict": VERDICT_UNKNOWN,
                "message": f"SURBL DNS lookup failed: {error}"}

    verdict = VERDICT_MALICIOUS if code else VERDICT_CLEAN

    await save_enrichment(db, "domain", domain, "surbl", verdict, raw_response={"code": code})

    return {"source": "surbl", "verdict": verdict, "code": code, "cached": False}


# ── URIBL (free DNS-based lookup, rate-limit-aware) ───────────────────────────
# URIBL's public mirrors return a sentinel 127.0.0.255 (sometimes 127.0.0.1)
# when a querying IP is rate-limited — that means "try again later", not
# "listed". Treating it as malicious would produce false positives at volume.
_URIBL_RATE_LIMIT_CODES = {"127.0.0.255", "127.0.0.1"}

async def enrich_url_uribl(db: AsyncSession, domain: str) -> dict:
    cached = await get_cached_enrichment(db, "domain", domain)
    ur_cache = [c for c in cached if c.source == "uribl"]
    if ur_cache:
        c = ur_cache[0]
        rr = c.raw_response or {}
        return {"source": "uribl", "verdict": c.verdict, "code": rr.get("code"), "cached": True}

    code, error = await asyncio.to_thread(_query_dnsbl_sync, domain, "multi.uribl.com")

    if error:
        return {"source": "uribl", "verdict": VERDICT_UNKNOWN,
                "message": f"URIBL DNS lookup failed: {error}"}

    if code in _URIBL_RATE_LIMIT_CODES:
        return {"source": "uribl", "verdict": VERDICT_UNKNOWN,
                "message": "URIBL public mirror rate-limited this query — try again later"}

    verdict = VERDICT_MALICIOUS if code else VERDICT_CLEAN

    await save_enrichment(db, "domain", domain, "uribl", verdict, raw_response={"code": code})

    return {"source": "uribl", "verdict": verdict, "code": code, "cached": False}


# ── SEM-URI (Spam Eating Monkey, free DNS-based lookup) ───────────────────────
async def enrich_url_sem(db: AsyncSession, domain: str) -> dict:
    cached = await get_cached_enrichment(db, "domain", domain)
    sem_cache = [c for c in cached if c.source == "sem"]
    if sem_cache:
        c = sem_cache[0]
        rr = c.raw_response or {}
        return {"source": "sem", "verdict": c.verdict, "code": rr.get("code"), "cached": True}

    code, error = await asyncio.to_thread(_query_dnsbl_sync, domain, "uribl.spameatingmonkey.net")

    if error:
        return {"source": "sem", "verdict": VERDICT_UNKNOWN,
                "message": f"SEM-URI DNS lookup failed: {error}"}

    verdict = VERDICT_MALICIOUS if code else VERDICT_CLEAN

    await save_enrichment(db, "domain", domain, "sem", verdict, raw_response={"code": code})

    return {"source": "sem", "verdict": verdict, "code": code, "cached": False}


# ── Email authentication (SPF / DMARC / best-effort DKIM) ────────────────────
# DKIM has no fixed, discoverable record location (the selector is arbitrary
# and only appears in a real email's headers), so this only probes a handful
# of very common selectors — a miss does NOT mean DKIM isn't configured, and
# is deliberately excluded from the verdict; it's shown as bonus info only.
_COMMON_DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "dkim"]

def _query_txt_sync(name: str) -> tuple[list[str], str | None]:
    """Blocking TXT lookup. Returns (list_of_txt_record_strings, error_message)."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=TI_TIMEOUT)
        records = []
        for a in answers:
            parts = getattr(a, "strings", [a.to_text()])
            records.append("".join(p.decode() if isinstance(p, bytes) else p for p in parts))
        return records, None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except Exception as exc:
        return [], str(exc)

async def enrich_url_email_auth(db: AsyncSession, domain: str) -> dict:
    cached = await get_cached_enrichment(db, "domain", domain)
    ea_cache = [c for c in cached if c.source == "email_auth"]
    if ea_cache:
        c = ea_cache[0]
        rr = c.raw_response or {}
        return {"source": "email_auth", "verdict": c.verdict, "spf": rr.get("spf"),
                "dmarc_policy": rr.get("dmarc_policy"),
                "dkim_selector_found": rr.get("dkim_selector_found"), "cached": True}

    spf_records, _ = await asyncio.to_thread(_query_txt_sync, domain)
    spf = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)

    dmarc_records, _ = await asyncio.to_thread(_query_txt_sync, f"_dmarc.{domain}")
    dmarc = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)
    dmarc_policy = None
    if dmarc:
        m = re.search(r"p=(\w+)", dmarc, re.IGNORECASE)
        dmarc_policy = m.group(1).lower() if m else None

    dkim_results = await asyncio.gather(*[
        asyncio.to_thread(_query_txt_sync, f"{sel}._domainkey.{domain}")
        for sel in _COMMON_DKIM_SELECTORS
    ])
    dkim_selector_found = None
    for selector, (records, _err) in zip(_COMMON_DKIM_SELECTORS, dkim_results):
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            dkim_selector_found = selector
            break

    if not spf and not dmarc:
        verdict = VERDICT_SUSPICIOUS
    elif dmarc_policy == "none":
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_CLEAN

    await save_enrichment(db, "domain", domain, "email_auth", verdict,
                           raw_response={"spf": spf, "dmarc_policy": dmarc_policy,
                                         "dkim_selector_found": dkim_selector_found})

    return {"source": "email_auth", "verdict": verdict, "spf": bool(spf),
            "dmarc_policy": dmarc_policy, "dkim_selector_found": dkim_selector_found,
            "cached": False}


# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────
async def enrich_url_urlhaus(db: AsyncSession, url: str) -> dict:
    if not URLHAUS_AUTH_KEY:
        return {"source": "urlhaus", "verdict": VERDICT_NO_KEY,
                "message": "Set URLHAUS_AUTH_KEY in .env (free at https://auth.abuse.ch/)"}

    cache_key = _cache_key_for_url(url)
    cached = await get_cached_enrichment(db, "url", cache_key)
    uh_cache = [c for c in cached if c.source == "urlhaus"]
    if uh_cache:
        c = uh_cache[0]
        rr = c.raw_response or {}
        return {"source": "urlhaus", "verdict": c.verdict, "threat": rr.get("threat"),
                "tags": c.tags, "payloads": rr.get("payloads"), "cached": True}

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url}, headers={"Auth-Key": URLHAUS_AUTH_KEY},
            )

        if resp.status_code == 401:
            return {"source": "urlhaus", "verdict": VERDICT_NO_KEY,
                    "message": "Invalid URLhaus Auth-Key"}
        if resp.status_code != 200:
            return {"source": "urlhaus", "verdict": VERDICT_UNKNOWN,
                    "message": f"URLhaus error: HTTP {resp.status_code}"}

        data = resp.json()
        if data.get("query_status") != "ok":
            await save_enrichment(db, "url", cache_key, "urlhaus", VERDICT_UNKNOWN,
                                   raw_response={"not_found": True})
            return {"source": "urlhaus", "verdict": VERDICT_UNKNOWN,
                    "message": "Not found in URLhaus database"}

        url_status = data.get("url_status", "unknown")
        threat     = data.get("threat")
        tags       = data.get("tags") or []
        payloads   = data.get("payloads") or []
        verdict    = VERDICT_MALICIOUS if url_status == "online" else VERDICT_SUSPICIOUS

        await save_enrichment(db, "url", cache_key, "urlhaus", verdict, tags=tags,
                               raw_response={"threat": threat, "url_status": url_status,
                                             "payloads": payloads})

        return {"source": "urlhaus", "verdict": verdict, "url_status": url_status,
                "threat": threat, "tags": tags, "payloads": payloads, "cached": False}

    except httpx.TimeoutException:
        return {"source": "urlhaus", "verdict": VERDICT_UNKNOWN,
                "message": "URLhaus request timed out"}
    except Exception as exc:
        log.error("URLhaus enrichment failed: %s", exc)
        return {"source": "urlhaus", "verdict": VERDICT_UNKNOWN, "message": str(exc)}


# ── RDAP domain age ────────────────────────────────────────────────────────────
# rdap.org is a free public bootstrap redirector (no API key) that resolves the
# right authoritative registry RDAP server for any TLD and redirects to it —
# needs follow_redirects=True. Rate-limited to ~10 req/10s; a freshly-
# registered domain is one of the strongest phishing signals, so a young
# domain contributes a "suspicious" verdict, not just an informational note.
_YOUNG_DOMAIN_THRESHOLD_DAYS = 30

async def enrich_url_domain_age(db: AsyncSession, domain: str) -> dict:
    cached = await get_cached_enrichment(db, "domain", domain)
    rdap_cache = [c for c in cached if c.source == "rdap"]
    if rdap_cache:
        c = rdap_cache[0]
        rr = c.raw_response or {}
        return {"source": "rdap", "verdict": c.verdict,
                "registered_at": rr.get("registered_at"),
                "age_days": rr.get("age_days"), "cached": True}

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(f"https://rdap.org/domain/{domain}")

        if resp.status_code == 404:
            await save_enrichment(db, "domain", domain, "rdap", VERDICT_UNKNOWN,
                                   raw_response={"not_found": True})
            return {"source": "rdap", "verdict": VERDICT_UNKNOWN,
                    "message": "Domain not found in RDAP (unregistered or unsupported TLD)"}
        if resp.status_code == 429:
            return {"source": "rdap", "verdict": VERDICT_UNKNOWN,
                    "message": "RDAP lookup rate-limited — try again shortly"}
        if resp.status_code != 200:
            return {"source": "rdap", "verdict": VERDICT_UNKNOWN,
                    "message": f"RDAP error: HTTP {resp.status_code}"}

        data = resp.json()
        events = data.get("events", []) or []
        registered_at = next(
            (e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)

        if not registered_at:
            return {"source": "rdap", "verdict": VERDICT_UNKNOWN,
                    "message": "RDAP response had no registration date"}

        registered_dt = datetime.fromisoformat(registered_at.replace("Z", "+00:00"))
        age_days = (datetime.now(UTC) - registered_dt).days
        verdict = VERDICT_SUSPICIOUS if age_days < _YOUNG_DOMAIN_THRESHOLD_DAYS else VERDICT_CLEAN

        await save_enrichment(db, "domain", domain, "rdap", verdict,
                               raw_response={"registered_at": registered_at, "age_days": age_days})

        return {"source": "rdap", "verdict": verdict,
                "registered_at": registered_at, "age_days": age_days, "cached": False}

    except httpx.TimeoutException:
        return {"source": "rdap", "verdict": VERDICT_UNKNOWN,
                "message": "RDAP request timed out"}
    except Exception as exc:
        log.error("RDAP domain-age lookup failed: %s", exc)
        return {"source": "rdap", "verdict": VERDICT_UNKNOWN, "message": str(exc)}


# ── Google Safe Browsing ──────────────────────────────────────────────────────
_GSB_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                     "POTENTIALLY_HARMFUL_APPLICATION"]

async def enrich_url_safe_browsing(db: AsyncSession, url: str) -> dict:
    if not GSB_API_KEY:
        return {"source": "safe_browsing", "verdict": VERDICT_NO_KEY,
                "message": "Set GOOGLE_SAFE_BROWSING_API_KEY in .env"}

    cache_key = _cache_key_for_url(url)
    cached = await get_cached_enrichment(db, "url", cache_key)
    gsb_cache = [c for c in cached if c.source == "safe_browsing"]
    if gsb_cache:
        c = gsb_cache[0]
        rr = c.raw_response or {}
        return {"source": "safe_browsing", "verdict": c.verdict,
                "threat_types": rr.get("threat_types", []), "cached": True}

    body = {
        "client": {"clientId": "threatos", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": _GSB_THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            resp = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": GSB_API_KEY}, json=body,
            )

        if resp.status_code == 403:
            return {"source": "safe_browsing", "verdict": VERDICT_NO_KEY,
                    "message": "Invalid Google Safe Browsing API key, or the API isn't "
                               "enabled on the associated GCP project"}
        if resp.status_code == 429:
            return {"source": "safe_browsing", "verdict": VERDICT_UNKNOWN,
                    "message": "Google Safe Browsing quota exceeded"}
        if resp.status_code != 200:
            return {"source": "safe_browsing", "verdict": VERDICT_UNKNOWN,
                    "message": f"Google Safe Browsing error: HTTP {resp.status_code}"}

        matches = resp.json().get("matches") or []
        threat_types = sorted({m.get("threatType") for m in matches if m.get("threatType")})
        verdict = VERDICT_MALICIOUS if matches else VERDICT_CLEAN

        await save_enrichment(db, "url", cache_key, "safe_browsing", verdict,
                               raw_response={"threat_types": threat_types})

        return {"source": "safe_browsing", "verdict": verdict,
                "threat_types": threat_types, "cached": False}

    except httpx.TimeoutException:
        return {"source": "safe_browsing", "verdict": VERDICT_UNKNOWN,
                "message": "Google Safe Browsing request timed out"}
    except Exception as exc:
        log.error("Google Safe Browsing enrichment failed: %s", exc)
        return {"source": "safe_browsing", "verdict": VERDICT_UNKNOWN, "message": str(exc)}


# ── PhishTank ─────────────────────────────────────────────────────────────────
# NOTE: PhishTank's current auth policy and exact response field names could
# not be freshly verified against their live docs at the time this was
# written (network-restricted research environment). app_key is sent when
# configured but treated as optional, matching PhishTank's historical
# behavior (unauthenticated lookups allowed at a stricter rate limit). All
# response fields are read defensively with .get() — if PhishTank's schema
# has since changed, this degrades to "not found" rather than crashing.
async def enrich_url_phishtank(db: AsyncSession, url: str) -> dict:
    cache_key = _cache_key_for_url(url)
    cached = await get_cached_enrichment(db, "url", cache_key)
    pt_cache = [c for c in cached if c.source == "phishtank"]
    if pt_cache:
        c = pt_cache[0]
        rr = c.raw_response or {}
        return {"source": "phishtank", "verdict": c.verdict,
                "phish_id": rr.get("phish_id"), "detail_url": rr.get("detail_url"),
                "cached": True}

    form = {"url": base64.b64encode(url.encode()).decode(), "format": "json"}
    if PHISHTANK_APP_KEY:
        form["app_key"] = PHISHTANK_APP_KEY

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            resp = await client.post("https://checkurl.phishtank.com/checkurl/", data=form)

        if resp.status_code == 509:
            return {"source": "phishtank", "verdict": VERDICT_UNKNOWN,
                    "message": "PhishTank rate limit exceeded — add PHISHTANK_APP_KEY "
                               "for a higher limit"}
        if resp.status_code != 200:
            return {"source": "phishtank", "verdict": VERDICT_UNKNOWN,
                    "message": f"PhishTank error: HTTP {resp.status_code}"}

        results = resp.json().get("results") or {}
        if not results.get("in_database"):
            await save_enrichment(db, "url", cache_key, "phishtank", VERDICT_UNKNOWN,
                                   raw_response={"not_found": True})
            return {"source": "phishtank", "verdict": VERDICT_UNKNOWN,
                    "message": "Not found in PhishTank database"}

        verified   = bool(results.get("verified"))
        valid      = bool(results.get("valid"))
        phish_id   = results.get("phish_id")
        detail_url = results.get("phish_detail_page")
        verdict    = VERDICT_MALICIOUS if (verified and valid) else VERDICT_SUSPICIOUS

        await save_enrichment(db, "url", cache_key, "phishtank", verdict,
                               raw_response={"phish_id": phish_id, "detail_url": detail_url,
                                             "verified": verified, "valid": valid})

        return {"source": "phishtank", "verdict": verdict, "phish_id": phish_id,
                "detail_url": detail_url, "verified": verified, "cached": False}

    except httpx.TimeoutException:
        return {"source": "phishtank", "verdict": VERDICT_UNKNOWN,
                "message": "PhishTank request timed out"}
    except Exception as exc:
        log.error("PhishTank enrichment failed: %s", exc)
        return {"source": "phishtank", "verdict": VERDICT_UNKNOWN, "message": str(exc)}


# ── Combined enrichment + report ─────────────────────────────────────────────
def _overall_verdict(verdicts: list[str]) -> str:
    if VERDICT_MALICIOUS in verdicts:  return VERDICT_MALICIOUS
    if VERDICT_SUSPICIOUS in verdicts: return VERDICT_SUSPICIOUS
    if VERDICT_CLEAN in verdicts:      return VERDICT_CLEAN
    return VERDICT_UNKNOWN

async def enrich_url(db: AsyncSession, raw_url: str,
                      investigated_by: str | None = None) -> dict:
    refresh_from_env_file()
    url, domain = parse_url(raw_url)

    sources = {}
    sources["virustotal"] = await enrich_url_virustotal(db, url)
    sources["urlscan"]    = await enrich_url_urlscan(db, url, domain)
    sources["spamhaus"]   = await enrich_url_spamhaus(db, domain)
    sources["surbl"]      = await enrich_url_surbl(db, domain)
    sources["uribl"]      = await enrich_url_uribl(db, domain)
    sources["sem"]        = await enrich_url_sem(db, domain)
    sources["urlhaus"]    = await enrich_url_urlhaus(db, url)
    sources["rdap"]       = await enrich_url_domain_age(db, domain)
    sources["safe_browsing"] = await enrich_url_safe_browsing(db, url)
    sources["phishtank"]  = await enrich_url_phishtank(db, url)
    sources["email_auth"] = await enrich_url_email_auth(db, domain)

    overall = _overall_verdict([s.get("verdict", VERDICT_UNKNOWN) for s in sources.values()])
    investigated_at = datetime.now(UTC)

    report_text = generate_investigation_report(
        url, domain, sources, overall, investigated_by, investigated_at)

    record = UrlInvestigation(
        id=str(uuid.uuid4()), url=url, domain=domain, overall_verdict=overall,
        report_text=report_text, investigated_by=investigated_by,
        investigated_at=investigated_at,
    )
    db.add(record)
    await db.flush()

    return {
        "id": record.id, "url": url, "domain": domain, "overall_verdict": overall,
        "sources": sources, "report_text": report_text,
        "investigated_at": investigated_at.isoformat(),
    }


async def list_investigations(db: AsyncSession, limit: int = 50) -> list[UrlInvestigation]:
    result = await db.execute(
        select(UrlInvestigation)
        .order_by(UrlInvestigation.investigated_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_investigation(db: AsyncSession, investigation_id: str) -> UrlInvestigation | None:
    result = await db.execute(
        select(UrlInvestigation).where(UrlInvestigation.id == investigation_id)
    )
    return result.scalar_one_or_none()


def generate_investigation_report(url: str, domain: str, sources: dict,
                                   overall_verdict: str,
                                   investigated_by: str | None,
                                   investigated_at: datetime) -> str:
    bar = "=" * 64
    dash = "-" * 64
    lines: list[str] = []

    lines.append(bar)
    lines.append("URL / DOMAIN INVESTIGATION REPORT")
    lines.append(bar)
    lines.append(f"Investigated URL : {url}")
    lines.append(f"Domain           : {domain}")
    lines.append(f"Investigated at  : {investigated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    if investigated_by:
        lines.append(f"Investigated by  : {investigated_by}")
    lines.append("")

    summary = {
        VERDICT_MALICIOUS:  "This URL is flagged as MALICIOUS by one or more threat "
                             "intelligence sources. Do not click it or interact with any "
                             "attachment/page it links to.",
        VERDICT_SUSPICIOUS: "This URL shows SUSPICIOUS indicators. Treat with caution "
                             "pending further review.",
        VERDICT_CLEAN:      "No malicious indicators were found across the sources checked. "
                             "This does not guarantee the URL is safe, only that it is not "
                             "currently flagged.",
        VERDICT_UNKNOWN:    "Insufficient data to reach a verdict — one or more sources "
                             "returned no result or are not configured.",
    }[overall_verdict]

    lines.append(f"VERDICT: {overall_verdict.upper()}")
    lines.append(dash)
    lines.append(summary)
    lines.append("")

    lines.append("TECHNICAL EVIDENCE")
    lines.append(dash)

    us = sources["urlscan"]
    lines.append("[urlscan.io]")
    if us["verdict"] in (VERDICT_NO_KEY,):
        lines.append(f"  {us.get('message', 'Not checked')}")
    elif "message" in us and us["verdict"] == VERDICT_UNKNOWN and not us.get("report_url"):
        lines.append(f"  {us['message']}")
    else:
        lines.append(f"  Scan verdict     : {us['verdict'].upper()}"
                      + (f" (score {us['score']})" if us.get("score") is not None else ""))
        if us.get("landing_ip"):
            lines.append(f"  Landing page IP  : {us['landing_ip']}"
                          + (f" (AS{us['asn']})" if us.get("asn") else "")
                          + (f" — {us['country']}" if us.get("country") else ""))
        if us.get("screenshot_url"):
            lines.append(f"  Screenshot       : {us['screenshot_url']}")
        if us.get("report_url"):
            lines.append(f"  Full report      : {us['report_url']}")
        if us.get("public"):
            lines.append("  NOTE: scanned with visibility=public — this submission is "
                          "publicly searchable on urlscan.io. Add URLSCAN_API_KEY for "
                          "unlisted/private scans of sensitive URLs.")
    lines.append("")

    vt = sources["virustotal"]
    lines.append("[VirusTotal]")
    if vt["verdict"] == VERDICT_NO_KEY:
        lines.append(f"  {vt.get('message', 'Not checked')}")
    elif vt.get("total_engines") is not None:
        lines.append(f"  Detection ratio  : {vt['malicious_engines']}/{vt['total_engines']} "
                      f"engines flagged this URL")
        if vt.get("final_url") and vt["final_url"] != url:
            lines.append(f"  Final URL        : {vt['final_url']} (after redirects)")
        if vt.get("categories"):
            cats = ", ".join(f"{k}: {v}" for k, v in list(vt["categories"].items())[:3])
            lines.append(f"  Categories       : {cats}")
        if vt.get("report_url"):
            lines.append(f"  Report link      : {vt['report_url']}")
    else:
        lines.append(f"  {vt.get('message', 'No result')}")
    lines.append("")

    sh = sources["spamhaus"]
    lines.append("[Spamhaus DBL]")
    if sh["verdict"] == VERDICT_UNKNOWN and sh.get("message"):
        lines.append(f"  {sh['message']}")
    elif sh.get("code"):
        lines.append(f"  Domain status    : LISTED — {sh['reason']} ({sh['code']})")
    else:
        lines.append("  Domain status    : NOT LISTED")
    lines.append("  NOTE: this is a DNS-based lookup; result reliability depends on this "
                 "server's configured DNS resolver (large public resolvers like 8.8.8.8 are "
                 "not reliably attributed by Spamhaus's fair-use policy).")
    lines.append("")

    su = sources.get("surbl", {})
    lines.append("[SURBL]")
    if su.get("verdict") == VERDICT_UNKNOWN and su.get("message"):
        lines.append(f"  {su['message']}")
    elif su.get("code"):
        lines.append(f"  Domain status    : LISTED ({su['code']})")
    else:
        lines.append("  Domain status    : NOT LISTED")
    lines.append("")

    ur = sources.get("uribl", {})
    lines.append("[URIBL]")
    if ur.get("verdict") == VERDICT_UNKNOWN and ur.get("message"):
        lines.append(f"  {ur['message']}")
    elif ur.get("code"):
        lines.append(f"  Domain status    : LISTED ({ur['code']})")
    else:
        lines.append("  Domain status    : NOT LISTED")
    lines.append("")

    sem = sources.get("sem", {})
    lines.append("[SEM-URI]")
    if sem.get("verdict") == VERDICT_UNKNOWN and sem.get("message"):
        lines.append(f"  {sem['message']}")
    elif sem.get("code"):
        lines.append(f"  Domain status    : LISTED ({sem['code']})")
    else:
        lines.append("  Domain status    : NOT LISTED")
    lines.append("")

    uh = sources["urlhaus"]
    lines.append("[URLhaus]")
    if uh["verdict"] == VERDICT_NO_KEY:
        lines.append(f"  {uh.get('message', 'Not checked')}")
    elif uh.get("threat"):
        lines.append(f"  Status           : Listed — {uh.get('url_status', 'unknown')}")
        lines.append(f"  Threat type      : {uh['threat']}")
        if uh.get("tags"):
            lines.append(f"  Tags             : {', '.join(uh['tags'][:8])}")
        if uh.get("payloads"):
            p = uh["payloads"][0]
            if isinstance(p, dict):
                lines.append(f"  Payload          : {p.get('file_type', '?')} "
                              f"({p.get('signature') or p.get('response_md5', '?')})")
    else:
        lines.append(f"  {uh.get('message', 'Not found in URLhaus database')}")
    lines.append("")

    rd = sources.get("rdap", {})
    lines.append("[Domain Age (RDAP)]")
    if rd.get("age_days") is not None:
        lines.append(f"  Registered on    : {rd.get('registered_at', '?')}")
        lines.append(f"  Domain age       : {rd['age_days']} days")
        if rd["verdict"] == VERDICT_SUSPICIOUS:
            lines.append(f"  NOTE: registered under {_YOUNG_DOMAIN_THRESHOLD_DAYS} days ago — "
                          f"newly-registered domains are commonly used for phishing/scam "
                          f"campaigns before being taken down.")
    else:
        lines.append(f"  {rd.get('message', 'Not checked')}")
    lines.append("")

    gsb = sources.get("safe_browsing", {})
    lines.append("[Google Safe Browsing]")
    if gsb.get("verdict") == VERDICT_NO_KEY:
        lines.append(f"  {gsb.get('message', 'Not checked')}")
    elif gsb.get("threat_types"):
        lines.append(f"  Status           : LISTED — {', '.join(gsb['threat_types'])}")
    elif gsb.get("verdict") == VERDICT_CLEAN:
        lines.append("  Status           : NOT LISTED")
    else:
        lines.append(f"  {gsb.get('message', 'No result')}")
    lines.append("")

    pt = sources.get("phishtank", {})
    lines.append("[PhishTank]")
    if pt.get("phish_id"):
        lines.append(f"  Status           : Listed — phish_id {pt['phish_id']}"
                      + (" (verified)" if pt.get("verified") else " (unverified report)"))
        if pt.get("detail_url"):
            lines.append(f"  Detail page      : {pt['detail_url']}")
    else:
        lines.append(f"  {pt.get('message', 'Not found in PhishTank database')}")
    lines.append("")

    ea = sources.get("email_auth", {})
    lines.append("[Email Authentication (SPF/DMARC/DKIM)]")
    lines.append(f"  SPF              : {'configured' if ea.get('spf') else 'NOT configured'}")
    if ea.get("dmarc_policy"):
        lines.append(f"  DMARC policy     : {ea['dmarc_policy']}")
    else:
        lines.append("  DMARC            : NOT configured")
    if ea.get("dkim_selector_found"):
        lines.append(f"  DKIM             : found (selector '{ea['dkim_selector_found']}')")
    else:
        lines.append("  DKIM             : not found under common selectors (inconclusive — "
                      "DKIM selectors are arbitrary and can't be fully enumerated via DNS)")
    if ea.get("verdict") == VERDICT_SUSPICIOUS:
        lines.append("  NOTE: missing/weak email authentication makes this domain easier to "
                      "spoof in phishing emails — relevant if this URL arrived via email.")
    lines.append("")

    lines.append("RECOMMENDATION")
    lines.append(dash)
    if overall_verdict == VERDICT_MALICIOUS:
        lines += [
            "1. Block this URL/domain at the email gateway, web proxy, and firewall.",
            "2. Do not click the link or open any attachment associated with it.",
            "3. If anyone already interacted with it, reset their credentials and scan "
            "   the affected endpoint.",
            "4. Report the sender/domain to your email security team for wider blocking.",
        ]
    elif overall_verdict == VERDICT_SUSPICIOUS:
        lines += [
            "1. Do not click the link or enter credentials on the linked page.",
            "2. Block at the proxy/firewall as a precaution while investigation continues.",
            "3. Re-check in a few hours — some sources may still be completing analysis.",
        ]
    elif overall_verdict == VERDICT_CLEAN:
        lines += [
            "1. No action required based on current data.",
            "2. Reputation can change — if this was reported as suspicious, keep treating "
            "   the original report with normal caution.",
        ]
    else:
        missing = [s for s, d in sources.items() if d.get("verdict") == VERDICT_NO_KEY]
        lines.append("1. Insufficient data to reach a verdict — treat as unverified and "
                      "avoid interacting with it.")
        if missing:
            lines.append(f"2. Add API keys for {', '.join(missing)} to improve coverage "
                          f"on future lookups.")
    lines.append("")
    lines.append(dash)
    lines.append("Report generated by ThreatOS. Cached results are refreshed automatically "
                  "after the TI cache TTL expires.")
    lines.append(bar)

    return "\n".join(lines)


def get_key_status() -> dict:
    """Whether optional API keys are configured — read live from this
    module's own globals (refreshed first) rather than a stale copy someone
    else might have imported at process-startup time."""
    refresh_from_env_file()
    return {"urlscan_key": bool(URLSCAN_API_KEY), "urlhaus_key": bool(URLHAUS_AUTH_KEY),
            "safe_browsing_key": bool(GSB_API_KEY), "phishtank_key": bool(PHISHTANK_APP_KEY)}
