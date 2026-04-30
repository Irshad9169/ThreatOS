from __future__ import annotations
import hashlib
import ipaddress
import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.models.ti_enrichment import TIEnrichment

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
VT_API_KEY      = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_API_KEY",  "")
TI_CACHE_HOURS  = int(os.environ.get("TI_CACHE_HOURS", "24"))
TI_TIMEOUT      = int(os.environ.get("TI_TIMEOUT_SECONDS", "10"))

# Verdicts
VERDICT_MALICIOUS   = "malicious"
VERDICT_SUSPICIOUS  = "suspicious"
VERDICT_CLEAN       = "clean"
VERDICT_UNKNOWN     = "unknown"
VERDICT_NO_KEY      = "no_api_key"

# ── IOC detection ─────────────────────────────────────────────────────────────
_IP_RE   = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_MD5_RE  = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA1_RE = re.compile(r'^[a-fA-F0-9]{40}$')
_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
_DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def detect_ioc_type(value: str) -> str | None:
    """Detect the type of IOC from its value."""
    if not value or len(value) > 500:
        return None
    v = value.strip()
    if _IP_RE.match(v):
        try:
            ip = ipaddress.ip_address(v)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                return None  # skip private IPs
            return "ip"
        except ValueError:
            return None
    if _SHA256_RE.match(v): return "sha256"
    if _MD5_RE.match(v):    return "md5"
    if _SHA1_RE.match(v):   return "sha1"
    if _DOMAIN_RE.match(v): return "domain"
    return None

def extract_iocs_from_alert(alert_data: dict) -> list[tuple[str, str]]:
    """
    Extract IOCs from alert fields.
    Returns list of (ioc_type, ioc_value) tuples.
    """
    iocs = []
    checks = [
        alert_data.get("entity_host"),
        alert_data.get("src_ip"),
        alert_data.get("dst_ip"),
        alert_data.get("file_hash"),
    ]
    # Also check raw_fields if present
    raw = alert_data.get("raw_fields", {}) or {}
    if isinstance(raw, dict):
        checks += [
            raw.get("file_hash"),
            raw.get("md5"),
            raw.get("sha256"),
            raw.get("sha1"),
            raw.get("src_ip"),
            raw.get("dst_ip"),
            raw.get("domain"),
        ]

    seen = set()
    for val in checks:
        if not val or not isinstance(val, str):
            continue
        ioc_type = detect_ioc_type(val.strip())
        if ioc_type and val not in seen:
            iocs.append((ioc_type, val.strip()))
            seen.add(val)

    return iocs

# ── Cache lookup ──────────────────────────────────────────────────────────────
async def get_cached_enrichment(db: AsyncSession, ioc_type: str,
                                 ioc_value: str) -> list[TIEnrichment]:
    """Get cached TI results for an IOC (not expired)."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(TIEnrichment).where(
            TIEnrichment.ioc_type  == ioc_type,
            TIEnrichment.ioc_value == ioc_value,
            TIEnrichment.expires_at > now,
        )
    )
    return list(result.scalars().all())

async def save_enrichment(db: AsyncSession, ioc_type: str, ioc_value: str,
                           source: str, verdict: str, score: int | None = None,
                           country: str | None = None, asn: str | None = None,
                           tags: list | None = None,
                           raw_response: dict | None = None) -> TIEnrichment:
    """Save or update a TI enrichment result."""
    now     = datetime.now(UTC)
    expires = now + timedelta(hours=TI_CACHE_HOURS)

    # Check if exists
    result = await db.execute(
        select(TIEnrichment).where(
            TIEnrichment.ioc_type  == ioc_type,
            TIEnrichment.ioc_value == ioc_value,
            TIEnrichment.source    == source,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.verdict      = verdict
        existing.score        = score
        existing.country      = country
        existing.asn          = asn
        existing.tags         = tags or []
        existing.raw_response = raw_response
        existing.enriched_at  = now
        existing.expires_at   = expires
        await db.flush()
        return existing

    entry = TIEnrichment(
        id=str(uuid.uuid4()), ioc_type=ioc_type, ioc_value=ioc_value,
        source=source, verdict=verdict, score=score, country=country,
        asn=asn, tags=tags or [], raw_response=raw_response,
        enriched_at=now, expires_at=expires,
    )
    db.add(entry)
    await db.flush()
    return entry

# ── VirusTotal ────────────────────────────────────────────────────────────────
async def enrich_virustotal(db: AsyncSession, ioc_type: str,
                             ioc_value: str) -> dict:
    """
    Query VirusTotal for IP, domain, file hash.
    Free tier: 4 requests/minute, 500/day.
    """
    if not VT_API_KEY:
        return {"source": "virustotal", "verdict": VERDICT_NO_KEY,
                "message": "Set VIRUSTOTAL_API_KEY in .env"}

    # Check cache first
    cached = await get_cached_enrichment(db, ioc_type, ioc_value)
    vt_cache = [c for c in cached if c.source == "virustotal"]
    if vt_cache:
        c = vt_cache[0]
        return {"source":"virustotal","verdict":c.verdict,"score":c.score,
                "country":c.country,"tags":c.tags,"cached":True}

    # Build URL
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif ioc_type in ("sha256","md5","sha1"):
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return {"source":"virustotal","verdict":VERDICT_UNKNOWN,
                "message":f"Unsupported IOC type: {ioc_type}"}

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            resp = await client.get(url, headers={"x-apikey": VT_API_KEY})

        if resp.status_code == 404:
            await save_enrichment(db, ioc_type, ioc_value, "virustotal",
                                   VERDICT_UNKNOWN, raw_response={"not_found": True})
            return {"source":"virustotal","verdict":VERDICT_UNKNOWN,
                    "message":"Not found in VirusTotal"}

        if resp.status_code == 401:
            return {"source":"virustotal","verdict":VERDICT_NO_KEY,
                    "message":"Invalid VirusTotal API key"}

        if resp.status_code != 200:
            return {"source":"virustotal","verdict":VERDICT_UNKNOWN,
                    "message":f"VT API error: HTTP {resp.status_code}"}

        data     = resp.json()
        attrs    = data.get("data",{}).get("attributes",{})
        stats    = attrs.get("last_analysis_stats",{})
        malicious= stats.get("malicious", 0)
        suspicious=stats.get("suspicious", 0)
        total    = sum(stats.values()) or 1

        if malicious >= 3:
            verdict = VERDICT_MALICIOUS
        elif malicious >= 1 or suspicious >= 3:
            verdict = VERDICT_SUSPICIOUS
        elif total > 0:
            verdict = VERDICT_CLEAN
        else:
            verdict = VERDICT_UNKNOWN

        score   = int(malicious / total * 100) if total else 0
        country = attrs.get("country")
        asn     = attrs.get("as_owner") or attrs.get("network")
        tags    = attrs.get("tags",[]) or []

        await save_enrichment(db, ioc_type, ioc_value, "virustotal",
                               verdict, score=score, country=country,
                               asn=asn, tags=tags,
                               raw_response={"stats": stats, "total": total})

        return {"source":"virustotal","verdict":verdict,"score":score,
                "malicious_engines":malicious,"total_engines":total,
                "country":country,"asn":asn,"tags":tags,"cached":False}

    except httpx.TimeoutException:
        return {"source":"virustotal","verdict":VERDICT_UNKNOWN,
                "message":"VirusTotal request timed out"}
    except Exception as exc:
        log.error("VirusTotal enrichment failed: %s", exc)
        return {"source":"virustotal","verdict":VERDICT_UNKNOWN,
                "message":str(exc)}

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
async def enrich_abuseipdb(db: AsyncSession, ip_address: str) -> dict:
    """
    Query AbuseIPDB for IP reputation.
    Free tier: 1,000 requests/day.
    """
    if not ABUSEIPDB_KEY:
        return {"source": "abuseipdb", "verdict": VERDICT_NO_KEY,
                "message": "Set ABUSEIPDB_API_KEY in .env"}

    # Check cache
    cached = await get_cached_enrichment(db, "ip", ip_address)
    abuse_cache = [c for c in cached if c.source == "abuseipdb"]
    if abuse_cache:
        c = abuse_cache[0]
        return {"source":"abuseipdb","verdict":c.verdict,"score":c.score,
                "country":c.country,"asn":c.asn,"tags":c.tags,"cached":True}

    try:
        async with httpx.AsyncClient(timeout=TI_TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip_address, "maxAgeInDays": 90,
                        "verbose": True},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )

        if resp.status_code == 401:
            return {"source":"abuseipdb","verdict":VERDICT_NO_KEY,
                    "message":"Invalid AbuseIPDB API key"}

        if resp.status_code != 200:
            return {"source":"abuseipdb","verdict":VERDICT_UNKNOWN,
                    "message":f"AbuseIPDB error: HTTP {resp.status_code}"}

        data  = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))

        if score >= 80:
            verdict = VERDICT_MALICIOUS
        elif score >= 25:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        country = data.get("countryCode")
        asn     = f"AS{data.get('abuseConfidenceScore','')} {data.get('isp','')}"
        tags    = data.get("usageType","").split(",") if data.get("usageType") else []
        total_reports = data.get("totalReports", 0)

        await save_enrichment(db, "ip", ip_address, "abuseipdb",
                               verdict, score=score, country=country,
                               asn=data.get("isp"), tags=tags,
                               raw_response={"score":score,"reports":total_reports,
                                             "isp":data.get("isp"),"domain":data.get("domain")})

        return {"source":"abuseipdb","verdict":verdict,"score":score,
                "country":country,"isp":data.get("isp"),
                "total_reports":total_reports,"tags":tags,"cached":False}

    except httpx.TimeoutException:
        return {"source":"abuseipdb","verdict":VERDICT_UNKNOWN,
                "message":"AbuseIPDB request timed out"}
    except Exception as exc:
        log.error("AbuseIPDB enrichment failed: %s", exc)
        return {"source":"abuseipdb","verdict":VERDICT_UNKNOWN,
                "message":str(exc)}

# ── Combined enrichment ────────────────────────────────────────────────────────
async def enrich_ioc(db: AsyncSession, ioc_type: str,
                      ioc_value: str) -> dict:
    """
    Enrich a single IOC from all available sources.
    Returns combined results with overall verdict.
    """
    results = {}

    if ioc_type == "ip":
        results["abuseipdb"]  = await enrich_abuseipdb(db, ioc_value)
        results["virustotal"] = await enrich_virustotal(db, ioc_type, ioc_value)
    elif ioc_type in ("sha256","md5","sha1"):
        results["virustotal"] = await enrich_virustotal(db, ioc_type, ioc_value)
    elif ioc_type == "domain":
        results["virustotal"] = await enrich_virustotal(db, ioc_type, ioc_value)

    # Overall verdict = worst across all sources
    verdicts = [r.get("verdict", VERDICT_UNKNOWN) for r in results.values()]
    if VERDICT_MALICIOUS  in verdicts: overall = VERDICT_MALICIOUS
    elif VERDICT_SUSPICIOUS in verdicts: overall = VERDICT_SUSPICIOUS
    elif VERDICT_CLEAN in verdicts: overall = VERDICT_CLEAN
    else: overall = VERDICT_UNKNOWN

    return {
        "ioc_type":       ioc_type,
        "ioc_value":      ioc_value,
        "overall_verdict":overall,
        "sources":        results,
    }

async def enrich_alert(db: AsyncSession, alert_data: dict) -> dict:
    """
    Extract all IOCs from an alert and enrich them.
    Returns enrichment summary to attach to the alert.
    """
    iocs     = extract_iocs_from_alert(alert_data)
    results  = []
    verdicts = []

    for ioc_type, ioc_value in iocs:
        result = await enrich_ioc(db, ioc_type, ioc_value)
        results.append(result)
        verdicts.append(result["overall_verdict"])

    # Overall alert verdict
    if VERDICT_MALICIOUS  in verdicts: overall = VERDICT_MALICIOUS
    elif VERDICT_SUSPICIOUS in verdicts: overall = VERDICT_SUSPICIOUS
    elif VERDICT_CLEAN    in verdicts: overall = VERDICT_CLEAN
    else: overall = VERDICT_UNKNOWN

    # Build human-readable summary
    malicious = [r for r in results if r["overall_verdict"] == VERDICT_MALICIOUS]
    suspicious= [r for r in results if r["overall_verdict"] == VERDICT_SUSPICIOUS]

    summary_parts = []
    if malicious:
        vals = ", ".join(r["ioc_value"] for r in malicious[:3])
        summary_parts.append(f"MALICIOUS: {vals}")
    if suspicious:
        vals = ", ".join(r["ioc_value"] for r in suspicious[:3])
        summary_parts.append(f"SUSPICIOUS: {vals}")
    if not summary_parts and results:
        summary_parts.append(f"{len(results)} IOC(s) checked — clean")

    return {
        "iocs_found":    len(iocs),
        "overall_verdict": overall,
        "summary":       " | ".join(summary_parts) or "No enrichable IOCs found",
        "enrichments":   results,
    }

async def cleanup_expired_enrichments(db: AsyncSession) -> int:
    """Delete expired TI cache entries."""
    result = await db.execute(
        delete(TIEnrichment).where(
            TIEnrichment.expires_at < datetime.now(UTC)
        ).returning(TIEnrichment.id)
    )
    return len(result.fetchall())

async def get_enrichment_stats(db: AsyncSession) -> dict:
    """Stats about TI cache."""
    from sqlalchemy import func
    total = await db.execute(select(func.count(TIEnrichment.id)))
    malicious = await db.execute(
        select(func.count(TIEnrichment.id))
        .where(TIEnrichment.verdict == VERDICT_MALICIOUS))
    suspicious = await db.execute(
        select(func.count(TIEnrichment.id))
        .where(TIEnrichment.verdict == VERDICT_SUSPICIOUS))
    return {
        "total_cached":   int(total.scalar() or 0),
        "malicious":      int(malicious.scalar() or 0),
        "suspicious":     int(suspicious.scalar() or 0),
        "cache_hours":    TI_CACHE_HOURS,
        "virustotal_key": bool(VT_API_KEY),
        "abuseipdb_key":  bool(ABUSEIPDB_KEY),
    }
