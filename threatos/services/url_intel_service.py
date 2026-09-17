from __future__ import annotations
import asyncio
import base64
import hashlib
import logging
import os
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from sqlalchemy.ext.asyncio import AsyncSession

from threatos.services.ti_service import (
    VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_NO_KEY, VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN, get_cached_enrichment, save_enrichment,
)

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
VT_API_KEY        = os.environ.get("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY    = os.environ.get("URLSCAN_API_KEY", "")
URLHAUS_AUTH_KEY   = os.environ.get("URLHAUS_AUTH_KEY", "")
TI_TIMEOUT         = int(os.environ.get("TI_TIMEOUT_SECONDS", "10"))

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

def _query_dbl_sync(domain: str) -> tuple[str | None, str | None]:
    """Blocking DNS lookup. Returns (code, error_message)."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(f"{domain}.dbl.spamhaus.org", "A", lifetime=TI_TIMEOUT)
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

    code, error = await asyncio.to_thread(_query_dbl_sync, domain)

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


# ── Combined enrichment + report ─────────────────────────────────────────────
def _overall_verdict(verdicts: list[str]) -> str:
    if VERDICT_MALICIOUS in verdicts:  return VERDICT_MALICIOUS
    if VERDICT_SUSPICIOUS in verdicts: return VERDICT_SUSPICIOUS
    if VERDICT_CLEAN in verdicts:      return VERDICT_CLEAN
    return VERDICT_UNKNOWN

async def enrich_url(db: AsyncSession, raw_url: str,
                      investigated_by: str | None = None) -> dict:
    url, domain = parse_url(raw_url)

    sources = {}
    sources["virustotal"] = await enrich_url_virustotal(db, url)
    sources["urlscan"]    = await enrich_url_urlscan(db, url, domain)
    sources["spamhaus"]   = await enrich_url_spamhaus(db, domain)
    sources["urlhaus"]    = await enrich_url_urlhaus(db, url)

    overall = _overall_verdict([s.get("verdict", VERDICT_UNKNOWN) for s in sources.values()])
    investigated_at = datetime.now(UTC)

    report_text = generate_investigation_report(
        url, domain, sources, overall, investigated_by, investigated_at)

    return {
        "url": url, "domain": domain, "overall_verdict": overall,
        "sources": sources, "report_text": report_text,
        "investigated_at": investigated_at.isoformat(),
    }


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
