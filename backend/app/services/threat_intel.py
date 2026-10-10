"""
CyberGuard Threat Intelligence Service

Abstraction layer for optional external threat-intelligence providers:
  - VirusTotal (domain / URL reputation)
  - Google Safe Browsing (URL safety)
  - URLhaus (malicious URL lookups)
  - AbuseIPDB (IP address reputation)

All providers are OPTIONAL. If no API key is configured, the function
returns a "not_checked" status and the caller falls back to local analysis.

No provider responses are ever faked or invented.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger("cyberguard")


# ------------------------------------------------------------------ #
# Provider status tracking
# ------------------------------------------------------------------ #

_provider_status: dict[str, str] = {}


def get_provider_status() -> dict[str, str]:
    """Return the availability status of each configured provider."""
    return dict(_provider_status)


# ------------------------------------------------------------------ #
# VirusTotal
# ------------------------------------------------------------------ #

async def check_virustotal(url: str) -> dict[str, Any]:
    """
    Submit *url* to VirusTotal for reputation analysis.

    Returns ``{"status": "not_configured"}`` if no API key is set.
    Returns ``{"status": "ok", "malicious": int, "suspicious": int, ...}`` on success.
    """
    api_key = settings.VIRUSTOTAL_API_KEY.strip()
    if not api_key:
        _provider_status["virustotal"] = "not_configured"
        return {"status": "not_configured", "provider": "virustotal"}

    _provider_status["virustotal"] = "unknown"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Submit URL for analysis
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": api_key},
                data={"url": url},
            )
            if submit.status_code != 200:
                _provider_status["virustotal"] = f"error_{submit.status_code}"
                return {"status": "error", "provider": "virustotal",
                        "code": submit.status_code}

            analysis_id = submit.json().get("data", {}).get("id", "")

            # Poll for result (best-effort, single attempt)
            if analysis_id:
                report = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": api_key},
                )
                if report.status_code == 200:
                    stats = (
                        report.json()
                        .get("data", {})
                        .get("attributes", {})
                        .get("stats", {})
                    )
                    _provider_status["virustotal"] = "available"
                    return {
                        "status": "ok",
                        "provider": "virustotal",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }

            _provider_status["virustotal"] = "available"
            return {"status": "submitted", "provider": "virustotal"}

    except Exception as exc:
        logger.warning("VirusTotal lookup failed: %s", exc)
        _provider_status["virustotal"] = "error"
        return {"status": "error", "provider": "virustotal", "detail": str(exc)[:200]}


# ------------------------------------------------------------------ #
# Google Safe Browsing
# ------------------------------------------------------------------ #

async def check_google_safe_browsing(url: str) -> dict[str, Any]:
    """
    Check *url* against Google Safe Browsing API.

    Returns ``{"status": "not_configured"}`` if no API key is set.
    Returns ``{"status": "ok", "safe": bool, "threats": [...]}`` on success.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()
    if not api_key:
        _provider_status["google_safe_browsing"] = "not_configured"
        return {"status": "not_configured", "provider": "google_safe_browsing"}

    _provider_status["google_safe_browsing"] = "unknown"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={
                    "client": {"clientId": "cyberguard", "clientVersion": "2.0.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            if response.status_code != 200:
                _provider_status["google_safe_browsing"] = f"error_{response.status_code}"
                return {"status": "error", "provider": "google_safe_browsing",
                        "code": response.status_code}

            matches = response.json().get("matches", [])
            _provider_status["google_safe_browsing"] = "available"
            return {
                "status": "ok",
                "provider": "google_safe_browsing",
                "safe": len(matches) == 0,
                "threats": matches,
            }

    except Exception as exc:
        logger.warning("Google Safe Browsing lookup failed: %s", exc)
        _provider_status["google_safe_browsing"] = "error"
        return {"status": "error", "provider": "google_safe_browsing",
                "detail": str(exc)[:200]}


# ------------------------------------------------------------------ #
# URLhaus
# ------------------------------------------------------------------ #

async def check_urlhaus(url: str) -> dict[str, Any]:
    """
    Check *url* against URLhaus malware URL database.

    Returns ``{"status": "not_configured"}`` if no API key is set.
    Returns ``{"status": "ok", "found": bool, "threat": str}`` on success.
    """
    api_key = settings.URLHAUS_API_KEY.strip()
    if not api_key:
        _provider_status["urlhaus"] = "not_configured"
        return {"status": "not_configured", "provider": "urlhaus"}

    _provider_status["urlhaus"] = "unknown"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": url, "api_key": api_key},
            )
            if response.status_code != 200:
                _provider_status["urlhaus"] = f"error_{response.status_code}"
                return {"status": "error", "provider": "urlhaus",
                        "code": response.status_code}

            data = response.json()
            found = data.get("url_exists", False)
            _provider_status["urlhaus"] = "available"
            return {
                "status": "ok",
                "provider": "urlhaus",
                "found": found,
                "threat": data.get("threat", ""),
                "tags": data.get("tags", []),
            }

    except Exception as exc:
        logger.warning("URLhaus lookup failed: %s", exc)
        _provider_status["urlhaus"] = "error"
        return {"status": "error", "provider": "urlhaus", "detail": str(exc)[:200]}


# ------------------------------------------------------------------ #
# AbuseIPDB
# ------------------------------------------------------------------ #

async def check_abuseipdb(ip_address: str) -> dict[str, Any]:
    """
    Check *ip_address* against AbuseIPDB.

    Returns ``{"status": "not_configured"}`` if no API key is set.
    Returns ``{"status": "ok", "abuse_score": int, ...}`` on success.
    """
    api_key = settings.ABUSEIPDB_API_KEY.strip()
    if not api_key:
        _provider_status["abuseipdb"] = "not_configured"
        return {"status": "not_configured", "provider": "abuseipdb"}

    _provider_status["abuseipdb"] = "unknown"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90},
            )
            if response.status_code != 200:
                _provider_status["abuseipdb"] = f"error_{response.status_code}"
                return {"status": "error", "provider": "abuseipdb",
                        "code": response.status_code}

            data = response.json().get("data", {})
            _provider_status["abuseipdb"] = "available"
            return {
                "status": "ok",
                "provider": "abuseipdb",
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "usage_type": data.get("usageType", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
            }

    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed: %s", exc)
        _provider_status["abuseipdb"] = "error"
        return {"status": "error", "provider": "abuseipdb", "detail": str(exc)[:200]}


# ------------------------------------------------------------------ #
# Unified lookup — run all configured providers in parallel
# ------------------------------------------------------------------ #

async def lookup_url_reputation(url: str) -> dict[str, Any]:
    """
    Run all configured URL reputation providers concurrently.

    Returns a combined result. Providers that are not configured or
    that fail are included with their individual status.
    """
    tasks = []

    if settings.VIRUSTOTAL_API_KEY.strip():
        tasks.append(("virustotal", check_virustotal(url)))
    if settings.GOOGLE_SAFE_BROWSING_API_KEY.strip():
        tasks.append(("google_safe_browsing", check_google_safe_browsing(url)))
    if settings.URLHAUS_API_KEY.strip():
        tasks.append(("urlhaus", check_urlhaus(url)))

    if not tasks:
        return {"status": "no_providers_configured", "providers": {}}

    results = {}
    completed = await asyncio.gather(
        *[task[1] for task in tasks],
        return_exceptions=True,
    )

    for (name, _), result in zip(tasks, completed):
        if isinstance(result, Exception):
            results[name] = {"status": "error", "detail": str(result)[:200]}
        else:
            results[name] = result

    return {"status": "ok", "providers": results}
