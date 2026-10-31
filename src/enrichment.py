import base64
import ipaddress
import os
import requests
from dotenv import load_dotenv

load_dotenv()
TIMEOUT = 8

def _get_json(url, headers=None, params=None):
    try:
        response = requests.get(url, headers=headers or {}, params=params or {}, timeout=TIMEOUT)
        if response.status_code == 429:
            return {"error": "Rate limit reached"}
        if response.status_code in (401, 403):
            return {"error": "API key missing, invalid, or not authorized"}
        if not response.ok:
            return {"error": f"Source returned HTTP {response.status_code}"}
        return response.json()
    except requests.RequestException as exc:
        return {"error": f"Request failed: {type(exc).__name__}"}
    except ValueError:
        return {"error": "Source returned a non-JSON response"}

def _virustotal(ioc, ioc_type):
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"source": "VirusTotal", "available": False, "note": "API key not configured"}
    headers = {"x-apikey": key}
    if ioc_type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return {"source": "VirusTotal", "available": False, "note": "Unsupported IOC type"}

    payload = _get_json(endpoint, headers=headers)
    if "error" in payload:
        return {"source": "VirusTotal", "available": False, "note": payload["error"]}
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "available": True,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "reputation": attrs.get("reputation"),
        "categories": attrs.get("categories", {}),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "meaning": "Detection counts are signals, not a definitive verdict."
    }

def _abuseipdb(ioc, ioc_type):
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if ioc_type != "ip":
        return {"source": "AbuseIPDB", "available": False, "note": "This source is used for IP addresses only"}
    try:
        ip_obj = ipaddress.ip_address(ioc)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return {"source": "AbuseIPDB", "available": False, "note": "Private/reserved IP; not queried"}
    except ValueError:
        return {"source": "AbuseIPDB", "available": False, "note": "Invalid IP"}
    if not key:
        return {"source": "AbuseIPDB", "available": False, "note": "API key not configured"}
    payload = _get_json(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""}
    )
    if "error" in payload:
        return {"source": "AbuseIPDB", "available": False, "note": payload["error"]}
    data = payload.get("data", {})
    return {
        "source": "AbuseIPDB",
        "available": True,
        "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0) or 0),
        "total_reports": int(data.get("totalReports", 0) or 0),
        "num_distinct_users": int(data.get("numDistinctUsers", 0) or 0),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "meaning": "Abuse confidence and report counts can be affected by shared hosting, NAT, and reporting bias."
    }

def enrich_ioc(ioc, ioc_type):
    return {
        "virustotal": _virustotal(ioc, ioc_type),
        "abuseipdb": _abuseipdb(ioc, ioc_type),
    }
