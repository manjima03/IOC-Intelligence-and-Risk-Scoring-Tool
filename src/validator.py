import ipaddress
import re
from urllib.parse import urlparse, urlunparse

HASH_PATTERNS = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\."
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\.?$"
)

def validate_and_normalize(value):
    raw = (value or "").strip()
    if not raw:
        return False, "", "unknown", "Enter an indicator first."

    try:
        ip = ipaddress.ip_address(raw)
        return True, str(ip), "ip", ""
    except ValueError:
        pass

    for name, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(raw):
            return True, raw.lower(), "hash", ""

    candidate = raw if "://" in raw else ""
    if candidate:
        try:
            parsed = urlparse(candidate)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                return False, "", "unknown", "Only valid HTTP/HTTPS URLs are supported."
            host = parsed.hostname.lower().rstrip(".")
            try:
                ipaddress.ip_address(host)
                normalized_host = host
            except ValueError:
                if not DOMAIN_RE.fullmatch(host):
                    return False, "", "unknown", "The URL hostname does not look like a valid domain or IP."
                normalized_host = host
            # Keep path/query for URL reputation lookup; remove fragment and normalize scheme/host.
            netloc = normalized_host
            if parsed.port:
                netloc = f"{normalized_host}:{parsed.port}"
            normalized = urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.params, parsed.query, ""))
            return True, normalized, "url", ""
        except Exception:
            return False, "", "unknown", "Could not parse this URL."

    domain = raw.lower().rstrip(".")
    if DOMAIN_RE.fullmatch(domain):
        return True, domain, "domain", ""
    return False, "", "unknown", "Unsupported or invalid IOC. Enter an IP, domain, HTTP/HTTPS URL, or MD5/SHA-1/SHA-256 hash."
