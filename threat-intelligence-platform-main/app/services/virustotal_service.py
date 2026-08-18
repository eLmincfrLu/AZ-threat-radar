import base64
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 30
CACHE_TTL_SECONDS = 1800
MAX_REQUESTS_PER_MINUTE = 4
URL_POLL_ATTEMPTS = 3
URL_POLL_DELAY_SECONDS = 2

_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_cache_lock = threading.Lock()
_request_times: deque[float] = deque()
_rate_lock = threading.Lock()


class VirusTotalError(Exception):
    code = "analysis.api_error"
    status_code = 502

    def __init__(self, code: str | None = None, status_code: int | None = None):
        if code:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        super().__init__(self.code)


class VirusTotalRateLimitError(VirusTotalError):
    code = "analysis.rate_limit"
    status_code = 429


class VirusTotalAuthError(VirusTotalError):
    code = "analysis.api_auth_error"
    status_code = 401


class VirusTotalMissingKeyError(VirusTotalError):
    code = "analysis.missing_api_key"
    status_code = 503


class VirusTotalNotFoundError(VirusTotalError):
    code = "analysis.not_found"
    status_code = 404


class VirusTotalPendingError(VirusTotalError):
    code = "analysis.url_pending"
    status_code = 202


def _api_key() -> str:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        raise VirusTotalMissingKeyError()
    return key


def _headers() -> dict[str, str]:
    return {"x-apikey": _api_key(), "Accept": "application/json"}


def _cache_key(target: str, target_type: str) -> tuple[str, str]:
    normalized = target.lower().strip()
    if target_type == "url":
        normalized = normalize_url_for_vt(target)
    return target_type, normalized


def normalize_url_for_vt(url: str) -> str:
    parsed = urlparse(url.strip())
    if not parsed.scheme:
        url = f"https://{url.strip()}"
        parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path}"


def _get_cached(target: str, target_type: str) -> dict | None:
    key = _cache_key(target, target_type)
    with _cache_lock:
        entry = _cache.get(key)
        if not entry:
            return None
        cached_at, payload = entry
        if time.time() - cached_at > CACHE_TTL_SECONDS:
            del _cache[key]
            return None
        return payload


def _set_cache(target: str, target_type: str, payload: dict) -> None:
    key = _cache_key(target, target_type)
    with _cache_lock:
        _cache[key] = (time.time(), payload)


def _wait_for_rate_limit() -> None:
    with _rate_lock:
        now = time.time()
        while _request_times and now - _request_times[0] >= 60:
            _request_times.popleft()
        if len(_request_times) >= MAX_REQUESTS_PER_MINUTE:
            wait_seconds = 60 - (now - _request_times[0]) + 0.5
            if wait_seconds > 0:
                time.sleep(wait_seconds)
            while _request_times and time.time() - _request_times[0] >= 60:
                _request_times.popleft()
        _request_times.append(time.time())


def _request(method: str, url: str, headers: dict[str, str], **kwargs) -> requests.Response:
    _wait_for_rate_limit()
    response = requests.request(method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            time.sleep(min(int(retry_after), 30))
            _wait_for_rate_limit()
            response = requests.request(method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)
    return response


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _handle_response(response: requests.Response) -> dict:
    if response.status_code == 429:
        raise VirusTotalRateLimitError()
    if response.status_code in (401, 403):
        raise VirusTotalAuthError()
    if response.status_code == 404:
        raise VirusTotalNotFoundError()
    if not response.ok:
        raise VirusTotalError(status_code=502)
    payload = response.json()
    attributes = payload.get("data", {}).get("attributes")
    if not attributes:
        raise VirusTotalError(status_code=502)
    return payload


def _poll_url_analysis(analysis_id: str, headers: dict[str, str]) -> None:
    analysis_url = f"{VT_BASE_URL}/analyses/{analysis_id}"
    for _ in range(URL_POLL_ATTEMPTS):
        time.sleep(URL_POLL_DELAY_SECONDS)
        response = _request("GET", analysis_url, headers)
        if response.status_code == 429:
            raise VirusTotalRateLimitError()
        if response.status_code in (401, 403):
            raise VirusTotalAuthError()
        if not response.ok:
            continue
        status = response.json().get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return
    raise VirusTotalPendingError()


def _lookup_url(target: str, headers: dict[str, str]) -> dict:
    normalized = normalize_url_for_vt(target)
    report_url = f"{VT_BASE_URL}/urls/{_url_id(normalized)}"
    response = _request("GET", report_url, headers)
    if response.status_code == 404:
        submit = _request(
            "POST",
            f"{VT_BASE_URL}/urls",
            headers,
            data={"url": normalized},
        )
        if submit.status_code == 429:
            raise VirusTotalRateLimitError()
        if submit.status_code in (401, 403):
            raise VirusTotalAuthError()
        if submit.status_code not in (200, 201):
            raise VirusTotalError(status_code=502)
        analysis_id = submit.json().get("data", {}).get("id")
        if analysis_id:
            _poll_url_analysis(analysis_id, headers)
        response = _request("GET", report_url, headers)
    return _handle_response(response)


def _lookup_resource(target: str, target_type: str, headers: dict[str, str]) -> dict:
    if target_type == "url":
        return _lookup_url(target, headers)

    if target_type == "ip":
        endpoint = f"{VT_BASE_URL}/ip_addresses/{target}"
    elif target_type == "domain":
        endpoint = f"{VT_BASE_URL}/domains/{target.lower()}"
    else:
        raise VirusTotalError(code="analysis.invalid_target_type", status_code=400)

    response = _request("GET", endpoint, headers)
    return _handle_response(response)


def _category_text(attributes: dict) -> str:
    categories = attributes.get("categories") or {}
    if isinstance(categories, dict):
        return " ".join(str(value).lower() for value in categories.values())
    return ""


def _parse_reputation(attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    flagged = malicious + suspicious
    total = sum(
        int(stats.get(key, 0))
        for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
    )

    category_text = _category_text(attributes)
    phishing = "phish" in category_text or any(
        tag in category_text for tag in ("credential", "fraud", "deceptive")
    )
    malware = malicious > 0 or any(
        tag in category_text for tag in ("malware", "trojan", "ransomware")
    )
    spam = "spam" in category_text

    if flagged == 0:
        vt_status = "Clean"
    else:
        vt_status = f"{flagged}/{total or flagged} engines flagged"

    return {
        "virustotal_status": vt_status,
        "blacklist_status": "Listed" if malicious >= 3 else "Not Listed",
        "malware_detection": "Detected" if malware else "None",
        "phishing_detection": "Detected" if phishing else "None",
        "spam_detection": "Detected" if spam else "None",
        "vt_malicious_count": malicious,
        "vt_suspicious_count": suspicious,
        "vt_reputation": attributes.get("reputation"),
        "source": "virustotal",
    }


def _resolve_hostname(target: str, target_type: str, attributes: dict) -> str:
    if target_type == "domain":
        return target.lower()
    if target_type == "url":
        return urlparse(normalize_url_for_vt(target)).netloc or target
    for record in attributes.get("last_dns_records") or []:
        if record.get("type") == "PTR" and record.get("value"):
            return str(record["value"]).rstrip(".")
    return target


def _parse_network(target: str, target_type: str, attributes: dict) -> dict:
    asn_value = attributes.get("asn")
    return {
        "country": attributes.get("country") or "Unknown",
        "isp": attributes.get("as_owner") or "Unknown",
        "asn": f"AS{asn_value}" if asn_value is not None else "Unknown",
        "hostname": _resolve_hostname(target, target_type, attributes),
    }


def _format_date(value) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
    return str(value)[:10]


def _parse_whois(attributes: dict) -> dict:
    whois = attributes.get("whois") or ""
    registrar = attributes.get("registrar")
    if not registrar and isinstance(whois, str) and "Registrar:" in whois:
        for line in whois.splitlines():
            if line.lower().startswith("registrar:"):
                registrar = line.split(":", 1)[1].strip()
                break
    return {
        "registrar": registrar or "Unknown",
        "registration_date": _format_date(
            attributes.get("creation_date") or attributes.get("whois_date")
        ),
        "expiration_date": _format_date(attributes.get("expiration_date")),
    }


def fetch_threat_intel(target: str, target_type: str) -> dict:
    cached = _get_cached(target, target_type)
    if cached:
        return cached

    payload = _lookup_resource(target, target_type, _headers())
    attributes = payload["data"]["attributes"]
    result = {
        "reputation": _parse_reputation(attributes),
        "network": _parse_network(target, target_type, attributes),
        "whois": _parse_whois(attributes),
    }
    _set_cache(target, target_type, result)
    return result
