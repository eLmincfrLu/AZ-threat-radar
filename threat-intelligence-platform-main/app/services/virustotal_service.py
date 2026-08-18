import base64
import os
from urllib.parse import urlparse

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 30


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


def _api_key() -> str:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        raise VirusTotalMissingKeyError()
    return key


def _headers() -> dict[str, str]:
    return {"x-apikey": _api_key(), "Accept": "application/json"}


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


def _lookup_url(target: str, headers: dict[str, str]) -> dict:
    report_url = f"{VT_BASE_URL}/urls/{_url_id(target)}"
    response = requests.get(report_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if response.status_code == 404:
        submit = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": target},
            timeout=REQUEST_TIMEOUT,
        )
        if submit.status_code == 429:
            raise VirusTotalRateLimitError()
        if submit.status_code in (401, 403):
            raise VirusTotalAuthError()
        if submit.status_code not in (200, 201):
            raise VirusTotalError(status_code=502)
        response = requests.get(report_url, headers=headers, timeout=REQUEST_TIMEOUT)
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

    response = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
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
    total = sum(int(stats.get(key, 0)) for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"))

    category_text = _category_text(attributes)
    phishing = "phish" in category_text or any(
        tag in category_text for tag in ("credential", "fraud", "deceptive")
    )
    malware = malicious > 0 or any(tag in category_text for tag in ("malware", "trojan", "ransomware"))
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


def _default_hostname(target: str, target_type: str) -> str:
    if target_type == "domain":
        return target.lower()
    if target_type == "url":
        return urlparse(target).netloc or target
    return target


def _parse_network(target: str, target_type: str, attributes: dict) -> dict:
    asn_value = attributes.get("asn")
    return {
        "country": attributes.get("country") or "Unknown",
        "isp": attributes.get("as_owner") or "Unknown",
        "asn": f"AS{asn_value}" if asn_value is not None else "Unknown",
        "hostname": attributes.get("network") or _default_hostname(target, target_type),
    }


def _format_date(value) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, (int, float)):
        from datetime import datetime, timezone

        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
    return str(value)[:10]


def _parse_whois(attributes: dict) -> dict:
    return {
        "registrar": attributes.get("registrar") or "Unknown",
        "registration_date": _format_date(attributes.get("creation_date") or attributes.get("whois_date")),
        "expiration_date": _format_date(attributes.get("expiration_date")),
    }


def fetch_threat_intel(target: str, target_type: str) -> dict:
    payload = _lookup_resource(target, target_type, _headers())
    attributes = payload["data"]["attributes"]
    return {
        "reputation": _parse_reputation(attributes),
        "network": _parse_network(target, target_type, attributes),
        "whois": _parse_whois(attributes),
    }
