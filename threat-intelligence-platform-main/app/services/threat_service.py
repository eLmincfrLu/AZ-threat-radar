import hashlib
from datetime import datetime, timedelta, timezone

from app.services.reputation_service import mock_reputation
from app.services.risk_engine import compute_risk


def _seed(value: str) -> int:
    return int(hashlib.sha256(value.encode()).hexdigest(), 16)


def _mock_whois(target: str, target_type: str) -> dict:
    seed = _seed(target)
    years = 2010 + (seed % 12)
    reg = datetime(years, 1 + (seed % 11), 1 + (seed % 27), tzinfo=timezone.utc)
    exp = reg + timedelta(days=365 * (3 + seed % 5))
    registrars = ["MarkMonitor Inc.", "GoDaddy.com, LLC", "NameCheap, Inc.", "Cloudflare, Inc."]
    return {
        "registrar": registrars[seed % len(registrars)],
        "registration_date": reg.strftime("%Y-%m-%d"),
        "expiration_date": exp.strftime("%Y-%m-%d"),
    }


def _mock_network(target: str, target_type: str) -> dict:
    seed = _seed(f"net:{target}")
    countries = ["United States", "Germany", "Netherlands", "Singapore", "Russia", "Brazil"]
    isps = ["Google LLC", "Cloudflare, Inc.", "Amazon Technologies Inc.", "OVH SAS", "Hetzner Online GmbH"]
    if target.lower() in ("google.com", "8.8.8.8"):
        return {
            "country": "United States",
            "isp": "Google LLC",
            "asn": "AS15169",
            "hostname": "dns.google" if target_type == "ip" else "google.com",
        }
    if "185.199" in target:
        return {
            "country": "United States",
            "isp": "GitHub, Inc.",
            "asn": "AS36459",
            "hostname": "pages.github.io",
        }
    return {
        "country": countries[seed % len(countries)],
        "isp": isps[seed % len(isps)],
        "asn": f"AS{10000 + (seed % 50000)}",
        "hostname": target if target_type != "url" else target.split("/")[2],
    }


def _category_weights(target: str, reputation: dict) -> dict[str, int]:
    weights = {
        "Phishing": 0,
        "Malware Hosting": 0,
        "Botnet Activity": 0,
        "Spam": 0,
        "Suspicious Network": 0,
    }
    if reputation["phishing_detection"] == "Detected":
        weights["Phishing"] = 25
    if reputation["malware_detection"] == "Detected":
        weights["Malware Hosting"] = 30
    if reputation["spam_detection"] == "Detected":
        weights["Spam"] = 10
    if reputation["blacklist_status"] == "Listed":
        weights["Suspicious Network"] = 15
    seed = _seed(target)
    if (seed % 29) == 0:
        weights["Botnet Activity"] = 20
    if target.lower() == "google.com" or target in ("8.8.8.8", "1.1.1.1"):
        return {k: 0 for k in weights}
    if "185.199" in target:
        weights["Phishing"] = 25
        weights["Malware Hosting"] = 30
        weights["Botnet Activity"] = 20
    return weights


def analyze_target(target: str, target_type: str) -> dict:
    reputation = mock_reputation(target, target_type)
    network = _mock_network(target, target_type)
    whois = _mock_whois(target, target_type)
    weights = _category_weights(target, reputation)

    seed = _seed(f"base:{target}")
    base = 8 + (seed % 25)
    if target.lower() == "google.com":
        base = 12
    if target in ("8.8.8.8", "1.1.1.1"):
        base = 10
    if "185.199" in target:
        base = 55

    risk = compute_risk(base, weights)
    threats = risk.categories if risk.categories else (["None"] if risk.status == "SAFE" else [])

    return {
        "target": target,
        "type": target_type,
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk.score,
        "status": risk.status,
        "recommendation": risk.recommendation,
        "threat_categories": threats,
        "country": network["country"],
        "isp": network["isp"],
        "asn": network["asn"],
        "hostname": network["hostname"],
        "whois": whois,
        "reputation": reputation,
    }
