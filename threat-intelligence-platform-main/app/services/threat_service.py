from datetime import datetime, timezone

from app.services.risk_engine import compute_risk
from app.services.virustotal_service import fetch_threat_intel


def _category_weights(reputation: dict) -> dict[str, int]:
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

    malicious = int(reputation.get("vt_malicious_count", 0))
    suspicious = int(reputation.get("vt_suspicious_count", 0))
    if malicious >= 10 or suspicious >= 5:
        weights["Botnet Activity"] = 20
    return weights


def _base_score(reputation: dict) -> int:
    malicious = int(reputation.get("vt_malicious_count", 0))
    suspicious = int(reputation.get("vt_suspicious_count", 0))
    return min(100, malicious * 8 + suspicious * 4)


def analyze_target(target: str, target_type: str) -> dict:
    intel = fetch_threat_intel(target, target_type)
    reputation = intel["reputation"]
    network = intel["network"]
    whois = intel["whois"]
    weights = _category_weights(reputation)
    base = _base_score(reputation)

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
