import hashlib


def _seed(value: str) -> int:
    return int(hashlib.sha256(value.encode()).hexdigest(), 16)


def mock_reputation(target: str, target_type: str) -> dict:
    seed = _seed(f"{target_type}:{target.lower()}")
    vt_detect = seed % 17
    blacklisted = (seed % 23) == 0
    malware = (seed % 11) == 0
    phishing = (seed % 13) == 0
    spam = (seed % 19) == 0

    safe_hosts = {"google.com", "cloudflare.com", "microsoft.com", "github.com"}
    host = target.lower().replace("https://", "").replace("http://", "").split("/")[0]
    if host in safe_hosts or target in ("8.8.8.8", "1.1.1.1"):
        vt_detect = 0
        blacklisted = False
        malware = False
        phishing = False
        spam = False

    if "185.199" in target:
        vt_detect = 12
        blacklisted = True
        malware = True
        phishing = True

    vt_status = "Clean" if vt_detect == 0 else f"{vt_detect}/70 engines flagged"

    return {
        "virustotal_status": vt_status,
        "blacklist_status": "Listed" if blacklisted else "Not Listed",
        "malware_detection": "Detected" if malware else "None",
        "phishing_detection": "Detected" if phishing else "None",
        "spam_detection": "Detected" if spam else "None",
    }
