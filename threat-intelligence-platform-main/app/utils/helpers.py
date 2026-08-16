import json
from datetime import datetime, timezone


def utc_iso(dt: datetime | None) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def status_badge_class(status: str) -> str:
    s = (status or "").upper()
    if s == "SAFE":
        return "badge-safe"
    if s == "SUSPICIOUS":
        return "badge-warning"
    if s == "MALICIOUS":
        return "badge-danger"
    return "badge-muted"


def risk_color_class(score: int) -> str:
    if score <= 30:
        return "risk-safe"
    if score <= 70:
        return "risk-suspicious"
    return "risk-malicious"


def serialize_payload(data: dict) -> str:
    return json.dumps(data, default=str)


def deserialize_payload(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}
