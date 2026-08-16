import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MIN_PASSWORD_LENGTH = 8
UPPERCASE_RE = re.compile(r"[A-Z]")
DIGIT_RE = re.compile(r"\d")
SPECIAL_CHAR_RE = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]")


def detect_target_type(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if value.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if DOMAIN_RE.match(value) or ("." in value and " " not in value and "/" not in value):
        return "domain"
    if "://" in value or value.startswith("www."):
        return "url"
    return None


def normalize_target(value: str, target_type: str) -> str:
    value = value.strip()
    if target_type == "url" and not value.startswith(("http://", "https://")):
        value = "https://" + value
    if target_type == "domain":
        value = value.lower().removeprefix("www.")
    return value


def validate_email(value: str) -> tuple[bool, str | None]:
    email = (value or "").strip().lower()
    if not email or not EMAIL_RE.match(email):
        return False, "validation.invalid_email"
    return True, email


def validate_password(value: str) -> tuple[bool, list[str]]:
    password = value or ""
    errors: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append("validation.password_issue_length")
    if not UPPERCASE_RE.search(password):
        errors.append("validation.password_issue_uppercase")
    if not DIGIT_RE.search(password):
        errors.append("validation.password_issue_digit")
    if not SPECIAL_CHAR_RE.search(password):
        errors.append("validation.password_issue_special")
    return len(errors) == 0, errors


def validate_target(value: str, expected_type: str | None = None) -> tuple[bool, str, str | None]:
    value = (value or "").strip()
    if not value:
        return False, "validation.target_required", None
    detected = detect_target_type(value)
    if not detected:
        return False, "validation.invalid_target", None
    if expected_type and detected != expected_type:
        return False, "validation.type_mismatch", None
    return True, normalize_target(value, detected), detected
