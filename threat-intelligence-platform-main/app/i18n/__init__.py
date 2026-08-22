from flask import request

SUPPORTED_LOCALES = ("az", "en", "ru")
DEFAULT_LOCALE = "az"

LOCALE_LABELS = {
    "az": "Azərbaycan",
    "en": "English",
    "ru": "Русский",
}

from app.i18n.translations import TRANSLATIONS  # noqa: E402


def resolve_locale() -> str:
    lang = request.cookies.get("lang", DEFAULT_LOCALE)
    return lang if lang in SUPPORTED_LOCALES else DEFAULT_LOCALE


def translate(locale: str, key: str, **kwargs) -> str:
    text = TRANSLATIONS.get(locale, {}).get(key) or TRANSLATIONS[DEFAULT_LOCALE].get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError):
            return text
    return text


def _join_issue_labels(labels: list[str], locale: str) -> str:
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    conjunction = {"az": "və", "en": "and", "ru": "и"}.get(locale, "and")
    if len(labels) == 2:
        return f"{labels[0]} {conjunction} {labels[1]}"
    return ", ".join(labels[:-1]) + f" {conjunction} {labels[-1]}"


def format_password_errors(locale: str, error_keys: list[str]) -> str:
    labels = [translate(locale, key) for key in error_keys]
    return translate(locale, "validation.password_issues", issues=_join_issue_labels(labels, locale))
