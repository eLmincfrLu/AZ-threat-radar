from app.database.connection import db
from app.models.user import User
from app.utils.security import hash_password, verify_password
from app.i18n import format_password_errors, translate
from app.utils.validators import validate_email, validate_password

DEFAULT_DEMO_EMAIL = "123@holbertonstudents.com"
DEFAULT_DEMO_PASSWORD = "Holbie123!"


def ensure_demo_user():
    user = User.query.filter_by(email=DEFAULT_DEMO_EMAIL).first()
    if user:
        return user
    user = User(email=DEFAULT_DEMO_EMAIL, password_hash=hash_password(DEFAULT_DEMO_PASSWORD))
    db.session.add(user)
    db.session.commit()
    return user


def authenticate(email: str, password: str) -> User | None:
    user = User.query.filter_by(email=email.strip().lower()).first()
    if user and verify_password(user.password_hash, password):
        return user
    return None


def register_user(email: str, password: str, locale: str) -> tuple[User | None, str | None]:
    ok, email_or_err = validate_email(email)
    if not ok:
        return None, translate(locale, email_or_err)
    ok, pwd_errors = validate_password(password)
    if not ok:
        return None, format_password_errors(locale, pwd_errors)
    if User.query.filter_by(email=email_or_err).first():
        return None, translate(locale, "register.email_taken")
    user = User(email=email_or_err, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user, None


def change_password(user: User, current_password: str, new_password: str, locale: str) -> str | None:
    if not verify_password(user.password_hash, current_password):
        return translate(locale, "settings.current_password_wrong")
    ok, pwd_errors = validate_password(new_password)
    if not ok:
        return format_password_errors(locale, pwd_errors)
    user.password_hash = hash_password(new_password)
    db.session.commit()
    return None
