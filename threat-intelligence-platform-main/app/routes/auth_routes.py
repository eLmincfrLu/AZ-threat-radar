from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.i18n import SUPPORTED_LOCALES, DEFAULT_LOCALE, resolve_locale, translate
from app.services.auth_service import authenticate, register_user

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"
        user = authenticate(email, password)
        if user:
            login_user(user, remember=remember)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.index"))
        flash(translate(resolve_locale(), "login.invalid_credentials"), "danger")
    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if password != confirm:
            flash(translate(resolve_locale(), "register.password_mismatch"), "danger")
        else:
            locale = resolve_locale()
            user, err = register_user(email, password, locale)
            if user:
                flash(translate(locale, "register.success"), "success")
                return redirect(url_for("auth.login"))
            flash(err, "danger")
    return render_template("register.html")


@auth_bp.route("/set-language/<lang>")
def set_language(lang):
    if lang not in SUPPORTED_LOCALES:
        lang = DEFAULT_LOCALE
    next_url = request.args.get("next") or request.referrer or url_for("auth.login")
    response = redirect(next_url)
    response.set_cookie("lang", lang, max_age=365 * 24 * 3600, samesite="Lax")
    return response


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))