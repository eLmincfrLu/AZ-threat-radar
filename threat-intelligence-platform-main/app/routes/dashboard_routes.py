from collections import Counter

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required, current_user

from app.i18n import resolve_locale, translate
from app.models.threat_analysis import ThreatAnalysis
from app.services.auth_service import change_password
from app.utils.helpers import utc_iso

dashboard_bp = Blueprint("dashboard", __name__)


def _stats():
    analyses = ThreatAnalysis.query.filter_by(user_id=current_user.id).all()
    total = len(analyses)
    safe = sum(1 for a in analyses if a.risk_score <= 30)
    suspicious = sum(1 for a in analyses if 31 <= a.risk_score <= 70)
    malicious = sum(1 for a in analyses if a.risk_score >= 71)
    return total, safe, suspicious, malicious


@dashboard_bp.route("/dashboard")
@login_required
def index():
    total, safe, suspicious, malicious = _stats()
    recent = (
        ThreatAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
        .limit(8)
        .all()
    )
    recent_searches = [
        {
            "target": a.target,
            "type": a.type,
            "risk_score": a.risk_score,
            "status": a.status,
            "date": utc_iso(a.created_at),
            "id": a.id,
        }
        for a in recent
    ]
    alerts = [r for r in recent_searches if r["status"] in ("SUSPICIOUS", "MALICIOUS")][:5]
    return render_template(
        "dashboard.html",
        stats={"total": total, "safe": safe, "suspicious": suspicious, "malicious": malicious},
        recent_searches=recent_searches,
        recent_alerts=alerts,
        risk_distribution={"safe": safe, "suspicious": suspicious, "malicious": malicious},
    )


@dashboard_bp.route("/api/dashboard/summary")
@login_required
def api_summary():
    total, safe, suspicious, malicious = _stats()
    recent = (
        ThreatAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
        .limit(10)
        .all()
    )
    categories = Counter()
    for a in recent:
        from app.utils.helpers import deserialize_payload

        payload = deserialize_payload(a.payload)
        for cat in payload.get("threat_categories") or []:
            if cat and cat != "None":
                categories[cat] += 1
    top_categories = [{"name": k, "count": v} for k, v in categories.most_common(5)]
    return jsonify(
        {
            "stats": {
                "total": total,
                "safe": safe,
                "suspicious": suspicious,
                "malicious": malicious,
            },
            "top_categories": top_categories,
        }
    )


@dashboard_bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@dashboard_bp.route("/settings/change-password", methods=["GET", "POST"])
@login_required
def change_password_page():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        locale = resolve_locale()
        if new_password != confirm_password:
            flash(translate(locale, "register.password_mismatch"), "danger")
        else:
            err = change_password(current_user, current_password, new_password, locale)
            if err:
                flash(err, "danger")
            else:
                flash(translate(locale, "settings.password_changed"), "success")
                return redirect(url_for("dashboard.settings"))
    return render_template("change_password.html")
