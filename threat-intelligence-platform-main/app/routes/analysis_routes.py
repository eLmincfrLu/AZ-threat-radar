from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.database.connection import db
from app.models.search_history import SearchHistory
from app.models.threat_analysis import ThreatAnalysis
from app.services.threat_service import analyze_target
from app.services.virustotal_service import VirusTotalError
from app.i18n import resolve_locale, translate
from app.utils.helpers import deserialize_payload, serialize_payload
from app.utils.validators import validate_target

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/analysis", methods=["GET", "POST"])
@login_required
def analyze_page():
    if request.method == "POST":
        target_type = request.form.get("target_type", "ip")
        raw_target = request.form.get("target", "")
        ok, normalized, detected = validate_target(raw_target, target_type)
        if not ok:
            flash(
                translate(resolve_locale(), normalized, expected_type=target_type),
                "danger",
            )
            return redirect(url_for("analysis.analyze_page"))
        try:
            result = analyze_target(normalized, detected)
        except VirusTotalError as exc:
            flash(translate(resolve_locale(), exc.code), "danger")
            return redirect(url_for("analysis.analyze_page"))
        analysis = ThreatAnalysis(
            user_id=current_user.id,
            target=result["target"],
            type=result["type"],
            risk_score=result["risk_score"],
            status=result["status"],
            country=result.get("country"),
            payload=serialize_payload(result),
        )
        db.session.add(analysis)
        db.session.flush()
        db.session.add(
            SearchHistory(analysis_id=analysis.id, user_id=current_user.id)
        )
        db.session.commit()
        return redirect(url_for("analysis.result", analysis_id=analysis.id))
    return render_template("analysis.html")


@analysis_bp.route("/result/<int:analysis_id>")
@login_required
def result(analysis_id):
    analysis = ThreatAnalysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        abort(404)
    data = deserialize_payload(analysis.payload)
    if not data:
        flash(translate(resolve_locale(), "analysis.result_unavailable"), "warning")
        return redirect(url_for("history.index"))
    return render_template("result.html", analysis=analysis, data=data)


@analysis_bp.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    body = request.get_json(silent=True) or {}
    target_type = body.get("target_type", "ip")
    raw_target = body.get("target", "")
    ok, normalized, detected = validate_target(raw_target, target_type)
    if not ok:
        return {"error": translate(resolve_locale(), normalized, expected_type=target_type)}, 400
    try:
        result = analyze_target(normalized, detected)
    except VirusTotalError as exc:
        return {
            "error": translate(resolve_locale(), exc.code),
            "error_code": exc.code,
        }, exc.status_code
    analysis = ThreatAnalysis(
        user_id=current_user.id,
        target=result["target"],
        type=result["type"],
        risk_score=result["risk_score"],
        status=result["status"],
        country=result.get("country"),
        payload=serialize_payload(result),
    )
    db.session.add(analysis)
    db.session.flush()
    db.session.add(SearchHistory(analysis_id=analysis.id, user_id=current_user.id))
    db.session.commit()
    result["analysis_id"] = analysis.id
    return result
