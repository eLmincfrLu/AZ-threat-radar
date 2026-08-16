from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from app.models.search_history import SearchHistory
from app.models.threat_analysis import ThreatAnalysis
from app.utils.helpers import utc_iso

history_bp = Blueprint("history", __name__)


@history_bp.route("/history")
@login_required
def index():
    q = request.args.get("q", "").strip().lower()
    type_filter = request.args.get("type", "")
    status_filter = request.args.get("status", "")

    query = (
        ThreatAnalysis.query.join(SearchHistory, SearchHistory.analysis_id == ThreatAnalysis.id)
        .filter(ThreatAnalysis.user_id == current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
    )
    if q:
        query = query.filter(ThreatAnalysis.target.ilike(f"%{q}%"))
    if type_filter:
        query = query.filter(ThreatAnalysis.type == type_filter)
    if status_filter:
        query = query.filter(ThreatAnalysis.status == status_filter.upper())

    rows = query.distinct().limit(200).all()
    items = [
        {
            "id": a.id,
            "target": a.target,
            "type": a.type,
            "risk_score": a.risk_score,
            "status": a.status,
            "date": utc_iso(a.created_at),
        }
        for a in rows
    ]
    return render_template(
        "history.html",
        items=items,
        q=q,
        type_filter=type_filter,
        status_filter=status_filter,
    )
