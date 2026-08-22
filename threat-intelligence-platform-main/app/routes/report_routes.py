import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from app.i18n import resolve_locale, translate
from app.database.connection import db
from app.models.report import Report
from app.models.threat_analysis import ThreatAnalysis
from app.utils.helpers import deserialize_payload, utc_iso

report_bp = Blueprint("reports", __name__)


@report_bp.route("/reports")
@login_required
def index():
    saved = (
        Report.query.join(ThreatAnalysis, Report.analysis_id == ThreatAnalysis.id)
        .filter(ThreatAnalysis.user_id == current_user.id)
        .order_by(Report.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template("reports.html", saved_reports=saved)


@report_bp.route("/reports/save/<int:analysis_id>", methods=["POST"])
@login_required
def save_report(analysis_id):
    analysis = ThreatAnalysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        abort(404)
    report = Report(analysis_id=analysis.id, title=f"Report — {analysis.target}")
    db.session.add(report)
    db.session.commit()
    flash(translate(resolve_locale(), "reports.saved_success"), "success")
    return redirect(url_for("reports.index"))


@report_bp.route("/reports/export/csv")
@login_required
def export_csv():
    analyses = (
        ThreatAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(ThreatAnalysis.created_at.desc())
        .all()
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Target", "Type", "Risk Score", "Status", "Country", "Date"])
    for a in analyses:
        writer.writerow(
            [a.target, a.type, a.risk_score, a.status, a.country or "", utc_iso(a.created_at)]
        )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat_analyses.csv"},
    )


def _minimal_pdf(text: str) -> bytes:
    """Build a minimal valid PDF with plain text content."""
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = escaped.split("\n")
    y = 750
    content_parts = ["BT /F1 11 Tf"]
    for line in lines[:40]:
        content_parts.append(f"50 {y} Td ({line}) Tj")
        content_parts.append("0 -14 Td")
        y -= 14
    content_parts.append("ET")
    stream = "\n".join(content_parts)
    stream_bytes = stream.encode("latin-1", errors="replace")
    objects = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
    )
    objects.append(
        f"4 0 obj<< /Length {len(stream_bytes)} >>stream\n".encode()
        + stream_bytes
        + b"\nendstream\nendobj\n"
    )
    objects.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")
    header = b"%PDF-1.4\n"
    body = b"".join(objects)
    xref_start = len(header) + len(body)
    xref = b"xref\n0 6\n0000000000 65535 f \n"
    offset = len(header)
    for obj in objects:
        xref += f"{offset:010d} 00000 n \n".encode()
        offset += len(obj)
    trailer = (
        b"trailer<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref_start).encode()
        + b"\n%%EOF"
    )
    return header + body + xref + trailer


@report_bp.route("/reports/export/pdf/<int:analysis_id>")
@login_required
def export_pdf(analysis_id):
    analysis = ThreatAnalysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        abort(404)
    data = deserialize_payload(analysis.payload)
    locale = resolve_locale()
    rec_code = data.get("recommendation")
    rec_text = translate(locale, f"result.recommendation.{rec_code.lower()}") if rec_code else "N/A"
    lines = [
        "Threat Intelligence Platform - Analysis Report",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Target: {analysis.target}",
        f"Type: {analysis.type}",
        f"Risk Score: {analysis.risk_score}",
        f"Status: {analysis.status}",
        f"Country: {analysis.country or 'N/A'}",
        f"Recommendation: {rec_text}",
        "Categories: " + ", ".join(data.get("threat_categories") or []),
    ]
    pdf_bytes = _minimal_pdf("\n".join(lines))
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=report_{analysis_id}.pdf",
        },
    )
