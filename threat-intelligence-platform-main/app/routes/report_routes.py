import io
from datetime import datetime, timezone

from fpdf import FPDF
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
    if not analyses:
        flash(translate(resolve_locale(), "reports.empty"), "warning")
        return redirect(url_for("reports.index"))

    output = io.StringIO()
    output.write("\ufeff")  # UTF-8 BOM — Excel-də AZ hərflərinin (ə, ö, ü) düzgün görünməsi üçün
    import csv

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


def _status_rgb(status: str) -> tuple[int, int, int]:
    s = (status or "").upper()
    if s == "SAFE":
        return (34, 197, 94)
    if s == "SUSPICIOUS":
        return (245, 158, 11)
    if s == "MALICIOUS":
        return (239, 68, 68)
    return (148, 163, 184)


def _build_pdf(analysis: ThreatAnalysis, data: dict, locale: str) -> bytes:
    rec_code = data.get("recommendation")
    rec_text = translate(locale, f"result.recommendation.{rec_code.lower()}") if rec_code else "N/A"
    status_color = _status_rgb(analysis.status)

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # --- Header band (matches --card dark theme) ---
    pdf.set_fill_color(17, 24, 39)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_xy(12, 8)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 8, "AZ THREAT RADAR", ln=1)
    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(180, 190, 210)
    pdf.cell(
        0, 6,
        f"Analysis Report - Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    )

    pdf.set_y(36)
    pdf.set_x(12)
    pdf.set_text_color(15, 23, 42)

    # --- Target block ---
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, str(analysis.target), ln=1)
    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 110, 130)
    pdf.cell(0, 6, f"Type: {str(analysis.type).upper()}", ln=1)
    pdf.ln(3)

    # --- Risk score + status badges ---
    pdf.set_x(12)
    pdf.set_fill_color(*status_color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(55, 9, f"Risk Score: {analysis.risk_score}", fill=True, align="C")
    pdf.cell(4)
    pdf.cell(45, 9, str(analysis.status), fill=True, align="C", ln=1)
    pdf.ln(6)

    # --- Recommendation banner ---
    pdf.set_x(12)
    pdf.set_text_color(15, 23, 42)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Recommendation", ln=1)
    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_fill_color(241, 245, 249)
    pdf.multi_cell(186, 6, rec_text, fill=True)
    pdf.ln(4)

    def section(title, rows):
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(37, 99, 235)
        pdf.cell(0, 7, title, ln=1)
        pdf.set_draw_color(226, 232, 240)
        pdf.line(12, pdf.get_y(), 198, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 41, 59)
        for label, value in rows:
            pdf.set_x(12)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(45, 6, label)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(141, 6, str(value) if value not in (None, "") else "N/A")
        pdf.ln(3)

    section("Network Details", [
        ("Country", data.get("country") or "Unknown"),
        ("ISP", data.get("isp") or "Unknown"),
        ("ASN", data.get("asn") or "Unknown"),
        ("Hostname", data.get("hostname") or "Unknown"),
    ])

    section("Threat Categories", [
        ("Categories", ", ".join(data.get("threat_categories") or []) or "None"),
    ])

    whois = data.get("whois") or {}
    section("WHOIS", [
        ("Registrar", whois.get("registrar") or "Unknown"),
        ("Registered", whois.get("registration_date") or "Unknown"),
        ("Expires", whois.get("expiration_date") or "Unknown"),
    ])

    rep = data.get("reputation") or {}
    section("Reputation", [
        ("VirusTotal", rep.get("virustotal_status") or "N/A"),
        ("Blacklist", rep.get("blacklist_status") or "N/A"),
        ("Malware", rep.get("malware_detection") or "N/A"),
        ("Phishing", rep.get("phishing_detection") or "N/A"),
        ("Spam", rep.get("spam_detection") or "N/A"),
    ])

    pdf.set_y(-15)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 10, "AZ THREAT RADAR - Confidential Threat Intelligence Report", align="C")

    return bytes(pdf.output())


@report_bp.route("/reports/export/pdf/<int:analysis_id>")
@login_required
def export_pdf(analysis_id):
    analysis = ThreatAnalysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        abort(404)
    data = deserialize_payload(analysis.payload)
    locale = resolve_locale()
    pdf_bytes = _build_pdf(analysis, data, locale)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=report_{analysis_id}.pdf",
        },
    )