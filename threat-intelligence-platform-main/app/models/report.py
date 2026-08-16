from datetime import datetime, timezone

from app.database.connection import db


def _utcnow():
    return datetime.now(timezone.utc)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("threat_analyses.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    title = db.Column(db.String(255), default="Threat Intelligence Report")

    analysis = db.relationship("ThreatAnalysis", back_populates="reports")
