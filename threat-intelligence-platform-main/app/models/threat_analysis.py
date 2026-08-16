from datetime import datetime, timezone

from app.database.connection import db


def _utcnow():
    return datetime.now(timezone.utc)


class ThreatAnalysis(db.Model):
    __tablename__ = "threat_analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    target = db.Column(db.String(512), nullable=False, index=True)
    type = db.Column(db.String(32), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(32), nullable=False, default="UNKNOWN")
    country = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    payload = db.Column(db.Text)

    search_entries = db.relationship("SearchHistory", back_populates="analysis", lazy="dynamic")
    reports = db.relationship("Report", back_populates="analysis", lazy="dynamic")

    def risk_level(self):
        if self.risk_score <= 30:
            return "safe"
        if self.risk_score <= 70:
            return "suspicious"
        return "malicious"
