from datetime import datetime, timezone

from app.database.connection import db


def _utcnow():
    return datetime.now(timezone.utc)


class SearchHistory(db.Model):
    __tablename__ = "search_history"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("threat_analyses.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    analysis = db.relationship("ThreatAnalysis", back_populates="search_entries")
    user = db.relationship("User", back_populates="search_history")
