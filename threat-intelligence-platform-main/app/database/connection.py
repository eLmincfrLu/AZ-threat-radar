import os
from pathlib import Path

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    db_dir = Path(app.instance_path) if app.instance_path else Path(__file__).resolve().parent
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = Path(__file__).resolve().parent / "database.db"  # app/database/database.db
    default_uri = f"sqlite:///{db_path.as_posix()}"
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.getenv("DATABASE_URL", default_uri))
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
