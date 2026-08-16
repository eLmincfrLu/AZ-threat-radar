import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_login import LoginManager

from app.database.connection import db, init_db
from app.models.user import User
from app.routes.analysis_routes import analysis_bp
from app.routes.auth_routes import auth_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.history_routes import history_bp
from app.routes.report_routes import report_bp
from app.i18n import LOCALE_LABELS, SUPPORTED_LOCALES, resolve_locale, translate
from app.services.auth_service import ensure_demo_user

load_dotenv()


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    init_db(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(report_bp)

    @app.context_processor
    def inject_globals():
        locale = resolve_locale()

        def t(key, **kwargs):
            return translate(locale, key, **kwargs)

        return {
            "app_name": "AZ THREAT RADAR",
            "t": t,
            "current_locale": locale,
            "locale_labels": LOCALE_LABELS,
            "supported_locales": SUPPORTED_LOCALES,
        }

    with app.app_context():
        db.create_all()
        ensure_demo_user()

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(debug=True, host="0.0.0.0", port=5000)
