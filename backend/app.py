"""
backend/app.py
================
Flask application factory for ABTD.
Registers all blueprints, CORS, error handlers, and initialises DB.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from flask import Flask, jsonify
from flask_cors import CORS
from backend.database import db
from backend.logger   import log_system


def create_app() -> Flask:
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        template_folder=str(config.TEMPLATES_DIR),
        static_folder=str(config.STATIC_DIR),
        static_url_path="/static",
    )

    app.config["SECRET_KEY"]     = config.FLASK_SECRET_KEY
    app.config["JSON_SORT_KEYS"] = False

    # ── CORS ──────────────────────────────────────────────────────────
    CORS(app, resources={
        r"/predict" : {"origins": "*"},
        r"/api/*"   : {"origins": "*"},
    })

    # ── MongoDB Atlas ─────────────────────────────────────────────────
    db.connect()

    # ── Blueprints ────────────────────────────────────────────────────
    from backend.routes.predict_routes  import predict_bp
    from backend.routes.scan_routes     import scan_bp
    from backend.routes.stats_routes    import stats_bp
    from backend.routes.alert_routes    import alert_bp
    from backend.routes.system_routes   import system_bp
    from backend.routes.settings_routes import settings_bp
    from backend.routes.awareness_routes import awareness_bp
    from backend.routes.page_routes     import page_bp
    from backend.routes.zero_trust_routes import zero_trust_bp
    from backend.routes.assessment_routes import assessment_bp

    app.register_blueprint(predict_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(awareness_bp)
    app.register_blueprint(page_bp)
    app.register_blueprint(zero_trust_bp)
    app.register_blueprint(assessment_bp)

    # ── Error Handlers ────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found", "status": 404}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error", "status": 500}), 500

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed", "status": 405}), 405

    log_system.info("Flask application created — all blueprints registered")
    return app
