"""Flask API for IDS dashboard."""

from pathlib import Path

from flask import (
    Flask,
    jsonify,
    send_from_directory,
)

from flask_cors import CORS


DASHBOARD_DIR = (
    Path(__file__).resolve().parent.parent
    / "dashboard"
)


def create_app(store, tracker):

    app = Flask(
        __name__,
        static_folder=None
    )

    CORS(app)

    @app.get("/")
    def index():

        return send_from_directory(
            DASHBOARD_DIR,
            "index.html"
        )

    @app.get("/api/alerts")
    def alerts():

        return jsonify(
            store.recent(100)
        )

    @app.post("/api/alerts/clear")
    def clear_alerts():
        """Clear all previously stored security events."""
        try:
            store.clear()
            return jsonify({
                "success": True,
                "message": "Previous security events cleared"
            })
        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.get("/api/alerts/<int:alert_id>")
    def alert_by_id(alert_id):

        rows = [
            alert
            for alert
            in store.recent(1000)
            if alert["id"] == alert_id
        ]

        if not rows:

            return jsonify(
                {"error": "not found"}
            ), 404

        return jsonify(rows[0])

    @app.get("/api/stats")
    def stats():

        return jsonify({
            "live": tracker.snapshot(),
            "db": store.stats(),
        })

    @app.get("/api/health")
    def health():

        return jsonify({
            "status": "ok"
        })

    return app
