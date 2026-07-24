import json
import time
from collections import deque
from datetime import datetime
from flask import Flask, Response, render_template, jsonify
from pathlib import Path


def create_app(alert_queue: deque) -> Flask:
    app = Flask(__name__, template_folder="templates")

    # --- Route 1: serve the dashboard HTML ---
    @app.route("/")
    def index():
        return render_template("dashboard.html")

    # --- Route 2: SSE stream --- 
    # this is the live connection the browser holds open
    # every time a new alert arrives in the queue, it gets pushed instantly
    @app.route("/api/alerts/stream")
    def alert_stream():
        def generate():
            last_index = 0
            seen = []
            while True:
                # check if there are new alerts in the queue
                current = list(alert_queue)
                if len(current) > last_index:
                    new_alerts = current[last_index:]
                    for alert in new_alerts:
                        payload = json.dumps({
                            "attack_type": alert.attack_type,
                            "source_ip":   alert.source_ip,
                            "severity":    alert.severity,
                            "message":     alert.message,
                            "timestamp":   alert.timestamp,
                        })
                        yield f"data: {payload}\n\n"
                    last_index = len(current)
                time.sleep(0.5)  # check every 500ms

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )

    # --- Route 3: historical alerts from log file ---
    # called once on page load to populate the dashboard with past alerts
    @app.route("/api/alerts/history")
    def alert_history():
        log_path = Path("logs/alerts.log")
        if not log_path.exists():
            return jsonify([])

        alerts = []
        with open(log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                alerts.append({"raw": line})

        return jsonify(alerts)

    return app