import threading
import logging
import os
from flask import Flask, render_template, jsonify
from database import get_alerts, get_logs, get_connection

logger = logging.getLogger(__name__)

# Point Flask to the templates folder
template_dir = os.path.abspath(os.path.dirname(__file__) + '/templates')
app = Flask(__name__, template_folder=template_dir)

@app.route('/')
def index():
    """Serve the main dashboard page."""
    blocked_ips = []
    try:
        conn = get_connection()
        # Fetch recently blocked IPs to pass to the template
        blocked_ips = list(conn.blocked_ips.find().sort("timestamp", -1).limit(50))
    except Exception as e:
        logger.error(f"Dashboard DB Error: {e}")
        
    return render_template('index.html', blocked_ips=blocked_ips)

@app.route('/api/alerts')
def api_alerts():
    """API endpoint returning recent alerts."""
    try:
        alerts = get_alerts(limit=500)
        for a in alerts:
            a['_id'] = str(a.get('_id', ''))
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"API Alerts Error: {e}")
        return jsonify([])

@app.route('/api/logs')
def api_logs():
    """API endpoint returning recent logs."""
    try:
        logs = get_logs(limit=500)
        for l in logs:
            l['_id'] = str(l.get('_id', ''))
        return jsonify(logs)
    except Exception as e:
        logger.error(f"API Logs Error: {e}")
        return jsonify([])

def run_app():
    """Run the Flask server."""
    # Suppress verbose Flask dev server output to keep terminal clean for alerts
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def start_dashboard():
    """Start the web dashboard application in a background thread."""
    logger.info("Starting Flask dashboard on http://0.0.0.0:5000")
    t = threading.Thread(target=run_app, daemon=True)
    t.start()
