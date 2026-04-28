from flask import Flask, render_template, jsonify, request
from alerts import AlertManager
from dotenv import load_dotenv
from datetime import datetime, timedelta
from database import *
import logging

load_dotenv()

app = Flask(
    __name__,
    template_folder = '../templates',
    static_folder = '../static'
)

# Suppress Flask's default logging to avoid cluttering the console
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Global variable to hold the AlertManager instance
_alert_manager = None

def set_alert_manager(manager):

    """"Sets the global AlertManager instance for use in API routes."""

    global _alert_manager
    _alert_manager = manager

#Init database and create tables if they don't exist 
init_db()

@app.route('/')
def index():

    """Renders the main dashboard page."""

    return render_template('index.html')

@app.route('/api/stats')
def get_stats_route():
    
    """API endpoint to retrieve current system statistics, including uptime."""

    stats = get_stats()

    # Track uptime since the dashboard started
    if 'start_time' not in app.config:
        app.config['start_time'] = datetime.now()

    uptime_seconds = (datetime.now() - app.config['start_time']).total_seconds()
    
    hours = int(uptime_seconds // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    seconds = int(uptime_seconds % 60)
    stats['uptime'] = f"{hours}h {minutes}m {seconds}s"

    return jsonify(stats)

@app.route('/api/traffic_history')
def get_traffic_history_route():

    """API endpoint to retrieve traffic history.
    Accepts an optional 'interval' query parameter to specify the time range (hour, day, week, month)."""

    interval = request.args.get('interval', 'hour')
    now = datetime.now()

    intervals = {
        'hour': timedelta(hours = 1),
        'day': timedelta(days = 1),
        'week': timedelta(weeks = 1),
        'month': timedelta(days = 30)
    }

    cutoff = now - intervals.get(interval, timedelta(hours = 1))

    #Return traffic history data since the cutoff time
    return jsonify(get_traffic_history(cutoff))

@app.route('/api/alerts')
def get_alerts_route():

    """Returns the lifetime alert history."""

    return jsonify(get_alert_history())

def add_traffic_event(event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence):

    """Logs a traffic event to the database."""

    log_traffic_event(event_type)

    if event_type in ('ALERT', 'THREAT_INTEL_MATCH'):
        log_alert(event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence)

@app.route('/api/subscriptions', methods = ['GET'])
def get_subcriptions_route():

    """Returns all current alert subscriptions."""

    return jsonify(_alert_manager.get_subscriptions())

@app.route('/api/subscriptions', methods = ['POST'])
def subscribe_route():

    """Subscribes a user to alert notifications."""

    data = request.json
    phone = data.get('phone_number')

    if not phone:
        return jsonify({'success': False, 'error': 'No phone number provided'}), 400
    success = _alert_manager.subscribe(phone)

    return jsonify({'success': success})

@app.route('/api/subscriptions/<phone>', methods = ['DELETE'])
def unsubscribe_route(phone):

    """Unsubscribes a user from alert notifications."""

    success = _alert_manager.unsubscribe(phone)
    return jsonify({'success': success})

def start_dashboard(host = '0.0.0.0', port = 5000, debug = False):

    """Starts the Flask dashboard server. Called from monitor.py. available on all interfaces by default."""

    print(f"Starting dashboard on {host}:{port}...")
    app.run(host = host, port = port, debug = debug, threaded = True)

if __name__ == "__main__":
    start_dashboard()