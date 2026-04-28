import sqlite3
from datetime import datetime

DB_PATH = 'nids.db'

def get_connection():

    """creates and returns SQLite database connection"""

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():

    """initialises the database with necessary tables"""

    conn = get_connection()
    cursor = conn.cursor()

    #Traffic History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            time TEXT NOT NULL,
            total INTEGER DEFAULT 0,
            benign INTEGER DEFAULT 0,
            alerts INTEGER DEFAULT 0,
            threats INTEGER DEFAULT 0
        )
    ''')

    #Alert History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            label TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            confidence REAL
        )
    ''')

    #Stats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_flows INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0,
            benign_flows INTEGER DEFAULT 0,
            threat_intel_matches INTEGER DEFAULT 0
        )
    ''')

    #Cooldown table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cooldowns (
            src_ip TEXT NOT NULL,
            label TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            PRIMARY KEY (src_ip, label)
        )
    ''')

    #Subscription table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            phone_number TEXT PRIMARY KEY,
            subscription_arn TEXT NOT NULL
        )
    ''')

    #Insert default stats row if it doesn't exist
    cursor.execute('''
        INSERT OR IGNORE INTO stats (id, total_flows, total_alerts, benign_flows, threat_intel_matches)
        VALUES (1, 0, 0, 0, 0)
    ''')

    conn.commit()
    conn.close()
    print("Database initialised.")

def log_traffic_event(event_type):

    """logs a traffic event to the database, updating both traffic history and lifetime stats"""

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now()
    time_str = now.strftime('%H:%M')
    timestamp = now.isoformat()

    cursor.execute(
        'SELECT id FROM traffic_history WHERE time = ? AND timestamp LIKE ?',
        (time_str, timestamp[:16] + '%')
    )
    existing = cursor.fetchone()

    if existing:
        if event_type in ('ALERT', 'ALERT_SUPPRESSED'):
            cursor.execute('UPDATE traffic_history SET total = total + 1, alerts = alerts + 1 WHERE id = ?', (existing['id'],))
        elif event_type == 'THREAT_INTEL_MATCH':
            cursor.execute('UPDATE traffic_history SET total = total + 1, threats = threats + 1 WHERE id = ?', (existing['id'],))
        else:
            cursor.execute('UPDATE traffic_history SET total = total + 1, benign = benign + 1 WHERE id = ?', (existing['id'],))
    else:
        alerts = 1 if event_type in ('ALERT', 'ALERT_SUPPRESSED') else 0
        threats = 1 if event_type == 'THREAT_INTEL_MATCH' else 0
        benign = 1 if event_type == 'OK' else 0
        
        cursor.execute(
            'INSERT INTO traffic_history (timestamp, time, total, benign, alerts, threats) VALUES (?, ?, 1, ?, ?, ?)',
            (timestamp, time_str, benign, alerts, threats)
        )

    # Update lifetime stats
    if event_type == 'ALERT':
        cursor.execute('UPDATE stats SET total_flows = total_flows + 1, total_alerts = total_alerts + 1 WHERE id = 1')
    elif event_type == 'ALERT_SUPPRESSED':
        cursor.execute('UPDATE stats SET total_flows = total_flows + 1 WHERE id = 1')
    elif event_type == 'THREAT_INTEL_MATCH':
        cursor.execute('UPDATE stats SET total_flows = total_flows + 1, threat_intel_matches = threat_intel_matches + 1 WHERE id = 1')
    else:
        cursor.execute('UPDATE stats SET total_flows = total_flows + 1, benign_flows = benign_flows + 1 WHERE id = 1')

    conn.commit()
    conn.close()

def log_alert(event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence):

    """logs an alert to the database"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO alert_history (timestamp, event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        event_type, label, src_ip, dst_ip, src_port, dst_port, protocol, round(confidence, 2) if confidence else None
    ))

    conn.commit()
    conn.close()

def get_stats():

    """retrieves lifetime stats from the database"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM stats WHERE id = 1')
    row = cursor.fetchone()

    conn.close()
    return dict(row) if row else {}

def get_traffic_history(cutoff):

    """retrieves traffic history from the database since the specified cutoff time"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM traffic_history WHERE timestamp >= ? ORDER BY timestamp ASC', (cutoff.isoformat(),))
    rows = cursor.fetchall()

    conn.close()
    return [dict(row) for row in rows]

def get_alert_history(limit = 100):

    """retrieves the alert history from the database"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM alert_history ORDER BY timestamp DESC LIMIT ?', (limit,))

    rows = cursor.fetchall()
    
    conn.close()
    return [dict(row) for row in rows]

def set_cooldown(src_ip, label):

    """sets a cooldown for a specific source IP and alert label"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        'INSERT OR REPLACE INTO cooldowns (src_ip, label, timestamp) VALUES (?, ?, ?)',
        (src_ip, label, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def get_cooldown(src_ip, label):

    """retrieves the cooldown timestamp for a specific source IP and alert label, if it exists"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT timestamp FROM cooldowns WHERE src_ip = ? AND label = ?', (src_ip, label))

    row = cursor.fetchone()
    conn.close()
    return datetime.fromisoformat(row['timestamp']) if row else None

def save_subscription(phone_number, subscription_arn):

    """saves or updates an alert subscription in the database"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('INSERT OR REPLACE INTO subscriptions (phone_number, subscription_arn) VALUES (?, ?)', (phone_number, subscription_arn))

    conn.commit()
    conn.close()

def delete_subscription(phone_number):

    """deletes an alert subscription from the database"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM subscriptions WHERE phone_number = ?', (phone_number,))

    conn.commit()
    conn.close()

def get_all_subscriptions():

    """retrieves all alert subscriptions from the database"""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT phone_number, subscription_arn FROM subscriptions')

    rows = cursor.fetchall()
    conn.close()

    return {row['phone_number']: row['subscription_arn'] for row in rows}