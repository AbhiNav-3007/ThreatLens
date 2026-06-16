import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forensics.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Evidence Repository table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            filesize INTEGER NOT NULL,
            creation_time TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            sha1 TEXT NOT NULL,
            file_type TEXT NOT NULL,
            ml_prediction TEXT NOT NULL,
            ml_confidence REAL NOT NULL,
            yara_matches TEXT NOT NULL,
            vt_positives INTEGER,
            vt_total INTEGER,
            threat_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            ai_report TEXT,
            scan_date TEXT NOT NULL
        )
    ''')
    
    # Monitored folders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS monitored_paths (
            path TEXT PRIMARY KEY,
            active INTEGER NOT NULL DEFAULT 1,
            added_date TEXT NOT NULL
        )
    ''''')
    
    # Configuration Settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    
    # Seed default settings
    default_settings = [
        ('vt_api_key', ''),
        ('llm_provider', 'ollama'),
        ('llm_url', 'http://localhost:11434'),
        ('llm_model', 'llama3')
    ]
    for key, val in default_settings:
        cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, val))
        
    conn.commit()
    conn.close()

def insert_evidence(data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if this SHA256 has been scanned before. If so, we can optionally update or allow duplicate records.
    # To maintain a timeline/audit log of investigations, we allow duplicate scans but record each timestamp.
    
    yara_str = json.dumps(data.get('yara_matches', []))
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO evidence (
            filename, filepath, filesize, creation_time, sha256, md5, sha1, 
            file_type, ml_prediction, ml_confidence, yara_matches, 
            vt_positives, vt_total, threat_score, risk_level, ai_report, scan_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['filename'],
        data['filepath'],
        data['filesize'],
        data['creation_time'],
        data['sha256'],
        data['md5'],
        data['sha1'],
        data['file_type'],
        data['ml_prediction'],
        data['ml_confidence'],
        yara_str,
        data.get('vt_positives'),
        data.get('vt_total'),
        data['threat_score'],
        data['risk_level'],
        data.get('ai_report', ''),
        scan_time
    ))
    
    inserted_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return inserted_id

def get_all_evidence():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM evidence ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        d = dict(r)
        d['yara_matches'] = json.loads(d['yara_matches'])
        result.append(d)
    return result

def get_evidence_by_id(evidence_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM evidence WHERE id = ?', (evidence_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        d = dict(row)
        d['yara_matches'] = json.loads(d['yara_matches'])
        return d
    return None

def add_monitored_path(path):
    conn = get_db_connection()
    cursor = conn.cursor()
    added_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('INSERT OR REPLACE INTO monitored_paths (path, active, added_date) VALUES (?, 1, ?)', (path, added_date))
    conn.commit()
    conn.close()

def remove_monitored_path(path):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM monitored_paths WHERE path = ?', (path,))
    conn.commit()
    conn.close()

def get_monitored_paths():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM monitored_paths')
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def set_setting(key, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, str(value)))
    conn.commit()
    conn.close()

def get_setting(key, default=''):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row['value']
    return default

def get_all_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM settings')
    rows = cursor.fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total scans
    cursor.execute('SELECT COUNT(*) as count FROM evidence')
    total_scans = cursor.fetchone()['count']
    
    # Risk distributions
    cursor.execute("SELECT COUNT(*) as count FROM evidence WHERE risk_level = 'Malicious'")
    malicious = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM evidence WHERE risk_level = 'Suspicious'")
    suspicious = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM evidence WHERE risk_level = 'Safe'")
    safe = cursor.fetchone()['count']
    
    # Average threat score
    cursor.execute('SELECT AVG(threat_score) as avg_score FROM evidence')
    avg_score = cursor.fetchone()['avg_score'] or 0.0
    
    # Zero day threats (ML predicted malware but VT had 0 positive detections, meaning VT returned 0 detections OR was not clean in VT database)
    # Note: If VT is not configured, we don't count it.
    cursor.execute("SELECT COUNT(*) as count FROM evidence WHERE ml_prediction = 'Malware' AND (vt_positives = 0 OR vt_positives IS NULL)")
    zero_days = cursor.fetchone()['count']
    
    # Scans timeline (last 7 days)
    cursor.execute('''
        SELECT DATE(scan_date) as date, COUNT(*) as count 
        FROM evidence 
        GROUP BY DATE(scan_date) 
        ORDER BY date DESC 
        LIMIT 7
    ''')
    timeline_rows = cursor.fetchall()
    timeline = [{ 'date': r['date'], 'count': r['count'] } for r in reversed(timeline_rows)]
    
    conn.close()
    
    return {
        'total_scans': total_scans,
        'malicious': malicious,
        'suspicious': suspicious,
        'safe': safe,
        'avg_score': round(avg_score, 1),
        'zero_days': zero_days,
        'timeline': timeline
    }

# Initialize database on import/startup
init_db()
