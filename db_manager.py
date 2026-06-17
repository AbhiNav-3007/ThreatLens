import pymysql
import pymysql.cursors
import os
import json
import time
from datetime import datetime

# Helper to load environmental configs from .env
def load_env_vars():
    env = {}
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        env[k.strip()] = v.strip().strip('"').strip("'")
        except Exception as e:
            print(f"Error reading .env file: {e}")
    return env

ENV = load_env_vars()

MYSQL_HOST = ENV.get('MYSQL_HOST', 'localhost')
MYSQL_USER = ENV.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = ENV.get('MYSQL_PASSWORD', '')
MYSQL_DATABASE = ENV.get('MYSQL_DATABASE', 'threatlens')
MYSQL_PORT = int(ENV.get('MYSQL_PORT', 3306))
MYSQL_UNIX_SOCKET = ENV.get('MYSQL_UNIX_SOCKET', '')

def get_db_connection():
    """Establish MySQL connection with dictionary cursors."""
    try:
        if MYSQL_UNIX_SOCKET:
            conn = pymysql.connect(
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                unix_socket=MYSQL_UNIX_SOCKET,
                cursorclass=pymysql.cursors.DictCursor,
                charset='utf8mb4'
            )
        else:
            conn = pymysql.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                port=MYSQL_PORT,
                cursorclass=pymysql.cursors.DictCursor,
                charset='utf8mb4'
            )
        return conn
    except pymysql.err.OperationalError as e:
        # Check if error is 'Unknown database' (code 1049)
        if e.args[0] == 1049:
            # Connect to server without specifying database to create it
            if MYSQL_UNIX_SOCKET:
                temp_conn = pymysql.connect(
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    unix_socket=MYSQL_UNIX_SOCKET
                )
            else:
                temp_conn = pymysql.connect(
                    host=MYSQL_HOST,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    port=MYSQL_PORT
                )
            cursor = temp_conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_DATABASE}")
            temp_conn.commit()
            temp_conn.close()
            
            # Reconnect with database
            if MYSQL_UNIX_SOCKET:
                return pymysql.connect(
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=MYSQL_DATABASE,
                    unix_socket=MYSQL_UNIX_SOCKET,
                    cursorclass=pymysql.cursors.DictCursor,
                    charset='utf8mb4'
                )
            else:
                return pymysql.connect(
                    host=MYSQL_HOST,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=MYSQL_DATABASE,
                    port=MYSQL_PORT,
                    cursorclass=pymysql.cursors.DictCursor,
                    charset='utf8mb4'
                )
        else:
            raise e

def init_db():
    """Create schemas and tables inside the MySQL database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Evidence Repository table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INT AUTO_INCREMENT PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            filepath VARCHAR(512) NOT NULL,
            filesize BIGINT NOT NULL,
            creation_time VARCHAR(50) NOT NULL,
            sha256 VARCHAR(64) NOT NULL,
            md5 VARCHAR(32) NOT NULL,
            sha1 VARCHAR(40) NOT NULL,
            file_type VARCHAR(100) NOT NULL,
            ml_prediction VARCHAR(50) NOT NULL,
            ml_confidence DOUBLE NOT NULL,
            yara_matches TEXT NOT NULL,
            vt_positives INT,
            vt_total INT,
            threat_score INT NOT NULL,
            risk_level VARCHAR(50) NOT NULL,
            ai_report LONGTEXT,
            scan_date VARCHAR(50) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ''')
    
    # 2. Monitored folders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS monitored_paths (
            path VARCHAR(512) PRIMARY KEY,
            active INT NOT NULL DEFAULT 1,
            added_date VARCHAR(50) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ''')
    
    # 3. Configuration Settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            `key` VARCHAR(255) PRIMARY KEY,
            `value` TEXT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ''')
    
    # Seed default settings
    default_settings = [
        ('vt_api_key', ''),
        ('llm_provider', 'ollama'),
        ('llm_url', 'http://localhost:11434'),
        ('llm_model', 'llama3')
    ]
    for key, val in default_settings:
        cursor.execute('INSERT IGNORE INTO settings (`key`, `value`) VALUES (%s, %s)', (key, val))
        
    conn.commit()
    conn.close()

def insert_evidence(data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    yara_str = json.dumps(data.get('yara_matches', []))
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO evidence (
            filename, filepath, filesize, creation_time, sha256, md5, sha1, 
            file_type, ml_prediction, ml_confidence, yara_matches, 
            vt_positives, vt_total, threat_score, risk_level, ai_report, scan_date
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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

def update_evidence_filepath(evidence_id, filepath):
    """Utility method to update vault filepath of an evidence record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE evidence SET filepath = %s WHERE id = %s', (filepath, evidence_id))
    conn.commit()
    conn.close()

def update_evidence_ai_report(evidence_id, report_content):
    """Utility method to update the GenAI text analysis report of an evidence record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE evidence SET ai_report = %s WHERE id = %s', (report_content, evidence_id))
    conn.commit()
    conn.close()

def delete_evidence(evidence_id):
    """Delete evidence record by id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM evidence WHERE id = %s', (evidence_id,))
    conn.commit()
    conn.close()

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
    cursor.execute('SELECT * FROM evidence WHERE id = %s', (evidence_id,))
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
    cursor.execute('REPLACE INTO monitored_paths (path, active, added_date) VALUES (%s, 1, %s)', (path, added_date))
    conn.commit()
    conn.close()

def remove_monitored_path(path):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM monitored_paths WHERE path = %s', (path,))
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
    cursor.execute('REPLACE INTO settings (`key`, `value`) VALUES (%s, %s)', (key, str(value)))
    conn.commit()
    conn.close()

def get_setting(key, default=''):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT `value` FROM settings WHERE `key` = %s', (key,))
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
    avg_score_raw = cursor.fetchone()['avg_score']
    avg_score = float(avg_score_raw) if avg_score_raw is not None else 0.0
    
    # Zero day threats
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
    timeline = [{ 'date': str(r['date']), 'count': r['count'] } for r in reversed(timeline_rows)]
    
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
try:
    init_db()
except Exception as e:
    print(f"WARNING: Could not connect to MySQL server to initialize database: {e}")
