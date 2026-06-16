import os
import shutil
import time
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

import db_manager
import forensic_pipeline
from folder_monitor import monitor_daemon
import metrics_exporter

# Setup directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
VAULT_FOLDER = os.path.join(BASE_DIR, 'evidence_vault')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(VAULT_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'forensics_super_secret_key'

# Initialize Prometheus Metrics
metrics_exporter.init_metrics()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Manual upload scanner."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty file name'}), 400
        
    try:
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(temp_path)
        
        # Run forensic pipeline
        result = forensic_pipeline.run_analysis_pipeline(temp_path)
        
        if result:
            # Archives the file permanently in the forensic vault
            # Use SHA256 as filename to preserve cryptographic integrity and prevent duplicates
            sha256 = result['sha256']
            _, ext = os.path.splitext(filename)
            vault_name = f"{sha256}{ext}"
            vault_path = os.path.join(VAULT_FOLDER, vault_name)
            
            # Copy temp file to vault and delete temp with Windows lock resilience
            copied = False
            for i in range(5):
                try:
                    shutil.copy2(temp_path, vault_path)
                    copied = True
                    break
                except Exception as e:
                    time.sleep(0.2)
            if not copied and not os.path.exists(vault_path):
                shutil.copy2(temp_path, vault_path)
                
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception as e:
                print(f"Warning: Could not remove temporary file {temp_path} due to OS lock: {e}")
                
            # Update database to point to the vault file
            conn = db_manager.get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE evidence SET filepath = ? WHERE id = ?', (vault_path, result['id']))
            conn.commit()
            conn.close()
            result['filepath'] = vault_path
            
            # Record Prometheus Metrics
            is_zero_day = (result['ml_prediction'] == 'Malware' and 
                           (result.get('vt_positives') == 0 or result.get('vt_positives') is None))
            metrics_exporter.record_scan_metrics(
                risk_level=result['risk_level'],
                source='manual',
                threat_score=result['threat_score'],
                is_zero_day=is_zero_day
            )
            
            return jsonify(result), 200
        else:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception as e:
                print(f"Warning: Could not remove temporary file {temp_path}: {e}")
            return jsonify({'error': 'Forensic pipeline analysis failed'}), 500
            
    except Exception as e:
        return jsonify({'error': f"Server upload error: {str(e)}"}), 500

@app.route('/api/monitor/start', methods=['POST'])
def api_monitor_start():
    data = request.json or {}
    path = data.get('path', '')
    if not path:
        return jsonify({'error': 'Path is required'}), 400
        
    success, msg = monitor_daemon.start(path)
    if success:
        metrics_exporter.update_monitor_state(True)
        return jsonify({'message': msg}), 200
    else:
        return jsonify({'error': msg}), 400

@app.route('/api/monitor/stop', methods=['POST'])
def api_monitor_stop():
    success, msg = monitor_daemon.stop()
    if success:
        metrics_exporter.update_monitor_state(False)
        return jsonify({'message': msg}), 200
    else:
        return jsonify({'error': msg}), 400

@app.route('/api/monitor/status', methods=['GET'])
def api_monitor_status():
    return jsonify(monitor_daemon.get_status()), 200

@app.route('/api/monitor/logs', methods=['GET'])
def api_monitor_logs():
    return jsonify({'logs': monitor_daemon.get_logs()}), 200

@app.route('/api/evidence', methods=['GET'])
def api_evidence_list():
    return jsonify(db_manager.get_all_evidence()), 200

@app.route('/api/evidence/<int:evidence_id>', methods=['GET'])
def api_evidence_detail(evidence_id):
    evidence = db_manager.get_evidence_by_id(evidence_id)
    if evidence:
        return jsonify(evidence), 200
    return jsonify({'error': 'Evidence record not found'}), 404

@app.route('/api/evidence/<int:evidence_id>', methods=['DELETE'])
def api_evidence_delete(evidence_id):
    evidence = db_manager.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({'error': 'Evidence record not found'}), 404
        
    try:
        # Delete from DB
        conn = db_manager.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM evidence WHERE id = ?', (evidence_id,))
        conn.commit()
        conn.close()
        
        # Delete vault file if exists
        vault_path = evidence.get('filepath', '')
        if vault_path and VAULT_FOLDER in vault_path and os.path.exists(vault_path):
            os.remove(vault_path)
            
        return jsonify({'message': 'Evidence deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f"Failed to delete evidence: {str(e)}"}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if request.method == 'GET':
        return jsonify(db_manager.get_all_settings()), 200
    else:
        data = request.json or {}
        for k, v in data.items():
            db_manager.set_setting(k, v)
        return jsonify({'message': 'Settings updated successfully', 'settings': db_manager.get_all_settings()}), 200

@app.route('/api/stats', methods=['GET'])
def api_stats():
    return jsonify(db_manager.get_stats()), 200

@app.route('/metrics', methods=['GET'])
def api_metrics():
    """Endpoint for Prometheus metric scrapers."""
    data, content_type = metrics_exporter.export_metrics()
    return data, 200, {'Content-Type': content_type}

# Startup hook to resume monitoring if path was active
@app.before_request
def resume_monitoring_on_first_load():
    app.before_request_funcs[None].remove(resume_monitoring_on_first_load)
    try:
        paths = db_manager.get_monitored_paths()
        for p in paths:
            if p['active'] == 1:
                success, msg = monitor_daemon.start(p['path'])
                if success:
                    metrics_exporter.update_monitor_state(True)
                    print(f"Resumed real-time monitoring on startup for: {p['path']}")
    except Exception as e:
        print(f"Failed to resume monitoring paths: {e}")

if __name__ == '__main__':
    # Start on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
