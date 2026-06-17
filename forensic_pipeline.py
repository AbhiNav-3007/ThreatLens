import os
import hashlib
import math
import mimetypes
import time
import json
import joblib
import pandas as pd
import pefile
import requests
from datetime import datetime

import db_manager

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'ml_model', 'malwareclassifier-V2.pkl')
YARA_RULES_PATH = os.path.join(BASE_DIR, 'yara_rules', 'forensic_rules.yar')

# Try importing YARA with a custom Python fallback
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    print("WARNING: yara-python not installed or failed to load. Using built-in regex fallback.")

# Load the ML Model on startup
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("ML Model loaded successfully.")
    except Exception as e:
        print(f"ERROR: Failed to load ML model: {e}")
else:
    print(f"WARNING: ML Model not found at {MODEL_PATH}")

# List of features expected by the ML model (23 features)
ML_FEATURE_NAMES = [
    'MajorLinkerVersion', 'MinorOperatingSystemVersion', 'MajorSubsystemVersion', 
    'SizeOfStackReserve', 'TimeDateStamp', 'MajorOperatingSystemVersion', 
    'Characteristics', 'ImageBase', 'Subsystem', 'MinorImageVersion', 
    'MinorSubsystemVersion', 'SizeOfInitializedData', 'DllCharacteristics', 
    'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'CheckSum', 
    'DirectoryEntryImportSize', 'SectionMaxChar', 'MajorImageVersion', 
    'AddressOfEntryPoint', 'SectionMinEntropy', 'SizeOfHeaders', 
    'SectionMinVirtualsize'
]

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def detect_file_type(file_path):
    """Detect file type by checking magic bytes first, fallback to extension."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            
        if header.startswith(b'MZ'):
            return "Windows Executable (PE)"
        elif header.startswith(b'\x7fELF'):
            return "Linux Executable (ELF)"
        elif header.startswith(b'PK\x03\x04'):
            return "ZIP Archive / OpenXML Document"
        elif header.startswith(b'%PDF'):
            return "PDF Document"
        elif header.startswith(b'\x89PNG\r\n\x1a\n'):
            return "PNG Image"
        elif header.startswith(b'\xff\xd8\xff'):
            return "JPEG Image"
        elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
            return "GIF Image"
        elif header.startswith(b'BM'):
            return "BMP Image"
    except Exception:
        pass

    # Fallback to extension
    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type:
        return mime_type
    
    _, ext = os.path.splitext(file_path)
    if ext:
        return f"{ext[1:].upper()} File"
    return "Unknown Binary"

def calculate_hashes(file_path):
    """Calculate MD5, SHA-1, and SHA-256 hashes of a file."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read in blocks of 64KB
        for byte_block in iter(lambda: f.read(65536), b""):
            md5_hash.update(byte_block)
            sha1_hash.update(byte_block)
            sha256_hash.update(byte_block)
            
    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()

def extract_pe_features(file_path):
    """Extract exactly the 23 PE features needed for the Random Forest model."""
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error parsing PE file {file_path}: {e}")
        return None

    # Base features dictionary
    features = {
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'DirectoryEntryExport': 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
        'ImageDirectoryEntryExport': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'DirectoryEntryImportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
        'SectionMaxChar': len(pe.sections),
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'SectionMinEntropy': 0.0,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'SectionMinVirtualsize': 0
    }

    # Calculate SectionMinEntropy
    entropies = []
    for section in pe.sections:
        try:
            entropy = calculate_entropy(section.get_data())
            entropies.append(entropy)
        except Exception:
            pass

    if entropies:
        features['SectionMinEntropy'] = min(entropies)

    # Calculate SectionMinVirtualsize
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections if section.Misc_VirtualSize > 0]
    if virtual_sizes:
        features['SectionMinVirtualsize'] = min(virtual_sizes)
    else:
        features['SectionMinVirtualsize'] = 0

    # Explicitly project columns in exact order
    df = pd.DataFrame([features])
    df = df[ML_FEATURE_NAMES]
    
    # Close PE file object to release handle
    pe.close()
    
    return df

def run_ml_prediction(file_path):
    """Predicts malware using the loaded Random Forest model."""
    if model is None:
        return "N/A (Model Unloaded)", 0.0
        
    try:
        # Features can only be extracted from PE files (EXE, DLL)
        features_df = extract_pe_features(file_path)
        if features_df is None:
            return "N/A (Not PE File)", 0.0
            
        prediction = model.predict(features_df)
        probabilities = model.predict_proba(features_df)
        
        predicted_class = "Malware" if prediction[0] == 1 else "Safe"
        confidence = float(probabilities[0][1]) if predicted_class == "Malware" else float(probabilities[0][0])
        
        return predicted_class, confidence
    except Exception as e:
        print(f"ML analysis error: {e}")
        return "N/A (Analysis Error)", 0.0

def fallback_yara_scan(file_path):
    """Fallback text signature matching if yara-python cannot load."""
    matched_rules = []
    try:
        # Read the file rules first to parse signatures
        if not os.path.exists(YARA_RULES_PATH):
            return matched_rules
            
        with open(YARA_RULES_PATH, 'r') as rf:
            rules_content = rf.read()
            
        # Read target file contents
        with open(file_path, 'rb') as f:
            file_data = f.read()
            
        # Parse basic rules by looking for strings block
        # We search for the specific strings defined in forensic_rules.yar
        signatures = {
            "UPX_Packed": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
            "Suspicious_Process_Injection_APIs": [
                b"VirtualAllocEx", b"WriteProcessMemory", 
                b"CreateRemoteThread", b"QueueUserAPC", b"SetThreadContext"
            ],
            "Obfuscated_Powershell_Download": [
                b"powershell", b"-nop", b"-w hidden", b"DownloadString", 
                b"DownloadFile", b"iex", b"bypass"
            ],
            "Cryptographic_Stealer_Activity": [
                b"wallet.dat", b"Local Extension Settings", b"Login Data", 
                b"Web Data", b"Appdata\\Local\\Temp"
            ],
            "Reverse_Shell_Strings": [
                b"/bin/sh", b"/bin/bash", b"cmd.exe /c", b"socket.socket", 
                b"connect((", b"WSAStartup"
            ]
        }
        
        # Perform matches
        for rule_name, sig_list in signatures.items():
            match_count = 0
            for sig in sig_list:
                # Case insensitive search where appropriate
                if sig.lower() in file_data.lower():
                    match_count += 1
            
            # Match condition triggers
            if rule_name == "UPX_Packed" and match_count > 0:
                matched_rules.append(rule_name)
            elif rule_name == "Suspicious_Process_Injection_APIs" and match_count >= 3:
                matched_rules.append(rule_name)
            elif rule_name == "Obfuscated_Powershell_Download" and match_count >= 4:
                matched_rules.append(rule_name)
            elif rule_name == "Cryptographic_Stealer_Activity" and match_count >= 3:
                matched_rules.append(rule_name)
            elif rule_name == "Reverse_Shell_Strings" and match_count >= 2:
                matched_rules.append(rule_name)
                
    except Exception as e:
        print(f"Fallback YARA error: {e}")
        
    return matched_rules

def run_yara_scan(file_path):
    """Scans the file using YARA rules."""
    if not YARA_AVAILABLE or not os.path.exists(YARA_RULES_PATH):
        return fallback_yara_scan(file_path)
        
    try:
        rules = yara.compile(YARA_RULES_PATH)
        matches = rules.match(file_path)
        return [m.rule for m in matches]
    except Exception as e:
        print(f"YARA matching error: {e}. Executing fallback scanner.")
        return fallback_yara_scan(file_path)

def get_virustotal_api_key():
    """Load API Key directly from .env in the project directory."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        if k.strip() == 'VIRUSTOTAL_API_KEY':
                            return v.strip().strip('"').strip("'")
        except Exception as e:
            print(f"Error reading .env file: {e}")
    return ''

def query_virustotal(file_hash):
    """Check VirusTotal V2 report for file hash. Gracefully bypasses if unconfigured/offline."""
    api_key = get_virustotal_api_key()
    if not api_key or api_key == 'your_virustotal_api_key_here':
        # Bypassed - not integrated
        return None, None, "unconfigured"
        
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_hash}
    
    try:
        # Bounded 8s timeout to prevent hanging the scan
        response = requests.get(url, params=params, timeout=8)
        if response.status_code == 204:
            # Rate limit exceeded
            return None, None, "rate_limited"
        if response.status_code != 200:
            return None, None, "failed_request"
            
        result = response.json()
        if result.get('response_code') == 1:
            positives = result.get('positives', 0)
            total = result.get('total', 0)
            return positives, total, "success"
        else:
            return 0, 0, "not_found"
    except Exception as e:
        print(f"VirusTotal query failed/timed out: {e}")
        return None, None, "error"

def calculate_threat_score(ml_pred, ml_conf, yara_matches, vt_pos, vt_total, vt_status):
    """Calculates threat score (0-100) and risk level."""
    # 1. Machine Learning Score (max 40)
    ml_score = 0.0
    if ml_pred == "Malware":
        ml_score = ml_conf * 40.0
    elif ml_pred == "Safe":
        ml_score = (1.0 - ml_conf) * 10.0 # Small suspicion if confidence is super low

    # 2. YARA Score (max 30)
    yara_score = 0.0
    if yara_matches:
        yara_score = min(30.0, len(yara_matches) * 15.0)

    # 3. VirusTotal Score (max 30)
    vt_score = 0.0
    vt_active = False
    
    if vt_status == "success" and vt_total is not None and vt_total > 0:
        vt_active = True
        vt_score = (vt_pos / vt_total) * 30.0
        # Boost score significantly if multiple engines flag it
        if vt_pos > 2:
            vt_score = max(vt_score, 20.0)
        if vt_pos > 5:
            vt_score = 30.0

    # Calculate final score and normalize if VT is bypassed
    if vt_active:
        total_score = ml_score + yara_score + vt_score
        final_score = int(round(total_score))
    else:
        # Scale score from 70 maximum up to 100
        raw_score = ml_score + yara_score
        final_score = int(round((raw_score / 70.0) * 100.0))
        
    final_score = max(0, min(100, final_score))
    
    # Classify Risk Level
    if final_score >= 60:
        risk_level = "Malicious"
    elif final_score >= 20:
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"
        
    return final_score, risk_level

def run_analysis_pipeline(file_path):
    """Runs the entire analysis flow on a file and stores it in the database."""
    if not os.path.exists(file_path):
        print(f"Error: Target file {file_path} does not exist.")
        return None
        
    try:
        # 1. Evidence Acquisition
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        creation_epoch = os.path.getctime(file_path)
        creation_time = datetime.fromtimestamp(creation_epoch).strftime('%Y-%m-%d %H:%M:%S')
        file_type = detect_file_type(file_path)
        
        # 2. Hash Generation
        md5_val, sha1_val, sha256_val = calculate_hashes(file_path)
        
        # 3. Machine Learning Analysis
        ml_pred, ml_conf = run_ml_prediction(file_path)
        
        # 4. YARA Signature Analysis
        yara_matches = run_yara_scan(file_path)
        
        # 5. VirusTotal Verification
        vt_pos, vt_total, vt_status = query_virustotal(sha256_val)
        
        # 6. Threat Scoring
        threat_score, risk_level = calculate_threat_score(
            ml_pred, ml_conf, yara_matches, vt_pos, vt_total, vt_status
        )
        
        # Prepare evidence dataset
        evidence_data = {
            'filename': filename,
            'filepath': file_path,
            'filesize': filesize,
            'creation_time': creation_time,
            'sha256': sha256_val,
            'md5': md5_val,
            'sha1': sha1_val,
            'file_type': file_type,
            'ml_prediction': ml_pred,
            'ml_confidence': ml_conf,
            'yara_matches': yara_matches,
            'vt_positives': vt_pos,
            'vt_total': vt_total,
            'threat_score': threat_score,
            'risk_level': risk_level,
            'ai_report': 'Generating report...'
        }
        
        # Insert evidence row
        inserted_id = db_manager.insert_evidence(evidence_data)
        evidence_data['id'] = inserted_id
        evidence_data['vt_status'] = vt_status
        
        # Trigger LLM report in background (or synchronous if needed)
        # Note: We import here to avoid circular imports
        import llm_reporter
        ai_report_content = llm_reporter.generate_report(evidence_data)
        
        # Update record in DB with completed AI report
        db_manager.update_evidence_ai_report(inserted_id, ai_report_content)
        
        evidence_data['ai_report'] = ai_report_content
        return evidence_data
        
    except Exception as e:
        print(f"Failed to execute forensic analysis pipeline: {e}")
        import traceback
        traceback.print_exc()
        return None
