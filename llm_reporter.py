import os
import requests
import json
import time
import db_manager

def get_gemini_api_key():
    """Load Gemini API Key directly from .env in the project directory."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        if k.strip() == 'GEMINI_API_KEY':
                            return v.strip().strip('"').strip("'")
        except Exception as e:
            print(f"Error reading .env file: {e}")
    return ''

def get_openai_api_key():
    """Load OpenAI API Key directly from .env in the project directory."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        if k.strip() == 'OPENAI_API_KEY':
                            return v.strip().strip('"').strip("'")
        except Exception as e:
            print(f"Error reading .env file: {e}")
    return ''

def generate_report(evidence):
    """Generates a forensic investigation report.
    Attempts local LLM (Ollama or OpenAI-compatible) or cloud Gemini; falls back to Expert Rules System if offline.
    """
    llm_provider = db_manager.get_setting('llm_provider', 'ollama').strip().lower()
    llm_url = db_manager.get_setting('llm_url', 'http://localhost:11434')
    llm_model = db_manager.get_setting('llm_model', 'llama3')
    
    # Formulate Prompt
    prompt = f"""You are a senior Digital Forensics and Malware Analyst. 
Generate a comprehensive, professional Forensic Investigation Report based on the following security telemetry:

### Telemetry Details:
- File Name: {evidence['filename']}
- File Path: {evidence['filepath']}
- File Size: {evidence['filesize']} bytes
- Creation Time: {evidence['creation_time']}
- MD5: {evidence['md5']}
- SHA1: {evidence['sha1']}
- SHA256: {evidence['sha256']}
- File Type: {evidence['file_type']}
- Machine Learning (Random Forest PE Header): {evidence['ml_prediction']} (Confidence: {evidence['ml_confidence']:.2f})
- YARA Rule Matches: {evidence['yara_matches']}
- VirusTotal: {evidence.get('vt_positives', 'N/A')} positive detections out of {evidence.get('vt_total', 'N/A')} engines (Status: {evidence.get('vt_status', 'N/A')})
- Overall Threat Score: {evidence['threat_score']} / 100
- Assigned Risk Level: {evidence['risk_level']}

Your report MUST be written in structured markdown and include these exact headers:
# FORENSIC INVESTIGATION REPORT

## 1. Executive Summary
Provide a high-level summary of the threat level, what type of file was scanned, and a brief conclusion on whether it presents an active threat.

## 2. Evidence Acquisition & Hash Ledger
Display the metadata and cryptographic hashes in a clean format for chain-of-custody tracking.

## 3. Telemetry Correlation Analysis
Analyze the findings from the three layers:
- ML structural PE features
- YARA static signatures
- VirusTotal reputation reputation
Correlate why these metrics led to the Threat Score of {evidence['threat_score']}.

## 4. Attack Vector & Structural Threat Assessment
Explain what kinds of malicious behaviors this file might perform (e.g. process injection, downloader cradle, packing, or stealer routines) based on the findings.

## 5. Containment & Remediation Recommendations
List concrete, actionable steps for a security response team to isolate the threat, conduct host forensics, and clean up.

Write the report in a neutral, authoritative, forensic investigator tone. Return ONLY the markdown report.
"""
    
    # 1. Google Gemini Cloud API
    if llm_provider == 'gemini':
        api_key = get_gemini_api_key()
        if not api_key or api_key == 'your_gemini_api_key_here':
            print("Gemini API key is missing or placeholder in .env. Falling back to Expert Rules System...")
            return generate_expert_fallback_report(evidence)
            
        model_name = llm_model if llm_model else 'gemini-1.5-flash'
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ]
        }
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                res_data = response.json()
                if 'candidates' in res_data and len(res_data['candidates']) > 0:
                    candidate = res_data['candidates'][0]
                    if 'content' in candidate and 'parts' in candidate['content'] and len(candidate['content']['parts']) > 0:
                        report_text = candidate['content']['parts'][0].get('text', '')
                        if report_text:
                            return report_text.strip()
            print(f"Gemini query returned status {response.status_code}: {response.text}")
        except Exception as e:
            print(f"Gemini API query failed: {e}. Falling back to Expert Rules System...")
            
    # 2. Ollama Native API (Local Default)
    elif llm_provider == 'ollama':
        endpoint = f"{llm_url}/api/generate"
        payload = {
            "model": llm_model,
            "prompt": prompt,
            "stream": False
        }
        try:
            response = requests.post(endpoint, json=payload, timeout=15)
            if response.status_code == 200:
                result = response.json()
                report_text = result.get('response', '')
                if report_text:
                    return report_text.strip()
        except Exception as e:
            print(f"Ollama local query failed (offline or model missing): {e}. Falling back to Expert Rules System...")

    # 3. OpenAI or OpenAI-Compatible APIs (LM Studio, llama.cpp, Custom Endpoint, etc.)
    else:
        # Construct endpoint. Ensure proper path endings
        base_url = llm_url.rstrip('/')
        if not base_url.endswith('/v1') and not base_url.endswith('/chat/completions'):
            endpoint = f"{base_url}/v1/chat/completions"
        elif base_url.endswith('/v1'):
            endpoint = f"{base_url}/chat/completions"
        else:
            endpoint = base_url
            
        api_key = get_openai_api_key() or "dummy-local-key"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        payload = {
            "model": llm_model,
            "messages": [
                {"role": "system", "content": "You are a senior Digital Forensics and Malware Analyst."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }
        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    report_text = result['choices'][0]['message'].get('content', '')
                    if report_text:
                        return report_text.strip()
            print(f"OpenAI-compatible server returned status {response.status_code}: {response.text}")
        except Exception as e:
            print(f"OpenAI-compatible server query failed: {e}. Falling back to Expert Rules System...")

    return generate_expert_fallback_report(evidence)

def generate_expert_fallback_report(evidence):
    """Fallback generator that mimics a highly skilled forensic expert using rules."""
    fn = evidence['filename']
    fp = evidence['filepath']
    size = evidence['filesize']
    ct = evidence['creation_time']
    md5 = evidence['md5']
    sha1 = evidence['sha1']
    sha256 = evidence['sha256']
    ft = evidence['file_type']
    ml_pred = evidence['ml_prediction']
    ml_conf = evidence['ml_confidence']
    yara = evidence['yara_matches']
    vt_pos = evidence.get('vt_positives')
    vt_tot = evidence.get('vt_total')
    score = evidence['threat_score']
    risk = evidence['risk_level']
    vt_status = evidence.get('vt_status', 'unconfigured')

    # Executive Summary text builder
    if risk == "Malicious":
        summary_text = f"CRITICAL THREAT DETECTED. The file `{fn}` has been classified as **{risk}** with a threat score of **{score}/100**. The multi-layer pipeline detected strong malicious characteristics. Immediate containment is highly recommended."
    elif risk == "Suspicious":
        summary_text = f"SUSPICIOUS ACTIVITY IDENTIFIED. The file `{fn}` exhibits structural or signature patterns commonly seen in threats. It has been assigned a risk level of **{risk}** (Score: **{score}/100**). Further manual inspection is advised."
    else:
        summary_text = f"FILE CLASSIFIED AS SAFE. No significant threat indicators were found in the file `{fn}`. It has been assigned a risk level of **{risk}** (Score: **{score}/100**). It appears to be a legitimate file or a low-risk executable."

    # ML Analysis text builder
    if "N/A" in ml_pred:
        ml_analysis = "The Machine Learning classifier was not executed on this file because it is not a Portable Executable (PE) file. The classifier is specifically trained on PE headers (EXEs and DLLs) to identify zero-day compilation features."
    else:
        ml_analysis = f"The Random Forest model analyzed the binary's PE headers and predicted the file as **{ml_pred}** with a classification confidence of **{ml_conf*100:.1f}%**. "
        if ml_pred == "Malware":
            ml_analysis += "This indicates that the compiler headers, section layouts, and DllCharacteristics closely align with known malware clusters, signifying a potential zero-day payload bypassing traditional signatures."
        else:
            ml_analysis += "The structural headers appear typical of standard benign Windows compilations."

    # YARA Analysis text builder
    if yara:
        yara_analysis = f"YARA signature analysis matched **{len(yara)}** rule(s): **{', '.join(yara)}**. "
        for rule in yara:
            if rule == "UPX_Packed":
                yara_analysis += "\n- **UPX_Packed**: The file is compressed using the UPX packer, a technique frequently used by malware to obfuscate code and delay analysis."
            elif rule == "Suspicious_Process_Injection_APIs":
                yara_analysis += "\n- **Suspicious_Process_Injection_APIs**: Code imports APIs such as VirtualAllocEx or WriteProcessMemory, which are core components of process hollowing or DLL injection techniques."
            elif rule == "Obfuscated_Powershell_Download":
                yara_analysis += "\n- **Obfuscated_Powershell_Download**: Script content contains obfuscated PowerShell strings indicating silent downloads and hidden execution."
            elif rule == "Cryptographic_Stealer_Activity":
                yara_analysis += "\n- **Cryptographic_Stealer_Activity**: Reference to localized browser paths or crypto wallet files indicating credential harvesting behavior."
            elif rule == "Reverse_Shell_Strings":
                yara_analysis += "\n- **Reverse_Shell_Strings**: Contains socket and command-line shell invocation patterns indicating backdoor beaconing."
    else:
        yara_analysis = "YARA signature scanning returned **no matches**. None of the static indicators for common backdoors, packers, or downloaders matched the binary's sections or byte structures."

    # VirusTotal Analysis text builder
    if vt_status == "unconfigured":
        vt_analysis = "VirusTotal verification was **bypassed** because the API key is not configured in the settings. External reputation threat indicators were skipped."
    elif vt_status == "success":
        if vt_pos > 0:
            vt_analysis = f"VirusTotal reputation matching returned **{vt_pos} / {vt_tot}** positive vendor detections. This indicates that this threat has already been registered and identified by external antivirus engines, validating it as a known threat."
        else:
            vt_analysis = "VirusTotal reputation matching returned **0 positive detections**. The file hash is clean in the database or represent a new, unindexed variant, supporting the zero-day threat hypothesis."
    elif vt_status == "not_found":
        vt_analysis = "VirusTotal did not find this file hash in its database (0/0 engines). This suggests the file has never been submitted to public repositories, which is typical for zero-day malware or custom payloads."
    else:
        vt_analysis = f"VirusTotal integration returned status: `{vt_status}`. The query could not be completed successfully (possibly due to network timeout or rate limits)."

    # Threat Characterization & Attack Vector
    attack_vector = ""
    if risk == "Malicious":
        attack_vector = "Given the telemetry, this file constitutes a high-risk security hazard. "
        if "UPX_Packed" in yara:
            attack_vector += "It utilizes packing techniques to bypass endpoint detection and response (EDR). "
        if "Suspicious_Process_Injection_APIs" in yara or ml_pred == "Malware":
            attack_vector += "It contains features typical of process hollowing, meaning it intends to spawn a legitimate process (like svchost.exe) and inject malicious code into its memory space. "
        if not attack_vector.endswith("hazard. "):
            pass
        else:
            attack_vector += "The binary characteristics point to an active payload delivery mechanism designed to compromise local system integrity."
    elif risk == "Suspicious":
        attack_vector = "The file exhibits minor anomalies. If it is an executable, it contains unusual compilation timestamps, section counts, or minor signature matches. It could represent a suspicious download or a packed administrative tool."
    else:
        attack_vector = "No malicious attack vectors were identified. The file structure reflects standard compiler layouts and follows benign operational paradigms."

    # Containment & Remediation Recommendations
    if risk == "Malicious":
        recommendations = """1. **Isolate Host**: Instantly isolate the affected system from the local network to prevent potential lateral movement.
2. **Block File Hash**: Add the SHA256 hash (`{sha256}`) to the endpoint security (EDR) block list.
3. **Capture Memory**: Take a volatile RAM capture of the host if the file was executed, to scan for active memory injection.
4. **Inspect Source Location**: Analyze the folder monitoring source path (`{fp}`) to see how the file arrived (e.g. browser logs, email headers).
5. **Delete/Quarantine File**: Move the file to a secure quarantine directory or delete it if authorized."""
    elif risk == "Suspicious":
        recommendations = """1. **Inspect Section Headers**: Run a PE viewer to inspect section names and imports manually.
2. **Execute in Sandbox**: Run the file inside an isolated, non-networked sandbox env to watch for process spawns and API calls.
3. **Monitor Host Actions**: Keep the host under monitoring to check for unauthorized network requests or registry alterations."""
    else:
        recommendations = """1. **Standard Logging**: Maintain normal audit logging. No security alerts or escalations are required.
2. **Whitelist**: If this file is part of a custom internal deployment, whitelist the SHA256 hash to avoid false positive triggers in the future."""

    # Assemble report
    report = f"""# FORENSIC INVESTIGATION REPORT

> **Generated by**: Digital Forensics Expert System (Ollama llama3 Offline Fallback)
> **Scan Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. Executive Summary
{summary_text}

---

## 2. Evidence Acquisition & Hash Ledger
| Property | Value |
| :--- | :--- |
| **File Name** | `{fn}` |
| **Monitored Path** | `{fp}` |
| **File Size** | `{size:,} Bytes` |
| **Creation Date** | `{ct}` |
| **File Type** | `{ft}` |
| **MD5 Hash** | `{md5}` |
| **SHA1 Hash** | `{sha1}` |
| **SHA256 Hash** | `{sha256}` |

---

## 3. Telemetry Correlation Analysis
### A. Machine Learning Layer
{ml_analysis}

### B. Static YARA Signatures
{yara_analysis}

### C. External Reputation (VirusTotal)
{vt_analysis}

---

## 4. Attack Vector & Structural Threat Assessment
{attack_vector}

---

## 5. Containment & Remediation Recommendations
{recommendations.format(sha256=sha256, fp=fp)}
"""
    return report
