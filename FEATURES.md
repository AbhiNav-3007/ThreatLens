# 📊 ThreatLens Technical Features & Roadmap

Welcome to the technical feature ledger of the **ThreatLens Digital Forensics and Malware Analysis Platform**. This document details our multi-layered detection layers, data custody schemas, and active development roadmap.

---

## 🚀 Active Platform Features

### 🔍 1. Tri-Layer Analysis Pipeline
ThreatLens scans files using three independent, concurrent layers of security telemetry:

| Layer | Technical Engine | Scope | Key Identifiers |
| :--- | :--- | :--- | :--- |
| **Layer 1: Structural ML** | Random Forest (EMBER-trained) | Windows PE (`.exe`, `.dll`) | Compiler characteristics, Section entropy, Stack size |
| **Layer 2: Static Signature** | YARA Rule Compiler | All Files (Scripts, Archives) | Shellcode APIs, reverse shells, obfuscation triggers |
| **Layer 3: Global Intel** | VirusTotal V2 HTTP API | Cryptographic Hashes (SHA-256) | Vendor reputation counts, scan dates |

> [!TIP]
> **Composite Scoring Logic**: The final Threat Score ($S_{threat}$) is calculated dynamically:
> $$S_{threat} = \text{Score}_{ML} \ (40\%) + \text{Score}_{YARA} \ (30\%) + \text{Score}_{VT} \ (30\%)$$
> This composite model scales from `0` to `100`, classifying files into **Safe** (green), **Suspicious** (amber), or **Malicious** (red) risk levels.

---

### 📂 2. Real-Time Watcher Node
An automated folder observer powered by native OS filesystem signals:
*   **Recursive Watchers**: Watches target directories and subdirectories dynamically.
*   **Thread-Safe Task Queue**: Uses Python's `queue.Queue` to coordinate analysis requests, ensuring that multiple rapid file drops do not lock up the Flask application thread.
*   **Interactive Terminal Console**: Streams event timestamps and detection telemetry directly to the web dashboard in real time.

---

### 🏛️ 3. Evidence Archiving & Chain-of-Custody
ThreatLens is built to preserve evidence for legal or organizational forensic audits:
*   **SQLite Ledger**: Saves file paths, MD5/SHA-1/SHA-256 hashes, file sizes, creation times, and analysis metrics in a structured local database ([forensics.db](file:///d:/STUDY%20MATERIAL/PROJECTS/Digital%20forensics%20project/Malware%20detection%20and%20digital%20forensics%20platform%20using%20ML/forensics.db)).
*   **SHA-256 Vault Renaming**: Flags and archives threats in an isolated `evidence_vault/` directory, renaming them to their SHA-256 hash value to prevent duplication and preserve integrity.

---

### 📝 4. AI-Powered Forensic Investigator
Generates professional-grade reports using a customizable LLM pipeline:
*   **Ollama Native integration**: Connects locally to offline models (e.g. `llama3` or `deepseek-coder`).
*   **Cloud Integrations**: Supports **Google Gemini API** (`gemini-1.5-flash`) and **OpenAI API** endpoints.
*   **Expert System Fallback**: Generates reports offline via a local rule-based expert parser if no LLM is configured.

---

### 📈 5. Observability Telemetry
*   Exposes system indicators (scans processed, average risk scores, zero-day threat speed) at the `/metrics` endpoint.
*   Compatible with **Prometheus** scraper daemons and **Grafana** visualization dashboards.

---

## 🔮 Future Development Roadmap

### 🧱 1. Dynamic Sandboxing (Behavioral Scan)
> [!IMPORTANT]
> *Executing files in a secure container to monitor system changes.*
*   **Registry Monitor**: Track keys created, modified, or deleted.
*   **File Monitor**: Monitor files dropped into system directories.
*   **Network Capture**: Log all outgoing DNS/TCP requests and save them as standard PCAP logs.

### ✂️ 2. Content Disarm & Reconstruction (CDR)
*   **Image Stripping**: Automatically clean EXIF metadata tags from incoming PNG/JPEG files.
*   **PDF Sanitizer**: Inspect and delete active objects like `/JavaScript` or `/OpenAction`.
*   **Office Macro Sanitizer**: Programmatically remove `vbaProject.bin` from MS Office packages.

### 🖼️ 3. Grayscale Binary-to-Image ML
*   Convert any file format (PDF, DOCX, EXE) to a 2D grayscale image.
*   Implement a **Convolutional Neural Network (CNN)** (e.g., ResNet-18) to identify malware families based on visual textures.
