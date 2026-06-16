# Contributing to ThreatLens

Welcome! We appreciate contributions from the cybersecurity and software engineering communities. Here is a quick guide on how to get started.

---

## 🔮 Active Roadmap (Where to Help)

We welcome contributions in the following roadmap areas:
1.  **Dynamic Sandboxing**: Run files in secure containers and capture system/network logs (PCAP).
2.  **File Sanitizers (CDR)**: Strip EXIF metadata from images, `/JavaScript` objects from PDFs, and VBA macros from Word/PowerPoint zip packages.
3.  **Grayscale ML Classification**: Build a pipeline mapping file bytes to grayscale images for CNN malware family classification.
4.  **Role-Based Access Control (RBAC)**: Secure the Flask backend APIs (`/api/settings` and `DELETE` requests) using JWT authentication.

---

## 🛠️ Developer Workflow

1.  Fork the repository and clone it locally.
2.  Create your feature branch:
    ```bash
    git checkout -b feature/your-feature-name
    ```
3.  Implement and test your changes.
4.  Commit using **Semantic Messages** (e.g. `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `ops:`).
5.  Open a Pull Request describing your changes.

---

## 📝 Commit Example
```bash
git add forensic_pipeline.py
git commit -m "feat: add PDF JavaScript disarmer module"
```

## 🎨 Code Standards
*   **Python**: Follow PEP 8 guidelines. Document functions cleanly.
*   **Security**: Always sanitize incoming file paths using `secure_filename`.
*   **UI/UX**: Keep styles consistent with the glassmorphism color palette.
