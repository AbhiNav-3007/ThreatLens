document.addEventListener('DOMContentLoaded', () => {
    // --- State Variables ---
    let activeTab = 'dashboard';
    let monitorInterval = null;
    let riskChart = null;
    let timelineChart = null;
    let currentEvidence = null; // Store currently viewed evidence item
    let scanAbortController = null;
    
    // --- DOM Elements ---
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const pageTitle = document.getElementById('page-title');
    const pageSubtitle = document.getElementById('page-subtitle');
    
    // --- Notification Helper ---
    function showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        let icon = 'fa-circle-info';
        if (type === 'success') icon = 'fa-circle-check';
        if (type === 'warning') icon = 'fa-triangle-exclamation';
        if (type === 'error') icon = 'fa-circle-exclamation';
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <i class="fa-solid ${icon}"></i>
                <span>${message}</span>
            </div>
            <button onclick="this.parentElement.remove()"><i class="fa-solid fa-xmark"></i></button>
        `;
        
        container.appendChild(notification);
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }

    // --- Tab Navigation Router ---
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });

    function switchTab(tabId) {
        activeTab = tabId;
        
        // Update Sidebar items
        navItems.forEach(nav => {
            if (nav.getAttribute('data-tab') === tabId) {
                nav.classList.add('active');
            } else {
                nav.classList.remove('active');
            }
        });
        
        // Update View Panels
        tabPanes.forEach(pane => {
            if (pane.id === `tab-${tabId}`) {
                pane.classList.add('active');
            } else {
                pane.classList.remove('active');
            }
        });

        // Clear folder monitor polling if leaving monitor tab
        if (tabId !== 'monitor') {
            if (monitorInterval) {
                clearInterval(monitorInterval);
                monitorInterval = null;
            }
        }
        
        // Load Tab-specific data
        if (tabId === 'dashboard') {
            pageTitle.textContent = "Operational Dashboard";
            pageSubtitle.textContent = "Platform overview and threat monitoring telemetry.";
            loadDashboardStats();
        } else if (tabId === 'scanner') {
            pageTitle.textContent = "Manual Threat Scanner";
            pageSubtitle.textContent = "Submit individual files to the multi-layer analysis pipeline.";
        } else if (tabId === 'monitor') {
            pageTitle.textContent = "Folder Monitor Node";
            pageSubtitle.textContent = "Configure and observe real-time directory security watchers.";
            loadMonitorStatus();
            // Start polling monitor logs
            monitorInterval = setInterval(loadMonitorLogs, 2000);
        } else if (tabId === 'vault') {
            pageTitle.textContent = "Forensic Evidence Vault";
            pageSubtitle.textContent = "Query preserved digital evidence and chain of custody data.";
            loadVaultEvidence();
        } else if (tabId === 'settings') {
            pageTitle.textContent = "Platform settings";
            pageSubtitle.textContent = "Manage threat intelligence integrations and AI reporter parameters.";
            loadSettings();
        }
    }

    // --- Settings handling ---
    function loadSettings() {
        fetch('/api/settings')
            .then(res => res.json())
            .then(settings => {
                document.getElementById('setting-llm-provider').value = settings.llm_provider || 'ollama';
                document.getElementById('setting-llm-url').value = settings.llm_url || '';
                document.getElementById('setting-llm-model').value = settings.llm_model || '';
            })
            .catch(err => {
                console.error("Error loading settings:", err);
                showNotification("Failed to load configuration settings.", "error");
            });
    }

    document.getElementById('btn-save-settings').addEventListener('click', () => {
        const llmProvider = document.getElementById('setting-llm-provider').value;
        const llmUrl = document.getElementById('setting-llm-url').value;
        const llmModel = document.getElementById('setting-llm-model').value;
        
        fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                llm_provider: llmProvider,
                llm_url: llmUrl,
                llm_model: llmModel
            })
        })
        .then(res => res.json())
        .then(res => {
            showNotification("Configuration settings updated successfully.", "success");
        })
        .catch(err => {
            console.error("Error saving settings:", err);
            showNotification("Failed to update configurations.", "error");
        });
    });

    // --- Dashboard logic & Charts ---
    function loadDashboardStats() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => {
                // Update KPI Cards
                document.getElementById('stat-total').textContent = stats.total_scans;
                document.getElementById('stat-malicious').textContent = stats.malicious;
                document.getElementById('stat-suspicious').textContent = stats.suspicious;
                document.getElementById('stat-zerodays').textContent = stats.zero_days;
                
                const avgScore = stats.avg_score;
                const scoreVal = document.getElementById('stat-avgscore');
                scoreVal.textContent = avgScore.toFixed(1);
                
                // Color avg score icon
                const scoreIcon = document.getElementById('stat-avgscore-icon');
                if (avgScore >= 60) {
                    scoreIcon.className = "kpi-icon red";
                    scoreVal.className = "kpi-value text-danger";
                } else if (avgScore >= 20) {
                    scoreIcon.className = "kpi-icon amber";
                    scoreVal.className = "kpi-value text-warning";
                } else {
                    scoreIcon.className = "kpi-icon green";
                    scoreVal.className = "kpi-value text-success";
                }
                
                // Render Charts
                renderRiskDonutChart(stats.safe, stats.suspicious, stats.malicious);
                renderTimelineBarChart(stats.timeline);
                
                // Load Recent scans
                loadRecentScans();
            })
            .catch(err => {
                console.error("Error loading stats:", err);
            });
    }

    function renderRiskDonutChart(safe, suspicious, malicious) {
        const ctx = document.getElementById('riskDonutChart');
        if (!ctx) return;
        
        // Destroy existing chart to rebuild
        if (riskChart) {
            riskChart.destroy();
        }
        
        // Update Legend Mocks first
        const total = safe + suspicious + malicious;
        const getPct = val => total > 0 ? Math.round((val / total) * 100) : 0;
        
        document.getElementById('donut-legend').innerHTML = `
            <div class="legend-item">
                <span class="legend-dot" style="background-color: #00a651;"></span>
                <span>Safe</span>
                <span class="legend-val">${safe} (${getPct(safe)}%)</span>
            </div>
            <div class="legend-item">
                <span class="legend-dot" style="background-color: #e67e00;"></span>
                <span>Suspicious</span>
                <span class="legend-val">${suspicious} (${getPct(suspicious)}%)</span>
            </div>
            <div class="legend-item">
                <span class="legend-dot" style="background-color: #e0245e;"></span>
                <span>Malicious</span>
                <span class="legend-val">${malicious} (${getPct(malicious)}%)</span>
            </div>
        `;

        if (typeof Chart === 'undefined') {
            console.log("Chart.js not loaded. Bypassed canvas drawing.");
            return;
        }

        riskChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Suspicious', 'Malicious'],
                datasets: [{
                    data: [safe, suspicious, malicious],
                    backgroundColor: ['#00a651', '#e67e00', '#e0245e'],
                    borderColor: '#ffffff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: false,
                cutout: '70%',
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    function renderTimelineBarChart(timeline) {
        const ctx = document.getElementById('timelineBarChart');
        if (!ctx) return;
        
        if (timelineChart) {
            timelineChart.destroy();
        }
        
        const labels = timeline.map(t => {
            // Reformat date from YYYY-MM-DD to MM/DD
            const parts = t.date.split('-');
            return parts.length === 3 ? `${parts[1]}/${parts[2]}` : t.date;
        });
        const data = timeline.map(t => t.count);

        if (typeof Chart === 'undefined') {
            // Render basic CSS bar elements if Chart.js is offline
            ctx.style.display = 'none';
            let mockBars = '<div style="display: flex; gap: 10px; align-items: flex-end; height: 160px; padding: 10px 0;">';
            data.forEach((cnt, idx) => {
                const height = cnt > 0 ? Math.min(100, (cnt / Math.max(...data)) * 100) : 5;
                mockBars += `
                    <div style="flex-grow: 1; display: flex; flex-direction: column; align-items: center; gap: 4px;">
                        <div style="width: 100%; height: ${height}%; background-color: var(--neon-green); border-radius: 4px; box-shadow: 0 0 10px var(--glow-green);"></div>
                        <span style="font-size: 9px; color: var(--color-text-muted);">${labels[idx] || ''}</span>
                    </div>
                `;
            });
            mockBars += '</div>';
            ctx.parentElement.innerHTML = mockBars;
            return;
        }

        timelineChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels.length > 0 ? labels : ['No Data'],
                datasets: [{
                    label: 'Files Scanned',
                    data: data.length > 0 ? data : [0],
                    backgroundColor: '#00a651',
                    borderRadius: 4,
                    hoverBackgroundColor: '#00c35f'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: 'rgba(0,0,0,0.04)' }, ticks: { color: '#68657d', font: { size: 10 } } },
                    y: { grid: { color: 'rgba(0,0,0,0.04)' }, ticks: { color: '#68657d', font: { size: 10 }, precision: 0 } }
                }
            }
        });
    }

    function loadRecentScans() {
        fetch('/api/evidence')
            .then(res => res.json())
            .then(evidences => {
                const tbody = document.querySelector('#recent-scans-table tbody');
                tbody.innerHTML = '';
                
                // Show only top 5 recent scans
                const recents = evidences.slice(0, 5);
                
                if (recents.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="6" class="text-center">No forensic records found. Perform a scan or start monitoring.</td>
                        </tr>
                    `;
                    return;
                }
                
                recents.forEach(ev => {
                    let badgeClass = 'badge-success';
                    if (ev.risk_level === 'Malicious') badgeClass = 'badge-danger';
                    if (ev.risk_level === 'Suspicious') badgeClass = 'badge-warning';
                    
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${ev.scan_date}</td>
                        <td style="font-weight: 500;">${ev.filename}</td>
                        <td><span style="color: var(--color-text-muted);">${ev.file_type}</span></td>
                        <td style="font-family: var(--font-mono); font-weight: 600;">${ev.threat_score}/100</td>
                        <td><span class="badge ${badgeClass}">${ev.risk_level}</span></td>
                        <td>
                            <button class="btn btn-small btn-secondary btn-view-report" data-id="${ev.id}">
                                <i class="fa-solid fa-file-invoice"></i> View Report
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
                
                // Attach event listeners
                tbody.querySelectorAll('.btn-view-report').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-id');
                        openForensicReport(id);
                    });
                });
            })
            .catch(err => console.error("Error loading recent scans:", err));
    }

    // Link Dashboard table redirect to Vault tab
    document.getElementById('view-vault-link').addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('vault');
    });

    // --- Manual Upload Scanner logic ---
    const dragZone = document.getElementById('drag-zone');
    const fileInput = document.getElementById('file-input');
    
    dragZone.addEventListener('click', () => fileInput.click());
    
    dragZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dragZone.classList.add('dragover');
    });
    
    dragZone.addEventListener('dragleave', () => {
        dragZone.classList.remove('dragover');
    });
    
    dragZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dragZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    function handleFileUpload(file) {
        // Reset steps UI
        const stepIds = ['acquisition', 'hashing', 'ml', 'yara', 'vt', 'reporting'];
        stepIds.forEach(id => {
            const step = document.getElementById(`step-${id}`);
            step.className = 'pipeline-step';
            step.querySelector('.step-indicator').innerHTML = '<i class="fa-regular fa-circle"></i>';
        });

        // Hide old card previews, show upload progress
        document.getElementById('scan-result-card').style.display = 'none';
        document.getElementById('upload-progress-container').style.display = 'block';
        document.getElementById('upload-filename').textContent = file.name;
        document.getElementById('progress-bar-fill').style.width = '0%';
        document.getElementById('upload-percentage').textContent = '0%';
        document.getElementById('scan-pipeline-card').style.display = 'block';
        
        // Progress Mock trigger as we start POST
        let progress = 0;
        const progInterval = setInterval(() => {
            if (progress < 90) {
                progress += Math.floor(Math.random() * 10) + 1;
                progress = Math.min(90, progress);
                document.getElementById('progress-bar-fill').style.width = `${progress}%`;
                document.getElementById('upload-percentage').textContent = `${progress}%`;
            }
        }, 150);

        // First step: Acquisition goes active
        setPipelineStepState('acquisition', 'active');

        // Form payload
        const formData = new FormData();
        formData.append('file', file);

        // Setup AbortController
        scanAbortController = new AbortController();
        const signal = scanAbortController.signal;

        // Cancel button listeners
        const cancelScan = () => {
            if (scanAbortController) {
                scanAbortController.abort();
                scanAbortController = null;
            }
            clearInterval(progInterval);
            document.getElementById('upload-progress-container').style.display = 'none';
            document.getElementById('scan-pipeline-card').style.display = 'none';
            fileInput.value = '';
        };

        const cancelUploadBtn = document.getElementById('btn-cancel-upload');
        const cancelScanBtn = document.getElementById('btn-cancel-scan');
        
        // Clear previous listeners to avoid double binds
        const newCancelUpload = cancelUploadBtn.cloneNode(true);
        cancelUploadBtn.replaceWith(newCancelUpload);
        newCancelUpload.addEventListener('click', cancelScan);

        const newCancelScan = cancelScanBtn.cloneNode(true);
        cancelScanBtn.replaceWith(newCancelScan);
        newCancelScan.addEventListener('click', cancelScan);

        fetch('/api/scan', {
            method: 'POST',
            body: formData,
            signal: signal
        })
        .then(res => {
            clearInterval(progInterval);
            if (!res.ok) {
                return res.json().then(data => { throw new Error(data.error || 'Pipeline upload failed') });
            }
            return res.json();
        })
        .then(result => {
            // Fill progress bar to 100
            document.getElementById('progress-bar-fill').style.width = '100%';
            document.getElementById('upload-percentage').textContent = '100%';
            
            // Sequence pipeline steps animations for a rich wow factor
            animatePipelineCompletion(result);
        })
        .catch(err => {
            clearInterval(progInterval);
            if (err.name === 'AbortError') {
                showNotification("Scanning process canceled by user.", "info");
                return;
            }
            document.getElementById('upload-progress-container').style.display = 'none';
            document.getElementById('scan-pipeline-card').style.display = 'none';
            showNotification(err.message || "Forensic scanning pipeline failed.", "error");
            setPipelineStepState('acquisition', 'failed');
        });
    }

    function setPipelineStepState(stepId, state) {
        const step = document.getElementById(`step-${stepId}`);
        step.className = `pipeline-step ${state}`;
        const indicator = step.querySelector('.step-indicator');
        
        if (state === 'active') {
            indicator.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
        } else if (state === 'completed') {
            indicator.innerHTML = '<i class="fa-solid fa-check"></i>';
        } else if (state === 'failed') {
            step.className = `pipeline-step failed`;
            indicator.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
            indicator.style.color = 'var(--neon-red)';
            indicator.style.borderColor = 'var(--neon-red)';
        }
    }

    function animatePipelineCompletion(result) {
        const steps = ['acquisition', 'hashing', 'ml', 'yara', 'vt', 'reporting'];
        let idx = 0;
        
        // Loop through each layer to light up with 400ms delay for visual wow impact!
        const interval = setInterval(() => {
            if (idx > 0) {
                setPipelineStepState(steps[idx - 1], 'completed');
            }
            
            if (idx < steps.length) {
                setPipelineStepState(steps[idx], 'active');
                
                // Show VT warning indicator inside steps if VT is unconfigured/failed
                if (steps[idx] === 'vt' && result.vt_status !== 'success') {
                    setTimeout(() => {
                        const vtStep = document.getElementById('step-vt');
                        vtStep.querySelector('.step-indicator').innerHTML = '<i class="fa-solid fa-info"></i>';
                        vtStep.querySelector('.step-details p').innerHTML = 
                            `<span class="text-warning"><i class="fa-solid fa-triangle-exclamation"></i> VirusTotal bypassed (Status: ${result.vt_status})</span>`;
                    }, 100);
                }
                
                idx++;
            } else {
                clearInterval(interval);
                // Last step complete
                setPipelineStepState(steps[steps.length - 1], 'completed');
                
                // Reveal Result Card
                showScanResultCard(result);
            }
        }, 400);
    }

    function showScanResultCard(result) {
        document.getElementById('upload-progress-container').style.display = 'none';
        
        const resultCard = document.getElementById('scan-result-card');
        resultCard.style.display = 'block';
        
        // Set Risk badge
        const badge = document.getElementById('result-risk-badge');
        badge.textContent = result.risk_level;
        badge.className = 'badge';
        
        const scoreGauge = resultCard.querySelector('.result-score-gauge');
        scoreGauge.className = 'result-score-gauge';
        
        if (result.risk_level === 'Malicious') {
            badge.classList.add('badge-danger');
            scoreGauge.classList.add('danger');
        } else if (result.risk_level === 'Suspicious') {
            badge.classList.add('badge-warning');
            scoreGauge.classList.add('suspicious');
        } else {
            badge.classList.add('badge-success');
            scoreGauge.classList.add('safe');
        }
        
        document.getElementById('result-score-value').textContent = result.threat_score;
        document.getElementById('result-filename').textContent = result.filename;
        document.getElementById('result-hash').textContent = result.sha256;
        
        // Attach Modal opener
        const viewReportBtn = document.getElementById('btn-view-scan-report');
        // Clear old listeners
        const newBtn = viewReportBtn.cloneNode(true);
        viewReportBtn.replaceWith(newBtn);
        
        newBtn.addEventListener('click', () => {
            openForensicReport(result.id);
        });
    }

    document.getElementById('btn-reset-scanner').addEventListener('click', () => {
        document.getElementById('scan-result-card').style.display = 'none';
        document.getElementById('scan-pipeline-card').style.display = 'none';
        document.getElementById('upload-progress-container').style.display = 'none';
        fileInput.value = '';
    });

    // --- Folder Monitor Panel Logic ---
    function loadMonitorStatus() {
        fetch('/api/monitor/status')
            .then(res => res.json())
            .then(status => {
                const pathInput = document.getElementById('monitor-path-input');
                const startBtn = document.getElementById('btn-start-monitor');
                const stopBtn = document.getElementById('btn-stop-monitor');
                const detailsBox = document.getElementById('monitor-details-box');
                const badgeDot = document.getElementById('monitor-status-dot');
                const badgeText = document.getElementById('monitor-status-text');
                
                if (status.is_running) {
                    pathInput.value = status.watch_path;
                    pathInput.disabled = true;
                    startBtn.style.display = 'none';
                    stopBtn.style.display = 'inline-flex';
                    
                    // Show stats details
                    detailsBox.style.display = 'flex';
                    detailsBox.className = 'monitor-details-box';
                    document.getElementById('monitor-status-badge').className = 'badge badge-success';
                    document.getElementById('monitor-status-badge').textContent = 'ACTIVE';
                    document.getElementById('monitor-active-path').textContent = status.watch_path;
                    document.getElementById('monitor-queue-badge').textContent = status.queue_size;
                    
                    // Update global sidebar badge
                    badgeDot.className = 'status-dot active';
                    badgeText.textContent = "Monitor: Active";
                } else {
                    pathInput.disabled = false;
                    startBtn.style.display = 'inline-flex';
                    stopBtn.style.display = 'none';
                    detailsBox.style.display = 'none';
                    
                    badgeDot.className = 'status-dot inactive';
                    badgeText.textContent = "Monitor: Inactive";
                }
            })
            .catch(err => console.error("Error fetching monitor status:", err));
    }

    document.getElementById('btn-start-monitor').addEventListener('click', () => {
        const path = document.getElementById('monitor-path-input').value;
        if (!path) {
            showNotification("Please specify a directory path to monitor.", "warning");
            return;
        }
        
        fetch('/api/monitor/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        })
        .then(res => {
            if (!res.ok) {
                return res.json().then(data => { throw new Error(data.error || 'Failed to start monitor') });
            }
            return res.json();
        })
        .then(res => {
            showNotification("Real-time folder watcher active.", "success");
            loadMonitorStatus();
        })
        .catch(err => {
            showNotification(err.message || "Failed to start monitoring.", "error");
        });
    });

    document.getElementById('btn-stop-monitor').addEventListener('click', () => {
        fetch('/api/monitor/stop', { method: 'POST' })
        .then(res => res.json())
        .then(res => {
            showNotification("Folder watcher monitoring stopped.", "info");
            loadMonitorStatus();
        })
        .catch(err => {
            showNotification("Failed to stop observer daemon.", "error");
        });
    });

    let lastLogCount = 0;
    function loadMonitorLogs() {
        fetch('/api/monitor/logs')
            .then(res => res.json())
            .then(data => {
                const logsDiv = document.getElementById('terminal-logs');
                
                // Check if queue count changed
                if (activeTab === 'monitor') {
                    // Update queue badge
                    fetch('/api/monitor/status')
                        .then(r => r.json())
                        .then(s => {
                            if (s.is_running) {
                                document.getElementById('monitor-queue-badge').textContent = s.queue_size;
                            }
                        });
                }
                
                if (data.logs.length === 0) return;
                
                // Repopulate console if logs array grew
                if (data.logs.length !== lastLogCount) {
                    logsDiv.innerHTML = '';
                    data.logs.forEach(log => {
                        const line = document.createElement('div');
                        line.className = 'log-line';
                        
                        // Style based on keywords
                        if (log.includes('[DETECTED]')) line.className = 'log-line system';
                        if (log.includes('[ERROR]')) line.className = 'log-line error';
                        if (log.includes('[WARN]')) line.className = 'log-line warn';
                        if (log.includes('Score:')) {
                            if (log.includes('Malicious')) line.innerHTML = log.replace('Malicious', '<span class="text-danger">Malicious</span>');
                            else if (log.includes('Suspicious')) line.innerHTML = log.replace('Suspicious', '<span class="text-warning">Suspicious</span>');
                            else line.innerHTML = log.replace('Safe', '<span class="text-success">Safe</span>');
                        }
                        
                        if (!line.innerHTML) line.textContent = log;
                        logsDiv.appendChild(line);
                    });
                    
                    // Scroll console to bottom
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                    lastLogCount = data.logs.length;
                }
            })
            .catch(err => console.error("Error reading monitor logs:", err));
    }

    document.getElementById('btn-clear-console').addEventListener('click', () => {
        document.getElementById('terminal-logs').innerHTML = `
            <div class="log-line system">[SYSTEM] ThreatLens digital forensics agent logs cleared. Ready.</div>
        `;
        lastLogCount = 0;
    });

    // --- Forensic Evidence Vault Logic ---
    const vaultSearch = document.getElementById('vault-search');
    const filterBtns = document.querySelectorAll('.filter-btn');
    let currentFilter = 'all';
    let rawVaultData = []; // Store fetched database elements

    function loadVaultEvidence() {
        fetch('/api/evidence')
            .then(res => res.json())
            .then(evidences => {
                rawVaultData = evidences;
                renderVaultTable();
            })
            .catch(err => {
                console.error("Error loading vault:", err);
                showNotification("Could not load evidence vault database.", "error");
            });
    }

    // Vault search triggers
    vaultSearch.addEventListener('input', () => renderVaultTable());

    // Filter button actions
    filterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter');
            renderVaultTable();
        });
    });

    function renderVaultTable() {
        const tbody = document.querySelector('#vault-table tbody');
        tbody.innerHTML = '';
        
        const query = vaultSearch.value.toLowerCase().trim();
        
        const filtered = rawVaultData.filter(ev => {
            // 1. Filter by category button
            if (currentFilter !== 'all' && ev.risk_level !== currentFilter) {
                return false;
            }
            
            // 2. Filter by search text query
            if (query) {
                return ev.filename.toLowerCase().includes(query) || 
                       ev.sha256.toLowerCase().includes(query) || 
                       ev.risk_level.toLowerCase().includes(query) || 
                       ev.file_type.toLowerCase().includes(query);
            }
            
            return true;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center">No forensic records found matching the search criteria.</td>
                </tr>
            `;
            return;
        }

        filtered.forEach(ev => {
            let badgeClass = 'badge-success';
            if (ev.risk_level === 'Malicious') badgeClass = 'badge-danger';
            if (ev.risk_level === 'Suspicious') badgeClass = 'badge-warning';
            
            // Compile YARA tag list
            const yaraTags = ev.yara_matches.length > 0 
                ? ev.yara_matches.map(y => `<span class="badge badge-danger" style="font-size: 8px; margin: 1px; padding: 2px 4px;">${y}</span>`).join('')
                : '<span style="color: var(--color-text-muted);">-</span>';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${ev.scan_date}</td>
                <td style="font-weight: 600; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${ev.filename}">${ev.filename}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;"><code>${ev.sha256.substring(0, 10)}...</code></td>
                <td style="font-family: var(--font-mono); font-weight: 600;">${ev.threat_score}/100</td>
                <td><span class="badge ${badgeClass}">${ev.risk_level}</span></td>
                <td><span style="font-weight: 500;">${ev.ml_prediction}</span></td>
                <td><div style="display: flex; flex-wrap: wrap; max-width: 150px;">${yaraTags}</div></td>
                <td>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-small btn-secondary btn-vault-view" data-id="${ev.id}" title="View Forensic Details"><i class="fa-solid fa-file-invoice"></i> Report</button>
                        <button class="btn btn-small btn-secondary btn-vault-delete" data-id="${ev.id}" style="color: var(--neon-red); border-color: rgba(255,42,95,0.15);" title="Delete Evidence"><i class="fa-solid fa-trash-can"></i></button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Attach listeners
        tbody.querySelectorAll('.btn-vault-view').forEach(btn => {
            btn.addEventListener('click', () => openForensicReport(btn.getAttribute('data-id')));
        });

        tbody.querySelectorAll('.btn-vault-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                if (confirm("Are you sure you want to permanently delete this forensic evidence record?")) {
                    deleteEvidenceRecord(id);
                }
            });
        });
    }

    function deleteEvidenceRecord(id) {
        fetch(`/api/evidence/${id}`, { method: 'DELETE' })
            .then(res => res.json())
            .then(res => {
                showNotification("Evidence record deleted successfully.", "info");
                // Reload lists
                if (activeTab === 'vault') loadVaultEvidence();
                if (activeTab === 'dashboard') loadDashboardStats();
            })
            .catch(err => {
                console.error("Error deleting evidence:", err);
                showNotification("Failed to delete evidence record.", "error");
            });
    }

    // --- Detailed Forensic report Modal ---
    const reportModal = document.getElementById('report-modal');
    const closeModalBtn = document.getElementById('btn-close-modal');
    const modalTabBtns = document.querySelectorAll('.modal-tab-btn');
    const modalTabPanes = document.querySelectorAll('.modal-tab-pane');

    closeModalBtn.addEventListener('click', () => {
        reportModal.classList.remove('active');
        currentEvidence = null;
    });

    // Close on overlay click
    reportModal.addEventListener('click', (e) => {
        if (e.target === reportModal) {
            reportModal.classList.remove('active');
            currentEvidence = null;
        }
    });

    // Modal tabs toggle
    modalTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            modalTabBtns.forEach(b => b.classList.remove('active'));
            modalTabPanes.forEach(p => p.classList.remove('active'));
            
            btn.classList.add('active');
            const targetPane = document.getElementById(`modal-pane-${btn.getAttribute('data-modaltab')}`);
            targetPane.classList.add('active');
        });
    });

    function openForensicReport(id) {
        fetch(`/api/evidence/${id}`)
            .then(res => res.json())
            .then(evidence => {
                currentEvidence = evidence;
                
                // Set Header details
                document.getElementById('modal-subtitle').innerHTML = `Evidence ID: ${evidence.id} | Filename: <strong>${evidence.filename}</strong>`;
                
                // Render Summary tab
                document.getElementById('modal-threat-score').textContent = evidence.threat_score;
                const riskLevelEl = document.getElementById('modal-risk-level');
                riskLevelEl.textContent = evidence.risk_level;
                
                // Color Score Gauge
                const scoreGauge = document.getElementById('modal-score-gauge');
                scoreGauge.className = 'large-score-gauge';
                if (evidence.risk_level === 'Malicious') {
                    scoreGauge.classList.add('danger');
                } else if (evidence.risk_level === 'Suspicious') {
                    scoreGauge.classList.add('suspicious');
                } else {
                    scoreGauge.classList.add('safe');
                }
                
                // Metadata populate
                document.getElementById('m-filename').textContent = evidence.filename;
                document.getElementById('m-filepath').textContent = evidence.filepath;
                document.getElementById('m-filesize').textContent = formatBytes(evidence.filesize);
                document.getElementById('m-scandate').textContent = evidence.scan_date;
                document.getElementById('m-creationtime').textContent = evidence.creation_time;
                document.getElementById('m-filetype').textContent = evidence.file_type;
                
                // Hashes ledger
                document.getElementById('m-md5').textContent = evidence.md5;
                document.getElementById('m-sha1').textContent = evidence.sha1;
                document.getElementById('m-sha256').textContent = evidence.sha256;
                
                // ML Layer details
                document.getElementById('m-ml-pred').textContent = evidence.ml_prediction;
                if (evidence.ml_prediction === 'Malware') {
                    document.getElementById('m-ml-pred').className = 'val text-danger';
                } else if (evidence.ml_prediction === 'Safe') {
                    document.getElementById('m-ml-pred').className = 'val text-success';
                } else {
                    document.getElementById('m-ml-pred').className = 'val text-warning';
                }
                
                // Hide confidence ratio if ML was N/A
                const confWrapper = document.getElementById('m-ml-confidence-wrapper');
                if (evidence.ml_prediction.includes('N/A')) {
                    confWrapper.style.display = 'none';
                } else {
                    confWrapper.style.display = 'flex';
                    document.getElementById('m-ml-conf').textContent = `${Math.round(evidence.ml_confidence * 100)}%`;
                }
                
                // YARA rule lists
                const yaraCount = document.getElementById('m-yara-matches-count');
                const yaraList = document.getElementById('m-yara-list');
                yaraList.innerHTML = '';
                
                if (evidence.yara_matches.length > 0) {
                    yaraCount.textContent = `${evidence.yara_matches.length} Match(es)`;
                    yaraCount.className = 'val text-danger';
                    evidence.yara_matches.forEach(y => {
                        const li = document.createElement('li');
                        li.textContent = y;
                        yaraList.appendChild(li);
                    });
                } else {
                    yaraCount.textContent = '0 Matches';
                    yaraCount.className = 'val text-success';
                    yaraList.innerHTML = '<li style="background-color: rgba(255,255,255,0.03); color: var(--color-text-muted); border: 1px solid var(--border-color);">No matches detected</li>';
                }
                
                // VirusTotal details
                const vtDetections = document.getElementById('m-vt-detections');
                const vtStatusVal = document.getElementById('m-vt-status');
                
                if (evidence.vt_total !== null && evidence.vt_total > 0) {
                    vtDetections.textContent = `${evidence.vt_positives} / ${evidence.vt_total} Engines`;
                    vtDetections.className = evidence.vt_positives > 0 ? 'val text-danger' : 'val text-success';
                    vtStatusVal.textContent = 'Scanned successfully';
                    vtStatusVal.className = 'val text-success';
                } else {
                    vtDetections.textContent = '-';
                    vtDetections.className = 'val';
                    
                    // Set status string
                    if (evidence.vt_positives === 0 && evidence.vt_total === 0) {
                        vtStatusVal.textContent = 'Clean / Hash Not Found';
                        vtStatusVal.className = 'val text-success';
                    } else {
                        vtStatusVal.textContent = 'Bypassed (Unconfigured)';
                        vtStatusVal.className = 'val text-warning';
                    }
                }
                
                // Render AI Report tab
                const reportContent = document.getElementById('m-ai-report-content');
                if (evidence.ai_report) {
                    reportContent.innerHTML = parseMarkdown(evidence.ai_report);
                } else {
                    reportContent.innerHTML = '<p class="text-center" style="padding: 40px; color: var(--color-text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Generating report telemetry...</p>';
                }
                
                // Render Raw JSON tab
                document.getElementById('m-raw-json').textContent = JSON.stringify(evidence, null, 4);
                
                // Set active modal tab to Summary
                modalTabBtns[0].click();
                
                // Open sliding panel overlay
                reportModal.classList.add('active');
            })
            .catch(err => {
                console.error("Error fetching evidence detail:", err);
                showNotification("Failed to fetch detailed evidence telemetry.", "error");
            });
    }

    // Modal Actions
    document.getElementById('btn-modal-delete').addEventListener('click', () => {
        if (currentEvidence && confirm("Are you sure you want to permanently delete this forensic evidence?")) {
            deleteEvidenceRecord(currentEvidence.id);
            reportModal.classList.remove('active');
        }
    });

    document.getElementById('btn-print-report').addEventListener('click', () => {
        const modalBody = document.querySelector('.forensic-modal');
        const printWindow = window.open('', '_blank');
        
        printWindow.document.write(`
            <html>
                <head>
                    <title>ThreatLens Forensic Report - ${currentEvidence.filename}</title>
                    <style>
                        body { font-family: 'Helvetica Neue', Arial, sans-serif; padding: 40px; color: #111; line-height: 1.6; }
                        h1, h2, h3 { font-family: 'Orbitron', 'Helvetica', sans-serif; border-bottom: 1px solid #ddd; padding-bottom: 8px; }
                        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                        th { background-color: #f5f5f5; }
                        code { font-family: monospace; background-color: #f7f7f7; padding: 2px 6px; border-radius: 4px; }
                        .score { font-size: 24px; font-weight: bold; }
                        .danger { color: #d9534f; }
                        .warning { color: #f0ad4e; }
                        .success { color: #5cb85c; }
                    </style>
                </head>
                <body>
                    <h1>THREATLENS SECURITY REPORT</h1>
                    <h3>Preserved File Evidence Timeline</h3>
                    <p><strong>Date of Scan</strong>: ${currentEvidence.scan_date}</p>
                    <p><strong>ThreatLens Score</strong>: <span class="score ${currentEvidence.risk_level === 'Malicious' ? 'danger' : currentEvidence.risk_level === 'Suspicious' ? 'warning' : 'success'}">${currentEvidence.threat_score} / 100 (${currentEvidence.risk_level})</span></p>
                    <hr/>
                    ${parseMarkdown(currentEvidence.ai_report)}
                    <script>window.print();</script>
                </body>
            </html>
        `);
        printWindow.document.close();
    });

    // --- UI Helper Utils ---
    function formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }

    // A lightweight markdown to HTML compiler utilizing RegEx replacements
    function parseMarkdown(md) {
        if (!md) return '';
        let html = md;
        
        // Headers
        html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
        html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
        html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
        
        // Bold
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        // Code blocks
        html = html.replace(/```(.*?)```/gs, '<pre><code>$1</code></pre>');
        html = html.replace(/`(.*?)`/g, '<code>$1</code>');
        
        // Horizontal rule
        html = html.replace(/^---$/gm, '<hr/>');
        
        // List items
        html = html.replace(/^\s*[-*+]\s+(.*?)$/gm, '<li>$1</li>');
        // Wrap contiguous list items in ul
        html = html.replace(/(<li>.*?<\/li>)+/gs, '<ul>$&</ul>');
        
        // Ordered List items
        html = html.replace(/^\s*\d+\.\s+(.*?)$/gm, '<li>$1</li>');
        
        // Blockquotes
        html = html.replace(/^>\s+(.*?)$/gm, '<blockquote>$1</blockquote>');
        
        // Simple Markdown Table compiler
        const lines = html.split('\n');
        let inTable = false;
        let tableHtml = '';
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line.startsWith('|') && line.endsWith('|')) {
                const cols = line.split('|').map(c => c.trim()).filter((c, idx) => idx > 0 && idx < line.split('|').length - 1);
                
                // Skip separator rows (e.g. | :--- | :--- |)
                if (cols.every(c => c.startsWith(':') || c.startsWith('-') || c.endsWith('-'))) {
                    continue;
                }
                
                if (!inTable) {
                    inTable = true;
                    tableHtml = '<table><thead><tr>';
                    cols.forEach(c => tableHtml += `<th>${c}</th>`);
                    tableHtml += '</tr></thead><tbody>';
                } else {
                    tableHtml += '<tr>';
                    cols.forEach(c => tableHtml += `<td>${c}</td>`);
                    tableHtml += '</tr>';
                }
                lines[i] = ''; // clear line
            } else {
                if (inTable) {
                    inTable = false;
                    tableHtml += '</tbody></table>';
                    lines[i - 1] = tableHtml; // insert compile table html into previous line
                }
            }
        }
        
        html = lines.join('\n');
        
        return html;
    }

    // --- Startup hook triggers ---
    // Initialize stats and active states on load
    loadDashboardStats();
    loadMonitorStatus();
});
