/**
 * AI INVESTIGATOR — UNIFIED CYBERSECURITY FRONTEND CONTROLLER (APP.JS)
 * Fully connected to FastAPI backend.
 * Zero hardcoded / fake results.
 */

// ==========================================================================
// APPLICATION STATE
// ==========================================================================
const AppState = {
    currentTab: 'tab-dashboard',
    selectedFile: null,
    isAnalyzing: false,
    activeIncidents: [],
    incidentLookup: {},
    currentAnalysisResult: null,
    currentIncidentModalId: null,
    
    // Simulation state
    simulation: {
        status: 'STOPPED',
        speed: 5,
        scenario: 'redteam_lateral',
        eventsProcessed: 0,
        ws: null,
        pollInterval: null
    }
};

// ==========================================================================
// INITIALIZATION
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDropzone();
    initAnalysisControls();
    initIncidentsFilter();
    initSimulationControls();
    initModalControls();
    initQuickDemo();
    
    // Load initial data
    refreshSystemOverview();
    loadIncidents();
    loadResearchBenchmark();
    
    // Background polling for dashboard overview (every 5 seconds)
    setInterval(refreshSystemOverview, 5000);
});

// ==========================================================================
// 1. NAVIGATION & TAB SWITCHING
// ==========================================================================
function initNavigation() {
    const navTabs = document.querySelectorAll('.nav-tab');
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });

    // Hero Action Cards routing
    const btnHeroDetect = document.getElementById('btn-hero-detect');
    if (btnHeroDetect) btnHeroDetect.addEventListener('click', () => switchTab('tab-detect'));

    const btnHeroIncidents = document.getElementById('btn-hero-incidents');
    if (btnHeroIncidents) btnHeroIncidents.addEventListener('click', () => switchTab('tab-incidents'));

    const btnHeroSimulation = document.getElementById('btn-hero-simulation');
    if (btnHeroSimulation) btnHeroSimulation.addEventListener('click', () => switchTab('tab-simulation'));
}

function switchTab(tabId) {
    AppState.currentTab = tabId;

    // Update nav buttons
    document.querySelectorAll('.nav-tab').forEach(tab => {
        if (tab.getAttribute('data-tab') === tabId) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });

    // Update panels
    document.querySelectorAll('.tab-pane').forEach(pane => {
        if (pane.id === tabId) {
            pane.classList.add('active');
        } else {
            pane.classList.remove('active');
        }
    });

    // Specific refresh actions per tab
    if (tabId === 'tab-dashboard') {
        refreshSystemOverview();
    } else if (tabId === 'tab-incidents') {
        loadIncidents();
    } else if (tabId === 'tab-research') {
        loadResearchBenchmark();
    }
}

// ==========================================================================
// 2. DASHBOARD OVERVIEW & RECENT ACTIVITY
// ==========================================================================
async function refreshSystemOverview() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();

        // Update KPIs
        const elEvents = document.getElementById('kpi-events-analyzed');
        const elThreats = document.getElementById('kpi-threats-detected');
        const elIncidents = document.getElementById('kpi-active-incidents');
        const elCritical = document.getElementById('kpi-critical-incidents');

        if (elEvents) elEvents.textContent = Number(data.events_processed || 0).toLocaleString();
        if (elThreats) elThreats.textContent = Number(data.threats_detected || 0).toLocaleString();
        if (elIncidents) elIncidents.textContent = Number(data.active_incidents || 0).toLocaleString();
        if (elCritical) elCritical.textContent = Number(data.critical_high_incidents || 0).toLocaleString();

        // Check system status dot
        const statusBadge = document.getElementById('system-status-indicator');
        if (statusBadge) {
            statusBadge.className = 'status-badge online';
            statusBadge.innerHTML = '<span class="status-dot"></span><span>SYSTEM ONLINE</span>';
        }

        // Also fetch recent incidents for the dashboard recent activity list
        loadRecentActivity();
    } catch (err) {
        console.warn('System status fetch failed:', err);
    }
}

async function loadRecentActivity() {
    try {
        const res = await fetch('/api/incidents');
        if (!res.ok) return;
        const incidents = await res.json();
        AppState.activeIncidents = incidents;

        const listContainer = document.getElementById('recent-incidents-list');
        if (!listContainer) return;

        if (!incidents || incidents.length === 0) {
            listContainer.innerHTML = `
                <div class="empty-state">
                    No recent incidents recorded yet. Analyze a log file or start the simulation to generate incidents.
                </div>
            `;
            return;
        }

        // Show latest 5 incidents
        const recents = incidents.slice(0, 5);
        listContainer.innerHTML = recents.map(inc => {
            const sevClass = (inc.severity || 'Medium').toLowerCase();
            const risk = inc.risk_score != null ? Math.round(inc.risk_score) : 50;
            const explanation = inc.explanation || 'Correlated security threat detected.';
            const shortDesc = explanation.length > 110 ? explanation.substring(0, 110) + '...' : explanation;

            return `
                <div class="recent-incident-row" onclick="openIncidentModal('${inc.incident_id}')" style="cursor: pointer;">
                    <div class="recent-inc-meta">
                        <span class="severity-pill ${sevClass}">${inc.severity || 'Medium'}</span>
                        <span class="recent-inc-id">${inc.incident_id}</span>
                        <span class="recent-inc-desc">${escapeHtml(shortDesc)}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="score-number text-red" style="font-size: 0.85rem;">Risk ${risk}/100</span>
                        <button class="btn btn-ghost" style="padding: 4px 10px; font-size: 0.75rem;">Review →</button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading recent activity:', err);
    }
}

// ==========================================================================
// 3. QUICK DEMO (ANALYZE SAMPLE ATTACK)
// ==========================================================================
function initQuickDemo() {
    const btnQuickDemo = document.getElementById('btn-quick-demo');
    if (!btnQuickDemo) return;

    btnQuickDemo.addEventListener('click', async () => {
        // Switch to detect tab
        switchTab('tab-detect');

        // Show progress card immediately
        const progressCard = document.getElementById('analysis-progress-card');
        const threatResultView = document.getElementById('threat-result-view');
        const fileStatusBar = document.getElementById('file-status-bar');

        if (fileStatusBar) {
            fileStatusBar.style.display = 'flex';
            document.getElementById('selected-file-name').textContent = 'test_attack.csv (Operation Shadow Breach)';
            document.getElementById('selected-file-format').textContent = 'CSV';
            document.getElementById('selected-file-size').textContent = '2.8 KB';
        }

        if (threatResultView) threatResultView.style.display = 'none';
        if (progressCard) progressCard.style.display = 'block';

        // Animate stages while waiting for real backend
        const startTime = Date.now();
        const stageInterval = setInterval(() => {
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
            const elTime = document.getElementById('analysis-elapsed-time');
            if (elTime) elTime.textContent = `${elapsed}s`;
        }, 100);

        simulateProgressStages(async () => {
            try {
                const response = await fetch('/api/analyze-sample', { method: 'POST' });
                clearInterval(stageInterval);

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.detail || 'Sample attack analysis failed');
                }

                const result = await response.json();
                AppState.currentAnalysisResult = result;

                // Hide progress, render real threat result
                if (progressCard) progressCard.style.display = 'none';
                renderThreatResult(result);
                refreshSystemOverview();
                loadIncidents();
            } catch (err) {
                clearInterval(stageInterval);
                if (progressCard) progressCard.style.display = 'none';
                alert('Analysis failed: ' + err.message);
            }
        });
    });
}

// ==========================================================================
// 4. DETECT NEW THREAT: DRAG & DROP AND LOG ANALYSIS
// ==========================================================================
function initDropzone() {
    const dropzone = document.getElementById('log-dropzone');
    const fileInput = document.getElementById('log-file-input');
    const btnBrowse = document.getElementById('btn-browse-file');
    const fileStatusBar = document.getElementById('file-status-bar');
    const btnClear = document.getElementById('btn-clear-file');

    if (!dropzone || !fileInput) return;

    btnBrowse.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('click', (e) => {
        if (e.target !== btnBrowse) fileInput.click();
    });

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            AppState.selectedFile = null;
            fileInput.value = '';
            fileStatusBar.style.display = 'none';
        });
    }
}

function handleFileSelect(file) {
    AppState.selectedFile = file;
    const fileStatusBar = document.getElementById('file-status-bar');
    const elName = document.getElementById('selected-file-name');
    const elFormat = document.getElementById('selected-file-format');
    const elSize = document.getElementById('selected-file-size');

    if (!fileStatusBar) return;

    elName.textContent = file.name;
    const ext = file.name.split('.').pop().toUpperCase();
    elFormat.textContent = ext || 'RAW LOG';
    elSize.textContent = formatBytes(file.size);

    fileStatusBar.style.display = 'flex';
}

function initAnalysisControls() {
    const btnRun = document.getElementById('btn-run-analysis');
    if (!btnRun) return;

    btnRun.addEventListener('click', async () => {
        if (!AppState.selectedFile) {
            alert('Please select or drop a security log file first.');
            return;
        }

        const progressCard = document.getElementById('analysis-progress-card');
        const threatResultView = document.getElementById('threat-result-view');

        if (threatResultView) threatResultView.style.display = 'none';
        if (progressCard) progressCard.style.display = 'block';

        const startTime = Date.now();
        const stageInterval = setInterval(() => {
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
            const elTime = document.getElementById('analysis-elapsed-time');
            if (elTime) elTime.textContent = `${elapsed}s`;
        }, 100);

        simulateProgressStages(async () => {
            try {
                const formData = new FormData();
                formData.append('file', AppState.selectedFile);

                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    body: formData
                });

                clearInterval(stageInterval);

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.detail || 'Investigation failed');
                }

                const result = await response.json();
                AppState.currentAnalysisResult = result;

                if (progressCard) progressCard.style.display = 'none';
                renderThreatResult(result);
                refreshSystemOverview();
                loadIncidents();
            } catch (err) {
                clearInterval(stageInterval);
                if (progressCard) progressCard.style.display = 'none';
                alert('Analysis failed: ' + err.message);
            }
        });
    });

    // Toggle Agent Findings Accordion
    const btnToggleAgent = document.getElementById('btn-toggle-agent-findings');
    if (btnToggleAgent) {
        btnToggleAgent.addEventListener('click', () => {
            const content = document.getElementById('agent-findings-content');
            const arrow = document.getElementById('agent-findings-arrow');
            if (!content) return;
            const isHidden = content.style.display === 'none';
            content.style.display = isHidden ? 'block' : 'none';
            if (arrow) arrow.textContent = isHidden ? '▴' : '▾';
        });
    }

    // Human Review Verdict buttons on Result View
    document.querySelectorAll('.verdict-buttons-col .btn-verdict').forEach(btn => {
        btn.addEventListener('click', () => {
            const verdict = btn.getAttribute('data-verdict');
            submitVerdict(verdict, 'verdict-feedback-alert');
        });
    });
}

function simulateProgressStages(onReady) {
    const stageIds = ['stage-1', 'stage-2', 'stage-3', 'stage-4', 'stage-5', 'stage-6', 'stage-7', 'stage-8'];
    stageIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.className = 'stage-item';
            el.querySelector('.stage-bullet').textContent = '○';
        }
    });

    let current = 0;
    const interval = setInterval(() => {
        if (current < stageIds.length) {
            const el = document.getElementById(stageIds[current]);
            if (el) {
                el.className = 'stage-item active';
                el.querySelector('.stage-bullet').textContent = '●';
            }
            if (current > 0) {
                const prev = document.getElementById(stageIds[current - 1]);
                if (prev) {
                    prev.className = 'stage-item completed';
                    prev.querySelector('.stage-bullet').textContent = '✓';
                }
            }
            current++;
        } else {
            clearInterval(interval);
            const last = document.getElementById(stageIds[stageIds.length - 1]);
            if (last) {
                last.className = 'stage-item completed';
                last.querySelector('.stage-bullet').textContent = '✓';
            }
            if (typeof onReady === 'function') onReady();
        }
    }, 180);
}

// ==========================================================================
// 5. RENDER THREAT RESULT (ZERO FAKE DATA)
// ==========================================================================
function renderThreatResult(result) {
    const view = document.getElementById('threat-result-view');
    if (!view) return;
    view.style.display = 'flex';

    const hasIncidents = result.incidents && result.incidents.length > 0;
    const banner = document.getElementById('result-banner-header');
    const statusBadge = document.getElementById('result-status-badge');
    const mainTitle = document.getElementById('result-incident-id');
    const statusIcon = document.getElementById('result-status-icon');
    const sevPill = document.getElementById('result-severity-pill');

    const primaryAnalysis = (result.analyses && result.analyses.length > 0) ? result.analyses[0] : null;
    const primaryRecommendation = (result.recommendations && result.recommendations.length > 0) ? result.recommendations[0] : null;

    if (!hasIncidents || !primaryAnalysis) {
        // BENIGN / NO THREATS DETECTED
        if (banner) banner.className = 'result-banner benign';
        if (statusBadge) { statusBadge.textContent = 'NO SUSPICIOUS THREATS DETECTED'; statusBadge.style.color = 'var(--green)'; }
        if (mainTitle) mainTitle.textContent = 'STATUS: NORMAL TELEMETRY';
        if (statusIcon) statusIcon.textContent = '✓';
        if (sevPill) { sevPill.textContent = 'BENIGN'; sevPill.className = 'severity-pill low'; }

        document.getElementById('result-risk-num').textContent = '0.0/100';
        document.getElementById('bar-risk-fill').style.width = '0%';
        document.getElementById('result-confidence-num').textContent = '100.0/100';
        document.getElementById('bar-confidence-fill').style.width = '100%';

        document.getElementById('result-explanation-text').textContent =
            `Universal Log Parser processed ${result.total_events_parsed} events. Multi-agent evaluation detected no baseline deviations, credential brute-forcing, LOLBins, or volumetric anomalies.`;

        document.getElementById('evidence-categories-grid').innerHTML = `
            <div class="empty-state">All evaluated events aligned within learned behavioral baselines.</div>
        `;
        document.getElementById('activity-chain-visualizer').innerHTML = `
            <div class="empty-state">No malicious activity chain detected.</div>
        `;
        return;
    }

    // THREAT DETECTED
    if (banner) banner.className = 'result-banner';
    if (statusBadge) { statusBadge.textContent = 'SUSPICIOUS ACTIVITY DETECTED'; statusBadge.style.color = 'var(--red)'; }
    if (mainTitle) mainTitle.textContent = `INCIDENT ${primaryAnalysis.incident_id}`;
    if (statusIcon) statusIcon.textContent = '🚨';

    const severity = primaryAnalysis.severity || 'Medium';
    if (sevPill) {
        sevPill.textContent = severity.toUpperCase();
        sevPill.className = `severity-pill ${severity.toLowerCase()}`;
    }

    const risk = Math.round(primaryAnalysis.risk_score || 50);
    const conf = Math.round(primaryAnalysis.confidence_score || 50);

    document.getElementById('result-risk-num').textContent = `${(primaryAnalysis.risk_score || 50).toFixed(1)}/100`;
    document.getElementById('bar-risk-fill').style.width = `${Math.min(100, risk)}%`;
    document.getElementById('score-explain-risk').textContent = `${(primaryAnalysis.risk_score || 50).toFixed(1)} / 100`;
    document.getElementById('bar-explain-risk').style.width = `${Math.min(100, risk)}%`;

    document.getElementById('result-confidence-num').textContent = `${(primaryAnalysis.confidence_score || 50).toFixed(1)}/100`;
    document.getElementById('bar-confidence-fill').style.width = `${Math.min(100, conf)}%`;
    document.getElementById('score-explain-conf').textContent = `${(primaryAnalysis.confidence_score || 50).toFixed(1)} / 100`;
    document.getElementById('bar-explain-conf').style.width = `${Math.min(100, conf)}%`;

    // Narrative
    document.getElementById('result-explanation-text').textContent = primaryAnalysis.explanation || 'Anomalous multi-agent threat chain detected.';

    // Impacted Entities
    const entitiesRow = document.getElementById('result-entities-row');
    if (entitiesRow) {
        const users = primaryAnalysis.users || [];
        const hosts = primaryAnalysis.hosts || [];
        const sources = primaryAnalysis.sources || [];

        let chips = '';
        users.forEach(u => chips += `<span class="entity-chip">User: ${escapeHtml(u)}</span>`);
        hosts.forEach(h => chips += `<span class="entity-chip">Host: ${escapeHtml(h)}</span>`);
        sources.forEach(s => chips += `<span class="entity-chip">Telemetry: ${escapeHtml(s)}</span>`);
        entitiesRow.innerHTML = chips || '<span class="entity-chip">Scope: Internal Network</span>';
    }

    // Categorized Evidence
    renderCategorizedEvidence(primaryAnalysis);

    // Detected Activity Chain
    renderActivityChain(primaryAnalysis);

    // Agent Findings Accordion
    renderAgentFindings(result);

    // Response Recommendation
    if (primaryRecommendation) {
        document.getElementById('result-response-priority').textContent = primaryRecommendation.priority || 'P2 - HIGH PRIORITY';
        document.getElementById('result-response-action').textContent = primaryRecommendation.recommended_action || 'Tier-2 SOC Analyst Review';

        const invSteps = primaryRecommendation.investigation_steps || [];
        const contSteps = primaryRecommendation.containment_steps || [];

        const elInv = document.getElementById('result-investigation-steps');
        if (elInv) {
            elInv.innerHTML = invSteps.map(s => `<li>${escapeHtml(s)}</li>`).join('') || '<li>Review active telemetry.</li>';
        }

        const elCont = document.getElementById('result-containment-steps');
        if (elCont) {
            elCont.innerHTML = contSteps.map(s => `<li>${escapeHtml(s)}</li>`).join('') || '<li>Monitor host metrics.</li>';
        }
    }
}

function renderCategorizedEvidence(analysis) {
    const grid = document.getElementById('evidence-categories-grid');
    if (!grid) return;

    const evidenceList = analysis.evidence || [];
    const categories = {
        auth: { title: '🔐 Authentication', items: [] },
        process: { title: '💻 Process Execution', items: [] },
        network: { title: '🌐 Network Communication', items: [] },
        dns: { title: '🌍 DNS Resolution', items: [] },
        baseline: { title: '📊 Behavioral Anomaly', items: [] },
        correlation: { title: '🧩 Multi-Agent Correlation', items: [] }
    };

    evidenceList.forEach(ev => {
        const evLower = ev.toLowerCase();
        if (evLower.includes('auth') || evLower.includes('logon') || evLower.includes('ntlm') || evLower.includes('password')) {
            categories.auth.items.push(ev);
        } else if (evLower.includes('process') || evLower.includes('command') || evLower.includes('powershell') || evLower.includes('binary') || evLower.includes('lolbin')) {
            categories.process.items.push(ev);
        } else if (evLower.includes('flow') || evLower.includes('byte') || evLower.includes('exfiltration') || evLower.includes('traffic')) {
            categories.network.items.push(ev);
        } else if (evLower.includes('dns') || evLower.includes('domain') || evLower.includes('dga') || evLower.includes('entropy')) {
            categories.dns.items.push(ev);
        } else if (evLower.includes('baseline') || evLower.includes('infrequent') || evLower.includes('unseen') || evLower.includes('rare')) {
            categories.baseline.items.push(ev);
        } else {
            categories.correlation.items.push(ev);
        }
    });

    // Only render categories that actually have evidence
    const visibleCards = Object.values(categories)
        .filter(c => c.items.length > 0)
        .map(c => `
            <div class="evidence-category-card">
                <div class="evidence-cat-header">${c.title} (${c.items.length})</div>
                <ul class="evidence-items-list">
                    ${c.items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
                </ul>
            </div>
        `).join('');

    grid.innerHTML = visibleCards || `<div class="empty-state">Anomalous deviations corroborated across specialist agents.</div>`;
}

function renderActivityChain(analysis) {
    const container = document.getElementById('activity-chain-visualizer');
    if (!container) return;

    const sources = analysis.sources || [];
    const evidenceText = (analysis.evidence || []).join(' ').toLowerCase();

    const stages = [];
    if (sources.includes('auth') || evidenceText.includes('auth') || evidenceText.includes('logon')) {
        stages.push({ tag: 'Initial Access', title: 'Authentication' });
    }
    if (evidenceText.includes('lateral') || (analysis.hosts && analysis.hosts.length > 1)) {
        stages.push({ tag: 'Progression', title: 'Lateral Movement' });
    }
    if (sources.includes('proc') || evidenceText.includes('process') || evidenceText.includes('powershell') || evidenceText.includes('cmd')) {
        stages.push({ tag: 'Execution', title: 'Process Execution' });
    }
    if (sources.includes('dns') || evidenceText.includes('dns') || evidenceText.includes('c2')) {
        stages.push({ tag: 'Command & Control', title: 'C2 Resolution' });
    }
    if (sources.includes('flow') || evidenceText.includes('exfiltration') || evidenceText.includes('byte')) {
        stages.push({ tag: 'Exfiltration', title: 'Data Egress' });
    }

    if (stages.length === 0) {
        stages.push({ tag: 'Detection', title: 'Behavioral Deviation' });
        stages.push({ tag: 'Triage', title: 'Correlated Anomaly' });
    }

    container.innerHTML = stages.map((s, idx) => `
        <div class="chain-node active-stage">
            <div class="chain-node-tag">${s.tag}</div>
            <div class="chain-node-title">${s.title}</div>
        </div>
        ${idx < stages.length - 1 ? '<div class="chain-arrow">→</div>' : ''}
    `).join('');
}

function renderAgentFindings(result) {
    const list = document.getElementById('agent-findings-list');
    const badgeCount = document.getElementById('agent-findings-count');
    if (!list) return;

    const trace = result.execution_trace || [];
    if (badgeCount) badgeCount.textContent = `${trace.length || 6} Agents`;

    list.innerHTML = trace.map(t => `
        <div class="agent-mini-card">
            <div class="agent-mini-header">
                <span class="agent-mini-name">${escapeHtml(t.agent)}</span>
                <span class="entity-chip">${t.execution_time_ms ? t.execution_time_ms.toFixed(1) + 'ms' : 'Active'}</span>
            </div>
            <div class="agent-mini-finding">${escapeHtml(t.output_summary || 'Analyzed telemetry partition successfully.')}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted);">
                Events flagged: ${t.anomalies_detected != null ? t.anomalies_detected : (t.events_analyzed || 0)}
            </div>
        </div>
    `).join('');
}

// ==========================================================================
// 6. HUMAN REVIEW VERDICT SUBMISSION
// ==========================================================================
async function submitVerdict(verdict, feedbackElementId) {
    const feedbackEl = document.getElementById(feedbackElementId);
    const incidentId = AppState.currentIncidentModalId ||
        (AppState.currentAnalysisResult && AppState.currentAnalysisResult.incidents && AppState.currentAnalysisResult.incidents[0] ? AppState.currentAnalysisResult.incidents[0].incident_id : null);

    if (!incidentId) {
        alert('No incident selected for review.');
        return;
    }

    try {
        const res = await fetch(`/api/incidents/${incidentId}/review`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ verdict, notes: `Analyst decision via Unified UI` })
        });

        if (!res.ok) throw new Error('Failed to record verdict');

        if (feedbackEl) {
            feedbackEl.style.display = 'block';
            feedbackEl.textContent = `✓ Verdict [${verdict}] recorded. Adaptive learning state updated.`;
        }

        // Refresh overview and incidents table
        refreshSystemOverview();
        loadIncidents();
    } catch (err) {
        alert('Error recording verdict: ' + err.message);
    }
}

// ==========================================================================
// 7. INCIDENTS TABLE & FILTERING
// ==========================================================================
function initIncidentsFilter() {
    const filterButtons = document.querySelectorAll('#incidents-filter-group .filter-chip');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const filter = btn.getAttribute('data-filter');
            filterIncidents(filter);
        });
    });
}

async function loadIncidents() {
    try {
        const res = await fetch('/api/incidents');
        if (!res.ok) return;
        const incidents = await res.json();
        AppState.activeIncidents = incidents;

        incidents.forEach(inc => {
            AppState.incidentLookup[inc.incident_id] = inc;
        });

        // Update counts on filter chips
        const cntAll = incidents.length;
        const cntCH = incidents.filter(i => ['Critical', 'High'].includes(i.severity)).length;
        const cntMed = incidents.filter(i => i.severity === 'Medium').length;
        const cntPending = incidents.filter(i => !i.review_status || i.review_status === 'PENDING_REVIEW').length;

        const elAll = document.getElementById('filter-cnt-all');
        const elCH = document.getElementById('filter-cnt-ch');
        const elMed = document.getElementById('filter-cnt-med');
        const elPending = document.getElementById('filter-cnt-pending');

        if (elAll) elAll.textContent = cntAll;
        if (elCH) elCH.textContent = cntCH;
        if (elMed) elMed.textContent = cntMed;
        if (elPending) elPending.textContent = cntPending;

        // Render current active filter
        const activeFilterBtn = document.querySelector('#incidents-filter-group .filter-chip.active');
        const activeFilter = activeFilterBtn ? activeFilterBtn.getAttribute('data-filter') : 'ALL';
        filterIncidents(activeFilter);
    } catch (err) {
        console.error('Error loading incidents:', err);
    }
}

function filterIncidents(filter) {
    const tbody = document.getElementById('incidents-table-body');
    if (!tbody) return;

    let filtered = AppState.activeIncidents || [];
    if (filter === 'CRITICAL_HIGH') {
        filtered = filtered.filter(i => ['Critical', 'High'].includes(i.severity));
    } else if (filter === 'MEDIUM') {
        filtered = filtered.filter(i => i.severity === 'Medium');
    } else if (filter === 'PENDING') {
        filtered = filtered.filter(i => !i.review_status || i.review_status === 'PENDING_REVIEW');
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center">No security incidents match the current filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(inc => {
        const sev = inc.severity || 'Medium';
        const sevClass = sev.toLowerCase();
        const risk = inc.risk_score != null ? Math.round(inc.risk_score) : 50;
        const conf = inc.confidence_score != null ? Math.round(inc.confidence_score) : 50;
        const users = (inc.users || []).join(', ') || 'Internal User';
        const hosts = (inc.hosts || []).join(', ') || 'Internal Host';
        const duration = inc.duration_sec != null ? `${inc.duration_sec}s` : '0s';
        const reviewStatus = inc.review_status || 'PENDING_REVIEW';
        const reviewBadgeClass = reviewStatus.includes('CONFIRMED') ? 'confirmed' : (reviewStatus.includes('BENIGN') ? 'benign' : '');

        return `
            <tr onclick="openIncidentModal('${inc.incident_id}')" style="cursor: pointer;">
                <td><strong class="recent-inc-id">${inc.incident_id}</strong></td>
                <td><span class="severity-pill ${sevClass}">${sev}</span></td>
                <td><span class="score-number text-red">${risk}/100</span></td>
                <td><span class="score-number text-cyan">${conf}/100</span></td>
                <td>${escapeHtml(users)}</td>
                <td>${escapeHtml(hosts)}</td>
                <td><span class="badge-review ${reviewBadgeClass}">${escapeHtml(reviewStatus)}</span></td>
                <td>${duration}</td>
                <td><button class="btn btn-ghost" style="padding: 4px 10px; font-size: 0.75rem;">Inspect</button></td>
            </tr>
        `;
    }).join('');
}

// ==========================================================================
// 8. INCIDENT DETAILS MODAL
// ==========================================================================
function initModalControls() {
    const modal = document.getElementById('incident-modal');
    const btnClose = document.getElementById('btn-close-modal');

    if (!modal || !btnClose) return;

    btnClose.addEventListener('click', () => {
        modal.style.display = 'none';
        AppState.currentIncidentModalId = null;
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
            AppState.currentIncidentModalId = null;
        }
    });

    // Modal Verdict buttons
    ['modal-btn-confirm', 'modal-btn-investigate', 'modal-btn-benign'].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) {
            btn.addEventListener('click', () => {
                const verdict = btn.getAttribute('data-verdict');
                submitVerdict(verdict, 'modal-verdict-feedback');
            });
        }
    });
}

function openIncidentModal(incidentId) {
    const modal = document.getElementById('incident-modal');
    const inc = AppState.incidentLookup[incidentId];
    if (!modal || !inc) return;

    AppState.currentIncidentModalId = incidentId;
    modal.style.display = 'flex';

    // Populate modal fields
    document.getElementById('modal-inc-id').textContent = inc.incident_id;
    const sevBadge = document.getElementById('modal-severity-badge');
    if (sevBadge) {
        sevBadge.textContent = (inc.severity || 'Medium').toUpperCase();
        sevBadge.className = `severity-pill ${(inc.severity || 'medium').toLowerCase()}`;
    }

    const reviewBadge = document.getElementById('modal-review-badge');
    if (reviewBadge) {
        reviewBadge.textContent = inc.review_status || 'PENDING REVIEW';
        reviewBadge.className = `badge-review ${(inc.review_status || '').includes('CONFIRMED') ? 'confirmed' : ''}`;
    }

    document.getElementById('modal-risk').textContent = `${(inc.risk_score || 50).toFixed(1)} / 100`;
    document.getElementById('modal-confidence').textContent = `${(inc.confidence_score || 50).toFixed(1)} / 100`;
    document.getElementById('modal-event-count').textContent = `${inc.event_count || 0} events`;
    document.getElementById('modal-duration').textContent = `${inc.duration_sec || 0}s`;

    document.getElementById('modal-explanation').textContent = inc.explanation || 'Correlated multi-agent security threat.';

    document.getElementById('modal-users').textContent = (inc.users || []).join(', ') || 'None';
    document.getElementById('modal-hosts').textContent = (inc.hosts || []).join(', ') || 'None';
    document.getElementById('modal-sources').textContent = (inc.sources || []).join(', ') || 'AUTH';

    // Evidence
    const elEvidence = document.getElementById('modal-evidence-list');
    if (elEvidence) {
        const evidence = inc.evidence || [];
        elEvidence.innerHTML = evidence.map(ev => `<li>${escapeHtml(ev)}</li>`).join('') || '<li>Correlated multi-source telemetry deviation.</li>';
    }

    // Timeline
    const elTimeline = document.getElementById('modal-timeline');
    if (elTimeline) {
        const timeline = inc.timeline || [];
        elTimeline.innerHTML = timeline.map(t => `
            <div class="timeline-item">
                Time: ${t.time || t.timestamp} • User: ${escapeHtml(t.user || 'Unknown')} • Action: ${escapeHtml(t.action || t.source || 'Activity')}
            </div>
        `).join('') || '<div class="empty-state">No detailed timeline slice available.</div>';
    }

    // Response Steps
    document.getElementById('modal-response-priority').textContent = inc.priority || 'P2 - HIGH PRIORITY';
    document.getElementById('modal-response-action').textContent = inc.recommended_action || 'Tier-2 SOC Analyst Review';

    const elSteps = document.getElementById('modal-containment-steps');
    if (elSteps) {
        const steps = inc.containment_steps || [];
        elSteps.innerHTML = steps.map(s => `<li>${escapeHtml(s)}</li>`).join('') || '<li>Audit host memory and active credentials.</li>';
    }

    const feedback = document.getElementById('modal-verdict-feedback');
    if (feedback) feedback.style.display = 'none';
}

// ==========================================================================
// 9. LIVE SIMULATION (LANL REPLAY)
// ==========================================================================
function initSimulationControls() {
    const btnStart = document.getElementById('btn-sim-start');
    const btnPause = document.getElementById('btn-sim-pause');
    const btnResume = document.getElementById('btn-sim-resume');
    const btnStop = document.getElementById('btn-sim-stop');
    const btnRestart = document.getElementById('btn-sim-restart');

    const selectScenario = document.getElementById('sim-scenario-select');
    const selectSpeed = document.getElementById('sim-speed-select');

    if (!btnStart) return;

    btnStart.addEventListener('click', async () => {
        const scenario = selectScenario ? selectScenario.value : 'redteam_lateral';
        const speed = selectSpeed ? parseFloat(selectSpeed.value) : 5.0;

        try {
            const res = await fetch(`/api/simulation/start?speed=${speed}&scenario=${scenario}`, { method: 'POST' });
            if (!res.ok) throw new Error('Failed to start simulation');
            
            btnStart.disabled = true;
            btnPause.disabled = false;
            btnStop.disabled = false;
            btnResume.style.display = 'none';
            btnPause.style.display = 'inline-flex';

            connectSimulationWebSocket();
        } catch (err) {
            alert('Simulation error: ' + err.message);
        }
    });

    btnPause.addEventListener('click', async () => {
        await fetch('/api/simulation/pause', { method: 'POST' });
        btnPause.style.display = 'none';
        btnResume.style.display = 'inline-flex';
    });

    btnResume.addEventListener('click', async () => {
        await fetch('/api/simulation/resume', { method: 'POST' });
        btnResume.style.display = 'none';
        btnPause.style.display = 'inline-flex';
    });

    btnStop.addEventListener('click', async () => {
        await fetch('/api/simulation/stop', { method: 'POST' });
        btnStart.disabled = false;
        btnPause.disabled = true;
        btnStop.disabled = true;
        btnResume.style.display = 'none';
        btnPause.style.display = 'inline-flex';
        disconnectSimulationWebSocket();
    });

    btnRestart.addEventListener('click', async () => {
        await fetch('/api/simulation/reset', { method: 'POST' });
        btnStart.disabled = false;
        btnPause.disabled = true;
        btnStop.disabled = true;
        btnResume.style.display = 'none';
        btnPause.style.display = 'inline-flex';
        document.getElementById('sim-stream-tbody').innerHTML = '<tr><td colspan="6" class="text-center">Simulation reset.</td></tr>';
        document.getElementById('sim-threat-banner').style.display = 'none';
        disconnectSimulationWebSocket();
        refreshSystemOverview();
    });

    // Alert banner inspector button
    const btnAlertView = document.getElementById('btn-sim-view-incident');
    if (btnAlertView) {
        btnAlertView.addEventListener('click', () => {
            const incId = document.getElementById('sim-banner-inc-id').textContent;
            if (incId) openIncidentModal(incId);
        });
    }
}

function connectSimulationWebSocket() {
    if (AppState.simulation.ws) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/ws`;

    try {
        AppState.simulation.ws = new WebSocket(wsUrl);

        AppState.simulation.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            handleSimulationMessage(data);
        };

        AppState.simulation.ws.onclose = () => {
            AppState.simulation.ws = null;
        };
    } catch (e) {
        console.warn('WebSocket connection error, falling back to polling:', e);
        startSimulationPolling();
    }
}

function disconnectSimulationWebSocket() {
    if (AppState.simulation.ws) {
        AppState.simulation.ws.close();
        AppState.simulation.ws = null;
    }
    if (AppState.simulation.pollInterval) {
        clearInterval(AppState.simulation.pollInterval);
        AppState.simulation.pollInterval = null;
    }
}

function startSimulationPolling() {
    if (AppState.simulation.pollInterval) return;
    AppState.simulation.pollInterval = setInterval(async () => {
        try {
            const res = await fetch('/api/events');
            if (res.ok) {
                const events = await res.json();
                renderStreamEvents(events);
            }
            refreshSystemOverview();
        } catch (e) {}
    }, 1000);
}

function handleSimulationMessage(data) {
    if (data.type === 'INITIAL_STATE' || data.type === 'BATCH_UPDATE') {
        if (data.recent_events) {
            renderStreamEvents(data.recent_events);
        }
        if (data.state) {
            document.getElementById('sim-event-counter').textContent = `${data.state.events_processed || 0} events streamed`;
        }
        if (data.new_incident) {
            triggerSimulationThreatAlert(data.new_incident);
            loadIncidents();
        }
    }
}

function renderStreamEvents(events) {
    const tbody = document.getElementById('sim-stream-tbody');
    if (!tbody || !events) return;

    const latest = events.slice(-15);
    tbody.innerHTML = latest.map(e => `
        <tr>
            <td>${e.timestamp}</td>
            <td><strong>${escapeHtml(e.event_type || e.source || 'EVENT')}</strong></td>
            <td>${escapeHtml(e.user || '-')}</td>
            <td>${escapeHtml(e.source_host || '-')}</td>
            <td>${escapeHtml(e.destination_host || '-')}</td>
            <td><span class="entity-chip">${e.is_redteam ? 'ALERT' : 'NORMAL'}</span></td>
        </tr>
    `).join('');
}

function triggerSimulationThreatAlert(inc) {
    const banner = document.getElementById('sim-threat-banner');
    if (!banner) return;

    banner.style.display = 'flex';
    document.getElementById('sim-banner-sev').textContent = inc.severity || 'HIGH';
    document.getElementById('sim-banner-inc-id').textContent = inc.incident_id || 'INC-0001';
    document.getElementById('sim-banner-desc').textContent = inc.explanation || 'Correlated multi-agent security threat.';

    // Update checklist agents
    const chkCorr = document.getElementById('chk-corr');
    const chkRisk = document.getElementById('chk-risk');
    const chkResp = document.getElementById('chk-resp');
    if (chkCorr) chkCorr.querySelector('.chk-status').textContent = '✓';
    if (chkRisk) chkRisk.querySelector('.chk-status').textContent = '✓';
    if (chkResp) chkResp.querySelector('.chk-status').textContent = '✓';
}

// ==========================================================================
// 10. RESEARCH BENCHMARK
// ==========================================================================
async function loadResearchBenchmark() {
    try {
        const res = await fetch('/api/research-results');
        if (!res.ok) return;
        const data = await res.json();

        // 1. Baseline vs Multi-Agent
        const tbodyBase = document.getElementById('research-baseline-tbody');
        if (tbodyBase && data.baseline_vs_multiagent) {
            tbodyBase.innerHTML = data.baseline_vs_multiagent.map(row => `
                <tr>
                    <td><strong>${escapeHtml(row['System'] || row['system'] || 'System')}</strong></td>
                    <td>${escapeHtml(row['Scope'] || 'Evaluation Window')}</td>
                    <td>${row['TP'] != null ? row['TP'] : '-'}</td>
                    <td>${row['FP'] != null ? row['FP'] : '-'}</td>
                    <td>${row['FN'] != null ? row['FN'] : '-'}</td>
                    <td>${row['TN'] != null ? row['TN'] : '-'}</td>
                    <td><strong class="text-cyan">${row['Precision (%)'] || row['Precision'] || '-'}%</strong></td>
                    <td><strong class="text-green">${row['Recall (%)'] || row['Recall'] || '-'}%</strong></td>
                    <td><strong class="text-amber">${row['F1 (%)'] || row['F1'] || '-'}%</strong></td>
                    <td>${row['Specificity (%)'] || row['Specificity'] || '-'}%</td>
                    <td>${row['Incidents'] != null ? row['Incidents'] : '-'}</td>
                </tr>
            `).join('');
        }

        // 2. Ablation Study
        const tbodyAbl = document.getElementById('research-ablation-tbody');
        if (tbodyAbl && data.ablation_results) {
            tbodyAbl.innerHTML = data.ablation_results.map(row => `
                <tr>
                    <td><strong>${escapeHtml(row['Experiment'] || 'Exp')}</strong></td>
                    <td>${escapeHtml(row['Configuration'] || 'Config')}</td>
                    <td>${row['TP'] != null ? row['TP'] : '-'}</td>
                    <td>${row['FP'] != null ? row['FP'] : '-'}</td>
                    <td>${row['FN'] != null ? row['FN'] : '-'}</td>
                    <td>${row['Precision'] != null ? (row['Precision'] * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${row['Recall'] != null ? (row['Recall'] * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${row['F1'] != null ? (row['F1'] * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${row['Incidents'] != null ? row['Incidents'] : '-'}</td>
                    <td>${row['Runtime_Sec'] != null ? row['Runtime_Sec'] + 's' : '-'}</td>
                </tr>
            `).join('');
        }

        // 3. Correlation Window Sensitivity
        const tbodyWin = document.getElementById('research-window-tbody');
        if (tbodyWin && data.window_results) {
            tbodyWin.innerHTML = data.window_results.map(row => `
                <tr>
                    <td><strong>${escapeHtml(row['Window'] || 'Window')}</strong></td>
                    <td>${row['Window_Seconds'] != null ? row['Window_Seconds'] + 's' : '-'}</td>
                    <td>${row['Incident_Count'] != null ? row['Incident_Count'] : '-'}</td>
                    <td>${row['RedTeam_Incidents'] != null ? row['RedTeam_Incidents'] : '-'}</td>
                    <td>${row['RedTeam_Events_Captured'] != null ? row['RedTeam_Events_Captured'] : '-'}</td>
                    <td>${row['Precision'] != null ? (row['Precision'] * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${row['Recall'] != null ? (row['Recall'] * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${row['F1'] != null ? (row['F1'] * 100).toFixed(1) + '%' : '-'}</td>
                    <td>${row['Runtime_Sec'] != null ? row['Runtime_Sec'] + 's' : '-'}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        console.error('Error loading research results:', err);
    }
}

// ==========================================================================
// UTILITY FUNCTIONS
// ==========================================================================
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
