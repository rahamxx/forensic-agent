/**
 * AI Digital Forensics Investigation Agent - Frontend Orchestration
 * BharatAgentic Hackathon powered by aiKart
 * 
 * Handles:
 * - Scenario quick-loading and evidence drag-and-drop
 * - Dynamic DAG workflow animation
 * - Step-by-step auditable agent decision feed
 * - Cross-source evidence correlation rendering
 * - Risk assessment gauges and human-in-the-loop triggers
 * - Actionable incident response playbook
 * - Forensic dossier print & JSON export
 */

let currentInvestigation = null;
let currentInvestigationId = null;

document.addEventListener('DOMContentLoaded', () => {
    initAgentScenarios();
    initAgentDropzone();
});

// ==============================================================================
// 1. SCENARIO INITIALIZATION & PRESETS
// ==============================================================================

async function initAgentScenarios() {
    try {
        const resp = await fetch('/api/agent/scenarios');
        if (!resp.ok) return;
        const data = await resp.json();
        const scenarios = data.scenarios || [];

        const container = document.getElementById('agent-scenarios-container');
        if (!container) return;

        container.innerHTML = '';
        scenarios.forEach(sc => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'px-3 py-1.5 rounded-lg border text-xs font-code-sm transition-all flex items-center gap-2 ' +
                (sc.type === 'email' ? 'border-cyber-lime/40 text-cyber-lime hover:bg-cyber-lime/10' :
                 sc.type === 'url' ? 'border-warning-amber/40 text-warning-amber hover:bg-warning-amber/10' :
                 'border-surface-variant text-on-surface-variant hover:text-on-surface hover:bg-surface-variant/30');

            let icon = 'description';
            if (sc.id.includes('apple')) icon = 'warning';
            else if (sc.id.includes('chase')) icon = 'account_balance';
            else if (sc.id.includes('paypal')) icon = 'link';
            else if (sc.id.includes('browser')) icon = 'history';
            else if (sc.id.includes('github')) icon = 'verified_user';

            btn.innerHTML = `<span class="material-symbols-outlined text-sm">${icon}</span> ${sc.title}`;
            btn.title = sc.description;
            btn.onclick = () => loadAgentScenario(sc);
            container.appendChild(btn);
        });
    } catch (e) {
        console.warn('Failed to load agent presets:', e);
    }
}

function loadAgentScenario(sc) {
    const inputArea = document.getElementById('agent-input-data');
    const typeSelect = document.getElementById('agent-type-select');
    const scenarioDesc = document.getElementById('agent-scenario-desc');

    if (inputArea) inputArea.value = sc.input || '';
    if (typeSelect) typeSelect.value = sc.type || 'auto';

    if (scenarioDesc) {
        scenarioDesc.innerHTML = `
            <div class="bg-surface-container-high/60 border border-glass-stroke p-3 rounded-lg text-xs font-code-sm flex items-start gap-2">
                <span class="material-symbols-outlined text-cyber-lime text-base shrink-0 mt-0.5">info</span>
                <div>
                    <span class="font-bold text-cyber-lime">${sc.title} (${sc.category}):</span>
                    <span class="text-on-surface-variant ml-1">${sc.description}</span>
                </div>
            </div>
        `;
    }
}

// ==============================================================================
// 2. DRAG & DROP EVIDENCE UPLOADER
// ==============================================================================

function initAgentDropzone() {
    const dropzone = document.getElementById('agent-dropzone');
    const fileInput = document.getElementById('agent-file-input');
    const inputArea = document.getElementById('agent-input-data');
    const typeSelect = document.getElementById('agent-type-select');

    if (!dropzone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('border-cyber-lime', 'bg-cyber-lime/5');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('border-cyber-lime', 'bg-cyber-lime/5');
        }, false);
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            handleUploadedFile(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleUploadedFile(fileInput.files[0]);
        }
    });

    function handleUploadedFile(file) {
        const reader = new FileReader();
        reader.onload = function(evt) {
            if (inputArea) inputArea.value = evt.target.result;
            if (typeSelect) {
                if (file.name.endsWith('.eml') || file.name.endsWith('.msg')) {
                    typeSelect.value = 'email';
                } else if (file.name.endsWith('.sqlite') || file.name.includes('history')) {
                    typeSelect.value = 'browser';
                } else {
                    typeSelect.value = 'auto';
                }
            }
            const desc = document.getElementById('agent-scenario-desc');
            if (desc) {
                desc.innerHTML = `
                    <div class="bg-surface-container-high/60 border border-cyber-lime/30 p-2.5 rounded text-xs font-code-sm text-cyber-lime flex items-center gap-2">
                        <span class="material-symbols-outlined text-sm">attach_file</span>
                        Uploaded file: <b>${file.name}</b> (${Math.round(file.size / 1024)} KB)
                    </div>
                `;
            }
        };
        reader.readAsText(file);
    }
}

// ==============================================================================
// 3. EXECUTE AUTONOMOUS INVESTIGATION
// ==============================================================================

async function runAgentInvestigation() {
    const inputArea = document.getElementById('agent-input-data');
    const typeSelect = document.getElementById('agent-type-select');
    const btn = document.getElementById('btn-run-agent');
    const loadingElem = document.getElementById('agent-loading-state');
    const resultsContainer = document.getElementById('agent-results-container');

    const inputData = inputArea ? inputArea.value.trim() : '';
    const reqType = typeSelect ? typeSelect.value : 'auto';

    if (!inputData) {
        alert("Please provide forensic evidence (paste email, URL, or select a demo scenario).");
        return;
    }

    // UI Loading State
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="material-symbols-outlined animate-spin text-base">sync</span> Reasoning & Investigating...`;
    }
    if (loadingElem) loadingElem.classList.remove('hidden');
    if (resultsContainer) resultsContainer.classList.add('hidden');

    resetDagAnimation();

    try {
        const resp = await fetch('/api/agent/investigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: reqType,
                input: inputData
            })
        });

        if (!resp.ok) {
            const errData = await resp.json();
            throw new Error(errData.error || `HTTP ${resp.status}`);
        }

        const report = await resp.json();
        currentInvestigation = report;
        currentInvestigationId = report.investigation_id;

        // Render Report
        renderAgentInvestigation(report);

        // Animate workflow DAG
        animateDagNodes(report.workflow_dag, report.agent_actions);

    } catch (err) {
        console.error('Agent investigation error:', err);
        alert(`Forensic Agent Error: ${err.message}`);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span class="material-symbols-outlined">psychology</span> Investigate with AI Agent`;
        }
        if (loadingElem) loadingElem.classList.add('hidden');
        if (resultsContainer) resultsContainer.classList.remove('hidden');
    }
}

// ==============================================================================
// 4. RENDER INVESTIGATION DASHBOARD
// ==============================================================================

function renderAgentInvestigation(report) {
    // 1. Meta & Header
    const idElem = document.getElementById('agent-inv-id');
    const timeElem = document.getElementById('agent-inv-time');
    const typeElem = document.getElementById('agent-inv-type');

    if (idElem) idElem.innerText = report.investigation_id || 'N/A';
    if (timeElem) timeElem.innerText = report.timestamp || '';
    if (typeElem) typeElem.innerText = (report.request_type || 'AUTO').toUpperCase();

    // 2. Risk Meter & Gauge
    const riskBadge = document.getElementById('agent-risk-badge');
    const riskScore = document.getElementById('agent-risk-score');
    const confScore = document.getElementById('agent-conf-score');
    const humanReviewCard = document.getElementById('agent-human-review-card');
    const humanReviewText = document.getElementById('agent-human-review-text');

    const risk = report.risk_level || 'LOW';
    const score = report.risk_score || 0;
    const conf = report.confidence_score || 0;

    let badgeClass = 'bg-cyber-lime/10 text-cyber-lime border-cyber-lime/40';
    let textClass = 'text-cyber-lime';
    if (risk === 'CRITICAL') {
        badgeClass = 'bg-neon-crimson/20 text-neon-crimson border-neon-crimson/50 animate-pulse';
        textClass = 'text-neon-crimson';
    } else if (risk === 'HIGH') {
        badgeClass = 'bg-neon-crimson/10 text-neon-crimson border-neon-crimson/30';
        textClass = 'text-neon-crimson';
    } else if (risk === 'MEDIUM') {
        badgeClass = 'bg-warning-amber/10 text-warning-amber border-warning-amber/30';
        textClass = 'text-warning-amber';
    }

    if (riskBadge) {
        riskBadge.className = `px-3 py-1 rounded-full font-label-caps text-label-caps font-bold border tracking-wider ${badgeClass}`;
        riskBadge.innerText = `${risk} THREAT`;
    }
    if (riskScore) {
        riskScore.className = `font-headline-lg text-4xl font-black ${textClass}`;
        riskScore.innerText = `${score}`;
    }
    if (confScore) confScore.innerText = `${conf}%`;

    // Human Review Flag
    if (humanReviewCard) {
        if (report.human_review_required) {
            humanReviewCard.className = 'glass-panel p-4 border-l-4 border-l-neon-crimson bg-neon-crimson/5 flex items-start gap-3 rounded-lg';
            if (humanReviewText) {
                humanReviewText.innerHTML = `
                    <div class="flex items-center gap-2 font-bold text-neon-crimson text-sm">
                        <span class="material-symbols-outlined text-base">gavel</span>
                        MANDATORY HUMAN-IN-THE-LOOP APPROVAL REQUIRED
                    </div>
                    <div class="text-xs text-on-surface-variant mt-1">${report.risk_rationale || 'High-risk automated actions are quarantined until a certified forensic analyst verifies the findings.'}</div>
                `;
            }
        } else {
            humanReviewCard.className = 'glass-panel p-4 border-l-4 border-l-cyber-lime bg-cyber-lime/5 flex items-start gap-3 rounded-lg';
            if (humanReviewText) {
                humanReviewText.innerHTML = `
                    <div class="flex items-center gap-2 font-bold text-cyber-lime text-sm">
                        <span class="material-symbols-outlined text-base">verified</span>
                        NO HUMAN REVIEW MANDATED (BASELINE OPERATIONAL RISK)
                    </div>
                    <div class="text-xs text-on-surface-variant mt-1">${report.risk_rationale || 'Indicators conform to legitimate baseline parameters.'}</div>
                `;
            }
        }
    }

    // 3. Executive Summary
    const summaryElem = document.getElementById('agent-summary-text');
    if (summaryElem) summaryElem.innerHTML = formatMarkdownHighlights(report.summary || '');

    // 4. Decision Log / Auditable Trace
    renderAgentDecisionFeed(report.agent_actions || []);

    // 5. Cross-Source Evidence Correlations
    renderAgentCorrelations(report.correlations || []);

    // 6. Evidence Table
    renderAgentEvidenceTable(report.evidence || []);

    // 7. Actionable Recommendations
    renderAgentRecommendations(report.recommendations || []);

    // 8. IOCs
    renderAgentIOCs(report.iocs || {});
}

function formatMarkdownHighlights(text) {
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong class="text-on-surface font-semibold">$1</strong>')
        .replace(/\*(.*?)\*/g, '<em class="text-on-surface-variant">$1</em>')
        .replace(/`([^`]+)`/g, '<code class="bg-surface-container-highest px-1.5 py-0.5 rounded text-cyber-lime font-code-sm text-xs">$1</code>');
}

// ==============================================================================
// 5. AUDITABLE AGENT DECISION FEED
// ==============================================================================

function renderAgentDecisionFeed(actions) {
    const feed = document.getElementById('agent-decision-feed');
    if (!feed) return;

    if (!actions || actions.length === 0) {
        feed.innerHTML = '<div class="text-on-surface-variant text-xs p-4 text-center">No agent decision trace available.</div>';
        return;
    }

    feed.innerHTML = actions.map(act => {
        let toolColor = 'text-cyber-lime';
        let toolIcon = 'smart_toy';
        if (act.tool_name === 'AgentPlanner') { toolColor = 'text-cyber-lime'; toolIcon = 'account_tree'; }
        else if (act.tool_name === 'EmailForensicsTool') { toolColor = 'text-warning-amber'; toolIcon = 'mail'; }
        else if (act.tool_name === 'URLForensicsTool') { toolColor = 'text-neon-crimson'; toolIcon = 'public'; }
        else if (act.tool_name === 'EvidenceCorrelator') { toolColor = 'text-[#e5c36f]'; toolIcon = 'hub'; }
        else if (act.tool_name === 'RiskAssessmentEngine') { toolColor = 'text-[#32ff7e]'; toolIcon = 'security'; }

        return `
            <div class="relative pl-6 pb-4 border-l border-glass-stroke last:border-0 last:pb-0 group">
                <div class="absolute -left-2.5 top-0 w-5 h-5 rounded-full bg-surface-container-high border border-glass-stroke flex items-center justify-center text-[10px] font-bold text-on-surface group-hover:border-cyber-lime transition-colors">
                    ${act.step}
                </div>
                <div class="bg-surface-container-high/40 hover:bg-surface-container-high/70 border border-glass-stroke rounded-lg p-3 transition-colors">
                    <div class="flex items-center justify-between mb-1.5">
                        <div class="flex items-center gap-2">
                            <span class="material-symbols-outlined text-sm ${toolColor}">${toolIcon}</span>
                            <span class="font-bold text-xs uppercase tracking-wider ${toolColor}">${act.tool_name}</span>
                        </div>
                        <span class="text-[10px] font-code-sm text-on-surface-variant">${act.duration_ms}ms</span>
                    </div>
                    <div class="text-xs text-on-surface-variant font-code-sm mb-1.5 leading-relaxed">
                        <span class="text-on-surface/80">Trigger:</span> ${act.reason}
                    </div>
                    <div class="bg-surface-container-lowest/60 border border-glass-stroke/40 px-2.5 py-1.5 rounded text-xs font-code-sm text-cyber-lime flex items-center gap-2">
                        <span class="material-symbols-outlined text-xs">arrow_right_alt</span>
                        <span><b>Finding:</b> ${act.key_finding}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ==============================================================================
// 6. CROSS-SOURCE EVIDENCE CORRELATIONS
// ==============================================================================

function renderAgentCorrelations(correlations) {
    const container = document.getElementById('agent-correlations-container');
    const countBadge = document.getElementById('agent-correlations-count');
    if (!container) return;

    if (countBadge) countBadge.innerText = correlations.length;

    if (!correlations || correlations.length === 0) {
        container.innerHTML = `
            <div class="glass-panel p-6 rounded-lg text-center text-on-surface-variant text-xs font-code-sm col-span-full">
                <span class="material-symbols-outlined text-2xl text-on-surface-variant mb-1">link_off</span>
                <p>No multi-vector correlation findings identified. Indicators are isolated single-vector events.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = correlations.map(c => {
        const isCrit = c.severity === 'CRITICAL';
        const color = isCrit ? 'neon-crimson' : 'warning-amber';
        const sources = (c.sources_linked || []).map(s => `<li class="font-code-sm text-[11px] text-on-surface-variant"><span class="text-cyber-lime">▪</span> ${s}</li>`).join('');

        return `
            <div class="glass-panel p-5 rounded-lg border-l-4 border-l-${color} flex flex-col justify-between hover:border-glass-stroke transition-all">
                <div>
                    <div class="flex justify-between items-start gap-2 mb-2">
                        <h4 class="font-bold text-sm text-${color} flex items-center gap-1.5">
                            <span class="material-symbols-outlined text-base">alt_route</span>
                            ${c.title}
                        </h4>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-${color}/10 text-${color} border border-${color}/30 uppercase tracking-widest shrink-0">
                            ${c.mitre_technique || 'T1566'}
                        </span>
                    </div>
                    <p class="text-xs text-on-surface-variant leading-relaxed mb-3">
                        ${c.description}
                    </p>
                </div>
                <div class="bg-surface-container-lowest/50 p-2.5 rounded border border-glass-stroke/30 mt-2">
                    <span class="text-[10px] font-bold uppercase tracking-wider text-on-surface-variant block mb-1">Linked Forensic Vectors:</span>
                    <ul class="flex flex-col gap-1 pl-1">${sources}</ul>
                </div>
            </div>
        `;
    }).join('');
}

// ==============================================================================
// 7. EVIDENCE INVENTORY TABLE
// ==============================================================================

function renderAgentEvidenceTable(evidence) {
    const tbody = document.getElementById('agent-evidence-tbody');
    const countBadge = document.getElementById('agent-evidence-count');
    if (!tbody) return;

    if (countBadge) countBadge.innerText = evidence.length;

    if (!evidence || evidence.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-on-surface-variant text-xs">No normalized evidence records extracted.</td></tr>';
        return;
    }

    tbody.innerHTML = evidence.map(e => {
        let sevColor = 'text-cyber-lime bg-cyber-lime/10 border-cyber-lime/30';
        if (e.severity === 'CRITICAL') sevColor = 'text-neon-crimson bg-neon-crimson/15 border-neon-crimson/40';
        else if (e.severity === 'HIGH') sevColor = 'text-neon-crimson bg-neon-crimson/10 border-neon-crimson/30';
        else if (e.severity === 'MEDIUM') sevColor = 'text-warning-amber bg-warning-amber/10 border-warning-amber/30';

        let catIcon = 'data_object';
        if (e.category === 'Header') catIcon = 'mail';
        else if (e.category === 'Cryptographic') catIcon = 'key';
        else if (e.category === 'Network') catIcon = 'lan';
        else if (e.category === 'NLP/Linguistic') catIcon = 'psychology';
        else if (e.category === 'Structural') catIcon = 'dns';
        else if (e.category === 'Reputation') catIcon = 'security';
        else if (e.category === 'Machine Learning') catIcon = 'model_training';

        return `
            <tr class="border-b border-glass-stroke/30 hover:bg-surface-variant/20 transition-colors">
                <td class="p-3 font-code-sm text-xs text-cyber-lime">${e.id}</td>
                <td class="p-3 font-code-sm text-xs text-on-surface font-semibold">
                    <span class="flex items-center gap-1.5">
                        <span class="material-symbols-outlined text-sm text-on-surface-variant">${catIcon}</span>
                        ${e.source}
                    </span>
                </td>
                <td class="p-3 font-code-sm text-xs text-on-surface-variant">${e.category}</td>
                <td class="p-3 font-code-sm text-xs text-on-surface break-all">${e.indicator}</td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[11px] font-bold border ${sevColor}">
                        ${e.detection_result} (${e.severity})
                    </span>
                </td>
                <td class="p-3 font-code-sm text-xs text-on-surface-variant">${e.supporting_info}</td>
            </tr>
        `;
    }).join('');
}

// ==============================================================================
// 8. ACTIONABLE INCIDENT RESPONSE PLAYBOOK
// ==============================================================================

function renderAgentRecommendations(recs) {
    const container = document.getElementById('agent-recommendations-container');
    if (!container) return;

    if (!recs || recs.length === 0) {
        container.innerHTML = '<div class="text-on-surface-variant text-xs p-4">No proactive incident response actions generated.</div>';
        return;
    }

    container.innerHTML = recs.map((r, idx) => {
        const requiresApproval = r.requires_approval;
        const badge = requiresApproval
            ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-neon-crimson/15 text-neon-crimson border border-neon-crimson/30 flex items-center gap-1">
                 <span class="material-symbols-outlined text-xs">shield</span> Analyst Approval Mandated
               </span>`
            : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyber-lime/10 text-cyber-lime border border-cyber-lime/30 flex items-center gap-1">
                 <span class="material-symbols-outlined text-xs">bolt</span> Automated Safe Action
               </span>`;

        return `
            <div class="glass-panel p-4 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4 border border-glass-stroke hover:border-cyber-lime/40 transition-colors">
                <div class="flex items-start gap-3">
                    <div class="w-8 h-8 rounded-lg bg-surface-container-high border border-glass-stroke flex items-center justify-center shrink-0 text-cyber-lime">
                        <span class="material-symbols-outlined text-base">checklist</span>
                    </div>
                    <div>
                        <div class="flex items-center gap-2 mb-1">
                            <span class="text-[11px] font-bold uppercase tracking-wider text-cyber-lime">[${r.phase}]</span>
                            <span class="font-bold text-sm text-on-surface">${r.action}</span>
                        </div>
                        <p class="text-xs text-on-surface-variant mb-1 leading-relaxed">${r.description}</p>
                        <span class="text-[11px] text-on-surface-variant/80 font-code-sm">Assigned Ops Unit: <b class="text-on-surface">${r.target}</b></span>
                    </div>
                </div>
                <div class="flex items-center gap-3 shrink-0 self-end md:self-center">
                    ${badge}
                    ${requiresApproval ? `
                        <button onclick="approveIRAction(this, '${r.action}')" class="bg-cyber-lime/10 hover:bg-cyber-lime hover:text-background text-cyber-lime border border-cyber-lime/50 px-3 py-1.5 rounded text-xs font-bold transition-all uppercase tracking-wider flex items-center gap-1">
                            <span class="material-symbols-outlined text-xs">check</span> Approve
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function approveIRAction(btn, actionName) {
    btn.disabled = true;
    btn.className = "bg-cyber-lime/20 text-cyber-lime border border-cyber-lime px-3 py-1.5 rounded text-xs font-bold uppercase cursor-default flex items-center gap-1";
    btn.innerHTML = `<span class="material-symbols-outlined text-xs">done_all</span> Dispatched`;
}

// ==============================================================================
// 9. IOCS CHIPS
// ==============================================================================

function renderAgentIOCs(iocs) {
    const domainsDiv = document.getElementById('agent-iocs-domains');
    const ipsDiv = document.getElementById('agent-iocs-ips');
    const urlsDiv = document.getElementById('agent-iocs-urls');

    if (domainsDiv) {
        const domains = iocs.domains || [];
        domainsDiv.innerHTML = domains.length ? domains.map(d => `<span class="bg-surface-container-high border border-glass-stroke px-2 py-0.5 rounded text-xs font-code-sm text-on-surface hover:border-cyber-lime cursor-pointer" onclick="copyText('${d}')">${d}</span>`).join(' ') : '<span class="text-on-surface-variant text-xs">None</span>';
    }
    if (ipsDiv) {
        const ips = iocs.ips || [];
        ipsDiv.innerHTML = ips.length ? ips.map(ip => `<span class="bg-surface-container-high border border-glass-stroke px-2 py-0.5 rounded text-xs font-code-sm text-on-surface hover:border-cyber-lime cursor-pointer" onclick="copyText('${ip}')">${ip}</span>`).join(' ') : '<span class="text-on-surface-variant text-xs">None</span>';
    }
    if (urlsDiv) {
        const urls = iocs.urls || [];
        urlsDiv.innerHTML = urls.length ? urls.map(u => `<span class="bg-surface-container-high border border-glass-stroke px-2 py-0.5 rounded text-xs font-code-sm text-on-surface hover:border-cyber-lime cursor-pointer max-w-xs truncate inline-block" onclick="copyText('${u}')" title="${u}">${u}</span>`).join(' ') : '<span class="text-on-surface-variant text-xs">None</span>';
    }
}

function copyText(txt) {
    navigator.clipboard.writeText(txt);
    showMiniToast(`Copied to clipboard: ${txt}`);
}

function showMiniToast(msg) {
    const toast = document.createElement('div');
    toast.className = 'fixed bottom-6 right-6 bg-surface-container-high border border-cyber-lime text-cyber-lime px-4 py-2 rounded-lg shadow-xl text-xs font-code-sm z-50 animate-bounce';
    toast.innerText = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
}

// ==============================================================================
// 10. DYNAMIC WORKFLOW DAG ANIMATION
// ==============================================================================

function resetDagAnimation() {
    const dagContainer = document.getElementById('agent-dag-canvas');
    if (!dagContainer) return;
    dagContainer.innerHTML = '<div class="text-center text-xs text-cyber-lime p-8 animate-pulse font-code-sm"><span class="material-symbols-outlined text-3xl mb-2 animate-spin">schema</span><br>Agent Planner is constructing dynamic execution graph...</div>';
}

function animateDagNodes(workflowDag, actions) {
    const dagContainer = document.getElementById('agent-dag-canvas');
    if (!dagContainer || !workflowDag) return;

    const nodes = workflowDag.nodes || [];
    const edges = workflowDag.edges || [];

    dagContainer.innerHTML = `
        <div class="flex flex-col items-center gap-4 py-4 w-full overflow-x-auto">
            <div class="flex flex-wrap items-center justify-center gap-3 w-full" id="dag-flow-row">
                ${nodes.map((node, i) => {
                    let nodeColor = 'border-cyber-lime/40 text-cyber-lime bg-cyber-lime/5';
                    let icon = 'smart_toy';

                    if (node.type === 'input') { nodeColor = 'border-on-surface-variant/40 text-on-surface bg-surface-container'; icon = 'input'; }
                    else if (node.type === 'planner') { nodeColor = 'border-cyber-lime text-cyber-lime bg-cyber-lime/10 shadow-[0_0_12px_rgba(50,255,126,0.15)]'; icon = 'psychology'; }
                    else if (node.type === 'tool') { nodeColor = 'border-warning-amber/50 text-warning-amber bg-warning-amber/5'; icon = 'build'; }
                    else if (node.type === 'enrichment') { nodeColor = 'border-[#00f3ff]/50 text-[#00f3ff] bg-[#00f3ff]/5'; icon = 'travel_explore'; }
                    else if (node.type === 'correlator') { nodeColor = 'border-[#e5c36f] text-[#e5c36f] bg-[#e5c36f]/10 shadow-[0_0_15px_rgba(229,195,111,0.2)]'; icon = 'hub'; }
                    else if (node.type === 'decision') { nodeColor = 'border-neon-crimson text-neon-crimson bg-neon-crimson/10 shadow-[0_0_15px_rgba(255,63,52,0.2)]'; icon = 'security'; }
                    else if (node.type === 'action') { nodeColor = 'border-cyber-lime text-cyber-lime bg-cyber-lime/10'; icon = 'task_alt'; }
                    else if (node.type === 'output') { nodeColor = 'border-on-surface text-on-surface bg-surface-container-high'; icon = 'summarize'; }

                    return `
                        <div class="dag-node px-3 py-2 rounded-lg border ${nodeColor} flex items-center gap-2 text-xs font-code-sm transition-all duration-300 transform hover:scale-105" id="dag-node-${node.id}">
                            <span class="material-symbols-outlined text-sm">${icon}</span>
                            <span class="font-bold">${node.label}</span>
                        </div>
                        ${i < nodes.length - 1 ? '<span class="material-symbols-outlined text-on-surface-variant/40 text-sm hidden sm:inline">arrow_forward</span>' : ''}
                    `;
                }).join('')}
            </div>
            <div class="text-[11px] font-code-sm text-on-surface-variant flex items-center gap-2 mt-2">
                <span class="w-2 h-2 rounded-full bg-cyber-lime inline-block animate-ping"></span>
                <span>Dynamic Agent Directed Acyclic Graph (DAG) executed ${nodes.length} stages across ${edges.length} correlated dependency links.</span>
            </div>
        </div>
    `;
}

// ==============================================================================
// 11. DOSSIER EXPORT & PRINT
// ==============================================================================

function exportAgentReport() {
    if (!currentInvestigationId) {
        alert("Please run an investigation first.");
        return;
    }
    const reportUrl = `/api/agent/report/${currentInvestigationId}`;
    window.open(reportUrl, '_blank');
}

function downloadAgentJson() {
    if (!currentInvestigation) {
        alert("Please run an investigation first.");
        return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentInvestigation, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `forensic_investigation_${currentInvestigation.investigation_id}.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
}

function openAgentWorkbench() {
    const agentLink = document.querySelector('[data-tab="tab-agent"]');
    if (agentLink) {
        agentLink.click();
    } else {
        const panes = document.querySelectorAll('.tab-content');
        panes.forEach(p => p.classList.add('hidden'));
        const agentTab = document.getElementById('tab-agent');
        if (agentTab) agentTab.classList.remove('hidden');
    }
}
