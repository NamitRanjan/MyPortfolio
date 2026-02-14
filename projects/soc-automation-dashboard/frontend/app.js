// SOC Automation Dashboard - Main Application

// Detect deployment environment
const isGitHubPages = window.location.hostname.includes('github.io') || 
                       (window.location.protocol === 'file:') ||
                       (!window.location.hostname.includes('localhost') && !window.location.port);

const API_BASE = isGitHubPages ? null : 'http://localhost:5000/api';

// API wrapper that uses mock data when backend unavailable
const API = {
    async fetch(endpoint, options = {}) {
        if (API_BASE && !isGitHubPages) {
            try {
                const response = await API.fetch(`${endpoint}`, options);
                if (response.ok) {
                    return response.json();
                }
            } catch (error) {
                console.log('Backend unavailable, falling back to mock data');
            }
        }
        
        // Use mock data
        return this.mockResponse(endpoint, options);
    },
    
    mockResponse(endpoint, options) {
        // Parse endpoint and return appropriate mock data
        if (endpoint === '/dashboard/stats') return MOCK_DATA.getDashboardStats();
        if (endpoint.startsWith('/alerts')) {
            if (endpoint.includes('/investigate')) {
                const alertId = parseInt(endpoint.match(/\/alerts\/(\d+)/)[1]);
                return MOCK_DATA.investigateAlert(alertId);
            }
            if (endpoint.includes('/respond')) {
                const alertId = parseInt(endpoint.match(/\/alerts\/(\d+)/)[1]);
                const action = options.body ? JSON.parse(options.body).action : 'isolate';
                return MOCK_DATA.respondToAlert(alertId, action);
            }
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getAlerts(Object.fromEntries(params));
        }
        if (endpoint === '/threats') return MOCK_DATA.getThreats();
        if (endpoint.startsWith('/incidents')) {
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getIncidents(Object.fromEntries(params));
        }
        if (endpoint.startsWith('/iocs')) {
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getIOCs(Object.fromEntries(params));
        }
        if (endpoint === '/playbooks') return MOCK_DATA.getPlaybooks();
        if (endpoint.startsWith('/team')) {
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getTeam(Object.fromEntries(params));
        }
        if (endpoint === '/timeline') return MOCK_DATA.getTimeline();
        if (endpoint === '/threat-map') return MOCK_DATA.getThreatMap();
        if (endpoint === '/threat-intel/feeds') return MOCK_DATA.getThreatFeeds();
        if (endpoint === '/threat-intel/recent') return MOCK_DATA.getRecentThreats();
        
        return {};
    }
};

// State Management
const state = {
    alerts: [],
    threats: [],
    incidents: [],
    playbooks: [],
    currentAlert: null
};

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadDashboard();
    startRealTimeUpdates();
    initFilters();
    initModal();
});

// Navigation
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            switchPage(page);
        });
    });
}

function switchPage(page) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-page="${page}"]`).classList.add('active');
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });
    document.getElementById(`${page}-page`).classList.add('active');
    
    // Load page data
    switch(page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'alerts':
            loadAlerts();
            break;
        case 'threats':
            loadThreats();
            break;
        case 'incidents':
            loadIncidents();
            break;
        case 'playbooks':
            loadPlaybooks();
            break;
        case 'team':
            loadTeam();
            break;
        case 'threat-intel':
            loadThreatIntel();
            break;
    }
}

// Dashboard
async function loadDashboard() {
    showLoading();
    try {
        const [stats, alerts, timeline] = await Promise.all([
            API.fetch(`/dashboard/stats`).then(r => r.json()),
            API.fetch(`/alerts`).then(r => r.json()),
            API.fetch(`/timeline`).then(r => r.json())
        ]);
        
        updateStats(stats);
        updateActivityFeed(alerts);
        renderTimelineChart(timeline);
        renderAlertDistributionChart(alerts);
        renderThreatMap();
    } catch (error) {
        showToast('Failed to load dashboard data', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function updateStats(stats) {
    document.getElementById('critical-alerts').textContent = stats.active_alerts || 0;
    document.getElementById('active-threats').textContent = stats.blocked_threats || 0;
    document.getElementById('automation-rate').textContent = stats.automation_rate || '0%';
    document.getElementById('mttr').textContent = stats.mttr || '0 min';
}

function updateActivityFeed(alerts) {
    const feed = document.getElementById('activity-feed');
    feed.innerHTML = '';
    
    // Show last 10 alerts
    alerts.slice(0, 10).forEach(alert => {
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <div class="activity-icon ${alert.severity}">
                <i class="fas fa-exclamation-triangle"></i>
            </div>
            <div class="activity-content">
                <h4>${alert.title}</h4>
                <p>${alert.description}</p>
                <div class="activity-time">
                    <i class="fas fa-clock"></i>
                    ${formatTime(alert.timestamp)}
                </div>
            </div>
        `;
        feed.appendChild(item);
    });
}

// Charts
function renderTimelineChart(data) {
    const ctx = document.getElementById('timeline-chart').getContext('2d');
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => new Date(d.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })),
            datasets: [
                {
                    label: 'Alerts',
                    data: data.map(d => d.alerts),
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Threats Blocked',
                    data: data.map(d => d.threats_blocked),
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Incidents',
                    data: data.map(d => d.incidents),
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#ffffff' }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#a0aec0' },
                    grid: { color: '#2d3748' }
                },
                x: {
                    ticks: { color: '#a0aec0' },
                    grid: { color: '#2d3748' }
                }
            }
        }
    });
}

function renderAlertDistributionChart(alerts) {
    const ctx = document.getElementById('alert-distribution-chart').getContext('2d');
    
    const severityCounts = alerts.reduce((acc, alert) => {
        acc[alert.severity] = (acc[alert.severity] || 0) + 1;
        return acc;
    }, {});
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(severityCounts).map(s => s.charAt(0).toUpperCase() + s.slice(1)),
            datasets: [{
                data: Object.values(severityCounts),
                backgroundColor: [
                    '#8b0000',  // critical
                    '#dc3545',  // high
                    '#ffc107',  // medium
                    '#00a3e0'   // low
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#ffffff' }
                }
            }
        }
    });
}

async function renderThreatMap() {
    try {
        const locations = await API.fetch(`/threat-map`).then(r => r.json());
        const mapDiv = document.getElementById('threat-map');
        mapDiv.innerHTML = '<div style="text-align: center; padding: 20px; color: #a0aec0;"><i class="fas fa-globe" style="font-size: 3rem; margin-bottom: 1rem;"></i><br>Global Threat Distribution<br><br>';
        
        locations.forEach(loc => {
            const marker = document.createElement('div');
            marker.style.padding = '10px';
            marker.style.borderBottom = '1px solid #2d3748';
            marker.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span><i class="fas fa-map-marker-alt" style="color: #dc3545; margin-right: 10px;"></i>${loc.country}</span>
                    <span style="background: rgba(220, 53, 69, 0.2); padding: 5px 15px; border-radius: 20px; color: #dc3545; font-weight: bold;">${loc.count}</span>
                </div>
            `;
            mapDiv.appendChild(marker);
        });
        
        mapDiv.innerHTML += '</div>';
    } catch (error) {
        console.error('Failed to load threat map:', error);
    }
}

// Alerts
async function loadAlerts(filters = {}) {
    showLoading();
    try {
        const params = new URLSearchParams(filters);
        const alerts = await API.fetch(`/alerts?${params}`).then(r => r.json());
        state.alerts = alerts;
        renderAlerts(alerts);
    } catch (error) {
        showToast('Failed to load alerts', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderAlerts(alerts) {
    const container = document.getElementById('alerts-list');
    container.innerHTML = '';
    
    if (alerts.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 3rem; color: #a0aec0;"><i class="fas fa-check-circle" style="font-size: 3rem; margin-bottom: 1rem; color: #28a745;"></i><br>No alerts found</div>';
        return;
    }
    
    alerts.forEach(alert => {
        const item = document.createElement('div');
        item.className = `alert-item ${alert.severity}`;
        item.innerHTML = `
            <div class="alert-header">
                <div>
                    <div class="alert-title">${alert.title}</div>
                    <div class="alert-meta">
                        <div class="meta-item">
                            <i class="fas fa-server"></i>
                            <span>${alert.host}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-user"></i>
                            <span>${alert.user}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-clock"></i>
                            <span>${formatTime(alert.timestamp)}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-database"></i>
                            <span>${alert.source}</span>
                        </div>
                    </div>
                </div>
                <div>
                    <span class="badge ${alert.severity}">${alert.severity}</span>
                    <span class="badge ${alert.status}" style="margin-left: 0.5rem;">${alert.status}</span>
                </div>
            </div>
            <div class="alert-description">${alert.description}</div>
            <div class="alert-indicators">
                ${alert.indicators.map(ind => `<span class="indicator-tag"><i class="fas fa-tag"></i> ${ind}</span>`).join('')}
            </div>
            <div class="alert-meta" style="margin-top: 1rem;">
                <div class="meta-item">
                    <i class="fas fa-crosshairs"></i>
                    <span>MITRE: ${alert.mitre_tactics.join(', ')}</span>
                </div>
                <div class="meta-item">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>Risk Score: ${alert.risk_score}/100</span>
                </div>
            </div>
        `;
        
        item.addEventListener('click', () => showAlertDetails(alert));
        container.appendChild(item);
    });
}

// Threats
async function loadThreats() {
    showLoading();
    try {
        const threats = await API.fetch(`/threats`).then(r => r.json());
        state.threats = threats;
        renderThreats(threats);
    } catch (error) {
        showToast('Failed to load threats', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderThreats(threats) {
    const container = document.getElementById('threats-list');
    container.innerHTML = '';
    
    threats.forEach(threat => {
        const item = document.createElement('div');
        item.className = 'threat-item';
        item.innerHTML = `
            <div class="threat-header">
                <div>
                    <div class="threat-title">${threat.name}</div>
                    <div class="alert-meta">
                        <div class="meta-item">
                            <i class="fas fa-shield-virus"></i>
                            <span>${threat.type}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-globe"></i>
                            <span>${threat.country}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-clock"></i>
                            <span>${formatTime(threat.timestamp)}</span>
                        </div>
                    </div>
                </div>
                <div>
                    <span class="badge ${threat.severity}">${threat.severity}</span>
                    <span class="badge ${threat.action}" style="margin-left: 0.5rem;">${threat.action}</span>
                </div>
            </div>
            <div class="alert-description">${threat.description}</div>
            <div class="alert-meta" style="margin-top: 1rem;">
                <div class="meta-item">
                    <i class="fas fa-network-wired"></i>
                    <span>${threat.source_ip} → ${threat.destination_ip}</span>
                </div>
                <div class="meta-item">
                    <i class="fas fa-fingerprint"></i>
                    <span>${threat.indicators} IOCs</span>
                </div>
                <div class="meta-item">
                    <i class="fas fa-percentage"></i>
                    <span>Confidence: ${threat.confidence}%</span>
                </div>
            </div>
        `;
        container.appendChild(item);
    });
}

// Incidents
async function loadIncidents() {
    showLoading();
    try {
        const incidents = await API.fetch(`/incidents`).then(r => r.json());
        state.incidents = incidents;
        renderIncidents(incidents);
    } catch (error) {
        showToast('Failed to load incidents', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderIncidents(incidents) {
    const container = document.getElementById('incidents-list');
    container.innerHTML = '';
    
    incidents.forEach(incident => {
        const item = document.createElement('div');
        item.className = `incident-item ${incident.severity}`;
        item.innerHTML = `
            <div class="incident-header">
                <div>
                    <div class="incident-title">${incident.title}</div>
                    <div class="alert-meta">
                        <div class="meta-item">
                            <i class="fas fa-user-shield"></i>
                            <span>${incident.assignee}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-clock"></i>
                            <span>Created: ${formatTime(incident.created)}</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-sync"></i>
                            <span>Updated: ${formatTime(incident.updated)}</span>
                        </div>
                    </div>
                </div>
                <div>
                    <span class="badge ${incident.severity}">${incident.severity}</span>
                    <span class="badge ${incident.status}" style="margin-left: 0.5rem;">${incident.status}</span>
                </div>
            </div>
            <div class="alert-description">${incident.description}</div>
            <div class="alert-description" style="margin-top: 0.5rem;"><strong>Impact:</strong> ${incident.impact}</div>
            <div style="margin-top: 1rem;">
                <strong style="color: #00a3e0;">Response Actions:</strong>
                <ul style="margin-top: 0.5rem; padding-left: 1.5rem; color: #a0aec0;">
                    ${incident.response_actions.map(action => `<li>${action}</li>`).join('')}
                </ul>
            </div>
            <div style="margin-top: 1rem;">
                <strong style="color: #00a3e0;">Affected Systems:</strong>
                <div class="alert-indicators">
                    ${incident.affected_systems.map(sys => `<span class="indicator-tag"><i class="fas fa-server"></i> ${sys}</span>`).join('')}
                </div>
            </div>
        `;
        container.appendChild(item);
    });
}

// Playbooks
async function loadPlaybooks() {
    showLoading();
    try {
        const playbooks = await API.fetch(`/playbooks`).then(r => r.json());
        state.playbooks = playbooks;
        renderPlaybooks(playbooks);
    } catch (error) {
        showToast('Failed to load playbooks', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderPlaybooks(playbooks) {
    const container = document.getElementById('playbooks-list');
    container.innerHTML = '';
    
    playbooks.forEach(playbook => {
        const card = document.createElement('div');
        card.className = 'playbook-card';
        card.innerHTML = `
            <div class="playbook-header">
                <h3><i class="fas fa-book"></i> ${playbook.name}</h3>
            </div>
            <div class="playbook-description">${playbook.description}</div>
            <div class="playbook-stats">
                <div class="playbook-stat">
                    <div class="playbook-stat-value">${playbook.steps}</div>
                    <div class="playbook-stat-label">Steps</div>
                </div>
                <div class="playbook-stat">
                    <div class="playbook-stat-value">${playbook.success_rate}</div>
                    <div class="playbook-stat-label">Success Rate</div>
                </div>
                <div class="playbook-stat">
                    <div class="playbook-stat-value">${playbook.avg_execution_time}</div>
                    <div class="playbook-stat-label">Avg Time</div>
                </div>
            </div>
            <div style="margin-top: 1rem;">
                <strong style="color: #00a3e0;">Triggers:</strong>
                <div class="playbook-triggers">
                    ${playbook.triggers.map(trigger => `<span class="trigger-tag"><i class="fas fa-bolt"></i> ${trigger}</span>`).join('')}
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

// Modal
function initModal() {
    const modal = document.getElementById('alert-modal');
    const closeBtns = document.querySelectorAll('.modal-close');
    
    closeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            modal.classList.remove('active');
        });
    });
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
        }
    });
    
    document.getElementById('investigate-btn').addEventListener('click', () => investigateAlert());
    document.getElementById('respond-btn').addEventListener('click', () => respondToAlert());
}

function showAlertDetails(alert) {
    state.currentAlert = alert;
    const modal = document.getElementById('alert-modal');
    const modalBody = document.getElementById('modal-body');
    
    document.getElementById('modal-title').innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${alert.title}`;
    
    modalBody.innerHTML = `
        <div style="display: flex; gap: 1rem; margin-bottom: 1rem;">
            <span class="badge ${alert.severity}">${alert.severity}</span>
            <span class="badge ${alert.status}">${alert.status}</span>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Description:</strong>
            <p style="margin-top: 0.5rem; color: #a0aec0;">${alert.description}</p>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Alert Details:</strong>
            <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                <div><i class="fas fa-server"></i> Host: <span style="color: #a0aec0;">${alert.host}</span></div>
                <div><i class="fas fa-user"></i> User: <span style="color: #a0aec0;">${alert.user}</span></div>
                <div><i class="fas fa-database"></i> Source: <span style="color: #a0aec0;">${alert.source}</span></div>
                <div><i class="fas fa-exclamation-circle"></i> Risk Score: <span style="color: #a0aec0;">${alert.risk_score}/100</span></div>
            </div>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">MITRE ATT&CK Tactics:</strong>
            <div class="alert-indicators" style="margin-top: 0.5rem;">
                ${alert.mitre_tactics.map(tactic => `<span class="indicator-tag">${tactic}</span>`).join('')}
            </div>
        </div>
        <div>
            <strong style="color: #00a3e0;">Indicators:</strong>
            <div class="alert-indicators" style="margin-top: 0.5rem;">
                ${alert.indicators.map(ind => `<span class="indicator-tag"><i class="fas fa-tag"></i> ${ind}</span>`).join('')}
            </div>
        </div>
    `;
    
    modal.classList.add('active');
}

async function investigateAlert() {
    if (!state.currentAlert) return;
    
    showLoading();
    try {
        const result = await API.fetch(`/alerts/${state.currentAlert.id}/investigate`, {
            method: 'POST'
        }).then(r => r.json());
        
        showToast(`Investigation completed! Threat score: ${result.findings.threat_score}, Recommended action: ${result.findings.recommended_action}`, 'success');
        
        // Update modal with findings
        const modalBody = document.getElementById('modal-body');
        modalBody.innerHTML += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(40, 167, 69, 0.1); border-left: 3px solid #28a745; border-radius: 8px;">
                <strong style="color: #28a745;">Investigation Results:</strong>
                <ul style="margin-top: 0.5rem; padding-left: 1.5rem; color: #a0aec0;">
                    ${result.steps_completed.map(step => `<li>${step}</li>`).join('')}
                </ul>
                <div style="margin-top: 1rem;">
                    <div>IOC Matches: ${result.findings.ioc_matches}</div>
                    <div>Threat Score: ${result.findings.threat_score}/100</div>
                    <div>Recommended Action: <strong style="color: #28a745; text-transform: uppercase;">${result.findings.recommended_action}</strong></div>
                    <div>Confidence: ${result.findings.confidence}%</div>
                </div>
            </div>
        `;
    } catch (error) {
        showToast('Investigation failed', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

async function respondToAlert() {
    if (!state.currentAlert) return;
    
    const action = prompt('Enter response action (isolate, block, or monitor):');
    if (!action || !['isolate', 'block', 'monitor'].includes(action.toLowerCase())) {
        showToast('Invalid action', 'error');
        return;
    }
    
    showLoading();
    try {
        const result = await API.fetch(`/alerts/${state.currentAlert.id}/respond`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action.toLowerCase() })
        }).then(r => r.json());
        
        showToast(`Response executed successfully! Action: ${action}`, 'success');
        
        // Update modal with response
        const modalBody = document.getElementById('modal-body');
        modalBody.innerHTML += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(0, 102, 204, 0.1); border-left: 3px solid #0066cc; border-radius: 8px;">
                <strong style="color: #0066cc;">Automated Response Executed:</strong>
                <ul style="margin-top: 0.5rem; padding-left: 1.5rem; color: #a0aec0;">
                    ${result.actions_taken.map(act => `<li>${act}</li>`).join('')}
                </ul>
            </div>
        `;
    } catch (error) {
        showToast('Response failed', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Filters
function initFilters() {
    document.getElementById('alert-filter-severity').addEventListener('change', (e) => {
        const filters = {
            severity: e.target.value,
            status: document.getElementById('alert-filter-status').value
        };
        loadAlerts(Object.fromEntries(Object.entries(filters).filter(([_, v]) => v)));
    });
    
    document.getElementById('alert-filter-status').addEventListener('change', (e) => {
        const filters = {
            severity: document.getElementById('alert-filter-severity').value,
            status: e.target.value
        };
        loadAlerts(Object.fromEntries(Object.entries(filters).filter(([_, v]) => v)));
    });
}

// Real-time Updates
function startRealTimeUpdates() {
    // Simulate real-time updates every 30 seconds
    setInterval(() => {
        if (document.querySelector('[data-page="dashboard"]').classList.contains('active')) {
            API.fetch(`/dashboard/stats`)
                .then(r => r.json())
                .then(stats => updateStats(stats))
                .catch(console.error);
        }
    }, 30000);
}

// Utility Functions
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function showLoading() {
    document.getElementById('loading').classList.add('active');
}

function hideLoading() {
    document.getElementById('loading').classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const iconMap = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    
    toast.innerHTML = `
        <div class="toast-content">
            <div class="toast-icon">
                <i class="fas fa-${iconMap[type]}"></i>
            </div>
            <div>${message}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Team
async function loadTeam(filters = {}) {
    showLoading();
    try {
        const params = new URLSearchParams(filters);
        const team = await API.fetch(`/team?${params}`).then(r => r.json());
        renderTeam(team);
    } catch (error) {
        showToast('Failed to load team data', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderTeam(team) {
    const container = document.getElementById('team-list');
    container.innerHTML = '';
    
    if (team.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 3rem; color: #a0aec0;"><i class="fas fa-users" style="font-size: 3rem; margin-bottom: 1rem; color: #0066cc;"></i><br>No team members found</div>';
        return;
    }
    
    team.forEach(member => {
        const card = document.createElement('div');
        card.className = 'team-member-card';
        card.innerHTML = `
            <div class="team-member-header">
                <div>
                    <div class="team-member-name">${member.name}</div>
                    <div class="team-member-role">${member.role}</div>
                </div>
                <div>
                    <span class="status-indicator ${member.status}"></span>
                </div>
            </div>
            <div style="margin: 1rem 0;">
                <div style="color: #a0aec0; font-size: 0.9rem; margin-bottom: 0.5rem;">
                    <i class="fas fa-envelope"></i> ${member.email}
                </div>
                <div style="color: #a0aec0; font-size: 0.9rem; margin-bottom: 0.5rem;">
                    <i class="fas fa-clock"></i> ${member.shift}
                </div>
                <div style="color: #a0aec0; font-size: 0.9rem;">
                    <i class="fas fa-briefcase"></i> ${member.experience_years} years experience
                </div>
            </div>
            <div class="team-member-stats">
                <div class="team-stat">
                    <div class="team-stat-value">${member.cases_handled}</div>
                    <div class="team-stat-label">Cases</div>
                </div>
                <div class="team-stat">
                    <div class="team-stat-value">${member.avg_response_time}</div>
                    <div class="team-stat-label">Avg Response</div>
                </div>
            </div>
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #2d3748;">
                <div style="color: #00a3e0; font-size: 0.85rem; font-weight: bold; margin-bottom: 0.5rem;">Specialization</div>
                <div style="color: #a0aec0; font-size: 0.85rem;">${member.specialization}</div>
            </div>
            <div class="team-member-certs">
                ${member.certifications.map(cert => `<span class="cert-badge">${cert}</span>`).join('')}
            </div>
        `;
        container.appendChild(card);
    });
}

// Threat Intelligence
async function loadThreatIntel() {
    showLoading();
    try {
        const [feeds, recentThreats] = await Promise.all([
            API.fetch(`/threat-intel/feeds`).then(r => r.json()),
            API.fetch(`/threat-intel/recent`).then(r => r.json())
        ]);
        renderThreatFeeds(feeds);
        renderRecentThreats(recentThreats);
    } catch (error) {
        showToast('Failed to load threat intelligence', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderThreatFeeds(feeds) {
    const container = document.getElementById('threat-feeds-list');
    container.innerHTML = '';
    
    feeds.forEach(feed => {
        const card = document.createElement('div');
        card.className = 'feed-card';
        card.innerHTML = `
            <div class="feed-header">
                <div class="feed-name">${feed.name}</div>
                <div class="feed-status">
                    <i class="fas fa-circle"></i>
                    <span>${feed.status}</span>
                </div>
            </div>
            <div class="feed-stats">
                ${feed.pulses_count ? `<div class="feed-stat-item"><span>Pulses</span><span class="feed-stat-value">${feed.pulses_count.toLocaleString()}</span></div>` : ''}
                ${feed.indicators_count ? `<div class="feed-stat-item"><span>Indicators</span><span class="feed-stat-value">${feed.indicators_count.toLocaleString()}</span></div>` : ''}
                ${feed.malicious_ips ? `<div class="feed-stat-item"><span>Malicious IPs</span><span class="feed-stat-value">${feed.malicious_ips.toLocaleString()}</span></div>` : ''}
                ${feed.reports_count ? `<div class="feed-stat-item"><span>Reports</span><span class="feed-stat-value">${feed.reports_count.toLocaleString()}</span></div>` : ''}
                ${feed.scans_today ? `<div class="feed-stat-item"><span>Scans Today</span><span class="feed-stat-value">${feed.scans_today}</span></div>` : ''}
                ${feed.detections ? `<div class="feed-stat-item"><span>Detections</span><span class="feed-stat-value">${feed.detections}</span></div>` : ''}
                ${feed.rules_count ? `<div class="feed-stat-item"><span>Rules</span><span class="feed-stat-value">${feed.rules_count.toLocaleString()}</span></div>` : ''}
                ${feed.events ? `<div class="feed-stat-item"><span>Events</span><span class="feed-stat-value">${feed.events}</span></div>` : ''}
                ${feed.attributes ? `<div class="feed-stat-item"><span>Attributes</span><span class="feed-stat-value">${feed.attributes.toLocaleString()}</span></div>` : ''}
            </div>
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #2d3748; color: #a0aec0; font-size: 0.85rem;">
                <i class="fas fa-clock"></i> Updated: ${formatTime(feed.last_update)}
            </div>
        `;
        container.appendChild(card);
    });
}

function renderRecentThreats(threats) {
    const container = document.getElementById('recent-threats-list');
    container.innerHTML = '';
    
    threats.forEach(threat => {
        const item = document.createElement('div');
        item.className = 'recent-threat-item';
        item.innerHTML = `
            <div class="recent-threat-header">
                <div>
                    <div class="recent-threat-title">${threat.title}</div>
                    <div class="recent-threat-meta">
                        <div><i class="fas fa-shield-virus"></i> ${threat.source}</div>
                        <div><i class="fas fa-clock"></i> ${formatTime(threat.published)}</div>
                        <div><i class="fas fa-fingerprint"></i> ${threat.indicators} indicators</div>
                    </div>
                </div>
                <span class="badge ${threat.severity}">${threat.severity}</span>
            </div>
            <div style="color: #a0aec0; margin-top: 0.75rem;">${threat.description}</div>
        `;
        container.appendChild(item);
    });
}

// Team filter initialization
function initTeamFilters() {
    const statusFilter = document.getElementById('team-filter-status');
    if (statusFilter) {
        statusFilter.addEventListener('change', (e) => {
            const filters = {};
            if (e.target.value) {
                filters.status = e.target.value;
            }
            loadTeam(filters);
        });
    }
}

// Initialize filters on load
document.addEventListener('DOMContentLoaded', () => {
    initTeamFilters();
});
