// SOC Automation Dashboard - Main Application

// Detect deployment environment
const isGitHubPages = window.location.hostname.includes('github.io') || 
                       (window.location.protocol === 'file:') ||
                       (!window.location.hostname.includes('localhost') && !window.location.port);

const API_BASE = isGitHubPages ? null : 'http://localhost:5000/api';

// API wrapper that uses mock data when backend unavailable
const API = {
    async fetch(endpoint, options = {}) {
        // Add Authorization header if token exists
        if (authState.token && (!options.headers || !options.headers.Authorization)) {
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${authState.token}`
            };
        }
        
        if (API_BASE && !isGitHubPages) {
            try {
                const response = await window.fetch(`${API_BASE}${endpoint}`, options);
                
                // Handle 401 Unauthorized
                if (response.status === 401) {
                    console.log('Unauthorized - clearing token and showing login');
                    localStorage.removeItem('auth_token');
                    localStorage.removeItem('user_info');
                    authState.token = null;
                    authState.user = null;
                    authState.isAuthenticated = false;
                    showLoginScreen();
                    return { ok: false, status: 401, json: async () => ({ error: 'Unauthorized' }) };
                }
                
                if (response.ok) {
                    return response;
                }
            } catch (error) {
                console.log('Backend unavailable, falling back to mock data');
            }
        }
        
        // Use mock data - return Response-like object
        // Note: Only .json() and .ok are needed by current call sites
        const data = this.mockResponse(endpoint, options);
        return {
            ok: true,
            json: async () => data
        };
    },
    
    mockResponse(endpoint, options) {
        // Parse endpoint and return appropriate mock data
        if (endpoint === '/auth/login') {
            const body = options.body ? JSON.parse(options.body) : {};
            // Use crypto.getRandomValues for better security in mock mode
            const randomValues = new Uint32Array(4);
            crypto.getRandomValues(randomValues);
            const token = 'mock-' + Array.from(randomValues).map(v => v.toString(16)).join('-');
            return {
                token,
                user: {
                    id: 1,
                    username: body.username || 'demo',
                    display_name: body.username === 'admin' ? 'Admin User' : 'Demo Analyst',
                    role: body.username === 'admin' ? 'admin' : 't1_analyst',
                    permissions: {
                        investigate: true,
                        respond: body.username === 'admin' || body.username === 't3_analyst',
                        manage_playbooks: body.username === 'admin' || body.username === 'soc_manager'
                    }
                }
            };
        }
        if (endpoint === '/auth/logout') return { success: true };
        if (endpoint === '/auth/validate') {
            return {
                valid: true,
                user: authState.user || { username: 'demo', display_name: 'Demo User', role: 'admin' }
            };
        }
        if (endpoint.startsWith('/audit-log')) {
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getAuditLogs ? MOCK_DATA.getAuditLogs(Object.fromEntries(params)) : { logs: [], total: 0 };
        }
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
        if (endpoint.startsWith('/playbooks/') && endpoint.includes('/execute')) {
            const playbookId = parseInt(endpoint.match(/\/playbooks\/(\d+)/)[1]);
            return MOCK_DATA.executePlaybook(playbookId);
        }
        if (endpoint.startsWith('/playbooks/') && endpoint.includes('/steps')) {
            const playbookId = parseInt(endpoint.match(/\/playbooks\/(\d+)/)[1]);
            return MOCK_DATA.getPlaybookSteps(playbookId);
        }
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

// Authentication State Management
const authState = {
    token: null,
    user: null,
    isAuthenticated: false
};

// Check for stored token on load
function checkAuth() {
    const token = localStorage.getItem('auth_token');
    if (token) {
        authState.token = token;
        authState.isAuthenticated = true;
        
        // Try to get user info from token or make API call
        const userInfo = localStorage.getItem('user_info');
        if (userInfo) {
            try {
                authState.user = JSON.parse(userInfo);
                updateUIForAuthenticatedUser();
            } catch (e) {
                console.error('Failed to parse user info:', e);
                showLoginScreen();
            }
        } else {
            // In production, validate token with backend
            if (!isGitHubPages) {
                validateToken().then(valid => {
                    if (!valid) showLoginScreen();
                });
            } else {
                // Mock mode - use stored user or default
                authState.user = { display_name: 'Demo User', role: 'admin' };
                updateUIForAuthenticatedUser();
            }
        }
    } else {
        showLoginScreen();
    }
}

async function validateToken() {
    try {
        const response = await window.fetch(`${API_BASE}/auth/validate`, {
            headers: { 'Authorization': `Bearer ${authState.token}` }
        });
        if (response.ok) {
            const data = await response.json();
            authState.user = data.user;
            localStorage.setItem('user_info', JSON.stringify(data.user));
            updateUIForAuthenticatedUser();
            return true;
        }
        return false;
    } catch (error) {
        console.error('Token validation failed:', error);
        return false;
    }
}

function showLoginScreen() {
    authState.isAuthenticated = false;
    const loginOverlay = document.getElementById('login-overlay');
    if (loginOverlay) {
        loginOverlay.style.display = 'flex';
    }
}

function hideLoginScreen() {
    const loginOverlay = document.getElementById('login-overlay');
    if (loginOverlay) {
        loginOverlay.style.display = 'none';
    }
}

function updateUIForAuthenticatedUser() {
    hideLoginScreen();
    
    if (!authState.user) return;
    
    // Update user display
    const displayName = document.getElementById('user-display-name');
    if (displayName) {
        displayName.textContent = authState.user.display_name || authState.user.username || 'User';
    }
    
    // Update role badge
    const roleBadge = document.getElementById('user-role-badge');
    if (roleBadge) {
        const role = authState.user.role || 'analyst';
        roleBadge.textContent = role.replace('_', ' ').toUpperCase();
        roleBadge.className = 'role-badge ' + role;
    }
    
    // Show logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.style.display = 'block';
    }
    
    // Role-based UI updates
    updateRoleBasedUI();
}

function updateRoleBasedUI() {
    if (!authState.user) return;
    
    const role = authState.user.role;
    
    // Show/hide audit log nav (only admin and soc_manager)
    const auditLogNav = document.getElementById('audit-log-nav');
    if (auditLogNav) {
        auditLogNav.style.display = (role === 'admin' || role === 'soc_manager') ? 'block' : 'none';
    }
    
    // Check permissions for investigate and respond buttons
    const permissions = authState.user.permissions || {};
    
    // Show/hide investigate button
    const investigateBtns = document.querySelectorAll('.investigate-btn, #investigate-btn');
    investigateBtns.forEach(btn => {
        if (permissions.investigate === false) {
            btn.style.display = 'none';
        }
    });
    
    // Show/hide respond button
    const respondBtns = document.querySelectorAll('.respond-btn, #respond-btn');
    respondBtns.forEach(btn => {
        if (permissions.respond === false) {
            btn.style.display = 'none';
        }
    });
}

// Login Handler
function initAuthHandlers() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username')?.value;
            const password = document.getElementById('password')?.value;
            const errorDiv = document.getElementById('login-error');
            
            if (!username && !password) {
                if (errorDiv) errorDiv.textContent = 'Please enter username and password';
                return;
            }
            if (!username) {
                if (errorDiv) errorDiv.textContent = 'Please enter username';
                return;
            }
            if (!password) {
                if (errorDiv) errorDiv.textContent = 'Please enter password';
                return;
            }
            
            try {
                const response = await API.fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok && data.token) {
                    // Store token and user info
                    localStorage.setItem('auth_token', data.token);
                    localStorage.setItem('user_info', JSON.stringify(data.user));
                    
                    authState.token = data.token;
                    authState.user = data.user;
                    authState.isAuthenticated = true;
                    
                    // Update UI
                    updateUIForAuthenticatedUser();
                    
                    // Clear form
                    loginForm.reset();
                    if (errorDiv) errorDiv.textContent = '';
                    
                    // Load dashboard
                    loadDashboard();
                } else {
                    if (errorDiv) errorDiv.textContent = data.error || 'Login failed';
                }
            } catch (error) {
                console.error('Login error:', error);
                if (errorDiv) errorDiv.textContent = 'Login failed. Please try again.';
            }
        });
    }
    
    // Logout Handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                // Call logout endpoint
                await API.fetch('/auth/logout', { method: 'POST' });
            } catch (error) {
                console.error('Logout error:', error);
            }
            
            // Clear local state
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_info');
            authState.token = null;
            authState.user = null;
            authState.isAuthenticated = false;
            
            // Show login screen
            showLoginScreen();
        });
    }
}

// State Management
const state = {
    alerts: [],
    threats: [],
    incidents: [],
    playbooks: [],
    currentAlert: null,
    currentThreat: null,
    currentIncident: null,
    currentPlaybook: null
};

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', async () => {
    // Wait for mock data to be ready before rendering
    if (typeof MOCK_DATA_READY !== 'undefined') {
        try {
            await MOCK_DATA_READY;
        } catch (error) {
            console.error('Failed to load mock data, dashboard may not display correctly:', error);
        }
    } else {
        console.warn('MOCK_DATA_READY is not defined - mock-api.js may not be loaded');
    }

    // Initialize authentication
    initAuthHandlers();
    checkAuth();
    
    initNavigation();
    
    // Only load dashboard if authenticated
    if (authState.isAuthenticated) {
        loadDashboard();
        startRealTimeUpdates();
    }
    
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
    document.querySelector(`[data-page="${page}"]`)?.classList.add('active');
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });
    document.getElementById(`${page}-page`)?.classList.add('active');
    
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
        case 'audit-log':
            loadAuditLog();
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
        
        item.addEventListener('click', () => showThreatDetails(threat));
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
        
        item.addEventListener('click', () => showIncidentDetails(incident));
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
            <div class="playbook-actions">
                <button class="playbook-btn playbook-btn-primary" onclick="runPlaybook(${playbook.id})">
                    <i class="fas fa-play"></i> Run Playbook
                </button>
                <button class="playbook-btn playbook-btn-secondary" onclick="viewPlaybookSteps(${playbook.id})">
                    <i class="fas fa-list"></i> View Steps
                </button>
            </div>
            <div id="playbook-steps-${playbook.id}" style="display: none;"></div>
            <div id="playbook-execution-${playbook.id}" style="display: none;"></div>
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
    
    // Create tabbed interface
    modalBody.innerHTML = `
        <div class="modal-tabs">
            <button class="modal-tab active" data-tab="details">Details</button>
            <button class="modal-tab" data-tab="notes">Notes</button>
            <button class="modal-tab" data-tab="evidence">Evidence</button>
            <button class="modal-tab" data-tab="sla">SLA</button>
        </div>
        <div class="tab-content active" id="details-tab">
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
        </div>
        <div class="tab-content" id="notes-tab">
            <div id="notes-content">Loading notes...</div>
        </div>
        <div class="tab-content" id="evidence-tab">
            <div id="evidence-content">Loading evidence...</div>
        </div>
        <div class="tab-content" id="sla-tab">
            <div id="sla-content">Loading SLA data...</div>
        </div>
    `;
    
    // Set up tab switching
    const tabs = modalBody.querySelectorAll('.modal-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.dataset.tab;
            
            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Update active content
            modalBody.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`${targetTab}-tab`).classList.add('active');
            
            // Load content if not already loaded
            if (targetTab === 'notes' && document.getElementById('notes-content').innerHTML === 'Loading notes...') {
                loadNotes(alert.id);
            } else if (targetTab === 'evidence' && document.getElementById('evidence-content').innerHTML === 'Loading evidence...') {
                loadEvidence(alert.id);
            } else if (targetTab === 'sla' && document.getElementById('sla-content').innerHTML === 'Loading SLA data...') {
                loadSLA(alert.id);
            }
        });
    });
    
    modal.classList.add('active');
}

// Load notes for alert
async function loadNotes(alertId) {
    const notesContent = document.getElementById('notes-content');
    try {
        const response = await API.fetch(`/alerts/${alertId}/notes`);
        const notes = await response.json();
        
        const permissions = authState.user?.permissions || {};
        const canAddNotes = permissions.add_notes || authState.user?.role === 'admin';
        
        let html = '<div style="max-height: 400px; overflow-y: auto;">';
        
        if (notes.length === 0) {
            html += '<p style="color: #a0aec0; text-align: center; padding: 2rem;">No notes yet</p>';
        } else {
            notes.forEach(note => {
                const pinnedClass = note.is_pinned ? ' pinned' : '';
                const pinnedIcon = note.is_pinned ? '<i class="fas fa-thumbtack" style="color: #ffc107; margin-right: 0.5rem;"></i>' : '';
                
                html += `
                    <div class="note-card${pinnedClass}">
                        <div class="note-header">
                            <div>
                                ${pinnedIcon}
                                <strong style="color: #00a3e0;">${note.author_name}</strong>
                                <span class="badge ${note.type}" style="margin-left: 0.5rem; font-size: 0.75rem;">${note.type.replace('_', ' ')}</span>
                            </div>
                            <span style="color: #6c757d; font-size: 0.875rem;">${new Date(note.created_at).toLocaleString()}</span>
                        </div>
                        <div class="note-content">
                            <p style="color: #a0aec0; margin: 0.5rem 0;">${note.content}</p>
                            ${note.tags && note.tags.length > 0 ? `
                                <div style="margin-top: 0.5rem;">
                                    ${note.tags.map(tag => `<span class="indicator-tag" style="font-size: 0.75rem;"><i class="fas fa-tag"></i> ${tag}</span>`).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
        }
        
        html += '</div>';
        
        // Add note form
        if (canAddNotes) {
            html += `
                <div class="add-form" style="margin-top: 1rem;">
                    <h4 style="color: #00a3e0; margin-bottom: 0.75rem;">Add Note</h4>
                    <form id="add-note-form">
                        <textarea id="note-content" placeholder="Enter investigation note..." rows="4" required style="width: 100%; margin-bottom: 0.75rem; padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px;"></textarea>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem;">
                            <select id="note-type" required style="padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px;">
                                <option value="">Select type...</option>
                                <option value="investigation_note">Investigation Note</option>
                                <option value="escalation_note">Escalation Note</option>
                                <option value="response_note">Response Note</option>
                            </select>
                            <input type="text" id="note-tags" placeholder="Tags (comma-separated)" style="padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px;">
                        </div>
                        <button type="submit" class="btn btn-primary">Add Note</button>
                    </form>
                </div>
            `;
        }
        
        notesContent.innerHTML = html;
        
        // Attach event listener for add note form
        if (canAddNotes) {
            const form = document.getElementById('add-note-form');
            if (form) {
                form.addEventListener('submit', (event) => handleAddNote(event, alertId));
            }
        }
    } catch (error) {
        notesContent.innerHTML = '<p style="color: #dc3545;">Failed to load notes</p>';
        console.error('Error loading notes:', error);
    }
}

// Handle add note form submission
async function handleAddNote(event, alertId) {
    event.preventDefault();
    
    const content = document.getElementById('note-content').value;
    const noteType = document.getElementById('note-type').value;
    const tagsInput = document.getElementById('note-tags').value;
    const tags = tagsInput ? tagsInput.split(',').map(t => t.trim()).filter(t => t) : [];
    
    try {
        await API.fetch(`/alerts/${alertId}/notes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                content,
                type: noteType,
                tags
            })
        });
        
        showToast('Note added successfully', 'success');
        loadNotes(alertId);
    } catch (error) {
        showToast('Failed to add note', 'error');
        console.error('Error adding note:', error);
    }
    
    return false;
}

// Load evidence for alert
async function loadEvidence(alertId) {
    const evidenceContent = document.getElementById('evidence-content');
    try {
        const response = await API.fetch(`/alerts/${alertId}/evidence`);
        const evidenceItems = await response.json();
        
        const permissions = authState.user?.permissions || {};
        const canAddEvidence = permissions.add_evidence || authState.user?.role === 'admin';
        
        let html = '<div style="max-height: 400px; overflow-y: auto;">';
        
        if (evidenceItems.length === 0) {
            html += '<p style="color: #a0aec0; text-align: center; padding: 2rem;">No evidence collected yet</p>';
        } else {
            evidenceItems.forEach(evidence => {
                const typeIcons = {
                    'file_hash': 'fa-file-code',
                    'ip_address': 'fa-network-wired',
                    'domain': 'fa-globe',
                    'url': 'fa-link',
                    'email': 'fa-envelope'
                };
                const icon = typeIcons[evidence.type] || 'fa-database';
                
                html += `
                    <div class="evidence-item">
                        <div class="evidence-header">
                            <div>
                                <i class="fas ${icon}" style="color: #00a3e0; margin-right: 0.5rem;"></i>
                                <strong style="color: #00a3e0;">${evidence.type.replace('_', ' ').toUpperCase()}</strong>
                                <span class="badge ${evidence.status}" style="margin-left: 0.5rem; font-size: 0.75rem;">${evidence.status}</span>
                            </div>
                        </div>
                        <div class="evidence-value" style="font-family: 'Courier New', monospace; color: #ffc107; margin: 0.5rem 0; padding: 0.5rem; background: #0d1117; border-radius: 4px;">
                            ${evidence.value}
                            ${evidence.hash_type ? `<span style="color: #6c757d; font-size: 0.875rem;"> (${evidence.hash_type})</span>` : ''}
                        </div>
                        ${evidence.description ? `
                            <p style="color: #a0aec0; margin: 0.5rem 0;">${evidence.description}</p>
                        ` : ''}
                        ${evidence.chain_of_custody && evidence.chain_of_custody.length > 0 ? `
                            <div style="margin-top: 0.75rem; padding-left: 1rem; border-left: 2px solid #2d3548;">
                                <strong style="color: #6c757d; font-size: 0.875rem;">Chain of Custody:</strong>
                                ${evidence.chain_of_custody.map(entry => `
                                    <div style="margin-top: 0.25rem; font-size: 0.875rem; color: #a0aec0;">
                                        <i class="fas fa-chevron-right" style="font-size: 0.5rem; margin-right: 0.25rem;"></i>
                                        ${entry.action} by ${entry.by} at ${new Date(entry.at).toLocaleString()}
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                        <div style="margin-top: 0.75rem; font-size: 0.875rem; color: #6c757d;">
                            Collected by <strong>${evidence.collected_by_name}</strong> at ${new Date(evidence.collected_at).toLocaleString()}
                        </div>
                        ${evidence.tags && evidence.tags.length > 0 ? `
                            <div style="margin-top: 0.5rem;">
                                ${evidence.tags.map(tag => `<span class="indicator-tag" style="font-size: 0.75rem;"><i class="fas fa-tag"></i> ${tag}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                `;
            });
        }
        
        html += '</div>';
        
        // Add evidence form
        if (canAddEvidence) {
            html += `
                <div class="add-form" style="margin-top: 1rem;">
                    <h4 style="color: #00a3e0; margin-bottom: 0.75rem;">Add Evidence</h4>
                    <form id="add-evidence-form">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem;">
                            <select id="evidence-type" required style="padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px;">
                                <option value="">Select type...</option>
                                <option value="file_hash">File Hash</option>
                                <option value="ip_address">IP Address</option>
                                <option value="domain">Domain</option>
                                <option value="url">URL</option>
                                <option value="email">Email</option>
                            </select>
                            <select id="hash-type" style="padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px; display: none;">
                                <option value="">Select hash type...</option>
                                <option value="md5">MD5</option>
                                <option value="sha1">SHA1</option>
                                <option value="sha256">SHA256</option>
                            </select>
                        </div>
                        <input type="text" id="evidence-value" placeholder="Evidence value" required style="width: 100%; margin-bottom: 0.75rem; padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px; font-family: 'Courier New', monospace;">
                        <textarea id="evidence-description" placeholder="Description (optional)" rows="2" style="width: 100%; margin-bottom: 0.75rem; padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px;"></textarea>
                        <input type="text" id="evidence-tags" placeholder="Tags (comma-separated)" style="width: 100%; margin-bottom: 0.75rem; padding: 0.5rem; background: #1a1f2e; border: 1px solid #2d3548; color: #e0e0e0; border-radius: 4px;">
                        <button type="submit" class="btn btn-primary">Add Evidence</button>
                    </form>
                </div>
            `;
        }
        
        evidenceContent.innerHTML = html;
        
        // Attach event listeners for add evidence form
        if (canAddEvidence) {
            const form = document.getElementById('add-evidence-form');
            if (form) {
                form.addEventListener('submit', (event) => handleAddEvidence(event, alertId));
            }
            
            const typeSelect = document.getElementById('evidence-type');
            if (typeSelect) {
                typeSelect.addEventListener('change', toggleHashType);
            }
        }
    } catch (error) {
        evidenceContent.innerHTML = '<p style="color: #dc3545;">Failed to load evidence</p>';
        console.error('Error loading evidence:', error);
    }
}

// Toggle hash type field visibility
function toggleHashType() {
    const evidenceType = document.getElementById('evidence-type').value;
    const hashTypeField = document.getElementById('hash-type');
    if (hashTypeField) {
        hashTypeField.style.display = evidenceType === 'file_hash' ? 'block' : 'none';
        hashTypeField.required = evidenceType === 'file_hash';
    }
}

// Handle add evidence form submission
async function handleAddEvidence(event, alertId) {
    event.preventDefault();
    
    const evidenceType = document.getElementById('evidence-type').value;
    const value = document.getElementById('evidence-value').value;
    const description = document.getElementById('evidence-description').value;
    const tagsInput = document.getElementById('evidence-tags').value;
    const tags = tagsInput ? tagsInput.split(',').map(t => t.trim()).filter(t => t) : [];
    
    const payload = {
        type: evidenceType,
        value,
        description,
        tags
    };
    
    if (evidenceType === 'file_hash') {
        const hashType = document.getElementById('hash-type').value;
        if (!hashType) {
            showToast('Please select hash type', 'error');
            return false;
        }
        payload.hash_type = hashType;
    }
    
    try {
        await API.fetch(`/alerts/${alertId}/evidence`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        showToast('Evidence added successfully', 'success');
        loadEvidence(alertId);
    } catch (error) {
        showToast('Failed to add evidence', 'error');
        console.error('Error adding evidence:', error);
    }
    
    return false;
}

// Load SLA data for alert
async function loadSLA(alertId) {
    const slaContent = document.getElementById('sla-content');
    try {
        const response = await API.fetch(`/alerts/${alertId}/sla`);
        const sla = await response.json();
        
        // Calculate percentage (already provided by backend)
        const percentage = sla.percentage || 0;
        
        // Determine status and color
        let statusColor = '#28a745'; // green
        let statusText = 'Normal';
        if (sla.status === 'breached') {
            statusColor = '#dc3545'; // red
            statusText = 'BREACHED';
        } else if (sla.status === 'warning') {
            statusColor = '#ffc107'; // yellow
            statusText = 'Warning';
        }
        
        // Format remaining time
        let remainingText = '';
        if (sla.is_breached) {
            remainingText = `<span style="color: #dc3545; font-weight: bold;">BREACHED</span>`;
        } else if (sla.remaining_minutes !== undefined) {
            const hours = Math.floor(Math.abs(sla.remaining_minutes) / 60);
            const minutes = Math.floor(Math.abs(sla.remaining_minutes) % 60);
            remainingText = `${hours}h ${minutes}m remaining`;
        }
        
        const html = `
            <div class="sla-timer">
                <div style="margin-bottom: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <h4 style="color: #00a3e0; margin: 0;">SLA Status: <span style="color: ${statusColor};">${statusText}</span></h4>
                        <span style="color: #a0aec0;">${remainingText}</span>
                    </div>
                    <div class="sla-progress">
                        <div class="sla-progress-bar" style="width: ${percentage}%; background-color: ${statusColor};"></div>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 1rem;">
                    <div style="padding: 1rem; background: rgba(0, 163, 224, 0.1); border-radius: 8px;">
                        <div style="color: #6c757d; font-size: 0.875rem; margin-bottom: 0.25rem;">Time Elapsed</div>
                        <div style="color: #00a3e0; font-size: 1.5rem; font-weight: bold;">
                            ${Math.floor(sla.elapsed_minutes / 60)}h ${Math.floor(sla.elapsed_minutes % 60)}m
                        </div>
                    </div>
                    <div style="padding: 1rem; background: rgba(0, 163, 224, 0.1); border-radius: 8px;">
                        <div style="color: #6c757d; font-size: 0.875rem; margin-bottom: 0.25rem;">SLA Target</div>
                        <div style="color: #00a3e0; font-size: 1.5rem; font-weight: bold;">
                            ${Math.floor(sla.sla_minutes / 60)}h ${Math.floor(sla.sla_minutes % 60)}m
                        </div>
                    </div>
                </div>
                
                <div style="padding: 1rem; background: rgba(45, 53, 72, 0.5); border-radius: 8px;">
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; font-size: 0.875rem;">
                        <div>
                            <span style="color: #6c757d;">Severity Level:</span>
                            <div style="color: #a0aec0; margin-top: 0.25rem; text-transform: uppercase;">${sla.severity}</div>
                        </div>
                        <div>
                            <span style="color: #6c757d;">Alert ID:</span>
                            <div style="color: #a0aec0; margin-top: 0.25rem;">#${sla.alert_id}</div>
                        </div>
                    </div>
                </div>
                
                ${sla.is_breached ? `
                    <div style="margin-top: 1rem; padding: 1rem; background: rgba(220, 53, 69, 0.1); border-left: 3px solid #dc3545; border-radius: 8px;">
                        <strong style="color: #dc3545;"><i class="fas fa-exclamation-triangle"></i> SLA Breach</strong>
                        <p style="margin-top: 0.5rem; color: #a0aec0;">
                            This alert has exceeded its SLA target by ${Math.floor(Math.abs(sla.remaining_minutes) / 60)} hours and ${Math.floor(Math.abs(sla.remaining_minutes) % 60)} minutes.
                        </p>
                    </div>
                ` : ''}
            </div>
        `;
        
        slaContent.innerHTML = html;
    } catch (error) {
        slaContent.innerHTML = '<p style="color: #dc3545;">Failed to load SLA data</p>';
        console.error('Error loading SLA:', error);
    }
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

// Threat Detail Modal
function showThreatDetails(threat) {
    state.currentThreat = threat;
    const modal = document.getElementById('alert-modal');
    const modalBody = document.getElementById('modal-body');
    
    // Derive MITRE ATT&CK mapping from threat type
    const mitreMapping = {
        'malware': ['Initial Access', 'Execution', 'Persistence'],
        'ransomware': ['Impact', 'Command and Control', 'Exfiltration'],
        'phishing': ['Initial Access', 'Credential Access'],
        'ddos': ['Impact', 'Resource Development'],
        'botnet': ['Command and Control', 'Execution'],
        'apt': ['Reconnaissance', 'Initial Access', 'Lateral Movement'],
        'intrusion': ['Initial Access', 'Privilege Escalation', 'Persistence']
    };
    
    const mitreTactics = mitreMapping[threat.type.toLowerCase()] || ['Unknown'];
    
    // Derive kill chain phase from threat type
    const killChainPhases = {
        'malware': 'Delivery / Installation',
        'ransomware': 'Actions on Objectives',
        'phishing': 'Reconnaissance / Weaponization',
        'ddos': 'Actions on Objectives',
        'botnet': 'Command and Control',
        'apt': 'Reconnaissance / Exploitation',
        'intrusion': 'Exploitation / Installation'
    };
    
    const killChain = killChainPhases[threat.type.toLowerCase()] || 'Unknown';
    
    // Generate recommended actions based on threat type
    const recommendedActions = {
        'malware': ['Isolate affected systems immediately', 'Run full malware scan', 'Block C2 communications', 'Update antivirus signatures'],
        'ransomware': ['Isolate infected hosts', 'Disable affected user accounts', 'Block file encryption activities', 'Initiate backup restoration procedures'],
        'phishing': ['Quarantine malicious emails', 'Block sender domain', 'Reset credentials of affected users', 'Increase email security awareness'],
        'ddos': ['Enable DDoS mitigation', 'Block attacking IP ranges', 'Scale infrastructure resources', 'Contact ISP for upstream filtering'],
        'botnet': ['Block C2 server communications', 'Isolate infected machines', 'Remove malware', 'Update security policies'],
        'apt': ['Preserve forensic evidence', 'Isolate compromised systems', 'Identify lateral movement paths', 'Engage incident response team'],
        'intrusion': ['Isolate compromised systems', 'Patch exploited vulnerabilities', 'Reset affected credentials', 'Review access logs']
    };
    
    const actions = recommendedActions[threat.type.toLowerCase()] || ['Investigate further', 'Monitor for suspicious activity'];
    
    document.getElementById('modal-title').innerHTML = `<i class="fas fa-bug"></i> ${threat.name}`;
    
    // Update button texts for threat context
    document.getElementById('investigate-btn').innerHTML = '<i class="fas fa-search"></i> Investigate';
    document.getElementById('respond-btn').innerHTML = '<i class="fas fa-ban"></i> Block Threat';
    
    modalBody.innerHTML = `
        <div style="display: flex; gap: 1rem; margin-bottom: 1rem;">
            <span class="badge ${threat.severity}">${threat.severity}</span>
            <span class="badge ${threat.action}">${threat.action}</span>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Description:</strong>
            <p style="margin-top: 0.5rem; color: #a0aec0;">${threat.description}</p>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Network Flow Details:</strong>
            <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                <div><i class="fas fa-arrow-right"></i> Source IP: <span style="color: #a0aec0;">${threat.source_ip}</span></div>
                <div><i class="fas fa-bullseye"></i> Destination IP: <span style="color: #a0aec0;">${threat.destination_ip}</span></div>
                <div><i class="fas fa-globe"></i> Country: <span style="color: #a0aec0;">${threat.country}</span></div>
                <div><i class="fas fa-shield-virus"></i> Type: <span style="color: #a0aec0;">${threat.type}</span></div>
            </div>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Threat Intelligence:</strong>
            <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                <div><i class="fas fa-fingerprint"></i> IOCs Detected: <span style="color: #a0aec0;">${threat.indicators}</span></div>
                <div><i class="fas fa-percentage"></i> Confidence: <span style="color: #a0aec0;">${threat.confidence}%</span></div>
                <div><i class="fas fa-layer-group"></i> Kill Chain: <span style="color: #a0aec0;">${killChain}</span></div>
                <div><i class="fas fa-clock"></i> Detected: <span style="color: #a0aec0;">${formatTime(threat.timestamp)}</span></div>
            </div>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">MITRE ATT&CK Mapping:</strong>
            <div class="alert-indicators" style="margin-top: 0.5rem;">
                ${mitreTactics.map(tactic => `<span class="indicator-tag">${tactic}</span>`).join('')}
            </div>
        </div>
        <div>
            <strong style="color: #00a3e0;">Recommended Containment Actions:</strong>
            <ul style="margin-top: 0.5rem; padding-left: 1.5rem; color: #a0aec0;">
                ${actions.map(action => `<li>${action}</li>`).join('')}
            </ul>
        </div>
    `;
    
    modal.classList.add('active');
}

// Incident Detail Modal
function showIncidentDetails(incident) {
    state.currentIncident = incident;
    const modal = document.getElementById('alert-modal');
    const modalBody = document.getElementById('modal-body');
    
    document.getElementById('modal-title').innerHTML = `<i class="fas fa-fire"></i> ${incident.title}`;
    
    // Update button texts for incident context
    document.getElementById('investigate-btn').innerHTML = '<i class="fas fa-level-up-alt"></i> Escalate';
    document.getElementById('respond-btn').innerHTML = '<i class="fas fa-edit"></i> Update Status';
    
    // Generate incident timeline entries
    const timeline = [
        { time: incident.created, event: 'Incident created', type: 'info' },
        { time: incident.updated, event: 'Last updated', type: 'info' },
        { time: new Date(new Date(incident.created).getTime() + 10*60000).toISOString(), event: `Assigned to ${incident.assignee}`, type: 'success' }
    ];
    
    // Add timeline entries for response actions
    incident.response_actions.forEach((action, index) => {
        const actionTime = new Date(new Date(incident.created).getTime() + (15 + index * 5) * 60000).toISOString();
        timeline.push({ time: actionTime, event: action, type: 'success' });
    });
    
    timeline.sort((a, b) => new Date(a.time) - new Date(b.time));
    
    modalBody.innerHTML = `
        <div style="display: flex; gap: 1rem; margin-bottom: 1rem;">
            <span class="badge ${incident.severity}">${incident.severity}</span>
            <span class="badge ${incident.status}">${incident.status}</span>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Description:</strong>
            <p style="margin-top: 0.5rem; color: #a0aec0;">${incident.description}</p>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Impact Assessment:</strong>
            <p style="margin-top: 0.5rem; color: #a0aec0;">${incident.impact}</p>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Incident Details:</strong>
            <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                <div><i class="fas fa-user-shield"></i> Assignee: <span style="color: #a0aec0;">${incident.assignee}</span></div>
                <div><i class="fas fa-clock"></i> Created: <span style="color: #a0aec0;">${formatTime(incident.created)}</span></div>
                <div><i class="fas fa-sync"></i> Updated: <span style="color: #a0aec0;">${formatTime(incident.updated)}</span></div>
                <div><i class="fas fa-exclamation-circle"></i> Severity: <span class="badge ${incident.severity}">${incident.severity}</span></div>
            </div>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Affected Systems:</strong>
            <div class="alert-indicators" style="margin-top: 0.5rem;">
                ${incident.affected_systems.map(sys => `<span class="indicator-tag"><i class="fas fa-server"></i> ${sys}</span>`).join('')}
            </div>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: #00a3e0;">Response Actions Taken:</strong>
            <ul style="margin-top: 0.5rem; padding-left: 1.5rem; color: #a0aec0;">
                ${incident.response_actions.map(action => `<li><i class="fas fa-check" style="color: #28a745; margin-right: 0.5rem;"></i>${action}</li>`).join('')}
            </ul>
        </div>
        <div>
            <strong style="color: #00a3e0;">Incident Timeline:</strong>
            <div style="margin-top: 0.75rem;">
                ${timeline.map(entry => `
                    <div style="padding: 0.5rem; margin-bottom: 0.5rem; background: rgba(255, 255, 255, 0.03); border-left: 3px solid var(--primary-color); border-radius: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #a0aec0;">${entry.event}</span>
                            <span style="color: #718096; font-size: 0.85rem;">${formatTime(entry.time)}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
    
    modal.classList.add('active');
}

// Playbook Functions
async function viewPlaybookSteps(playbookId) {
    const container = document.getElementById(`playbook-steps-${playbookId}`);
    
    if (container.style.display === 'block') {
        container.style.display = 'none';
        return;
    }
    
    showLoading();
    try {
        const steps = await API.fetch(`/playbooks/${playbookId}/steps`).then(r => r.json());
        
        container.innerHTML = `
            <div class="playbook-steps-list">
                <strong style="color: #00a3e0; margin-bottom: 0.75rem; display: block;">
                    <i class="fas fa-list-ol"></i> Playbook Steps
                </strong>
                ${steps.map((step, index) => `
                    <div class="playbook-step">
                        <div class="step-number">${step.order}</div>
                        <div class="step-content">
                            <div class="step-name">${step.name}</div>
                            <div class="step-duration"><i class="fas fa-clock"></i> Expected duration: ${step.duration}</div>
                        </div>
                        <div class="step-status pending">Pending</div>
                    </div>
                `).join('')}
            </div>
        `;
        
        container.style.display = 'block';
    } catch (error) {
        showToast('Failed to load playbook steps', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

async function runPlaybook(playbookId) {
    const playbook = state.playbooks.find(p => p.id === playbookId);
    if (!playbook) return;
    
    const executionContainer = document.getElementById(`playbook-execution-${playbookId}`);
    const stepsContainer = document.getElementById(`playbook-steps-${playbookId}`);
    
    // Hide steps if visible
    stepsContainer.style.display = 'none';
    
    showLoading();
    
    try {
        const result = await API.fetch(`/playbooks/${playbookId}/execute`, {
            method: 'POST'
        }).then(r => r.json());
        
        // Show execution in progress
        executionContainer.innerHTML = `
            <div class="playbook-execution">
                <div class="execution-header">
                    <div class="execution-title"><i class="fas fa-cog fa-spin"></i> Executing Playbook...</div>
                    <div class="execution-status">
                        <span id="exec-progress-${playbookId}">0/${result.steps.length}</span>
                    </div>
                </div>
                <div class="step-progress">
                    <div class="progress-bar">
                        <div class="progress-fill" id="exec-progress-bar-${playbookId}" style="width: 0%;"></div>
                    </div>
                </div>
                <div id="exec-steps-${playbookId}" style="margin-top: 1rem;"></div>
            </div>
        `;
        executionContainer.style.display = 'block';
        
        hideLoading();
        
        // Animate step execution
        const stepsDiv = document.getElementById(`exec-steps-${playbookId}`);
        const progressBar = document.getElementById(`exec-progress-bar-${playbookId}`);
        const progressText = document.getElementById(`exec-progress-${playbookId}`);
        
        for (let i = 0; i < result.steps.length; i++) {
            const step = result.steps[i];
            const duration = parseInt(step.duration) || 15;
            
            // Add step to execution display
            const stepDiv = document.createElement('div');
            stepDiv.className = 'playbook-step';
            stepDiv.innerHTML = `
                <div class="step-number">${step.order}</div>
                <div class="step-content">
                    <div class="step-name">${step.name}</div>
                    <div class="step-duration"><i class="fas fa-clock"></i> ${step.duration}</div>
                </div>
                <div class="step-status running"><i class="fas fa-spinner fa-spin"></i> Running</div>
            `;
            stepsDiv.appendChild(stepDiv);
            
            // Simulate step execution
            await new Promise(resolve => setTimeout(resolve, duration * 50)); // Faster for demo
            
            // Update step status
            const statusDiv = stepDiv.querySelector('.step-status');
            statusDiv.className = `step-status ${step.status}`;
            statusDiv.innerHTML = step.status === 'completed' 
                ? '<i class="fas fa-check"></i> Completed' 
                : '<i class="fas fa-times"></i> Failed';
            
            // Update progress
            const progress = ((i + 1) / result.steps.length) * 100;
            progressBar.style.width = `${progress}%`;
            progressText.textContent = `${i + 1}/${result.steps.length}`;
        }
        
        // Show final result
        const resultDiv = document.createElement('div');
        resultDiv.className = `execution-result ${result.status === 'completed' ? 'success' : 'failure'}`;
        resultDiv.innerHTML = `
            <i class="fas fa-${result.status === 'completed' ? 'check-circle' : 'exclamation-triangle'}"></i>
            <div>
                <strong>${result.status === 'completed' ? 'Success!' : 'Execution Failed'}</strong>
                <div style="margin-top: 0.25rem; color: #a0aec0;">${result.message}</div>
            </div>
        `;
        executionContainer.querySelector('.playbook-execution').appendChild(resultDiv);
        
        // Update execution header
        document.querySelector(`#playbook-execution-${playbookId} .execution-title`).innerHTML = 
            result.status === 'completed' 
                ? '<i class="fas fa-check-circle" style="color: #28a745;"></i> Execution Complete'
                : '<i class="fas fa-exclamation-triangle" style="color: #dc3545;"></i> Execution Failed';
        
        // Show toast notification
        showToast(
            result.status === 'completed' 
                ? `Playbook "${playbook.name}" executed successfully!`
                : `Playbook "${playbook.name}" execution failed.`,
            result.status === 'completed' ? 'success' : 'error'
        );
        
    } catch (error) {
        hideLoading();
        showToast('Failed to execute playbook', 'error');
        console.error(error);
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

// Audit Log Functionality
async function loadAuditLog(filters = {}) {
    showLoading();
    try {
        // Build query string
        const params = new URLSearchParams(filters);
        const response = await API.fetch(`/audit-log?${params.toString()}`);
        const data = await response.json();
        
        // Handle both array and object responses
        const logs = Array.isArray(data) ? data : (data.logs || []);
        renderAuditLog(logs);
    } catch (error) {
        showToast('Failed to load audit logs', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

function renderAuditLog(logs) {
    const tbody = document.getElementById('audit-log-tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #a0aec0;">No audit logs found</td></tr>';
        return;
    }
    
    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatTime(log.timestamp)}</td>
            <td>${log.user || 'System'}</td>
            <td><span class="badge ${getActionClass(log.action)}">${log.action}</span></td>
            <td>${log.resource || '-'}</td>
            <td>${log.details || '-'}</td>
            <td>${log.ip_address || '-'}</td>
        `;
        tbody.appendChild(row);
    });
}

function getActionClass(action) {
    const actionLower = (action || '').toLowerCase();
    if (actionLower.includes('delete') || actionLower.includes('remove')) return 'critical';
    if (actionLower.includes('create') || actionLower.includes('add')) return 'low';
    if (actionLower.includes('update') || actionLower.includes('modify')) return 'medium';
    if (actionLower.includes('login') || actionLower.includes('logout')) return 'info';
    return 'info';
}

function initAuditLogFilters() {
    const applyBtn = document.getElementById('audit-filter-apply');
    const resetBtn = document.getElementById('audit-filter-reset');
    
    if (applyBtn) {
        applyBtn.addEventListener('click', () => {
            const filters = {};
            
            const userFilter = document.getElementById('audit-filter-user')?.value;
            if (userFilter) filters.user = userFilter;
            
            const actionFilter = document.getElementById('audit-filter-action')?.value;
            if (actionFilter) filters.action = actionFilter;
            
            const dateFromFilter = document.getElementById('audit-filter-date-from')?.value;
            if (dateFromFilter) filters.date_from = dateFromFilter;
            
            const dateToFilter = document.getElementById('audit-filter-date-to')?.value;
            if (dateToFilter) filters.date_to = dateToFilter;
            
            loadAuditLog(filters);
        });
    }
    
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            const userInput = document.getElementById('audit-filter-user');
            const actionSelect = document.getElementById('audit-filter-action');
            const dateFromInput = document.getElementById('audit-filter-date-from');
            const dateToInput = document.getElementById('audit-filter-date-to');
            
            if (userInput) userInput.value = '';
            if (actionSelect) actionSelect.value = '';
            if (dateFromInput) dateFromInput.value = '';
            if (dateToInput) dateToInput.value = '';
            
            loadAuditLog();
        });
    }
}

// Initialize filters on load
document.addEventListener('DOMContentLoaded', () => {
    initTeamFilters();
    initAuditLogFilters();
});
