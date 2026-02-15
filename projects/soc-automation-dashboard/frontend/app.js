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
        
        // Phase 2: Correlation endpoints
        if (endpoint.startsWith('/correlations')) {
            if (endpoint.includes('/stats')) return MOCK_DATA.getCorrelationStats();
            if (endpoint.includes('/analyze')) return MOCK_DATA.analyzeCorrelations();
            if (endpoint.match(/\/correlations\/\d+$/)) {
                const correlationId = parseInt(endpoint.match(/\/correlations\/(\d+)/)[1]);
                return MOCK_DATA.getCorrelationDetail(correlationId);
            }
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getCorrelations(Object.fromEntries(params));
        }
        if (endpoint.startsWith('/alerts/') && endpoint.includes('/related')) {
            const alertId = parseInt(endpoint.match(/\/alerts\/(\d+)/)[1]);
            return MOCK_DATA.getRelatedAlerts(alertId);
        }
        if (endpoint.startsWith('/alerts/') && endpoint.includes('/kill-chain')) {
            const alertId = parseInt(endpoint.match(/\/alerts\/(\d+)/)[1]);
            return MOCK_DATA.getAlertKillChain(alertId);
        }
        if (endpoint.includes('/duplicates')) return MOCK_DATA.getDuplicateAlerts();
        if (endpoint.includes('/deduplicate')) return MOCK_DATA.deduplicateAlerts();
        
        // Phase 2: Notification endpoints
        if (endpoint.startsWith('/notifications')) {
            if (endpoint.includes('/count')) return MOCK_DATA.getNotificationCount(authState.user?.id);
            if (endpoint.includes('/read-all')) return MOCK_DATA.markAllNotificationsRead(authState.user?.id);
            if (endpoint.includes('/test')) return MOCK_DATA.sendTestNotification(authState.user?.id);
            if (endpoint.match(/\/notifications\/\d+\/read$/)) {
                const notificationId = parseInt(endpoint.match(/\/notifications\/(\d+)/)[1]);
                return MOCK_DATA.markNotificationRead(notificationId);
            }
            const params = new URLSearchParams(endpoint.split('?')[1]);
            const filters = Object.fromEntries(params);
            filters.user_id = authState.user?.id;
            return MOCK_DATA.getNotifications(filters);
        }
        
        // Phase 2: Escalation endpoints
        if (endpoint.startsWith('/escalation-policies')) {
            if (endpoint.includes('/toggle')) {
                const policyId = parseInt(endpoint.match(/\/escalation-policies\/(\d+)/)[1]);
                return MOCK_DATA.toggleEscalationPolicy(policyId);
            }
            if (endpoint.match(/\/escalation-policies\/\d+$/)) {
                const policyId = parseInt(endpoint.match(/\/escalation-policies\/(\d+)/)[1]);
                return MOCK_DATA.getEscalationPolicy(policyId);
            }
            return MOCK_DATA.getEscalationPolicies();
        }
        if (endpoint.includes('/escalation-status')) {
            const alertId = parseInt(endpoint.match(/\/alerts\/(\d+)/)[1]);
            return MOCK_DATA.getAlertEscalationStatus(alertId);
        }
        
        // Phase 2: On-call endpoints
        if (endpoint === '/oncall') return MOCK_DATA.getCurrentOncall();
        if (endpoint === '/oncall/schedule') return MOCK_DATA.getOncallSchedule();
        if (endpoint === '/oncall/override') return MOCK_DATA.setOncallOverride(options.body ? JSON.parse(options.body) : {});
        
        // Phase 2: Webhook endpoints
        if (endpoint.startsWith('/webhooks')) {
            if (endpoint.includes('/test')) {
                const webhookId = parseInt(endpoint.match(/\/webhooks\/(\d+)/)[1]);
                return MOCK_DATA.testWebhook(webhookId);
            }
            if (endpoint.includes('/toggle')) {
                const webhookId = parseInt(endpoint.match(/\/webhooks\/(\d+)/)[1]);
                return MOCK_DATA.toggleWebhook(webhookId);
            }
            return MOCK_DATA.getWebhooks();
        }
        
        // Phase 3: Compliance endpoints
        if (endpoint.startsWith('/compliance')) {
            if (endpoint.includes('/frameworks')) return MOCK_DATA.getComplianceFrameworks();
            if (endpoint.includes('/posture')) return MOCK_DATA.getCompliancePosture();
            if (endpoint.includes('/coverage/')) {
                const framework = endpoint.match(/\/coverage\/([^/?]+)/)[1];
                return MOCK_DATA.getComplianceCoverage(framework);
            }
            if (endpoint.includes('/gaps')) return MOCK_DATA.getComplianceGaps();
        }
        if (endpoint === '/mitre/heatmap') return MOCK_DATA.getMitreHeatmap();
        if (endpoint.startsWith('/reports')) {
            if (endpoint.includes('/generate') && options.method === 'POST') {
                const body = options.body ? JSON.parse(options.body) : {};
                return MOCK_DATA.generateReport(body.report_type, body.parameters);
            }
            return MOCK_DATA.getReports();
        }
        
        // Phase 3: Threat hunting endpoints
        if (endpoint.startsWith('/hunts')) {
            if (endpoint === '/hunts' && options.method === 'POST') {
                const body = options.body ? JSON.parse(options.body) : {};
                return MOCK_DATA.createHunt(body);
            }
            if (endpoint === '/hunts/custom' && options.method === 'POST') {
                const body = options.body ? JSON.parse(options.body) : {};
                return MOCK_DATA.createCustomHunt(body);
            }
            if (endpoint.match(/\/hunts\/\d+$/)) {
                const huntId = endpoint.match(/\/hunts\/(\d+)/)[1];
                return MOCK_DATA.getHunt(huntId);
            }
            if (endpoint.includes('/query') && options.method === 'PUT') {
                const huntId = endpoint.match(/\/hunts\/(\d+)/)[1];
                const body = options.body ? JSON.parse(options.body) : {};
                return MOCK_DATA.updateHuntQuery(huntId, body);
            }
            if (endpoint.includes('/findings')) {
                const huntId = endpoint.match(/\/hunts\/(\d+)/)[1];
                if (options.method === 'POST') {
                    const body = options.body ? JSON.parse(options.body) : {};
                    return MOCK_DATA.addHuntFinding(huntId, body);
                }
                return MOCK_DATA.getHuntFindings(huntId);
            }
            if (endpoint.includes('/journal')) {
                const huntId = endpoint.match(/\/hunts\/(\d+)/)[1];
                if (options.method === 'POST') {
                    const body = options.body ? JSON.parse(options.body) : {};
                    return MOCK_DATA.addHuntJournalEntry(huntId, body);
                }
                return MOCK_DATA.getHuntJournal(huntId);
            }
            if (endpoint.includes('/complete') && options.method === 'PUT') {
                const huntId = endpoint.match(/\/hunts\/(\d+)/)[1];
                const body = options.body ? JSON.parse(options.body) : {};
                return MOCK_DATA.completeHunt(huntId, body);
            }
            const params = new URLSearchParams(endpoint.split('?')[1]);
            return MOCK_DATA.getHunts(Object.fromEntries(params));
        }
        if (endpoint === '/hunt-library') return MOCK_DATA.getHuntLibrary();
        if (endpoint === '/hunt-metrics') return MOCK_DATA.getHuntMetrics();
        
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
    
    // Show notification bell
    const notificationContainer = document.getElementById('notification-bell-container');
    if (notificationContainer) {
        notificationContainer.style.display = 'block';
    }
    
    // Start notification polling
    startNotificationPolling();
    
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
    
    // Show/hide settings nav (only admin and soc_manager)
    const settingsNav = document.getElementById('settings-nav');
    if (settingsNav) {
        settingsNav.style.display = (role === 'admin' || role === 'soc_manager') ? 'block' : 'none';
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
            console.log('Dashboard ready to load');
        } catch (error) {
            console.error('Failed to load mock data, dashboard may not display correctly:', error);
            showToast('Failed to initialize dashboard data. Please refresh the page.', 'error');
        }
    } else {
        console.warn('MOCK_DATA_READY is not defined - mock-api.js may not be loaded');
        showToast('Mock API not loaded. Dashboard functionality may be limited.', 'warning');
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
        case 'correlations':
            loadCorrelations();
            break;
        case 'notifications':
            loadNotifications();
            break;
        case 'settings':
            loadSettings();
            break;
        case 'audit-log':
            loadAuditLog();
            break;
        case 'compliance':
            loadCompliancePage();
            break;
        case 'reports':
            loadReportsPage();
            break;
        case 'threat-hunting':
            loadThreatHuntingPage();
            break;
    }
}

// Dashboard
async function loadDashboard() {
    showLoading();
    try {
        const promises = [
            API.fetch(`/dashboard/stats`).then(r => r.json()),
            API.fetch(`/alerts`).then(r => r.json()),
            API.fetch(`/timeline`).then(r => r.json())
        ];
        
        // Optionally load Phase 3 stats if elements exist
        if (document.getElementById('compliance-score')) {
            promises.push(API.fetch('/compliance/posture').then(r => r.json()).catch(() => null));
        }
        if (document.getElementById('active-hunts')) {
            promises.push(API.fetch('/hunt-metrics').then(r => r.json()).catch(() => null));
        }
        
        const results = await Promise.all(promises);
        const [stats, alerts, timeline, compliancePosture, huntMetrics] = results;
        
        updateStats(stats, compliancePosture, huntMetrics);
        updateActivityFeed(alerts);
        renderTimelineChart(timeline);
        renderAlertDistributionChart(alerts);
        renderThreatMap();
    } catch (error) {
        console.error('Dashboard loading error:', error);
        showToast('Failed to load dashboard data. Please check the console for details.', 'error');
        console.error('Possible causes: Missing data files, API endpoint issues, or network errors.');
    } finally {
        hideLoading();
    }
}

function updateStats(stats, compliancePosture = null, huntMetrics = null) {
    document.getElementById('critical-alerts').textContent = stats.active_alerts || 0;
    document.getElementById('active-threats').textContent = stats.blocked_threats || 0;
    document.getElementById('automation-rate').textContent = stats.automation_rate || '0%';
    document.getElementById('mttr').textContent = stats.mttr || '0 min';
    
    // Update Phase 3 stats if available
    if (compliancePosture && document.getElementById('compliance-score')) {
        document.getElementById('compliance-score').textContent = compliancePosture.overall_compliance + '%';
    }
    if (huntMetrics && document.getElementById('active-hunts')) {
        document.getElementById('active-hunts').textContent = huntMetrics.active_hunts || 0;
    }
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
    initNotificationBell();
    
    // Start notification polling if authenticated
    if (authState.isAuthenticated) {
        startNotificationPolling();
    }
});
// ===== PHASE 2: CORRELATION ENGINE FUNCTIONS =====

// Load correlations page
async function loadCorrelations() {
    showLoading();
    try {
        const [correlations, stats] = await Promise.all([
            API.fetch('/correlations').then(r => r.json()),
            API.fetch('/correlations/stats').then(r => r.json())
        ]);
        
        renderCorrelationStats(stats);
        renderCorrelations(correlations);
        initCorrelationHandlers();
    } catch (error) {
        showToast('Failed to load correlations', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Render correlation statistics
function renderCorrelationStats(stats) {
    const container = document.getElementById('correlation-stats');
    if (!container) return;
    
    container.innerHTML = `
        <div class="stat-card info">
            <div class="stat-icon"><i class="fas fa-project-diagram"></i></div>
            <div class="stat-content">
                <div class="stat-value">${stats.total_groups || 0}</div>
                <div class="stat-label">Correlation Groups</div>
            </div>
        </div>
        <div class="stat-card primary">
            <div class="stat-icon"><i class="fas fa-chart-line"></i></div>
            <div class="stat-content">
                <div class="stat-value">${stats.average_score || 0}</div>
                <div class="stat-label">Avg Correlation Score</div>
            </div>
        </div>
        <div class="stat-card success">
            <div class="stat-icon"><i class="fas fa-link"></i></div>
            <div class="stat-content">
                <div class="stat-value">${stats.alerts_correlated || 0}</div>
                <div class="stat-label">Alerts Correlated</div>
            </div>
        </div>
        <div class="stat-card warning">
            <div class="stat-icon"><i class="fas fa-compress"></i></div>
            <div class="stat-content">
                <div class="stat-value">${stats.deduplication_rate || 0}%</div>
                <div class="stat-label">De-duplication Rate</div>
            </div>
        </div>
    `;
}

// Render correlations grid
function renderCorrelations(correlations) {
    const container = document.getElementById('correlations-grid');
    if (!container) return;
    
    if (!correlations || correlations.length === 0) {
        container.innerHTML = '<p>No correlation groups found.</p>';
        return;
    }
    
    container.innerHTML = '';
    
    correlations.forEach(correlation => {
        const card = document.createElement('div');
        card.className = `correlation-card ${correlation.risk_level}`;
        card.onclick = () => showCorrelationDetail(correlation.id);
        
        const entities = correlation.shared_entities || {};
        const entityTags = [];
        if (entities.hosts && entities.hosts.length) entityTags.push(...entities.hosts.slice(0, 2));
        if (entities.users && entities.users.length) entityTags.push(...entities.users.slice(0, 2));
        
        card.innerHTML = `
            <div class="correlation-card-header">
                <div>
                    <div class="correlation-card-title">${correlation.name}</div>
                    <span class="badge ${correlation.risk_level}">${correlation.risk_level.toUpperCase()}</span>
                </div>
                <div class="correlation-score-badge">${correlation.correlation_score}</div>
            </div>
            <div class="correlation-card-description">${correlation.description}</div>
            <div class="correlation-card-stats">
                <div class="correlation-stat">
                    <div class="correlation-stat-value">${correlation.alert_ids.length}</div>
                    <div class="correlation-stat-label">Alerts</div>
                </div>
                <div class="correlation-stat">
                    <div class="correlation-stat-value">${correlation.kill_chain_coverage}/${correlation.total_kill_chain_stages}</div>
                    <div class="correlation-stat-label">Kill Chain</div>
                </div>
            </div>
            <div class="correlation-entities">
                ${entityTags.map(tag => `<span class="entity-tag">${tag}</span>`).join('')}
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Show correlation detail modal
async function showCorrelationDetail(correlationId) {
    showLoading();
    try {
        const correlation = await API.fetch(`/correlations/${correlationId}`).then(r => r.json());
        
        const modal = document.getElementById('correlation-modal');
        const title = document.getElementById('correlation-modal-title');
        const body = document.getElementById('correlation-modal-body');
        
        if (!modal || !title || !body) return;
        
        title.textContent = correlation.name;
        
        body.innerHTML = `
            <div class="correlation-detail">
                <div class="detail-section">
                    <h4>Risk Assessment</h4>
                    <p><strong>Risk Level:</strong> <span class="badge ${correlation.risk_level}">${correlation.risk_level.toUpperCase()}</span></p>
                    <p><strong>Correlation Score:</strong> ${correlation.correlation_score}/100</p>
                    <p><strong>Status:</strong> <span class="badge ${correlation.status === 'active' ? 'warning' : 'info'}">${correlation.status.toUpperCase()}</span></p>
                </div>
                
                <div class="detail-section">
                    <h4>Description</h4>
                    <p>${correlation.description}</p>
                </div>
                
                <div class="detail-section">
                    <h4>Recommended Action</h4>
                    <p>${correlation.recommended_action}</p>
                </div>
                
                ${renderKillChainTimeline(correlation.kill_chain)}
                
                <div class="detail-section">
                    <h4>Shared Entities</h4>
                    <div class="correlation-entities">
                        ${Object.entries(correlation.shared_entities || {}).map(([key, values]) => 
                            values.length ? `<div><strong>${key}:</strong> ${values.map(v => `<span class="entity-tag">${v}</span>`).join('')}</div>` : ''
                        ).join('')}
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4>Correlated Alerts (${correlation.alert_ids.length})</h4>
                    <div class="correlated-alerts-list">
                        ${correlation.alerts ? correlation.alerts.map(alert => `
                            <div class="correlated-alert-item ${alert.severity}" onclick="event.stopPropagation(); showAlertDetails(${JSON.stringify(alert).replace(/"/g, '&quot;')})">
                                <div><strong>${alert.title}</strong></div>
                                <div style="font-size: 0.9rem; color: var(--text-secondary);">
                                    ${alert.host} • ${alert.user} • ${formatTime(alert.timestamp)}
                                </div>
                            </div>
                        `).join('') : '<p>Loading alerts...</p>'}
                    </div>
                </div>
            </div>
        `;
        
        modal.classList.add('active');
    } catch (error) {
        showToast('Failed to load correlation details', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Render kill chain timeline
function renderKillChainTimeline(killChain) {
    if (!killChain || killChain.length === 0) {
        return '';
    }
    
    const stages = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
                    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 
                    'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
    
    const activeStages = new Set(killChain.map(k => k.stage));
    
    return `
        <div class="detail-section">
            <h4 class="kill-chain-timeline-title">Kill Chain Timeline</h4>
            <div class="kill-chain-timeline">
                <div class="kill-chain-stages">
                    <div class="kill-chain-line"></div>
                    ${stages.slice(0, 8).map(stage => `
                        <div class="kill-chain-stage ${activeStages.has(stage) ? 'active' : ''}">
                            <div class="kill-chain-node">${activeStages.has(stage) ? '✓' : ''}</div>
                            <div class="kill-chain-label">${stage}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// Initialize correlation handlers
function initCorrelationHandlers() {
    const analyzeBtn = document.getElementById('analyze-correlations-btn');
    if (analyzeBtn) {
        analyzeBtn.onclick = async () => {
            showLoading();
            try {
                await API.fetch('/correlations/analyze', { method: 'POST' });
                showToast('Correlation analysis completed', 'success');
                loadCorrelations();
            } catch (error) {
                showToast('Failed to analyze correlations', 'error');
                console.error(error);
            } finally {
                hideLoading();
            }
        };
    }
}

// ===== PHASE 2: NOTIFICATION ENGINE FUNCTIONS =====

// Notification polling interval
let notificationPollInterval = null;

// Start notification polling
function startNotificationPolling() {
    if (notificationPollInterval) return;
    
    // Poll every 30 seconds
    notificationPollInterval = setInterval(async () => {
        if (authState.isAuthenticated) {
            await updateNotificationBadge();
        }
    }, 30000);
    
    // Initial update
    updateNotificationBadge();
}

// Stop notification polling
function stopNotificationPolling() {
    if (notificationPollInterval) {
        clearInterval(notificationPollInterval);
        notificationPollInterval = null;
    }
}

// Update notification badge count
async function updateNotificationBadge() {
    try {
        const data = await API.fetch('/notifications/count').then(r => r.json());
        const badge = document.getElementById('notification-badge');
        const bell = document.getElementById('notification-bell');
        
        if (badge && bell) {
            if (data.unread_count > 0) {
                badge.textContent = data.unread_count;
                badge.style.display = 'flex';
                bell.classList.add('has-notifications');
            } else {
                badge.style.display = 'none';
                bell.classList.remove('has-notifications');
            }
        }
    } catch (error) {
        console.error('Failed to update notification count:', error);
    }
}

// Initialize notification bell
function initNotificationBell() {
    const bell = document.getElementById('notification-bell');
    const dropdown = document.getElementById('notification-dropdown');
    const container = document.getElementById('notification-bell-container');
    
    if (!bell || !dropdown || !container) return;
    
    // Show container when authenticated
    if (authState.isAuthenticated) {
        container.style.display = 'block';
    }
    
    // Toggle dropdown
    bell.onclick = (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('active');
        if (dropdown.classList.contains('active')) {
            loadNotificationDropdown();
        }
    };
    
    // Close on click outside
    document.addEventListener('click', (e) => {
        if (!container.contains(e.target)) {
            dropdown.classList.remove('active');
        }
    });
    
    // Mark all read button
    const markAllReadBtn = document.getElementById('mark-all-read-btn');
    if (markAllReadBtn) {
        markAllReadBtn.onclick = async () => {
            try {
                await API.fetch('/notifications/read-all', { method: 'PUT' });
                showToast('All notifications marked as read', 'success');
                updateNotificationBadge();
                loadNotificationDropdown();
            } catch (error) {
                showToast('Failed to mark notifications as read', 'error');
                console.error(error);
            }
        };
    }
}

// Load notifications for dropdown
async function loadNotificationDropdown() {
    try {
        const notifications = await API.fetch('/notifications?read=false').then(r => r.json());
        const listContainer = document.getElementById('notification-dropdown-list');
        
        if (!listContainer) return;
        
        if (!notifications || notifications.length === 0) {
            listContainer.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-secondary);">No new notifications</div>';
            return;
        }
        
        listContainer.innerHTML = '';
        
        notifications.slice(0, 10).forEach(notification => {
            const item = document.createElement('div');
            item.className = `notification-item ${notification.read ? '' : 'unread'}`;
            
            const icon = getNotificationIcon(notification.type);
            const timeAgo = getTimeAgo(notification.created_at);
            
            item.innerHTML = `
                <div class="notification-item-header">
                    <i class="${icon} notification-item-icon ${notification.severity}"></i>
                    <div class="notification-item-title">${notification.title}</div>
                    <span class="notification-item-time">${timeAgo}</span>
                </div>
                <div class="notification-item-message">${notification.message}</div>
            `;
            
            item.onclick = () => markNotificationRead(notification.id);
            
            listContainer.appendChild(item);
        });
    } catch (error) {
        console.error('Failed to load notifications:', error);
    }
}

// Get notification icon based on type
function getNotificationIcon(type) {
    const icons = {
        'alert_assigned': 'fas fa-user-check',
        'alert_escalated': 'fas fa-exclamation-triangle',
        'sla_breach': 'fas fa-clock',
        'playbook_completed': 'fas fa-check-circle',
        'correlation_detected': 'fas fa-project-diagram',
        'system_alert': 'fas fa-info-circle'
    };
    return icons[type] || 'fas fa-bell';
}

// Get time ago string
function getTimeAgo(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diff = Math.floor((now - time) / 1000); // seconds
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

// Mark notification as read
async function markNotificationRead(notificationId) {
    try {
        await API.fetch(`/notifications/${notificationId}/read`, { method: 'PUT' });
        updateNotificationBadge();
        loadNotificationDropdown();
    } catch (error) {
        console.error('Failed to mark notification as read:', error);
    }
}

// Load notifications page
async function loadNotifications() {
    showLoading();
    try {
        const notifications = await API.fetch('/notifications').then(r => r.json());
        renderNotificationsPage(notifications);
        initNotificationFilters();
    } catch (error) {
        showToast('Failed to load notifications', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Render notifications page
function renderNotificationsPage(notifications) {
    const container = document.getElementById('notifications-list');
    if (!container) return;
    
    if (!notifications || notifications.length === 0) {
        container.innerHTML = '<p>No notifications found.</p>';
        return;
    }
    
    container.innerHTML = '';
    
    notifications.forEach(notification => {
        const card = document.createElement('div');
        card.className = `notification-card ${notification.severity} ${notification.read ? '' : 'unread'}`;
        
        const icon = getNotificationIcon(notification.type);
        const timeAgo = getTimeAgo(notification.created_at);
        
        card.innerHTML = `
            ${!notification.read ? '<div class="notification-unread-indicator"></div>' : ''}
            <div class="notification-card-header">
                <i class="${icon} notification-type-icon ${notification.severity}"></i>
                <div style="flex: 1;">
                    <div class="notification-card-title">${notification.title}</div>
                </div>
            </div>
            <div class="notification-card-content">
                <div class="notification-card-message">${notification.message}</div>
                <div class="notification-card-meta">
                    <span>${timeAgo}</span>
                    <span class="badge ${notification.severity}">${notification.severity}</span>
                </div>
            </div>
        `;
        
        if (!notification.read) {
            card.onclick = () => markNotificationRead(notification.id);
        }
        
        container.appendChild(card);
    });
}

// Initialize notification filters
function initNotificationFilters() {
    const typeFilter = document.getElementById('notification-type-filter');
    const severityFilter = document.getElementById('notification-severity-filter');
    const readFilter = document.getElementById('notification-read-filter');
    
    const applyFilters = () => {
        const params = new URLSearchParams();
        if (typeFilter?.value) params.set('type', typeFilter.value);
        if (severityFilter?.value) params.set('severity', severityFilter.value);
        if (readFilter?.value) params.set('read', readFilter.value);
        
        API.fetch(`/notifications?${params.toString()}`)
            .then(r => r.json())
            .then(notifications => renderNotificationsPage(notifications))
            .catch(error => {
                showToast('Failed to filter notifications', 'error');
                console.error(error);
            });
    };
    
    if (typeFilter) typeFilter.onchange = applyFilters;
    if (severityFilter) severityFilter.onchange = applyFilters;
    if (readFilter) readFilter.onchange = applyFilters;
}

// ===== PHASE 2: SETTINGS PAGE FUNCTIONS =====

// Load settings page
async function loadSettings() {
    showLoading();
    try {
        await loadEscalationPolicies();
        initSettingsTabs();
    } catch (error) {
        showToast('Failed to load settings', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Initialize settings tabs
function initSettingsTabs() {
    const tabs = document.querySelectorAll('.settings-tab');
    tabs.forEach(tab => {
        tab.onclick = async () => {
            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Update active content
            document.querySelectorAll('.settings-tab-content').forEach(c => c.classList.remove('active'));
            const tabName = tab.dataset.tab;
            const content = document.getElementById(`${tabName}-tab`);
            if (content) content.classList.add('active');
            
            // Load tab data
            if (tabName === 'escalation') {
                await loadEscalationPolicies();
            } else if (tabName === 'oncall') {
                await loadOnCallSchedule();
            } else if (tabName === 'webhooks') {
                await loadWebhooks();
            }
        };
    });
}

// Load escalation policies
async function loadEscalationPolicies() {
    try {
        const policies = await API.fetch('/escalation-policies').then(r => r.json());
        renderEscalationPolicies(policies);
    } catch (error) {
        console.error('Failed to load escalation policies:', error);
    }
}

// Render escalation policies
function renderEscalationPolicies(policies) {
    const container = document.getElementById('escalation-policies-list');
    if (!container) return;
    
    if (!policies || policies.length === 0) {
        container.innerHTML = '<p>No escalation policies found.</p>';
        return;
    }
    
    container.innerHTML = '';
    
    policies.forEach(policy => {
        const card = document.createElement('div');
        card.className = 'escalation-policy-card';
        
        card.innerHTML = `
            <div class="escalation-policy-header">
                <div>
                    <div class="escalation-policy-title">${policy.name}</div>
                    <div style="color: var(--text-secondary); font-size: 0.9rem;">${policy.description}</div>
                </div>
                <button class="escalation-toggle ${policy.enabled ? 'enabled' : ''}" 
                        onclick="toggleEscalationPolicy(${policy.id})">
                    ${policy.enabled ? 'Enabled' : 'Disabled'}
                </button>
            </div>
            <div class="escalation-levels">
                ${policy.levels.map(level => `
                    <div class="escalation-level">
                        <div class="escalation-level-header">
                            <div class="escalation-level-number">${level.level}</div>
                            <div class="escalation-level-time">After ${level.escalate_after_minutes} minutes</div>
                        </div>
                        <div class="escalation-level-roles">
                            <strong>Action:</strong> ${level.action} | 
                            <strong>Notify:</strong> ${level.notify_roles.join(', ')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Toggle escalation policy
async function toggleEscalationPolicy(policyId) {
    try {
        await API.fetch(`/escalation-policies/${policyId}/toggle`, { method: 'PUT' });
        showToast('Escalation policy updated', 'success');
        loadEscalationPolicies();
    } catch (error) {
        showToast('Failed to update policy', 'error');
        console.error(error);
    }
}

// Load on-call schedule
async function loadOnCallSchedule() {
    try {
        const schedule = await API.fetch('/oncall/schedule').then(r => r.json());
        renderOnCallSchedule(schedule);
    } catch (error) {
        console.error('Failed to load on-call schedule:', error);
    }
}

// Render on-call schedule
function renderOnCallSchedule(schedule) {
    const currentContainer = document.getElementById('oncall-current');
    const scheduleContainer = document.getElementById('oncall-schedule');
    
    if (currentContainer && schedule.current_oncall) {
        const current = schedule.current_oncall;
        currentContainer.innerHTML = `
            <div class="oncall-current">
                <div class="oncall-card">
                    <h4><span class="oncall-status-dot"></span> Primary On-Call</h4>
                    <div class="oncall-person">${current.primary?.name || 'Not assigned'}</div>
                    <div class="oncall-role">${current.primary?.role || ''}</div>
                </div>
                <div class="oncall-card">
                    <h4><span class="oncall-status-dot"></span> Secondary On-Call</h4>
                    <div class="oncall-person">${current.secondary?.name || 'Not assigned'}</div>
                    <div class="oncall-role">${current.secondary?.role || ''}</div>
                </div>
            </div>
        `;
    }
    
    if (scheduleContainer && schedule.schedule) {
        scheduleContainer.innerHTML = `
            <h4 style="margin-top: 2rem;">Upcoming Schedule</h4>
            <table class="oncall-schedule-table">
                <thead>
                    <tr>
                        <th>Week Starting</th>
                        <th>Primary</th>
                        <th>Secondary</th>
                    </tr>
                </thead>
                <tbody>
                    ${schedule.schedule.map(week => `
                        <tr>
                            <td>${week.week_start}</td>
                            <td>User ${week.primary_user_id}</td>
                            <td>User ${week.secondary_user_id}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }
}

// Load webhooks
async function loadWebhooks() {
    try {
        const webhooks = await API.fetch('/webhooks').then(r => r.json());
        renderWebhooks(webhooks);
    } catch (error) {
        console.error('Failed to load webhooks:', error);
    }
}

// Render webhooks
function renderWebhooks(webhooks) {
    const container = document.getElementById('webhooks-list');
    if (!container) return;
    
    if (!webhooks || webhooks.length === 0) {
        container.innerHTML = '<p>No webhooks configured.</p>';
        return;
    }
    
    container.innerHTML = '';
    
    webhooks.forEach(webhook => {
        const card = document.createElement('div');
        card.className = 'webhook-card';
        
        const iconClass = {
            'slack': 'fab fa-slack',
            'teams': 'fab fa-microsoft',
            'pagerduty': 'fas fa-pager',
            'email': 'fas fa-envelope'
        }[webhook.type] || 'fas fa-plug';
        
        card.innerHTML = `
            <i class="${iconClass} webhook-icon ${webhook.type}"></i>
            <div class="webhook-info">
                <div class="webhook-name">${webhook.name}</div>
                <div class="webhook-type">${webhook.type.toUpperCase()} • ${webhook.enabled ? 'Enabled' : 'Disabled'}</div>
            </div>
            <div class="webhook-actions">
                <button class="webhook-test-btn" onclick="testWebhook(${webhook.id})">Test</button>
                <button class="webhook-toggle-btn ${webhook.enabled ? 'enabled' : ''}" 
                        onclick="toggleWebhook(${webhook.id})">
                    ${webhook.enabled ? 'Disable' : 'Enable'}
                </button>
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Test webhook
async function testWebhook(webhookId) {
    try {
        const result = await API.fetch(`/webhooks/${webhookId}/test`, { method: 'POST' }).then(r => r.json());
        showToast(result.message || 'Webhook test successful', 'success');
    } catch (error) {
        showToast('Webhook test failed', 'error');
        console.error(error);
    }
}

// Toggle webhook
async function toggleWebhook(webhookId) {
    try {
        await API.fetch(`/webhooks/${webhookId}/toggle`, { method: 'PUT' });
        showToast('Webhook updated', 'success');
        loadWebhooks();
    } catch (error) {
        showToast('Failed to update webhook', 'error');
        console.error(error);
    }
}

// ============================================================================
// PHASE 3: COMPLIANCE PAGE FUNCTIONS
// ============================================================================

// Main compliance page loader
async function loadCompliancePage() {
    showLoading();
    try {
        await Promise.all([
            loadCompliancePosture(),
            loadFrameworkCards(),
            loadGapAnalysis(),
            loadMitreHeatmap()
        ]);
    } catch (error) {
        showToast('Failed to load compliance data', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Load and display overall compliance posture with gauge chart
async function loadCompliancePosture() {
    try {
        const posture = await API.fetch('/compliance/posture').then(r => r.json());
        
        // Update posture stats using correct HTML element IDs
        const gaugeValue = document.getElementById('gauge-value');
        if (gaugeValue) {
            gaugeValue.textContent = posture.overall_compliance + '%';
        }
        
        const controlsPassed = document.getElementById('controls-passed');
        if (controlsPassed) {
            controlsPassed.textContent = posture.covered_controls;
        }
        
        const controlsFailed = document.getElementById('controls-failed');
        if (controlsFailed) {
            controlsFailed.textContent = posture.gap_controls;
        }
        
        const controlsPartial = document.getElementById('controls-partial');
        if (controlsPartial) {
            // Calculate partial from total - covered - gaps
            const partial = posture.total_controls - posture.covered_controls - posture.gap_controls;
            controlsPartial.textContent = partial > 0 ? partial : 0;
        }
        
        // Draw gauge chart
        const canvas = document.getElementById('compliance-gauge-chart') || document.getElementById('compliance-gauge');
        if (canvas) {
            drawPostureGauge(canvas, posture.overall_compliance);
        }
        
        // Update last updated time
        const lastUpdated = document.getElementById('compliance-last-updated');
        if (lastUpdated) {
            lastUpdated.textContent = 'Last updated: ' + formatTime(posture.last_updated);
        }
    } catch (error) {
        console.error('Failed to load compliance posture:', error);
    }
}

// Draw circular gauge chart for compliance score
function drawPostureGauge(canvas, score) {
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 10;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw background arc
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 2.25 * Math.PI);
    ctx.lineWidth = 20;
    ctx.strokeStyle = '#2d3748';
    ctx.stroke();
    
    // Draw score arc
    const scoreAngle = 0.75 * Math.PI + (1.5 * Math.PI * (score / 100));
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, scoreAngle);
    ctx.lineWidth = 20;
    
    // Color based on score
    if (score >= 80) {
        ctx.strokeStyle = '#48bb78';
    } else if (score >= 60) {
        ctx.strokeStyle = '#ed8936';
    } else {
        ctx.strokeStyle = '#f56565';
    }
    ctx.stroke();
    
    // Draw score text
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 48px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(score + '%', centerX, centerY);
    
    // Draw label
    ctx.font = '14px Arial';
    ctx.fillStyle = '#a0aec0';
    ctx.fillText('Compliance Score', centerX, centerY + 30);
}

// Load and display framework score cards
async function loadFrameworkCards() {
    try {
        const frameworks = await API.fetch('/compliance/frameworks').then(r => r.json());
        
        if (frameworks.length === 0) {
            console.warn('No frameworks data available');
            return;
        }
        
        // Update each framework card with data
        frameworks.forEach(framework => {
            const frameworkKey = framework.id.toLowerCase().replace(/_/g, '');
            const percentage = framework.compliance_percentage;
            const statusClass = percentage >= 80 ? 'success' : percentage >= 60 ? 'warning' : 'error';
            
            // Update score value
            const scoreEl = document.getElementById(`${frameworkKey}-score`);
            if (scoreEl) {
                scoreEl.textContent = percentage + '%';
                scoreEl.className = `score-value ${statusClass}`;
            }
            
            // Update score bar
            const barEl = document.getElementById(`${frameworkKey}-bar`);
            if (barEl) {
                barEl.style.width = percentage + '%';
                barEl.className = `score-fill ${statusClass}`;
            }
            
            // Update passed count
            const passedEl = document.getElementById(`${frameworkKey}-passed`);
            if (passedEl) {
                passedEl.textContent = framework.covered_controls;
            }
            
            // Update failed count
            const failedEl = document.getElementById(`${frameworkKey}-failed`);
            if (failedEl) {
                failedEl.textContent = framework.total_controls - framework.covered_controls;
            }
        });
    } catch (error) {
        console.error('Failed to load framework cards:', error);
    }
}

// Load and display top compliance gaps
async function loadGapAnalysis() {
    try {
        const gapsData = await API.fetch('/compliance/gaps').then(r => r.json());
        const container = document.getElementById('gap-analysis-list');
        
        if (!container) return;
        
        container.innerHTML = '';
        
        if (gapsData.gaps.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 2rem; color: #a0aec0;">No compliance gaps found</div>';
            return;
        }
        
        // Show top 10 gaps
        gapsData.gaps.slice(0, 10).forEach(gap => {
            const item = document.createElement('div');
            item.className = 'gap-item';
            
            const priorityBadge = gap.priority === 'high' ? 
                '<span class="badge critical">High Priority</span>' : 
                '<span class="badge warning">Medium Priority</span>';
            
            item.innerHTML = `
                <div class="gap-header">
                    <div>
                        <strong>${gap.framework}</strong> - ${gap.control_id}
                        ${priorityBadge}
                    </div>
                    <span class="badge ${gap.coverage_status === 'gap' ? 'error' : 'warning'}">${gap.coverage_status}</span>
                </div>
                <div class="gap-description">${gap.control_name}</div>
                ${gap.mitre_techniques && gap.mitre_techniques.length > 0 ? 
                    `<div class="gap-techniques">
                        <i class="fas fa-shield-alt"></i> MITRE: ${gap.mitre_techniques.join(', ')}
                    </div>` : ''}
                ${gap.gaps && gap.gaps.length > 0 ? 
                    `<div class="gap-details">
                        <strong>Gaps:</strong> ${gap.gaps.join(', ')}
                    </div>` : ''}
            `;
            
            container.appendChild(item);
        });
    } catch (error) {
        console.error('Failed to load gap analysis:', error);
    }
}

// Load and display MITRE ATT&CK heatmap
async function loadMitreHeatmap() {
    try {
        const heatmap = await API.fetch('/mitre/heatmap').then(r => r.json());
        const container = document.getElementById('mitre-heatmap');
        
        if (!container) return;
        
        container.innerHTML = '';
        
        // Group techniques by tactic
        const tacticGroups = {};
        heatmap.forEach(item => {
            if (!tacticGroups[item.tactic]) {
                tacticGroups[item.tactic] = [];
            }
            tacticGroups[item.tactic].push(item);
        });
        
        // Render each tactic group
        Object.keys(tacticGroups).forEach(tactic => {
            const tacticSection = document.createElement('div');
            tacticSection.className = 'mitre-tactic-section';
            
            const tacticHeader = document.createElement('div');
            tacticHeader.className = 'mitre-tactic-header';
            tacticHeader.textContent = tactic;
            tacticSection.appendChild(tacticHeader);
            
            const techniqueGrid = document.createElement('div');
            techniqueGrid.className = 'mitre-technique-grid';
            
            tacticGroups[tactic].forEach(technique => {
                const cell = document.createElement('div');
                cell.className = 'mitre-technique-cell';
                cell.title = `${technique.technique_id}: ${technique.technique_name}\nAlerts: ${technique.alert_count}\nCoverage: ${technique.coverage_status}`;
                
                // Color based on alert count and coverage
                let intensityClass = 'low';
                if (technique.alert_count > 10) {
                    intensityClass = 'critical';
                } else if (technique.alert_count > 5) {
                    intensityClass = 'high';
                } else if (technique.alert_count > 0) {
                    intensityClass = 'medium';
                }
                
                if (technique.coverage_status === 'gap') {
                    cell.classList.add('no-coverage');
                }
                
                cell.classList.add(intensityClass);
                cell.innerHTML = `
                    <div class="technique-id">${technique.technique_id}</div>
                    <div class="technique-count">${technique.alert_count}</div>
                `;
                
                techniqueGrid.appendChild(cell);
            });
            
            tacticSection.appendChild(techniqueGrid);
            container.appendChild(tacticSection);
        });
    } catch (error) {
        console.error('Failed to load MITRE heatmap:', error);
    }
}

// View detailed framework coverage matrix
async function viewFrameworkDetails(frameworkId) {
    showLoading();
    try {
        const coverage = await API.fetch(`/compliance/coverage/${frameworkId}`).then(r => r.json());
        
        // Create modal content
        const modal = document.getElementById('framework-detail-modal') || createFrameworkModal();
        const modalBody = modal.querySelector('.modal-body');
        
        modalBody.innerHTML = `
            <div class="framework-detail-header">
                <h2>${coverage.framework_name}</h2>
                <div class="framework-summary">
                    <div class="summary-stat">
                        <span class="stat-value ${coverage.covered_controls > 0 ? 'success' : ''}">${coverage.covered_controls}</span>
                        <span class="stat-label">Covered</span>
                    </div>
                    <div class="summary-stat">
                        <span class="stat-value ${coverage.partial_controls > 0 ? 'warning' : ''}">${coverage.partial_controls}</span>
                        <span class="stat-label">Partial</span>
                    </div>
                    <div class="summary-stat">
                        <span class="stat-value ${coverage.gap_controls > 0 ? 'error' : ''}">${coverage.gap_controls}</span>
                        <span class="stat-label">Gaps</span>
                    </div>
                </div>
            </div>
            <div class="framework-controls-list">
                ${coverage.controls.map(control => `
                    <div class="control-item ${control.coverage_status}">
                        <div class="control-header">
                            <strong>${control.control_id}</strong>
                            <span class="badge ${control.coverage_status === 'covered' ? 'success' : control.coverage_status === 'partial' ? 'warning' : 'error'}">
                                ${control.coverage_status}
                            </span>
                        </div>
                        <div class="control-name">${control.control_name}</div>
                        ${control.mitre_techniques && control.mitre_techniques.length > 0 ? 
                            `<div class="control-mitre">
                                <i class="fas fa-shield-alt"></i> ${control.mitre_techniques.join(', ')}
                            </div>` : ''}
                        ${control.detection_rules && control.detection_rules.length > 0 ? 
                            `<div class="control-rules">
                                <i class="fas fa-check-circle"></i> ${control.detection_rules.length} detection rules
                            </div>` : ''}
                        ${control.gaps && control.gaps.length > 0 ? 
                            `<div class="control-gaps">
                                <i class="fas fa-exclamation-triangle"></i> ${control.gaps.join(', ')}
                            </div>` : ''}
                    </div>
                `).join('')}
            </div>
        `;
        
        modal.style.display = 'block';
    } catch (error) {
        showToast('Failed to load framework details', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Create framework detail modal if it doesn't exist
function createFrameworkModal() {
    const modal = document.createElement('div');
    modal.id = 'framework-detail-modal';
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content large">
            <span class="modal-close" onclick="document.getElementById('framework-detail-modal').style.display='none'">&times;</span>
            <div class="modal-body"></div>
        </div>
    `;
    document.body.appendChild(modal);
    
    // Close on outside click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    return modal;
}

// ============================================================================
// PHASE 3: REPORTS PAGE FUNCTIONS
// ============================================================================

// Main reports page loader
async function loadReportsPage() {
    showLoading();
    try {
        await loadReportsList();
    } catch (error) {
        showToast('Failed to load reports', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Load and display list of reports
async function loadReportsList() {
    try {
        const reports = await API.fetch('/reports').then(r => r.json());
        const container = document.getElementById('reports-list');
        
        if (!container) return;
        
        container.innerHTML = '';
        
        if (reports.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 3rem; color: #a0aec0;"><i class="fas fa-file-alt" style="font-size: 3rem; margin-bottom: 1rem; color: #0066cc;"></i><br>No reports generated yet</div>';
            return;
        }
        
        reports.forEach(report => {
            const card = document.createElement('div');
            card.className = 'report-card';
            
            const typeIcons = {
                'daily': 'calendar-day',
                'weekly': 'calendar-week',
                'monthly': 'calendar-alt',
                'executive': 'chart-pie',
                'compliance': 'shield-alt',
                'incident': 'exclamation-circle'
            };
            
            const icon = typeIcons[report.type] || 'file-alt';
            
            card.innerHTML = `
                <div class="report-icon">
                    <i class="fas fa-${icon}"></i>
                </div>
                <div class="report-info">
                    <h3>${report.title}</h3>
                    <div class="report-meta">
                        <span><i class="fas fa-tag"></i> ${report.type}</span>
                        <span><i class="fas fa-clock"></i> ${formatTime(report.generated_at)}</span>
                    </div>
                    ${report.description ? `<p class="report-description">${report.description}</p>` : ''}
                </div>
                <div class="report-actions">
                    <button class="btn-primary" onclick="viewReport(${report.id})">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn-secondary" onclick="exportReport(${report.id}, 'pdf')">
                        <i class="fas fa-file-pdf"></i> PDF
                    </button>
                    <button class="btn-secondary" onclick="exportReport(${report.id}, 'json')">
                        <i class="fas fa-file-code"></i> JSON
                    </button>
                </div>
            `;
            
            container.appendChild(card);
        });
    } catch (error) {
        console.error('Failed to load reports list:', error);
    }
}

// Generate new report
async function generateReport(type) {
    const button = event.target;
    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
    
    try {
        const params = { type };
        
        // Add date range if specified
        const startDate = document.getElementById('report-start-date')?.value;
        const endDate = document.getElementById('report-end-date')?.value;
        
        if (startDate) params.start_date = startDate;
        if (endDate) params.end_date = endDate;
        
        const result = await API.fetch('/reports/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        }).then(r => r.json());
        
        showToast(`${type} report generated successfully`, 'success');
        
        // Reload reports list
        await loadReportsList();
        
        // Auto-view the new report
        if (result.report_id) {
            setTimeout(() => viewReport(result.report_id), 500);
        }
    } catch (error) {
        showToast('Failed to generate report', 'error');
        console.error(error);
    } finally {
        button.disabled = false;
        button.innerHTML = button.getAttribute('data-original-text') || 'Generate';
    }
}

// View full report in viewer
async function viewReport(reportId) {
    showLoading();
    try {
        const report = await API.fetch(`/reports/${reportId}`).then(r => r.json());
        
        // Create or get report viewer modal
        const modal = document.getElementById('report-viewer-modal') || createReportViewerModal();
        const modalBody = modal.querySelector('.modal-body');
        
        modalBody.innerHTML = formatReportContent(report);
        
        modal.style.display = 'block';
    } catch (error) {
        showToast('Failed to load report', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Format report content for display
function formatReportContent(report) {
    let html = `
        <div class="report-viewer">
            <div class="report-header">
                <h1>${report.title}</h1>
                <div class="report-metadata">
                    <span><i class="fas fa-calendar"></i> ${new Date(report.generated_at).toLocaleString()}</span>
                    <span><i class="fas fa-tag"></i> ${report.type}</span>
                </div>
            </div>
    `;
    
    if (report.summary) {
        html += `
            <div class="report-section">
                <h2>Executive Summary</h2>
                <p>${report.summary}</p>
            </div>
        `;
    }
    
    if (report.data) {
        // Format based on report type
        if (report.type === 'daily' || report.type === 'weekly' || report.type === 'monthly') {
            html += `
                <div class="report-section">
                    <h2>Key Metrics</h2>
                    <div class="report-metrics">
                        <div class="metric-card">
                            <div class="metric-value">${report.data.total_alerts || 0}</div>
                            <div class="metric-label">Total Alerts</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.data.critical_alerts || 0}</div>
                            <div class="metric-label">Critical Alerts</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.data.incidents_created || 0}</div>
                            <div class="metric-label">Incidents</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.data.threats_blocked || 0}</div>
                            <div class="metric-label">Threats Blocked</div>
                        </div>
                    </div>
                </div>
            `;
            
            if (report.data.top_threats && report.data.top_threats.length > 0) {
                html += `
                    <div class="report-section">
                        <h2>Top Threats</h2>
                        <table class="report-table">
                            <thead>
                                <tr>
                                    <th>Threat</th>
                                    <th>Count</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${report.data.top_threats.map(threat => `
                                    <tr>
                                        <td>${threat.name}</td>
                                        <td>${threat.count}</td>
                                        <td><span class="badge ${threat.severity}">${threat.severity}</span></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        } else if (report.type === 'compliance') {
            html += `
                <div class="report-section">
                    <h2>Compliance Status</h2>
                    <div class="report-metrics">
                        <div class="metric-card">
                            <div class="metric-value">${report.data.overall_compliance || 0}%</div>
                            <div class="metric-label">Overall Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.data.frameworks_count || 0}</div>
                            <div class="metric-label">Frameworks</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.data.total_controls || 0}</div>
                            <div class="metric-label">Total Controls</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${report.data.gap_controls || 0}</div>
                            <div class="metric-label">Gaps</div>
                        </div>
                    </div>
                </div>
            `;
        }
    }
    
    html += '</div>';
    return html;
}

// Export report as PDF or JSON
async function exportReport(reportId, format) {
    try {
        const report = await API.fetch(`/reports/${reportId}`).then(r => r.json());
        
        if (format === 'json') {
            // Export as JSON
            const dataStr = JSON.stringify(report, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `report_${reportId}_${Date.now()}.json`;
            link.click();
            URL.revokeObjectURL(url);
            showToast('Report exported as JSON', 'success');
        } else if (format === 'pdf') {
            // In mock mode, just download the JSON with PDF extension
            // In real backend mode, this would call the backend PDF generation endpoint
            if (API_BASE && !isGitHubPages) {
                const response = await API.fetch(`/reports/${reportId}/export?format=pdf`);
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `report_${reportId}.pdf`;
                link.click();
                URL.revokeObjectURL(url);
            } else {
                showToast('PDF export available with backend', 'info');
            }
        }
    } catch (error) {
        showToast('Failed to export report', 'error');
        console.error(error);
    }
}

// Create report viewer modal
function createReportViewerModal() {
    const modal = document.createElement('div');
    modal.id = 'report-viewer-modal';
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content large">
            <span class="modal-close" onclick="document.getElementById('report-viewer-modal').style.display='none'">&times;</span>
            <div class="modal-body"></div>
        </div>
    `;
    document.body.appendChild(modal);
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    return modal;
}

// ============================================================================
// PHASE 3: THREAT HUNTING PAGE FUNCTIONS
// ============================================================================

// Initialize threat hunting event listeners
function initThreatHuntingListeners() {
    // Create Custom Hunt button
    const createHuntBtn = document.getElementById('create-custom-hunt');
    if (createHuntBtn) {
        createHuntBtn.addEventListener('click', () => {
            showCreateCustomHuntModal();
        });
    }
    
    // Launch Hunt buttons (static HTML cards)
    document.querySelectorAll('.btn-launch-hunt').forEach(btn => {
        const card = btn.closest('.hunt-package-card');
        if (card) {
            btn.addEventListener('click', () => {
                const huntType = card.getAttribute('data-hunt');
                launchHuntFromStatic(huntType, card);
            });
        }
    });
}

// Main threat hunting page loader
async function loadThreatHuntingPage() {
    showLoading();
    try {
        await Promise.all([
            loadHuntStatistics(),
            loadHuntLibrary(),
            loadActiveHunts()
        ]);
        // Initialize event listeners after content is loaded
        initThreatHuntingListeners();
    } catch (error) {
        showToast('Failed to load threat hunting data', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Load and display hunt statistics
async function loadHuntStatistics() {
    try {
        const stats = await API.fetch('/hunt-metrics').then(r => r.json());
        
        // Update hunt stats using correct HTML element IDs
        const huntActive = document.getElementById('hunt-active');
        if (huntActive) {
            huntActive.textContent = stats.active_hunts || 0;
        }
        
        const huntCompleted = document.getElementById('hunt-completed');
        if (huntCompleted) {
            huntCompleted.textContent = stats.completed_hunts || 0;
        }
        
        const huntFindings = document.getElementById('hunt-findings');
        if (huntFindings) {
            huntFindings.textContent = stats.total_findings || 0;
        }
        
        const huntLaunched = document.getElementById('hunt-launched');
        if (huntLaunched) {
            huntLaunched.textContent = stats.total_hunts || 0;
        }
    } catch (error) {
        console.error('Failed to load hunt statistics:', error);
    }
}

// Load and display hunt library (packages)
async function loadHuntLibrary() {
    try {
        const library = await API.fetch('/hunt-library').then(r => r.json());
        const container = document.getElementById('hunt-library-list');
        
        if (!container) return;
        
        container.innerHTML = '';
        
        if (library.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 2rem; color: #a0aec0;">No hunt packages available</div>';
            return;
        }
        
        library.forEach(pkg => {
            const card = document.createElement('div');
            card.className = 'hunt-package-card';
            
            card.innerHTML = `
                <div class="hunt-package-header">
                    <h3>${pkg.name}</h3>
                    ${pkg.mitre_technique ? `<span class="badge info">${pkg.mitre_technique}</span>` : ''}
                </div>
                <p class="hunt-package-description">${pkg.description}</p>
                <div class="hunt-package-meta">
                    <span><i class="fas fa-layer-group"></i> ${pkg.category}</span>
                    <span><i class="fas fa-signal"></i> ${pkg.difficulty}</span>
                </div>
                <button class="btn-primary" onclick="startHunt(${pkg.id})">
                    <i class="fas fa-play"></i> Start Hunt
                </button>
            `;
            
            container.appendChild(card);
        });
    } catch (error) {
        console.error('Failed to load hunt library:', error);
    }
}

// Load and display active hunts
async function loadActiveHunts() {
    try {
        const hunts = await API.fetch('/hunts?status=active').then(r => r.json());
        const container = document.getElementById('active-hunts-list');
        
        if (!container) return;
        
        container.innerHTML = '';
        
        if (hunts.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 2rem; color: #a0aec0;">No active hunts</div>';
            return;
        }
        
        hunts.forEach(hunt => {
            const card = document.createElement('div');
            card.className = 'hunt-card';
            card.onclick = () => viewHuntDetails(hunt.id);
            
            const statusBadge = {
                'active': '<span class="badge info">Active</span>',
                'completed': '<span class="badge success">Completed</span>',
                'on_hold': '<span class="badge warning">On Hold</span>'
            }[hunt.status] || '<span class="badge">Unknown</span>';
            
            card.innerHTML = `
                <div class="hunt-card-header">
                    <h3>${hunt.name}</h3>
                    ${statusBadge}
                </div>
                <p class="hunt-hypothesis">${hunt.hypothesis}</p>
                <div class="hunt-card-meta">
                    <span><i class="fas fa-user"></i> ${hunt.analyst}</span>
                    <span><i class="fas fa-clock"></i> ${formatTime(hunt.created_at)}</span>
                    <span><i class="fas fa-search"></i> ${hunt.findings_count || 0} findings</span>
                </div>
                <div class="hunt-card-progress">
                    <div class="progress-label">Progress</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${hunt.progress || 0}%"></div>
                    </div>
                </div>
            `;
            
            container.appendChild(card);
        });
    } catch (error) {
        console.error('Failed to load active hunts:', error);
    }
}

// Start a new hunt from a package
async function startHunt(packageId) {
    showLoading();
    try {
        const result = await API.fetch('/hunts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                package_id: packageId,
                analyst: authState.user?.username || 'analyst'
            })
        }).then(r => r.json());
        
        showToast('Hunt started successfully', 'success');
        
        // Reload active hunts
        await loadActiveHunts();
        await loadHuntStatistics();
        
        // Open hunt details
        setTimeout(() => viewHuntDetails(result.hunt_id), 500);
    } catch (error) {
        showToast('Failed to start hunt', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// View hunt details
async function viewHuntDetails(huntId) {
    showLoading();
    try {
        const [hunt, findings, journal] = await Promise.all([
            API.fetch(`/hunts/${huntId}`).then(r => r.json()),
            API.fetch(`/hunts/${huntId}/findings`).then(r => r.json()),
            API.fetch(`/hunts/${huntId}/journal`).then(r => r.json())
        ]);
        
        // Create or get hunt detail modal
        const modal = document.getElementById('hunt-detail-modal') || createHuntDetailModal();
        const modalBody = modal.querySelector('.modal-body');
        
        modalBody.innerHTML = `
            <div class="hunt-detail-view">
                <div class="hunt-detail-header">
                    <h1>${hunt.name}</h1>
                    <div class="hunt-actions">
                        ${hunt.status === 'active' ? `
                            <button class="btn-success" onclick="completeHunt(${huntId})">
                                <i class="fas fa-check"></i> Complete Hunt
                            </button>
                        ` : ''}
                        <button class="btn-secondary" onclick="document.getElementById('hunt-detail-modal').style.display='none'">
                            <i class="fas fa-times"></i> Close
                        </button>
                    </div>
                </div>
                
                <div class="hunt-detail-meta">
                    <span><i class="fas fa-user"></i> ${hunt.analyst}</span>
                    <span><i class="fas fa-clock"></i> Started ${formatTime(hunt.created_at)}</span>
                    <span class="badge ${hunt.status === 'active' ? 'info' : 'success'}">${hunt.status}</span>
                    ${hunt.mitre_technique ? `<span class="badge warning">${hunt.mitre_technique}</span>` : ''}
                </div>
                
                <div class="hunt-section">
                    <h2>Hypothesis</h2>
                    <p class="hunt-hypothesis">${hunt.hypothesis}</p>
                </div>
                
                <div class="hunt-section">
                    <h2>Query</h2>
                    <div class="hunt-query-editor">
                        <textarea id="hunt-query-${huntId}" class="hunt-query-input" rows="6">${hunt.query || ''}</textarea>
                        <button class="btn-primary" onclick="updateHuntQuery(${huntId})">
                            <i class="fas fa-play"></i> Execute Query
                        </button>
                    </div>
                </div>
                
                <div class="hunt-section">
                    <div class="section-header">
                        <h2>Findings (${findings.length})</h2>
                        <button class="btn-secondary" onclick="addHuntFinding(${huntId})">
                            <i class="fas fa-plus"></i> Add Finding
                        </button>
                    </div>
                    <div id="hunt-findings-list" class="findings-list">
                        ${findings.length === 0 ? 
                            '<div style="text-align: center; padding: 2rem; color: #a0aec0;">No findings yet</div>' :
                            findings.map(finding => `
                                <div class="finding-item">
                                    <div class="finding-header">
                                        <strong>${finding.title}</strong>
                                        <span class="badge ${finding.severity}">${finding.severity}</span>
                                    </div>
                                    <p>${finding.description}</p>
                                    <div class="finding-meta">
                                        <span><i class="fas fa-clock"></i> ${formatTime(finding.timestamp)}</span>
                                        ${finding.ioc ? `<span><i class="fas fa-fingerprint"></i> ${finding.ioc}</span>` : ''}
                                    </div>
                                </div>
                            `).join('')
                        }
                    </div>
                </div>
                
                <div class="hunt-section">
                    <div class="section-header">
                        <h2>Hunt Journal</h2>
                        <button class="btn-secondary" onclick="addJournalEntry(${huntId})">
                            <i class="fas fa-plus"></i> Add Entry
                        </button>
                    </div>
                    <div id="hunt-journal-list" class="journal-list">
                        ${journal.length === 0 ? 
                            '<div style="text-align: center; padding: 2rem; color: #a0aec0;">No journal entries</div>' :
                            journal.map(entry => `
                                <div class="journal-entry">
                                    <div class="journal-header">
                                        <strong>${entry.analyst}</strong>
                                        <span class="journal-time">${formatTime(entry.timestamp)}</span>
                                    </div>
                                    <p>${entry.entry}</p>
                                </div>
                            `).join('')
                        }
                    </div>
                </div>
            </div>
        `;
        
        modal.style.display = 'block';
    } catch (error) {
        showToast('Failed to load hunt details', 'error');
        console.error(error);
    } finally {
        hideLoading();
    }
}

// Update and execute hunt query
async function updateHuntQuery(huntId) {
    const textarea = document.getElementById(`hunt-query-${huntId}`);
    const query = textarea.value;
    
    try {
        const result = await API.fetch(`/hunts/${huntId}/query`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        }).then(r => r.json());
        
        showToast(`Query executed: ${result.results_count || 0} results found`, 'success');
        
        // If results found, prompt to add as finding
        if (result.results_count > 0) {
            if (confirm(`Found ${result.results_count} results. Add as finding?`)) {
                addHuntFinding(huntId);
            }
        }
    } catch (error) {
        showToast('Failed to execute query', 'error');
        console.error(error);
    }
}

// Add finding to hunt
async function addHuntFinding(huntId) {
    const title = prompt('Finding title:');
    if (!title) return;
    
    const description = prompt('Finding description:');
    if (!description) return;
    
    const severity = prompt('Severity (low/medium/high/critical):', 'medium');
    
    try {
        await API.fetch(`/hunts/${huntId}/findings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                title, 
                description, 
                severity,
                analyst: authState.user?.username || 'analyst'
            })
        });
        
        showToast('Finding added successfully', 'success');
        
        // Reload hunt details
        viewHuntDetails(huntId);
    } catch (error) {
        showToast('Failed to add finding', 'error');
        console.error(error);
    }
}

// Add journal entry
async function addJournalEntry(huntId) {
    const entry = prompt('Journal entry:');
    if (!entry) return;
    
    try {
        await API.fetch(`/hunts/${huntId}/journal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                entry,
                analyst: authState.user?.username || 'analyst'
            })
        });
        
        showToast('Journal entry added', 'success');
        
        // Reload hunt details
        viewHuntDetails(huntId);
    } catch (error) {
        showToast('Failed to add journal entry', 'error');
        console.error(error);
    }
}

// Complete hunt
async function completeHunt(huntId) {
    if (!confirm('Mark this hunt as completed?')) return;
    
    const conclusion = prompt('Hunt conclusion:');
    
    try {
        await API.fetch(`/hunts/${huntId}/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ conclusion })
        });
        
        showToast('Hunt completed successfully', 'success');
        
        // Close modal and reload lists
        document.getElementById('hunt-detail-modal').style.display = 'none';
        await loadActiveHunts();
        await loadHuntStatistics();
    } catch (error) {
        showToast('Failed to complete hunt', 'error');
        console.error(error);
    }
}

// Build query from query builder inputs
function buildQuery() {
    const dataSource = document.getElementById('query-data-source')?.value || 'logs';
    const timeRange = document.getElementById('query-time-range')?.value || '24h';
    const conditions = [];
    
    // Get all condition rows
    document.querySelectorAll('.query-condition-row').forEach(row => {
        const field = row.querySelector('.condition-field')?.value;
        const operator = row.querySelector('.condition-operator')?.value;
        const value = row.querySelector('.condition-value')?.value;
        
        if (field && operator && value) {
            conditions.push({ field, operator, value });
        }
    });
    
    // Build query string
    let query = `source=${dataSource} timerange=${timeRange}`;
    
    if (conditions.length > 0) {
        query += ' | where ';
        query += conditions.map(c => {
            if (c.operator === 'contains') {
                return `${c.field} contains "${c.value}"`;
            } else if (c.operator === 'equals') {
                return `${c.field} == "${c.value}"`;
            } else if (c.operator === 'not_equals') {
                return `${c.field} != "${c.value}"`;
            } else {
                return `${c.field} ${c.operator} "${c.value}"`;
            }
        }).join(' and ');
    }
    
    // Set query in textarea
    const queryInput = document.getElementById('built-query-output');
    if (queryInput) {
        queryInput.value = query;
    }
    
    return query;
}

// Create hunt detail modal
function createHuntDetailModal() {
    const modal = document.createElement('div');
    modal.id = 'hunt-detail-modal';
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content large">
            <div class="modal-body"></div>
        </div>
    `;
    document.body.appendChild(modal);
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    return modal;
}

// Show custom hunt creation modal
function showCreateCustomHuntModal() {
    const modal = document.createElement('div');
    modal.id = 'create-hunt-modal';
    modal.className = 'modal';
    
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2>Create Custom Hunt</h2>
                <button class="modal-close" onclick="this.closest('.modal').remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="create-hunt-form">
                    <div class="form-group">
                        <label for="hunt-name">Hunt Name *</label>
                        <input type="text" id="hunt-name" name="name" required 
                               placeholder="e.g., Suspicious PowerShell Activity">
                    </div>
                    
                    <div class="form-group">
                        <label for="hunt-hypothesis">Hypothesis *</label>
                        <textarea id="hunt-hypothesis" name="hypothesis" required rows="3"
                                  placeholder="Describe what you're looking for and why..."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="hunt-category">Category *</label>
                        <select id="hunt-category" name="category" required>
                            <option value="">Select a category...</option>
                            <option value="Initial Access">Initial Access</option>
                            <option value="Execution">Execution</option>
                            <option value="Persistence">Persistence</option>
                            <option value="Privilege Escalation">Privilege Escalation</option>
                            <option value="Defense Evasion">Defense Evasion</option>
                            <option value="Credential Access">Credential Access</option>
                            <option value="Discovery">Discovery</option>
                            <option value="Lateral Movement">Lateral Movement</option>
                            <option value="Collection">Collection</option>
                            <option value="Command and Control">Command and Control</option>
                            <option value="Exfiltration">Exfiltration</option>
                            <option value="Impact">Impact</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="hunt-query">Query (Optional)</label>
                        <textarea id="hunt-query" name="query" rows="4"
                                  placeholder="source=logs | where process_name contains 'powershell.exe'"></textarea>
                        <small>You can also build the query later in the hunt detail page</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="hunt-mitre">MITRE Technique (Optional)</label>
                        <input type="text" id="hunt-mitre" name="mitre_technique" 
                               placeholder="e.g., T1059.001">
                    </div>
                    
                    <div class="modal-actions">
                        <button type="button" class="btn-secondary" onclick="this.closest('.modal').remove()">
                            Cancel
                        </button>
                        <button type="submit" class="btn-primary">
                            <i class="fas fa-plus"></i> Create Hunt
                        </button>
                    </div>
                </form>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    
    // Handle form submission
    const form = modal.querySelector('#create-hunt-form');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(form);
        const huntData = {
            name: formData.get('name'),
            hypothesis: formData.get('hypothesis'),
            category: formData.get('category'),
            query: formData.get('query') || '',
            mitre_technique: formData.get('mitre_technique') || '',
            analyst: authState.user?.username || 'analyst'
        };
        
        // Validate required fields
        if (!huntData.name || !huntData.hypothesis || !huntData.category) {
            showToast('Please fill in all required fields', 'error');
            return;
        }
        
        showLoading();
        try {
            const result = await API.fetch('/hunts/custom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(huntData)
            }).then(r => r.json());
            
            showToast('Custom hunt created successfully', 'success');
            modal.remove();
            
            // Reload active hunts and statistics
            await loadActiveHunts();
            await loadHuntStatistics();
            
            // Open hunt details
            setTimeout(() => viewHuntDetails(result.hunt_id), 500);
        } catch (error) {
            showToast('Failed to create custom hunt', 'error');
            console.error(error);
        } finally {
            hideLoading();
        }
    });
    
    // Close on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Launch hunt from static HTML card
function launchHuntFromStatic(huntType, card) {
    const modal = document.createElement('div');
    modal.id = 'launch-hunt-modal';
    modal.className = 'modal';
    
    // Get hunt details from card
    const title = card.querySelector('h4')?.textContent || 'Unknown Hunt';
    const description = card.querySelector('.hunt-package-description')?.textContent || '';
    const tags = Array.from(card.querySelectorAll('.tag')).map(t => t.textContent);
    
    // Map hunt types to hypotheses and queries
    const huntTemplates = {
        'lateral-movement': {
            hypothesis: 'Adversaries are attempting lateral movement using remote execution tools and authentication protocols (Pass-the-Hash, RDP, SMB).',
            query: 'source=windows_events | where (event_id=4624 AND logon_type=3) OR (process_name contains "psexec" OR process_name contains "wmic")',
            category: 'Lateral Movement'
        },
        'credential-theft': {
            hypothesis: 'Attackers are attempting to steal credentials through dumping, spraying, or accessing credential stores.',
            query: 'source=edr | where process_name contains "mimikatz" OR command_line contains "sekurlsa" OR (event_id=4625 AND failure_count>5)',
            category: 'Credential Access'
        },
        'data-exfil': {
            hypothesis: 'Suspicious data transfer patterns indicate potential data exfiltration to external locations.',
            query: 'source=network | where (bytes_out > 100MB OR connections_to_external > 50) AND protocol in ("https", "dns", "ftp")',
            category: 'Exfiltration'
        },
        'persistence': {
            hypothesis: 'Adversaries are establishing persistence through registry modifications, scheduled tasks, or service creation.',
            query: 'source=sysmon | where (event_id=13 AND registry_key contains "Run") OR (event_id=1 AND parent_process contains "schtasks")',
            category: 'Persistence'
        },
        'c2-detection': {
            hypothesis: 'Command and control beaconing patterns detected through network traffic analysis and DNS queries.',
            query: 'source=network | where (connection_frequency > 10 AND connection_size < 1KB) OR dns_query_entropy > 3.5',
            category: 'Command and Control'
        },
        'powershell-abuse': {
            hypothesis: 'Malicious PowerShell usage detected through obfuscation, download cradles, and encoded commands.',
            query: 'source=powershell_logs | where command_line contains "-enc" OR command_line contains "IEX" OR command_line contains "DownloadString"',
            category: 'Execution'
        }
    };
    
    const template = huntTemplates[huntType] || {
        hypothesis: 'Investigate suspicious activity patterns.',
        query: '',
        category: 'Discovery'
    };
    
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2>Launch Hunt: ${title}</h2>
                <button class="modal-close" onclick="this.closest('.modal').remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div style="margin-bottom: 1rem; padding: 1rem; background: #2d3748; border-radius: 4px;">
                    <p style="color: #a0aec0; margin: 0;">${description}</p>
                </div>
                
                <form id="launch-hunt-form">
                    <div class="form-group">
                        <label for="launch-hunt-name">Hunt Name *</label>
                        <input type="text" id="launch-hunt-name" name="name" required 
                               value="${title}">
                    </div>
                    
                    <div class="form-group">
                        <label for="launch-hunt-hypothesis">Hypothesis *</label>
                        <textarea id="launch-hunt-hypothesis" name="hypothesis" required rows="3">${template.hypothesis}</textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="launch-hunt-query">Query</label>
                        <textarea id="launch-hunt-query" name="query" rows="4">${template.query}</textarea>
                    </div>
                    
                    <div class="modal-actions">
                        <button type="button" class="btn-secondary" onclick="this.closest('.modal').remove()">
                            Cancel
                        </button>
                        <button type="submit" class="btn-primary">
                            <i class="fas fa-play"></i> Launch Hunt
                        </button>
                    </div>
                </form>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    
    // Handle form submission
    const form = modal.querySelector('#launch-hunt-form');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(form);
        const huntData = {
            name: formData.get('name'),
            hypothesis: formData.get('hypothesis'),
            query: formData.get('query'),
            category: template.category,
            mitre_techniques: tags.filter(t => t.includes('MITRE:')).map(t => t.replace('MITRE:', '').trim()),
            analyst: authState.user?.username || 'analyst'
        };
        
        showLoading();
        try {
            const result = await API.fetch('/hunts/custom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(huntData)
            }).then(r => r.json());
            
            showToast('Hunt launched successfully', 'success');
            modal.remove();
            
            // Reload active hunts and statistics
            await loadActiveHunts();
            await loadHuntStatistics();
            
            // Open hunt details
            setTimeout(() => viewHuntDetails(result.hunt_id), 500);
        } catch (error) {
            showToast('Failed to launch hunt', 'error');
            console.error(error);
        } finally {
            hideLoading();
        }
    });
    
    // Close on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}
