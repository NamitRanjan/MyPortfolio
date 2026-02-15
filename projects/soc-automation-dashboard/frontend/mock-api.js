// Mock API for GitHub Pages deployment (works without backend)
// This file provides all data statically when backend is not available

const MOCK_DATA = {
    // Dashboard stats
    stats: null,
    
    // All security data
    alerts: [],
    threats: [],
    incidents: [],
    iocs: [],
    team: [],
    
    // Authentication and workbench data
    users: [],
    caseNotes: [],
    evidence: [],
    auditLog: [],
    
    // Threat intel
    threatFeeds: [],
    recentThreats: [],
    
    // Phase 2: Correlations and notifications
    correlations: [],
    notifications: [],
    escalationPolicies: [],
    oncallSchedule: {},
    webhookConfig: [],
    
    // Phase 3: Compliance and hunting
    complianceMappings: [],
    reports: [],
    hunts: [],
    huntLibrary: [],
    huntMetrics: {},
    
    // Flag to indicate if data is ready
    ready: false,
    
    // Initialize function
    async init() {
        try {
            // Helper to load data with better error tracking
            const loadDataFile = async (filename, defaultValue = []) => {
                try {
                    const response = await fetch(`./data/${filename}`);
                    if (!response.ok) {
                        console.warn(`Failed to load ${filename}: ${response.status} ${response.statusText}`);
                        return defaultValue;
                    }
                    return await response.json();
                } catch (error) {
                    console.warn(`Failed to load ${filename}:`, error.message);
                    return defaultValue;
                }
            };
            
            // Load all data files
            const [alerts, threats, incidents, iocs, team, users, caseNotes, evidence, correlations, notifications, escalationPolicies, oncallSchedule, webhookConfig, complianceMappings, reports, hunts, huntLibrary, huntMetrics] = await Promise.all([
                loadDataFile('alerts.json'),
                loadDataFile('threats.json'),
                loadDataFile('incidents.json'),
                loadDataFile('iocs.json'),
                loadDataFile('team.json'),
                loadDataFile('users.json'),
                loadDataFile('case_notes.json'),
                loadDataFile('evidence.json'),
                loadDataFile('correlations.json'),
                loadDataFile('notifications.json'),
                loadDataFile('escalation_policies.json'),
                loadDataFile('oncall_schedule.json', {}),
                loadDataFile('webhook_config.json'),
                loadDataFile('compliance_mappings.json'),
                loadDataFile('reports.json'),
                loadDataFile('hunts.json'),
                loadDataFile('hunt_library.json'),
                loadDataFile('hunt_metrics.json', {})
            ]);
            
            this.alerts = alerts;
            this.threats = threats;
            this.incidents = incidents;
            this.iocs = iocs;
            this.team = team;
            this.users = users;
            this.caseNotes = caseNotes;
            this.evidence = evidence;
            this.auditLog = []; // Start empty, will populate on actions
            this.correlations = correlations;
            this.notifications = notifications;
            this.escalationPolicies = escalationPolicies;
            this.oncallSchedule = oncallSchedule;
            this.webhookConfig = webhookConfig;
            this.complianceMappings = complianceMappings;
            this.reports = reports;
            this.hunts = hunts;
            this.huntLibrary = huntLibrary;
            this.huntMetrics = huntMetrics;
            
            // Calculate stats
            const activeAlerts = alerts.filter(a => a.status === 'active');
            const criticalIncidents = incidents.filter(i => i.severity === 'critical');
            
            this.stats = {
                total_alerts: alerts.length,
                active_alerts: activeAlerts.length,
                total_incidents: incidents.length,
                critical_incidents: criticalIncidents.length,
                blocked_threats: threats.filter(t => t.action === 'blocked').length,
                iocs_detected: iocs.length,
                mttr: '45 min',
                automation_rate: '87%'
            };
            
            // Generate threat feeds
            this.threatFeeds = [
                {
                    name: 'AlienVault OTX',
                    status: 'active',
                    last_update: new Date().toISOString(),
                    pulses_count: 1247,
                    indicators_count: 15832
                },
                {
                    name: 'AbuseIPDB',
                    status: 'active',
                    last_update: new Date().toISOString(),
                    malicious_ips: 892,
                    reports_count: 5643
                },
                {
                    name: 'VirusTotal',
                    status: 'active',
                    last_update: new Date().toISOString(),
                    scans_today: 234,
                    detections: 67
                },
                {
                    name: 'Emerging Threats',
                    status: 'active',
                    last_update: new Date().toISOString(),
                    rules_count: 8942,
                    categories: 45
                },
                {
                    name: 'MISP',
                    status: 'active',
                    last_update: new Date().toISOString(),
                    events: 523,
                    attributes: 7891
                }
            ];
            
            // Generate recent threats
            this.recentThreats = [
                {
                    id: 1,
                    title: 'New Ransomware Campaign Targeting Healthcare',
                    severity: 'critical',
                    published: new Date(Date.now() - 2*3600000).toISOString(),
                    source: 'AlienVault OTX',
                    indicators: 23,
                    description: 'New variant of LockBit targeting healthcare institutions'
                },
                {
                    id: 2,
                    title: 'APT Group Using Zero-Day in Exchange Servers',
                    severity: 'critical',
                    published: new Date(Date.now() - 5*3600000).toISOString(),
                    source: 'CISA',
                    indicators: 15,
                    description: 'State-sponsored actors exploiting previously unknown vulnerability'
                },
                {
                    id: 3,
                    title: 'Phishing Campaign Impersonating Microsoft',
                    severity: 'high',
                    published: new Date(Date.now() - 8*3600000).toISOString(),
                    source: 'PhishTank',
                    indicators: 47,
                    description: 'Large-scale phishing targeting Office 365 credentials'
                },
                {
                    id: 4,
                    title: 'Botnet C2 Infrastructure Discovered',
                    severity: 'high',
                    published: new Date(Date.now() - 12*3600000).toISOString(),
                    source: 'Emerging Threats',
                    indicators: 89,
                    description: 'New Mirai variant command and control servers identified'
                },
                {
                    id: 5,
                    title: 'Critical Vulnerability in Popular CMS',
                    severity: 'critical',
                    published: new Date(Date.now() - 18*3600000).toISOString(),
                    source: 'NVD',
                    indicators: 12,
                    description: 'Remote code execution in WordPress plugin affecting 1M+ sites'
                }
            ];
            
            this.ready = true;
            console.log('Mock data initialized successfully');
            return true;
        } catch (error) {
            console.error('Failed to initialize mock data:', error);
            console.error('Please ensure all required data files exist in ./data/ directory');
            return false;
        }
    },
    
    // API methods
    getDashboardStats() {
        return this.stats;
    },
    
    getAlerts(filters = {}) {
        let filtered = [...this.alerts];
        if (filters.status) {
            filtered = filtered.filter(a => a.status === filters.status);
        }
        if (filters.severity) {
            filtered = filtered.filter(a => a.severity === filters.severity);
        }
        return filtered;
    },
    
    getThreats() {
        return this.threats;
    },
    
    getIncidents(filters = {}) {
        let filtered = [...this.incidents];
        if (filters.status) {
            filtered = filtered.filter(i => i.status === filters.status);
        }
        return filtered;
    },
    
    getIOCs(filters = {}) {
        let filtered = [...this.iocs];
        if (filters.type) {
            filtered = filtered.filter(i => i.type === filters.type);
        }
        return filtered;
    },
    
    getTeam(filters = {}) {
        let filtered = [...this.team];
        if (filters.status) {
            filtered = filtered.filter(t => t.status === filters.status);
        }
        if (filters.role) {
            filtered = filtered.filter(t => t.role.toLowerCase().includes(filters.role.toLowerCase()));
        }
        return filtered;
    },
    
    getPlaybooks() {
        return [
            {
                id: 1,
                name: 'Malware Detection Response',
                description: 'Automated response to malware detection alerts',
                steps: 6,
                avg_execution_time: '2 min',
                success_rate: '94%',
                triggers: ['malware_detected', 'suspicious_file']
            },
            {
                id: 2,
                name: 'Phishing Email Investigation',
                description: 'Investigate and respond to phishing attempts',
                steps: 8,
                avg_execution_time: '3 min',
                success_rate: '91%',
                triggers: ['phishing_detected', 'suspicious_email']
            },
            {
                id: 3,
                name: 'Brute Force Attack Mitigation',
                description: 'Block and investigate brute force attempts',
                steps: 5,
                avg_execution_time: '1 min',
                success_rate: '97%',
                triggers: ['brute_force', 'multiple_failed_logins']
            },
            {
                id: 4,
                name: 'Data Exfiltration Prevention',
                description: 'Detect and prevent unauthorized data transfers',
                steps: 7,
                avg_execution_time: '4 min',
                success_rate: '89%',
                triggers: ['abnormal_data_transfer', 'dlp_violation']
            },
            {
                id: 5,
                name: 'Insider Threat Investigation',
                description: 'Investigate suspicious insider activities',
                steps: 9,
                avg_execution_time: '6 min',
                success_rate: '85%',
                triggers: ['insider_threat', 'privilege_abuse']
            }
        ];
    },
    
    getPlaybookSteps(playbookId) {
        const stepsMap = {
            1: [ // Malware Detection Response
                { name: 'Isolate infected host', duration: '15s', order: 1 },
                { name: 'Collect forensic artifacts', duration: '30s', order: 2 },
                { name: 'Block C2 communications', duration: '20s', order: 3 },
                { name: 'Scan for lateral movement', duration: '25s', order: 4 },
                { name: 'Update threat signatures', duration: '10s', order: 5 },
                { name: 'Generate incident report', duration: '20s', order: 6 }
            ],
            2: [ // Phishing Email Investigation
                { name: 'Extract email headers', duration: '10s', order: 1 },
                { name: 'Analyze URLs and attachments', duration: '25s', order: 2 },
                { name: 'Check sender reputation', duration: '15s', order: 3 },
                { name: 'Search for similar emails', duration: '20s', order: 4 },
                { name: 'Quarantine malicious messages', duration: '15s', order: 5 },
                { name: 'Block sender domain', duration: '10s', order: 6 },
                { name: 'Notify affected users', duration: '15s', order: 7 },
                { name: 'Update email filters', duration: '15s', order: 8 }
            ],
            3: [ // Brute Force Attack Mitigation
                { name: 'Identify attack source', duration: '10s', order: 1 },
                { name: 'Block source IP address', duration: '5s', order: 2 },
                { name: 'Reset compromised credentials', duration: '20s', order: 3 },
                { name: 'Enable MFA for account', duration: '15s', order: 4 },
                { name: 'Generate security alert', duration: '10s', order: 5 }
            ],
            4: [ // Data Exfiltration Prevention
                { name: 'Identify data transfer', duration: '20s', order: 1 },
                { name: 'Block outbound connection', duration: '10s', order: 2 },
                { name: 'Isolate affected endpoint', duration: '15s', order: 3 },
                { name: 'Analyze transferred data', duration: '30s', order: 4 },
                { name: 'Check for data staging', duration: '25s', order: 5 },
                { name: 'Update DLP policies', duration: '15s', order: 6 },
                { name: 'Notify security team', duration: '10s', order: 7 }
            ],
            5: [ // Insider Threat Investigation
                { name: 'Collect user activity logs', duration: '25s', order: 1 },
                { name: 'Analyze access patterns', duration: '30s', order: 2 },
                { name: 'Review privilege usage', duration: '20s', order: 3 },
                { name: 'Check data access history', duration: '25s', order: 4 },
                { name: 'Correlate with external events', duration: '30s', order: 5 },
                { name: 'Enable enhanced monitoring', duration: '15s', order: 6 },
                { name: 'Restrict sensitive access', duration: '20s', order: 7 },
                { name: 'Notify HR and legal', duration: '15s', order: 8 },
                { name: 'Generate investigation report', duration: '20s', order: 9 }
            ]
        };
        
        return stepsMap[playbookId] || [];
    },
    
    executePlaybook(playbookId) {
        const steps = this.getPlaybookSteps(playbookId);
        const success = Math.random() > 0.1; // 90% success rate
        
        return {
            playbook_id: playbookId,
            status: success ? 'completed' : 'failed',
            steps: steps.map((step, index) => ({
                ...step,
                status: success ? 'completed' : (index < steps.length - 1 ? 'completed' : 'failed')
            })),
            execution_time: steps.reduce((sum, step) => {
                const duration = parseInt(step.duration);
                return sum + duration;
            }, 0),
            timestamp: new Date().toISOString(),
            message: success 
                ? 'Playbook executed successfully. All steps completed.'
                : 'Playbook execution failed. Please review the logs.'
        };
    },
    
    getThreatFeeds() {
        return this.threatFeeds;
    },
    
    getRecentThreats() {
        return this.recentThreats;
    },
    
    getTimeline(hours = 24) {
        const timeline = [];
        for (let i = 0; i < hours; i++) {
            const hourAgo = new Date(Date.now() - (hours - i) * 3600000);
            timeline.push({
                timestamp: hourAgo.toISOString(),
                alerts: Math.floor(Math.random() * 25) + 5,
                threats_blocked: Math.floor(Math.random() * 15),
                incidents: Math.floor(Math.random() * 3)
            });
        }
        return timeline;
    },
    
    getThreatMap() {
        return [
            {country: 'United States', lat: 37.0902, lon: -95.7129, count: 1247},
            {country: 'China', lat: 35.8617, lon: 104.1954, count: 892},
            {country: 'Russia', lat: 61.5240, lon: 105.3188, count: 743},
            {country: 'Brazil', lat: -14.2350, lon: -51.9253, count: 456},
            {country: 'Germany', lat: 51.1657, lon: 10.4515, count: 389},
            {country: 'India', lat: 20.5937, lon: 78.9629, count: 612},
            {country: 'United Kingdom', lat: 55.3781, lon: -3.4360, count: 334},
            {country: 'France', lat: 46.2276, lon: 2.2137, count: 287},
            {country: 'Japan', lat: 36.2048, lon: 138.2529, count: 423},
            {country: 'South Korea', lat: 35.9078, lon: 127.7669, count: 298}
        ];
    },
    
    investigateAlert(alertId) {
        return {
            alert_id: alertId,
            status: 'investigating',
            steps_completed: [
                'IOC enrichment completed',
                'Threat intelligence lookup completed',
                'User behavior analysis completed',
                'Network flow analysis completed'
            ],
            findings: {
                ioc_matches: Math.floor(Math.random() * 5) + 1,
                threat_score: Math.floor(Math.random() * 35) + 60,
                recommended_action: ['isolate', 'block', 'monitor'][Math.floor(Math.random() * 3)],
                confidence: Math.floor(Math.random() * 24) + 75
            },
            timestamp: new Date().toISOString()
        };
    },
    
    respondToAlert(alertId, action) {
        const actionsMap = {
            isolate: [
                'Host isolated from network',
                'Active connections terminated',
                'Notification sent to SOC team',
                'Incident ticket created'
            ],
            block: [
                'IP address added to blocklist',
                'Firewall rules updated',
                'Threat intel feed updated',
                'Alert notification sent'
            ],
            monitor: [
                'Enhanced monitoring enabled',
                'Additional logging configured',
                'Behavior analytics updated',
                'Watchlist updated'
            ]
        };
        
        return {
            alert_id: alertId,
            action: action,
            status: 'executed',
            actions_taken: actionsMap[action] || [],
            timestamp: new Date().toISOString()
        };
    },
    
    // Authentication methods
    mockLogin(username, password) {
        const user = this.users.find(u => u.username === username);
        if (!user || password !== 'SOCdemo2026!') {
            return null;
        }
        
        // Generate mock token
        const token = 'mock_' + Math.random().toString(36).substr(2) + Date.now().toString(36);
        
        // Log action
        this.addAuditEntry(user.id, user.username, 'login', 'auth', null, {});
        
        return {
            token: token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                display_name: user.display_name,
                email: user.email
            }
        };
    },
    
    mockLogout(username) {
        // Log action
        this.addAuditEntry(null, username, 'logout', 'auth', null, {});
        return { message: 'Logged out successfully' };
    },
    
    mockGetCurrentUser(username) {
        const user = this.users.find(u => u.username === username);
        if (!user) return null;
        
        return {
            id: user.id,
            username: user.username,
            role: user.role,
            display_name: user.display_name,
            email: user.email
        };
    },
    
    // Case Notes methods
    getAlertNotes(alertId) {
        return this.caseNotes.filter(n => n.alert_id === alertId);
    },
    
    getIncidentNotes(incidentId) {
        return this.caseNotes.filter(n => n.incident_id === incidentId);
    },
    
    addNote(note) {
        const newId = Math.max(...this.caseNotes.map(n => n.id), 0) + 1;
        const newNote = {
            id: newId,
            ...note,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        this.caseNotes.push(newNote);
        
        // Log action
        this.addAuditEntry(note.author_id, note.author_name, 'note_added', 
                          note.alert_id ? 'alert' : 'incident', 
                          note.alert_id || note.incident_id,
                          { note_type: note.type });
        
        return newNote;
    },
    
    // Evidence methods
    getAlertEvidence(alertId) {
        return this.evidence.filter(e => e.alert_id === alertId);
    },
    
    getIncidentEvidence(incidentId) {
        return this.evidence.filter(e => e.incident_id === incidentId);
    },
    
    addEvidence(evidence) {
        const newId = Math.max(...this.evidence.map(e => e.id), 0) + 1;
        const newEvidence = {
            id: newId,
            ...evidence,
            collected_at: new Date().toISOString(),
            chain_of_custody: [
                {
                    action: 'collected',
                    by: evidence.collected_by_name,
                    at: new Date().toISOString(),
                    notes: evidence.initial_notes || 'Evidence collected'
                }
            ],
            status: 'collected'
        };
        this.evidence.push(newEvidence);
        
        // Log action
        this.addAuditEntry(evidence.collected_by_id, evidence.collected_by_name, 'evidence_added',
                          evidence.alert_id ? 'alert' : 'incident',
                          evidence.alert_id || evidence.incident_id,
                          { evidence_type: evidence.type });
        
        return newEvidence;
    },
    
    // Audit Log methods
    addAuditEntry(userId, username, action, resourceType, resourceId, details) {
        const newId = Math.max(...this.auditLog.map(e => e.id), 0) + 1;
        const entry = {
            id: newId,
            timestamp: new Date().toISOString(),
            user_id: userId,
            username: username,
            action: action,
            resource_type: resourceType,
            resource_id: resourceId,
            details: details,
            ip_address: '127.0.0.1'
        };
        this.auditLog.push(entry);
        return entry;
    },
    
    getAuditLog(filters = {}) {
        let filtered = [...this.auditLog];
        
        if (filters.user_id) {
            filtered = filtered.filter(e => e.user_id === filters.user_id);
        }
        if (filters.action) {
            filtered = filtered.filter(e => e.action === filters.action);
        }
        if (filters.resource_type) {
            filtered = filtered.filter(e => e.resource_type === filters.resource_type);
        }
        
        // Sort by timestamp descending
        filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Paginate
        const page = filters.page || 1;
        const perPage = filters.per_page || 50;
        const start = (page - 1) * perPage;
        const end = start + perPage;
        const paginated = filtered.slice(start, end);
        
        return {
            entries: paginated,
            total: filtered.length,
            page: page,
            per_page: perPage,
            total_pages: Math.ceil(filtered.length / perPage)
        };
    },
    
    // SLA calculation
    getAlertSLA(alertId) {
        const alert = this.alerts.find(a => a.id === alertId);
        if (!alert) return null;
        
        const slaMinutes = {
            'critical': 15,
            'high': 60,
            'medium': 240,
            'low': 1440
        };
        
        const severity = alert.severity || 'medium';
        const sla = slaMinutes[severity] || 240;
        
        const alertTime = new Date(alert.timestamp);
        const elapsed = (Date.now() - alertTime.getTime()) / (1000 * 60);
        const remaining = sla - elapsed;
        const percentage = Math.min(100, (elapsed / sla) * 100);
        
        return {
            alert_id: alertId,
            severity: severity,
            sla_minutes: sla,
            elapsed_minutes: Math.floor(elapsed),
            remaining_minutes: Math.floor(remaining),
            is_breached: remaining < 0,
            percentage: Math.round(percentage * 100) / 100,
            status: remaining < 0 ? 'breached' : (percentage > 75 ? 'warning' : 'normal')
        };
    },
    
    // ===== CORRELATION ENGINE METHODS =====
    
    getCorrelations(filters = {}) {
        let correlations = [...this.correlations];
        
        if (filters.status) {
            correlations = correlations.filter(c => c.status === filters.status);
        }
        if (filters.risk_level) {
            correlations = correlations.filter(c => c.risk_level === filters.risk_level);
        }
        if (filters.min_score) {
            correlations = correlations.filter(c => c.correlation_score >= filters.min_score);
        }
        
        return correlations;
    },
    
    getCorrelationDetail(correlationId) {
        const correlation = this.correlations.find(c => c.id === correlationId);
        if (!correlation) return null;
        
        // Enrich with full alert details
        const alerts = this.alerts.filter(a => correlation.alert_ids.includes(a.id));
        return { ...correlation, alerts };
    },
    
    analyzeCorrelations() {
        // Return existing correlations as if freshly analyzed
        return {
            success: true,
            groups_found: this.correlations.length,
            correlations: this.correlations
        };
    },
    
    getCorrelationStats() {
        if (this.correlations.length === 0) {
            return {
                total_groups: 0,
                average_score: 0,
                deduplication_rate: 0,
                alerts_correlated: 0,
                alerts_uncorrelated: this.alerts.length,
                by_risk_level: { critical: 0, high: 0, medium: 0, low: 0 }
            };
        }
        
        const totalGroups = this.correlations.length;
        const avgScore = this.correlations.reduce((sum, c) => sum + c.correlation_score, 0) / totalGroups;
        
        const correlatedAlertIds = new Set();
        this.correlations.forEach(c => {
            c.alert_ids.forEach(id => correlatedAlertIds.add(id));
        });
        
        const alertsCorrelated = correlatedAlertIds.size;
        const alertsUncorrelated = this.alerts.length - alertsCorrelated;
        
        // Simple deduplication rate estimate
        const deduplicationRate = 15.0;
        
        return {
            total_groups: totalGroups,
            average_score: Math.round(avgScore * 10) / 10,
            deduplication_rate: deduplicationRate,
            alerts_correlated: alertsCorrelated,
            alerts_uncorrelated: alertsUncorrelated,
            by_risk_level: {
                critical: this.correlations.filter(c => c.risk_level === 'critical').length,
                high: this.correlations.filter(c => c.risk_level === 'high').length,
                medium: this.correlations.filter(c => c.risk_level === 'medium').length,
                low: this.correlations.filter(c => c.risk_level === 'low').length
            }
        };
    },
    
    getRelatedAlerts(alertId) {
        const targetAlert = this.alerts.find(a => a.id === alertId);
        if (!targetAlert) return { alert_id: alertId, related_alerts: [] };
        
        // Find correlation group containing this alert
        const correlation = this.correlations.find(c => c.alert_ids.includes(alertId));
        
        let relatedAlerts = [];
        
        if (correlation) {
            // Get other alerts from the same correlation
            const otherAlertIds = correlation.alert_ids.filter(id => id !== alertId);
            relatedAlerts = this.alerts
                .filter(a => otherAlertIds.includes(a.id))
                .map(a => ({
                    alert: a,
                    similarity_score: 75 + Math.floor(Math.random() * 20),
                    entity_similarity: 70 + Math.floor(Math.random() * 25),
                    time_proximity: 60 + Math.floor(Math.random() * 30),
                    shared_entities: {
                        hosts: targetAlert.host === a.host ? [a.host] : [],
                        users: targetAlert.user === a.user ? [a.user] : [],
                        mitre_tactics: targetAlert.mitre_tactics.filter(t => a.mitre_tactics.includes(t))
                    }
                }));
        } else {
            // Find similar alerts by matching properties
            relatedAlerts = this.alerts
                .filter(a => a.id !== alertId)
                .filter(a => 
                    a.host === targetAlert.host || 
                    a.user === targetAlert.user ||
                    a.mitre_tactics.some(t => targetAlert.mitre_tactics.includes(t))
                )
                .slice(0, 5)
                .map(a => ({
                    alert: a,
                    similarity_score: 50 + Math.floor(Math.random() * 30),
                    entity_similarity: 45 + Math.floor(Math.random() * 35),
                    time_proximity: 40 + Math.floor(Math.random() * 40),
                    shared_entities: {
                        hosts: targetAlert.host === a.host ? [a.host] : [],
                        users: targetAlert.user === a.user ? [a.user] : [],
                        mitre_tactics: targetAlert.mitre_tactics.filter(t => a.mitre_tactics.includes(t))
                    }
                }));
        }
        
        return { alert_id: alertId, related_alerts: relatedAlerts };
    },
    
    getAlertKillChain(alertId) {
        const correlation = this.correlations.find(c => c.alert_ids.includes(alertId));
        
        if (!correlation) {
            return {
                alert_id: alertId,
                in_correlation: false,
                kill_chain_position: null
            };
        }
        
        const killChainItem = correlation.kill_chain.find(k => k.alert_id === alertId);
        
        return {
            alert_id: alertId,
            in_correlation: true,
            correlation_id: correlation.id,
            correlation_name: correlation.name,
            kill_chain_position: killChainItem,
            kill_chain_coverage: correlation.kill_chain_coverage,
            risk_level: correlation.risk_level
        };
    },
    
    getDuplicateAlerts() {
        // Simple duplication detection
        const duplicates = [];
        const seen = new Set();
        
        for (let i = 0; i < this.alerts.length; i++) {
            if (seen.has(i)) continue;
            
            const alert = this.alerts[i];
            const duplicateGroup = [];
            
            for (let j = i + 1; j < this.alerts.length; j++) {
                if (seen.has(j)) continue;
                
                const other = this.alerts[j];
                if (alert.title === other.title && alert.host === other.host) {
                    duplicateGroup.push(other.id);
                    seen.add(j);
                }
            }
            
            if (duplicateGroup.length > 0) {
                duplicates.push({
                    primary_alert_id: alert.id,
                    duplicate_alert_ids: duplicateGroup,
                    count: duplicateGroup.length + 1,
                    primary_alert: alert,
                    duplicate_alerts: this.alerts.filter(a => duplicateGroup.includes(a.id))
                });
            }
        }
        
        return {
            duplicate_groups: duplicates,
            total_duplicates: duplicates.reduce((sum, d) => sum + d.count - 1, 0)
        };
    },
    
    deduplicateAlerts() {
        const result = this.getDuplicateAlerts();
        return {
            success: true,
            ...result,
            deduplication_rate: this.alerts.length > 0 
                ? Math.round((result.total_duplicates / this.alerts.length) * 1000) / 10 
                : 0
        };
    },
    
    // ===== NOTIFICATION ENGINE METHODS =====
    
    getNotifications(filters = {}) {
        let notifications = [...this.notifications];
        
        // Filter by current user (in mock mode, show all)
        if (filters.user_id) {
            notifications = notifications.filter(n => n.user_id === filters.user_id);
        }
        
        if (filters.read !== undefined) {
            const isRead = filters.read === 'true' || filters.read === true;
            notifications = notifications.filter(n => n.read === isRead);
        }
        
        if (filters.type) {
            notifications = notifications.filter(n => n.type === filters.type);
        }
        
        if (filters.severity) {
            notifications = notifications.filter(n => n.severity === filters.severity);
        }
        
        return notifications;
    },
    
    getNotificationCount(userId) {
        return {
            unread_count: this.notifications.filter(n => 
                (!userId || n.user_id === userId) && !n.read
            ).length
        };
    },
    
    markNotificationRead(notificationId) {
        const notification = this.notifications.find(n => n.id === notificationId);
        if (notification) {
            notification.read = true;
            return { success: true, notification };
        }
        return { success: false, error: 'Notification not found' };
    },
    
    markAllNotificationsRead(userId) {
        this.notifications.forEach(n => {
            if (!userId || n.user_id === userId) {
                n.read = true;
            }
        });
        return { success: true, message: 'All notifications marked as read' };
    },
    
    sendTestNotification(userId) {
        const notification = {
            id: this.notifications.length + 1,
            user_id: userId,
            type: 'system_alert',
            title: 'Test Notification',
            message: 'This is a test notification from the SOC Automation Platform',
            severity: 'medium',
            resource_type: 'system',
            resource_id: null,
            read: false,
            acknowledged_at: null,
            created_at: new Date().toISOString()
        };
        
        this.notifications.unshift(notification);
        return { success: true, notification };
    },
    
    // ===== ESCALATION POLICY METHODS =====
    
    getEscalationPolicies() {
        return this.escalationPolicies;
    },
    
    getEscalationPolicy(policyId) {
        return this.escalationPolicies.find(p => p.id === policyId) || null;
    },
    
    updateEscalationPolicy(policyId, updates) {
        const policy = this.escalationPolicies.find(p => p.id === policyId);
        if (policy) {
            Object.assign(policy, updates);
            return { success: true, policy };
        }
        return { success: false, error: 'Policy not found' };
    },
    
    toggleEscalationPolicy(policyId) {
        const policy = this.escalationPolicies.find(p => p.id === policyId);
        if (policy) {
            policy.enabled = !policy.enabled;
            return { success: true, policy };
        }
        return { success: false, error: 'Policy not found' };
    },
    
    getAlertEscalationStatus(alertId) {
        const alert = this.alerts.find(a => a.id === alertId);
        if (!alert) return null;
        
        const alertTime = new Date(alert.timestamp);
        const alertAgeMinutes = (Date.now() - alertTime.getTime()) / (1000 * 60);
        
        // Find matching policy
        const policy = this.escalationPolicies.find(p => 
            p.trigger_severity === alert.severity && p.enabled
        );
        
        if (!policy) {
            return {
                alert_id: alertId,
                alert_age_minutes: Math.floor(alertAgeMinutes),
                escalation: null
            };
        }
        
        // Find current escalation level
        let currentLevel = null;
        for (const level of policy.levels) {
            if (alertAgeMinutes >= level.escalate_after_minutes) {
                currentLevel = level;
            }
        }
        
        if (!currentLevel) {
            return {
                alert_id: alertId,
                alert_age_minutes: Math.floor(alertAgeMinutes),
                escalation: null
            };
        }
        
        // Find next level
        let nextLevel = null;
        for (const level of policy.levels) {
            if (level.level > currentLevel.level) {
                nextLevel = level;
                break;
            }
        }
        
        return {
            alert_id: alertId,
            alert_age_minutes: Math.floor(alertAgeMinutes),
            escalation: {
                policy_id: policy.id,
                policy_name: policy.name,
                current_level: currentLevel.level,
                current_action: currentLevel.action,
                notified_roles: currentLevel.notify_roles,
                next_escalation_in_minutes: nextLevel 
                    ? Math.floor(nextLevel.escalate_after_minutes - alertAgeMinutes)
                    : null,
                next_level: nextLevel ? nextLevel.level : null
            }
        };
    },
    
    // ===== ON-CALL METHODS =====
    
    getCurrentOncall() {
        return this.oncallSchedule.current_oncall || {};
    },
    
    getOncallSchedule() {
        return this.oncallSchedule;
    },
    
    setOncallOverride(data) {
        this.oncallSchedule.override = {
            ...data,
            set_by: 'system',
            set_at: new Date().toISOString()
        };
        return { success: true, schedule: this.oncallSchedule };
    },
    
    // ===== WEBHOOK METHODS =====
    
    getWebhooks() {
        return this.webhookConfig;
    },
    
    testWebhook(webhookId) {
        const webhook = this.webhookConfig.find(w => w.id === webhookId);
        if (!webhook) {
            return { success: false, error: 'Webhook not found' };
        }
        
        return {
            success: true,
            webhook_id: webhook.id,
            webhook_name: webhook.name,
            webhook_type: webhook.type,
            url: webhook.url,
            event: 'test',
            timestamp: new Date().toISOString(),
            simulated: true,
            message: `Simulated ${webhook.type} webhook trigger successful`
        };
    },
    
    toggleWebhook(webhookId) {
        const webhook = this.webhookConfig.find(w => w.id === webhookId);
        if (webhook) {
            webhook.enabled = !webhook.enabled;
            return { success: true, webhook };
        }
        return { success: false, error: 'Webhook not found' };
    },
    
    // ===== COMPLIANCE METHODS =====
    
    getComplianceFrameworks() {
        // Extract unique frameworks from compliance mappings
        const frameworks = new Set();
        this.complianceMappings.forEach(mapping => {
            frameworks.add(mapping.framework);
        });
        
        return Array.from(frameworks).map(framework => {
            const mappings = this.complianceMappings.filter(m => m.framework === framework);
            return {
                id: framework.toLowerCase().replace(/\s+/g, '_'),
                name: framework,
                total_controls: mappings.length,
                covered_controls: mappings.filter(m => m.coverage_status === 'covered').length,
                compliance_percentage: Math.round((mappings.filter(m => m.coverage_status === 'covered').length / mappings.length) * 100)
            };
        });
    },
    
    getCompliancePosture() {
        const frameworks = this.getComplianceFrameworks();
        const totalControls = frameworks.reduce((sum, f) => sum + f.total_controls, 0);
        const coveredControls = frameworks.reduce((sum, f) => sum + f.covered_controls, 0);
        
        return {
            overall_compliance: totalControls > 0 ? Math.round((coveredControls / totalControls) * 100) : 0,
            frameworks: frameworks,
            total_controls: totalControls,
            covered_controls: coveredControls,
            gap_controls: totalControls - coveredControls,
            last_updated: new Date().toISOString()
        };
    },
    
    getComplianceCoverage(frameworkId) {
        const framework = frameworkId.toUpperCase().replace(/_/g, ' ');
        const mappings = this.complianceMappings.filter(m => m.framework === framework);
        
        return {
            framework_id: frameworkId,
            framework_name: framework,
            controls: mappings.map(m => ({
                control_id: m.control_id,
                control_name: m.control_name,
                mitre_techniques: m.mitre_techniques || [],
                coverage_status: m.coverage_status,
                detection_rules: m.detection_rules || [],
                gaps: m.gaps || []
            })),
            total_controls: mappings.length,
            covered_controls: mappings.filter(m => m.coverage_status === 'covered').length,
            partial_controls: mappings.filter(m => m.coverage_status === 'partial').length,
            gap_controls: mappings.filter(m => m.coverage_status === 'gap').length
        };
    },
    
    getComplianceGaps() {
        const gaps = this.complianceMappings
            .filter(m => m.coverage_status === 'gap' || m.coverage_status === 'partial')
            .map(m => ({
                framework: m.framework,
                control_id: m.control_id,
                control_name: m.control_name,
                coverage_status: m.coverage_status,
                mitre_techniques: m.mitre_techniques || [],
                gaps: m.gaps || [],
                priority: m.coverage_status === 'gap' ? 'high' : 'medium'
            }));
        
        return {
            total_gaps: gaps.length,
            critical_gaps: gaps.filter(g => g.priority === 'high').length,
            gaps: gaps
        };
    },
    
    getMitreHeatmap() {
        // Generate MITRE ATT&CK heatmap based on alerts and coverage
        const techniqueCount = {};
        const techniqueCoverage = {};
        
        // Count alerts per technique
        this.alerts.forEach(alert => {
            if (alert.mitre_tactics) {
                alert.mitre_tactics.forEach(technique => {
                    techniqueCount[technique] = (techniqueCount[technique] || 0) + 1;
                });
            }
        });
        
        // Check coverage from compliance mappings
        this.complianceMappings.forEach(mapping => {
            if (mapping.mitre_techniques) {
                mapping.mitre_techniques.forEach(technique => {
                    if (!techniqueCoverage[technique] || mapping.coverage_status === 'covered') {
                        techniqueCoverage[technique] = mapping.coverage_status;
                    }
                });
            }
        });
        
        // Build heatmap data
        const heatmap = Object.keys({...techniqueCount, ...techniqueCoverage}).map(technique => ({
            technique: technique,
            alert_count: techniqueCount[technique] || 0,
            coverage: techniqueCoverage[technique] || 'gap',
            score: (techniqueCount[technique] || 0) * (techniqueCoverage[technique] === 'covered' ? 0.5 : 1)
        }));
        
        return {
            heatmap: heatmap.sort((a, b) => b.score - a.score),
            total_techniques: heatmap.length,
            covered_techniques: heatmap.filter(h => h.coverage === 'covered').length,
            gap_techniques: heatmap.filter(h => h.coverage === 'gap').length
        };
    },
    
    getReports() {
        return this.reports.map(report => ({
            ...report,
            generated_at: report.generated_at || new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString()
        }));
    },
    
    generateReport(reportType, params = {}) {
        const reportId = this.reports.length + 1;
        const newReport = {
            id: reportId,
            type: reportType,
            name: `${reportType.replace(/_/g, ' ').toUpperCase()} Report`,
            status: 'generating',
            generated_at: new Date().toISOString(),
            generated_by: 'system',
            format: params.format || 'pdf',
            parameters: params
        };
        
        this.reports.push(newReport);
        
        // Simulate async generation
        setTimeout(() => {
            const report = this.reports.find(r => r.id === reportId);
            if (report) {
                report.status = 'completed';
                report.file_path = `/reports/${reportType}_${reportId}.${params.format || 'pdf'}`;
                report.file_size = Math.floor(Math.random() * 5000000) + 100000; // Random size 100KB-5MB
            }
        }, 2000);
        
        return { success: true, report: newReport };
    },
    
    // ===== THREAT HUNTING METHODS =====
    
    getHunts(filters = {}) {
        let filtered = [...this.hunts];
        
        if (filters.status) {
            filtered = filtered.filter(h => h.status === filters.status);
        }
        if (filters.priority) {
            filtered = filtered.filter(h => h.priority === filters.priority);
        }
        if (filters.hunter) {
            filtered = filtered.filter(h => h.hunter === filters.hunter);
        }
        
        return filtered;
    },
    
    createHunt(huntData) {
        const huntId = Math.max(...this.hunts.map(h => h.id), 0) + 1;
        const newHunt = {
            id: huntId,
            name: huntData.name,
            description: huntData.description || '',
            hypothesis: huntData.hypothesis || '',
            status: 'planning',
            priority: huntData.priority || 'medium',
            hunter: huntData.hunter || 'system',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            findings: [],
            journal_entries: [],
            queries: [],
            data_sources: huntData.data_sources || [],
            mitre_tactics: huntData.mitre_tactics || [],
            tags: huntData.tags || []
        };
        
        this.hunts.push(newHunt);
        return { success: true, hunt: newHunt };
    },
    
    getHunt(huntId) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { error: 'Hunt not found' };
        }
        return hunt;
    },
    
    updateHuntQuery(huntId, queryData) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { success: false, error: 'Hunt not found' };
        }
        
        if (!hunt.queries) hunt.queries = [];
        
        const queryId = hunt.queries.length + 1;
        const newQuery = {
            id: queryId,
            query: queryData.query,
            data_source: queryData.data_source || 'siem',
            executed_at: new Date().toISOString(),
            results_count: Math.floor(Math.random() * 100),
            status: 'completed'
        };
        
        hunt.queries.push(newQuery);
        hunt.updated_at = new Date().toISOString();
        
        return { success: true, query: newQuery };
    },
    
    getHuntFindings(huntId) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { error: 'Hunt not found' };
        }
        return hunt.findings || [];
    },
    
    addHuntFinding(huntId, findingData) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { success: false, error: 'Hunt not found' };
        }
        
        if (!hunt.findings) hunt.findings = [];
        
        const findingId = hunt.findings.length + 1;
        const newFinding = {
            id: findingId,
            title: findingData.title,
            description: findingData.description || '',
            severity: findingData.severity || 'medium',
            confidence: findingData.confidence || 'medium',
            indicators: findingData.indicators || [],
            mitre_techniques: findingData.mitre_techniques || [],
            created_at: new Date().toISOString(),
            created_by: findingData.created_by || 'system'
        };
        
        hunt.findings.push(newFinding);
        hunt.updated_at = new Date().toISOString();
        
        return { success: true, finding: newFinding };
    },
    
    getHuntJournal(huntId) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { error: 'Hunt not found' };
        }
        return hunt.journal_entries || [];
    },
    
    addHuntJournalEntry(huntId, entryData) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { success: false, error: 'Hunt not found' };
        }
        
        if (!hunt.journal_entries) hunt.journal_entries = [];
        
        const entryId = hunt.journal_entries.length + 1;
        const newEntry = {
            id: entryId,
            entry: entryData.entry,
            entry_type: entryData.entry_type || 'note',
            created_at: new Date().toISOString(),
            created_by: entryData.created_by || 'system',
            attachments: entryData.attachments || []
        };
        
        hunt.journal_entries.push(newEntry);
        hunt.updated_at = new Date().toISOString();
        
        return { success: true, entry: newEntry };
    },
    
    getHuntLibrary() {
        return this.huntLibrary;
    },
    
    getHuntMetrics() {
        return {
            total_hunts: this.hunts.length,
            active_hunts: this.hunts.filter(h => h.status === 'active').length,
            completed_hunts: this.hunts.filter(h => h.status === 'completed').length,
            total_findings: this.hunts.reduce((sum, h) => sum + (h.findings?.length || 0), 0),
            high_severity_findings: this.hunts.reduce((sum, h) => 
                sum + (h.findings?.filter(f => f.severity === 'high' || f.severity === 'critical').length || 0), 0),
            ...this.huntMetrics
        };
    },
    
    completeHunt(huntId, completionData = {}) {
        const hunt = this.hunts.find(h => h.id === parseInt(huntId));
        if (!hunt) {
            return { success: false, error: 'Hunt not found' };
        }
        
        hunt.status = 'completed';
        hunt.completed_at = new Date().toISOString();
        hunt.completion_notes = completionData.notes || '';
        hunt.updated_at = new Date().toISOString();
        
        return { success: true, hunt: hunt };
    }
};

// Initialize mock data on page load
// Expose the promise so app.js can wait for data to be ready before rendering.
const MOCK_DATA_READY = new Promise((resolve, reject) => {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('Initializing mock data');
        MOCK_DATA.init().then(() => {
            console.log('Mock data initialized successfully');
            resolve();
        }).catch((error) => {
            console.error('Failed to initialize mock data:', error);
            reject(error);
        });
    });
});
