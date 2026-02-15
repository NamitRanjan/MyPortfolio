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
    
    // Threat intel
    threatFeeds: [],
    recentThreats: [],
    
    // Flag to indicate if data is ready
    ready: false,
    
    // Initialize function
    async init() {
        try {
            // Load all data files
            const [alerts, threats, incidents, iocs, team] = await Promise.all([
                fetch('./data/alerts.json').then(r => r.json()).catch(() => []),
                fetch('./data/threats.json').then(r => r.json()).catch(() => []),
                fetch('./data/incidents.json').then(r => r.json()).catch(() => []),
                fetch('./data/iocs.json').then(r => r.json()).catch(() => []),
                fetch('./data/team.json').then(r => r.json()).catch(() => [])
            ]);
            
            this.alerts = alerts;
            this.threats = threats;
            this.incidents = incidents;
            this.iocs = iocs;
            this.team = team;
            
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
            return true;
        } catch (error) {
            console.error('Failed to initialize mock data:', error);
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
