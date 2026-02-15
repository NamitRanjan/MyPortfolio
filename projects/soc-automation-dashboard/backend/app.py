"""
SOC Automation Dashboard - Backend API
A production-ready Flask application for security operations automation
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import json
import random
import os

# Import authentication and audit modules
from auth import (
    authenticate, generate_token, verify_token, invalidate_token,
    requires_auth, requires_role, get_token_from_request, get_user_by_id,
    load_users
)
from audit import log_action, filter_audit_log

# Import correlation and notification engines
from correlation_engine import CorrelationEngine
from notification_engine import NotificationEngine

# Import compliance and hunting engines
from compliance_engine import ComplianceEngine
from hunting_engine import HuntingEngine

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# Load security data
def load_data():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'alerts.json'), 'r') as f:
        alerts = json.load(f)
    with open(os.path.join(data_dir, 'threats.json'), 'r') as f:
        threats = json.load(f)
    with open(os.path.join(data_dir, 'incidents.json'), 'r') as f:
        incidents = json.load(f)
    with open(os.path.join(data_dir, 'iocs.json'), 'r') as f:
        iocs = json.load(f)
    with open(os.path.join(data_dir, 'team.json'), 'r') as f:
        team = json.load(f)
    return alerts, threats, incidents, iocs, team

def load_case_notes():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'case_notes.json'), 'r') as f:
        return json.load(f)

def save_case_notes(notes):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'case_notes.json'), 'w') as f:
        json.dump(notes, f, indent=2)

def load_evidence():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'evidence.json'), 'r') as f:
        return json.load(f)

def save_evidence(evidence):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'evidence.json'), 'w') as f:
        json.dump(evidence, f, indent=2)

def load_correlations():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    try:
        with open(os.path.join(data_dir, 'correlations.json'), 'r') as f:
            return json.load(f)
    except:
        return []

def save_correlations(correlations):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'correlations.json'), 'w') as f:
        json.dump(correlations, f, indent=2)

def load_notifications():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    try:
        with open(os.path.join(data_dir, 'notifications.json'), 'r') as f:
            return json.load(f)
    except:
        return []

def save_notifications(notifications):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'notifications.json'), 'w') as f:
        json.dump(notifications, f, indent=2)

def load_escalation_policies():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    try:
        with open(os.path.join(data_dir, 'escalation_policies.json'), 'r') as f:
            return json.load(f)
    except:
        return []

def save_escalation_policies(policies):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'escalation_policies.json'), 'w') as f:
        json.dump(policies, f, indent=2)

def load_oncall_schedule():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    try:
        with open(os.path.join(data_dir, 'oncall_schedule.json'), 'r') as f:
            return json.load(f)
    except:
        return {}

def save_oncall_schedule(schedule):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'oncall_schedule.json'), 'w') as f:
        json.dump(schedule, f, indent=2)

def load_webhook_config():
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    try:
        with open(os.path.join(data_dir, 'webhook_config.json'), 'r') as f:
            return json.load(f)
    except:
        return []

def save_webhook_config(webhooks):
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'webhook_config.json'), 'w') as f:
        json.dump(webhooks, f, indent=2)

alerts_data, threats_data, incidents_data, iocs_data, team_data = load_data()

# Initialize correlation and notification engines
correlation_engine = CorrelationEngine(time_window_hours=4)
data_dir = os.path.join(os.path.dirname(__file__), '../data')
notification_engine = NotificationEngine(data_dir=data_dir)

# Initialize compliance and hunting engines
compliance_engine = ComplianceEngine(data_dir=data_dir)
hunting_engine = HuntingEngine(data_dir=data_dir)

# Playbook steps configuration
PLAYBOOK_STEPS = {
    1: [  # Malware Detection Response
        {'name': 'Isolate infected host', 'duration': '15s', 'order': 1},
        {'name': 'Collect forensic artifacts', 'duration': '30s', 'order': 2},
        {'name': 'Block C2 communications', 'duration': '20s', 'order': 3},
        {'name': 'Scan for lateral movement', 'duration': '25s', 'order': 4},
        {'name': 'Update threat signatures', 'duration': '10s', 'order': 5},
        {'name': 'Generate incident report', 'duration': '20s', 'order': 6}
    ],
    2: [  # Phishing Email Investigation
        {'name': 'Extract email headers', 'duration': '10s', 'order': 1},
        {'name': 'Analyze URLs and attachments', 'duration': '25s', 'order': 2},
        {'name': 'Check sender reputation', 'duration': '15s', 'order': 3},
        {'name': 'Search for similar emails', 'duration': '20s', 'order': 4},
        {'name': 'Quarantine malicious messages', 'duration': '15s', 'order': 5},
        {'name': 'Block sender domain', 'duration': '10s', 'order': 6},
        {'name': 'Notify affected users', 'duration': '15s', 'order': 7},
        {'name': 'Update email filters', 'duration': '15s', 'order': 8}
    ],
    3: [  # Brute Force Attack Mitigation
        {'name': 'Identify attack source', 'duration': '10s', 'order': 1},
        {'name': 'Block source IP address', 'duration': '5s', 'order': 2},
        {'name': 'Reset compromised credentials', 'duration': '20s', 'order': 3},
        {'name': 'Enable MFA for account', 'duration': '15s', 'order': 4},
        {'name': 'Generate security alert', 'duration': '10s', 'order': 5}
    ],
    4: [  # Data Exfiltration Prevention
        {'name': 'Identify data transfer', 'duration': '20s', 'order': 1},
        {'name': 'Block outbound connection', 'duration': '10s', 'order': 2},
        {'name': 'Isolate affected endpoint', 'duration': '15s', 'order': 3},
        {'name': 'Analyze transferred data', 'duration': '30s', 'order': 4},
        {'name': 'Check for data staging', 'duration': '25s', 'order': 5},
        {'name': 'Update DLP policies', 'duration': '15s', 'order': 6},
        {'name': 'Notify security team', 'duration': '10s', 'order': 7}
    ],
    5: [  # Insider Threat Investigation
        {'name': 'Collect user activity logs', 'duration': '25s', 'order': 1},
        {'name': 'Analyze access patterns', 'duration': '30s', 'order': 2},
        {'name': 'Review privilege usage', 'duration': '20s', 'order': 3},
        {'name': 'Check data access history', 'duration': '25s', 'order': 4},
        {'name': 'Correlate with external events', 'duration': '30s', 'order': 5},
        {'name': 'Enable enhanced monitoring', 'duration': '15s', 'order': 6},
        {'name': 'Restrict sensitive access', 'duration': '20s', 'order': 7},
        {'name': 'Notify HR and legal', 'duration': '15s', 'order': 8},
        {'name': 'Generate investigation report', 'duration': '20s', 'order': 9}
    ]
}

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

# ============= Authentication Endpoints =============

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = authenticate(username, password)
    
    if not user:
        # Log failed login attempt
        log_action(None, username, 'login_failed', 'auth', None, {'reason': 'invalid_credentials'})
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Generate JWT token
    token = generate_token(user)
    
    # Log successful login
    log_action(user['id'], user['username'], 'login', 'auth', None)
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'display_name': user['display_name'],
            'email': user['email']
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
@requires_auth
def logout():
    """User logout endpoint"""
    token = get_token_from_request()
    
    # Log logout
    user = request.current_user
    log_action(user['user_id'], user['username'], 'logout', 'auth', None)
    
    # Invalidate token
    invalidate_token(token)
    
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/auth/me')
@requires_auth
def get_current_user():
    """Get current user info from token"""
    user_payload = request.current_user
    user = get_user_by_id(user_payload['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'display_name': user['display_name'],
        'email': user['email']
    })

@app.route('/api/auth/change-password', methods=['POST'])
@requires_auth
def change_password():
    """Change user password"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password required'}), 400
    
    user_payload = request.current_user
    user = get_user_by_id(user_payload['user_id'])
    
    # Verify current password
    if not check_password_hash(user['password_hash'], current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update password in data file
    users = load_users()
    for u in users:
        if u['id'] == user['id']:
            u['password_hash'] = generate_password_hash(new_password)
            break
    
    # Save updated users
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    with open(os.path.join(data_dir, 'users.json'), 'w') as f:
        json.dump(users, f, indent=2)
    
    # Log password change
    log_action(user['id'], user['username'], 'password_changed', 'auth', None)
    
    return jsonify({'message': 'Password changed successfully'})

# ============= Audit Log Endpoints =============

@app.route('/api/audit-log')
@requires_role('view_audit_log')
def get_audit_log():
    """Get audit log with filtering and pagination"""
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    resource_type = request.args.get('resource_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    result = filter_audit_log(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        start_date=start_date,
        end_date=end_date,
        page=page,
        per_page=per_page
    )
    
    return jsonify(result)

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get overall dashboard statistics"""
    active_alerts = [a for a in alerts_data if a['status'] == 'active']
    critical_incidents = [i for i in incidents_data if i['severity'] == 'critical']
    
    stats = {
        'total_alerts': len(alerts_data),
        'active_alerts': len(active_alerts),
        'total_incidents': len(incidents_data),
        'critical_incidents': len(critical_incidents),
        'blocked_threats': sum(1 for t in threats_data if t['action'] == 'blocked'),
        'iocs_detected': len(iocs_data),
        'mttr': '45 min',  # Mean Time To Respond
        'automation_rate': '87%'
    }
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """Get all security alerts with optional filtering"""
    status = request.args.get('status', None)
    severity = request.args.get('severity', None)
    
    filtered_alerts = alerts_data
    if status:
        filtered_alerts = [a for a in filtered_alerts if a['status'] == status]
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
    
    return jsonify(filtered_alerts)

@app.route('/api/alerts/<int:alert_id>/investigate', methods=['POST'])
@requires_role('investigate')
def investigate_alert(alert_id):
    """Trigger automated investigation playbook"""
    alert = next((a for a in alerts_data if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    user = request.current_user
    
    # Simulate automated investigation
    investigation = {
        'alert_id': alert_id,
        'status': 'investigating',
        'steps_completed': [
            'IOC enrichment completed',
            'Threat intelligence lookup completed',
            'User behavior analysis completed',
            'Network flow analysis completed'
        ],
        'findings': {
            'ioc_matches': random.randint(1, 5),
            'threat_score': random.randint(60, 95),
            'recommended_action': random.choice(['isolate', 'block', 'monitor']),
            'confidence': random.randint(75, 99)
        },
        'timestamp': datetime.now().isoformat()
    }
    
    # Log action
    log_action(user['user_id'], user['username'], 'alert_investigated', 'alert', alert_id)
    
    return jsonify(investigation)

@app.route('/api/alerts/<int:alert_id>/respond', methods=['POST'])
@requires_role('execute_response')
def respond_to_alert(alert_id):
    """Execute automated response playbook"""
    action = request.json.get('action')
    user = request.current_user
    
    response = {
        'alert_id': alert_id,
        'action': action,
        'status': 'executed',
        'actions_taken': [],
        'timestamp': datetime.now().isoformat()
    }
    
    if action == 'isolate':
        response['actions_taken'] = [
            'Host isolated from network',
            'Active connections terminated',
            'Notification sent to SOC team',
            'Incident ticket created'
        ]
    elif action == 'block':
        response['actions_taken'] = [
            'IP address added to blocklist',
            'Firewall rules updated',
            'Threat intel feed updated',
            'Alert notification sent'
        ]
    elif action == 'monitor':
        response['actions_taken'] = [
            'Enhanced monitoring enabled',
            'Additional logging configured',
            'Behavior analytics updated',
            'Watchlist updated'
        ]
    
    # Log action
    log_action(user['user_id'], user['username'], 'alert_response_executed', 'alert', alert_id,
               {'action': action})
    
    return jsonify(response)

@app.route('/api/threats')
def get_threats():
    """Get detected threats"""
    return jsonify(threats_data)

@app.route('/api/incidents')
def get_incidents():
    """Get security incidents"""
    status = request.args.get('status', None)
    incidents = incidents_data
    if status:
        incidents = [i for i in incidents if i['status'] == status]
    return jsonify(incidents)

@app.route('/api/iocs')
def get_iocs():
    """Get Indicators of Compromise"""
    ioc_type = request.args.get('type', None)
    iocs = iocs_data
    if ioc_type:
        iocs = [i for i in iocs if i['type'] == ioc_type]
    return jsonify(iocs)

@app.route('/api/timeline')
def get_timeline():
    """Get security event timeline"""
    hours = int(request.args.get('hours', 24))
    
    timeline = []
    for i in range(hours):
        hour_ago = datetime.now() - timedelta(hours=hours-i)
        timeline.append({
            'timestamp': hour_ago.isoformat(),
            'alerts': random.randint(5, 30),
            'threats_blocked': random.randint(0, 15),
            'incidents': random.randint(0, 3)
        })
    
    return jsonify(timeline)

@app.route('/api/threat-map')
def get_threat_map():
    """Get geographic threat distribution"""
    threat_locations = [
        {'country': 'United States', 'lat': 37.0902, 'lon': -95.7129, 'count': 1247},
        {'country': 'China', 'lat': 35.8617, 'lon': 104.1954, 'count': 892},
        {'country': 'Russia', 'lat': 61.5240, 'lon': 105.3188, 'count': 743},
        {'country': 'Brazil', 'lat': -14.2350, 'lon': -51.9253, 'count': 456},
        {'country': 'Germany', 'lat': 51.1657, 'lon': 10.4515, 'count': 389},
        {'country': 'India', 'lat': 20.5937, 'lon': 78.9629, 'count': 612},
        {'country': 'United Kingdom', 'lat': 55.3781, 'lon': -3.4360, 'count': 334},
        {'country': 'France', 'lat': 46.2276, 'lon': 2.2137, 'count': 287},
        {'country': 'Japan', 'lat': 36.2048, 'lon': 138.2529, 'count': 423},
        {'country': 'South Korea', 'lat': 35.9078, 'lon': 127.7669, 'count': 298}
    ]
    
    return jsonify(threat_locations)

@app.route('/api/playbooks')
def get_playbooks():
    """Get automated response playbooks"""
    playbooks = [
        {
            'id': 1,
            'name': 'Malware Detection Response',
            'description': 'Automated response to malware detection alerts',
            'steps': 6,
            'avg_execution_time': '2 min',
            'success_rate': '94%',
            'triggers': ['malware_detected', 'suspicious_file']
        },
        {
            'id': 2,
            'name': 'Phishing Email Investigation',
            'description': 'Investigate and respond to phishing attempts',
            'steps': 8,
            'avg_execution_time': '3 min',
            'success_rate': '91%',
            'triggers': ['phishing_detected', 'suspicious_email']
        },
        {
            'id': 3,
            'name': 'Brute Force Attack Mitigation',
            'description': 'Block and investigate brute force attempts',
            'steps': 5,
            'avg_execution_time': '1 min',
            'success_rate': '97%',
            'triggers': ['brute_force', 'multiple_failed_logins']
        },
        {
            'id': 4,
            'name': 'Data Exfiltration Prevention',
            'description': 'Detect and prevent unauthorized data transfers',
            'steps': 7,
            'avg_execution_time': '4 min',
            'success_rate': '89%',
            'triggers': ['abnormal_data_transfer', 'dlp_violation']
        },
        {
            'id': 5,
            'name': 'Insider Threat Investigation',
            'description': 'Investigate suspicious insider activities',
            'steps': 9,
            'avg_execution_time': '6 min',
            'success_rate': '85%',
            'triggers': ['insider_threat', 'privilege_abuse']
        }
    ]
    
    return jsonify(playbooks)

@app.route('/api/playbooks/<int:playbook_id>/steps')
def get_playbook_steps(playbook_id):
    """Get detailed steps for a specific playbook"""
    steps = PLAYBOOK_STEPS.get(playbook_id, [])
    if not steps:
        return jsonify({'error': 'Playbook not found'}), 404
    
    return jsonify(steps)

@app.route('/api/playbooks/<int:playbook_id>/execute', methods=['POST'])
@requires_role('manage_playbooks')
def execute_playbook(playbook_id):
    """Execute a playbook and return step-by-step results"""
    steps = PLAYBOOK_STEPS.get(playbook_id, [])
    if not steps:
        return jsonify({'error': 'Playbook not found'}), 404
    
    user = request.current_user
    
    # Simulate execution with 90% success rate
    success = random.random() > 0.1
    
    # Add status to each step
    steps_with_status = []
    for i, step in enumerate(steps):
        step_copy = step.copy()
        step_copy['status'] = 'completed' if success else ('completed' if i < len(steps) - 1 else 'failed')
        steps_with_status.append(step_copy)
    
    # Calculate total execution time
    execution_time = sum(int(step['duration'].replace('s', '')) for step in steps)
    
    result = {
        'playbook_id': playbook_id,
        'status': 'completed' if success else 'failed',
        'steps': steps_with_status,
        'execution_time': execution_time,
        'timestamp': datetime.now().isoformat(),
        'message': 'Playbook executed successfully. All steps completed.' if success else 'Playbook execution failed. Please review the logs.'
    }
    
    # Log action
    log_action(user['user_id'], user['username'], 'playbook_executed', 'playbook', playbook_id,
               {'status': result['status']})
    
    return jsonify(result)

@app.route('/api/metrics/performance')
def get_performance_metrics():
    """Get SOC performance metrics"""
    metrics = {
        'alert_processing': {
            'avg_time': '1.2 min',
            'automated': '87%',
            'manual': '13%'
        },
        'incident_resolution': {
            'avg_time': '45 min',
            'within_sla': '92%',
            'escalated': '8%'
        },
        'threat_detection': {
            'true_positive_rate': '94%',
            'false_positive_rate': '6%',
            'detection_coverage': '89%'
        },
        'automation_impact': {
            'time_saved': '156 hours/week',
            'cost_reduction': '64%',
            'efficiency_gain': '73%'
        }
    }
    
    return jsonify(metrics)

@app.route('/api/team')
def get_team():
    """Get SOC team members"""
    status_filter = request.args.get('status', None)
    role_filter = request.args.get('role', None)
    
    filtered_team = team_data
    if status_filter:
        filtered_team = [t for t in filtered_team if t['status'] == status_filter]
    if role_filter:
        filtered_team = [t for t in filtered_team if role_filter.lower() in t['role'].lower()]
    
    return jsonify(filtered_team)

@app.route('/api/team/<int:member_id>')
def get_team_member(member_id):
    """Get specific team member details"""
    member = next((t for t in team_data if t['id'] == member_id), None)
    if not member:
        return jsonify({'error': 'Team member not found'}), 404
    return jsonify(member)

@app.route('/api/threat-intel/feeds')
def get_threat_feeds():
    """Get aggregated threat intelligence feeds"""
    # In production, this would integrate with real APIs (AbuseIPDB, AlienVault OTX, etc.)
    # For now, return simulated feed data
    feeds = [
        {
            'name': 'AlienVault OTX',
            'status': 'active',
            'last_update': datetime.now().isoformat(),
            'pulses_count': 1247,
            'indicators_count': 15832
        },
        {
            'name': 'AbuseIPDB',
            'status': 'active',
            'last_update': datetime.now().isoformat(),
            'malicious_ips': 892,
            'reports_count': 5643
        },
        {
            'name': 'VirusTotal',
            'status': 'active',
            'last_update': datetime.now().isoformat(),
            'scans_today': 234,
            'detections': 67
        },
        {
            'name': 'Emerging Threats',
            'status': 'active',
            'last_update': datetime.now().isoformat(),
            'rules_count': 8942,
            'categories': 45
        },
        {
            'name': 'MISP',
            'status': 'active',
            'last_update': datetime.now().isoformat(),
            'events': 523,
            'attributes': 7891
        }
    ]
    return jsonify(feeds)

@app.route('/api/threat-intel/check-ip/<ip>')
def check_ip_reputation(ip):
    """Check IP reputation (simulated)"""
    # In production, integrate with AbuseIPDB API
    reputation_score = random.randint(0, 100)
    is_malicious = reputation_score > 75
    
    result = {
        'ip': ip,
        'reputation_score': reputation_score,
        'is_malicious': is_malicious,
        'country': random.choice(['US', 'RU', 'CN', 'BR', 'DE']),
        'reports': random.randint(0, 500),
        'last_reported': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
        'categories': random.sample(['bruteforce', 'spam', 'malware', 'scanning'], k=random.randint(1, 3)) if is_malicious else []
    }
    return jsonify(result)

@app.route('/api/threat-intel/recent')
def get_recent_threats():
    """Get recent threat intelligence"""
    recent_threats = [
        {
            'id': 1,
            'title': 'New Ransomware Campaign Targeting Healthcare',
            'severity': 'critical',
            'published': (datetime.now() - timedelta(hours=2)).isoformat(),
            'source': 'AlienVault OTX',
            'indicators': 23,
            'description': 'New variant of LockBit targeting healthcare institutions'
        },
        {
            'id': 2,
            'title': 'APT Group Using Zero-Day in Exchange Servers',
            'severity': 'critical',
            'published': (datetime.now() - timedelta(hours=5)).isoformat(),
            'source': 'CISA',
            'indicators': 15,
            'description': 'State-sponsored actors exploiting previously unknown vulnerability'
        },
        {
            'id': 3,
            'title': 'Phishing Campaign Impersonating Microsoft',
            'severity': 'high',
            'published': (datetime.now() - timedelta(hours=8)).isoformat(),
            'source': 'PhishTank',
            'indicators': 47,
            'description': 'Large-scale phishing targeting Office 365 credentials'
        },
        {
            'id': 4,
            'title': 'Botnet C2 Infrastructure Discovered',
            'severity': 'high',
            'published': (datetime.now() - timedelta(hours=12)).isoformat(),
            'source': 'Emerging Threats',
            'indicators': 89,
            'description': 'New Mirai variant command and control servers identified'
        },
        {
            'id': 5,
            'title': 'Critical Vulnerability in Popular CMS',
            'severity': 'critical',
            'published': (datetime.now() - timedelta(hours=18)).isoformat(),
            'source': 'NVD',
            'indicators': 12,
            'description': 'Remote code execution in WordPress plugin affecting 1M+ sites'
        }
    ]
    return jsonify(recent_threats)

@app.route('/api/stats/advanced')
def get_advanced_stats():
    """Get advanced SOC statistics"""
    stats = {
        'alert_trends': {
            'today': random.randint(40, 60),
            'yesterday': random.randint(35, 55),
            'week_avg': 47,
            'trend': 'increasing' if random.random() > 0.5 else 'decreasing'
        },
        'threat_landscape': {
            'top_attack_type': 'phishing',
            'top_target': 'endpoints',
            'most_active_actor': 'APT29',
            'emerging_threats': 3
        },
        'soc_performance': {
            'alerts_closed_today': random.randint(30, 50),
            'false_positive_rate': '6.2%',
            'escalation_rate': '8.5%',
            'sla_compliance': '94%'
        },
        'team_productivity': {
            'analysts_online': sum(1 for t in team_data if t['status'] == 'online'),
            'total_analysts': len(team_data),
            'avg_case_load': 12,
            'cases_this_week': 187
        }
    }
    return jsonify(stats)

# ============= Case Notes Endpoints =============

@app.route('/api/alerts/<int:alert_id>/notes')
@requires_role('view_alerts')
def get_alert_notes(alert_id):
    """Get all notes for an alert"""
    notes = load_case_notes()
    alert_notes = [n for n in notes if n['alert_id'] == alert_id]
    return jsonify(alert_notes)

@app.route('/api/alerts/<int:alert_id>/notes', methods=['POST'])
@requires_role('add_notes')
def add_alert_note(alert_id):
    """Add a note to an alert"""
    data = request.get_json()
    user = request.current_user
    
    notes = load_case_notes()
    
    # Generate new ID
    new_id = max([n['id'] for n in notes], default=0) + 1
    
    new_note = {
        'id': new_id,
        'alert_id': alert_id,
        'incident_id': data.get('incident_id'),
        'author_id': user['user_id'],
        'author_name': user['display_name'],
        'content': data.get('content', ''),
        'type': data.get('type', 'investigation_note'),
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z',
        'is_pinned': data.get('is_pinned', False),
        'tags': data.get('tags', [])
    }
    
    notes.append(new_note)
    save_case_notes(notes)
    
    # Log action
    log_action(user['user_id'], user['username'], 'note_added', 'alert', alert_id, 
               {'note_type': new_note['type']})
    
    return jsonify(new_note), 201

@app.route('/api/incidents/<int:incident_id>/notes')
@requires_role('view_alerts')
def get_incident_notes(incident_id):
    """Get all notes for an incident"""
    notes = load_case_notes()
    incident_notes = [n for n in notes if n['incident_id'] == incident_id]
    return jsonify(incident_notes)

@app.route('/api/incidents/<int:incident_id>/notes', methods=['POST'])
@requires_role('add_notes')
def add_incident_note(incident_id):
    """Add a note to an incident"""
    data = request.get_json()
    user = request.current_user
    
    notes = load_case_notes()
    
    # Generate new ID
    new_id = max([n['id'] for n in notes], default=0) + 1
    
    new_note = {
        'id': new_id,
        'alert_id': data.get('alert_id'),
        'incident_id': incident_id,
        'author_id': user['user_id'],
        'author_name': user['display_name'],
        'content': data.get('content', ''),
        'type': data.get('type', 'investigation_note'),
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z',
        'is_pinned': data.get('is_pinned', False),
        'tags': data.get('tags', [])
    }
    
    notes.append(new_note)
    save_case_notes(notes)
    
    # Log action
    log_action(user['user_id'], user['username'], 'note_added', 'incident', incident_id,
               {'note_type': new_note['type']})
    
    return jsonify(new_note), 201

@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@requires_role('add_notes')
def update_note(note_id):
    """Update a note (only author or admin)"""
    data = request.get_json()
    user = request.current_user
    
    notes = load_case_notes()
    note = next((n for n in notes if n['id'] == note_id), None)
    
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    
    # Check if user is author or admin
    if note['author_id'] != user['user_id'] and user['role'] != 'admin':
        return jsonify({'error': 'Not authorized to update this note'}), 403
    
    # Update note
    if 'content' in data:
        note['content'] = data['content']
    if 'type' in data:
        note['type'] = data['type']
    if 'is_pinned' in data:
        note['is_pinned'] = data['is_pinned']
    if 'tags' in data:
        note['tags'] = data['tags']
    
    note['updated_at'] = datetime.utcnow().isoformat() + 'Z'
    
    save_case_notes(notes)
    
    # Log action
    log_action(user['user_id'], user['username'], 'note_updated', 'note', note_id)
    
    return jsonify(note)

@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@requires_role('add_notes')
def delete_note(note_id):
    """Delete a note (only author or admin)"""
    user = request.current_user
    
    notes = load_case_notes()
    note = next((n for n in notes if n['id'] == note_id), None)
    
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    
    # Check if user is author or admin
    if note['author_id'] != user['user_id'] and user['role'] != 'admin':
        return jsonify({'error': 'Not authorized to delete this note'}), 403
    
    # Remove note
    notes = [n for n in notes if n['id'] != note_id]
    save_case_notes(notes)
    
    # Log action
    log_action(user['user_id'], user['username'], 'note_deleted', 'note', note_id)
    
    return jsonify({'message': 'Note deleted successfully'})

# ============= Evidence Endpoints =============

@app.route('/api/alerts/<int:alert_id>/evidence')
@requires_role('view_alerts')
def get_alert_evidence(alert_id):
    """Get evidence for an alert"""
    evidence = load_evidence()
    alert_evidence = [e for e in evidence if e['alert_id'] == alert_id]
    return jsonify(alert_evidence)

@app.route('/api/alerts/<int:alert_id>/evidence', methods=['POST'])
@requires_role('add_evidence')
def add_alert_evidence(alert_id):
    """Add evidence to an alert"""
    data = request.get_json()
    user = request.current_user
    
    evidence = load_evidence()
    
    # Generate new ID
    new_id = max([e['id'] for e in evidence], default=0) + 1
    
    new_evidence = {
        'id': new_id,
        'alert_id': alert_id,
        'incident_id': data.get('incident_id'),
        'type': data.get('type', 'file_hash'),
        'value': data.get('value', ''),
        'hash_type': data.get('hash_type'),
        'description': data.get('description', ''),
        'collected_by_id': user['user_id'],
        'collected_by_name': user['display_name'],
        'collected_at': datetime.utcnow().isoformat() + 'Z',
        'chain_of_custody': [
            {
                'action': 'collected',
                'by': user['display_name'],
                'at': datetime.utcnow().isoformat() + 'Z',
                'notes': data.get('initial_notes', 'Evidence collected')
            }
        ],
        'tags': data.get('tags', []),
        'status': 'collected'
    }
    
    evidence.append(new_evidence)
    save_evidence(evidence)
    
    # Log action
    log_action(user['user_id'], user['username'], 'evidence_added', 'alert', alert_id,
               {'evidence_type': new_evidence['type']})
    
    return jsonify(new_evidence), 201

@app.route('/api/incidents/<int:incident_id>/evidence')
@requires_role('view_alerts')
def get_incident_evidence(incident_id):
    """Get evidence for an incident"""
    evidence = load_evidence()
    incident_evidence = [e for e in evidence if e['incident_id'] == incident_id]
    return jsonify(incident_evidence)

@app.route('/api/incidents/<int:incident_id>/evidence', methods=['POST'])
@requires_role('add_evidence')
def add_incident_evidence(incident_id):
    """Add evidence to an incident"""
    data = request.get_json()
    user = request.current_user
    
    evidence = load_evidence()
    
    # Generate new ID
    new_id = max([e['id'] for e in evidence], default=0) + 1
    
    new_evidence = {
        'id': new_id,
        'alert_id': data.get('alert_id'),
        'incident_id': incident_id,
        'type': data.get('type', 'file_hash'),
        'value': data.get('value', ''),
        'hash_type': data.get('hash_type'),
        'description': data.get('description', ''),
        'collected_by_id': user['user_id'],
        'collected_by_name': user['display_name'],
        'collected_at': datetime.utcnow().isoformat() + 'Z',
        'chain_of_custody': [
            {
                'action': 'collected',
                'by': user['display_name'],
                'at': datetime.utcnow().isoformat() + 'Z',
                'notes': data.get('initial_notes', 'Evidence collected')
            }
        ],
        'tags': data.get('tags', []),
        'status': 'collected'
    }
    
    evidence.append(new_evidence)
    save_evidence(evidence)
    
    # Log action
    log_action(user['user_id'], user['username'], 'evidence_added', 'incident', incident_id,
               {'evidence_type': new_evidence['type']})
    
    return jsonify(new_evidence), 201

@app.route('/api/evidence/<int:evidence_id>/custody', methods=['PUT'])
@requires_role('add_evidence')
def add_custody_entry(evidence_id):
    """Add a chain-of-custody entry"""
    data = request.get_json()
    user = request.current_user
    
    evidence = load_evidence()
    evidence_item = next((e for e in evidence if e['id'] == evidence_id), None)
    
    if not evidence_item:
        return jsonify({'error': 'Evidence not found'}), 404
    
    # Add custody entry
    custody_entry = {
        'action': data.get('action', 'transferred'),
        'by': user['display_name'],
        'at': datetime.utcnow().isoformat() + 'Z',
        'notes': data.get('notes', '')
    }
    
    evidence_item['chain_of_custody'].append(custody_entry)
    
    # Update status if provided
    if 'status' in data:
        evidence_item['status'] = data['status']
    
    save_evidence(evidence)
    
    # Log action
    log_action(user['user_id'], user['username'], 'custody_updated', 'evidence', evidence_id,
               {'action': custody_entry['action']})
    
    return jsonify(evidence_item)

# ============= Analyst Assignment & SLA Endpoints =============

@app.route('/api/alerts/<int:alert_id>/assign', methods=['POST'])
@requires_role('assign_analyst')
def assign_alert(alert_id):
    """Assign an analyst to an alert"""
    data = request.get_json()
    user = request.current_user
    analyst_id = data.get('analyst_id')
    
    # Find the alert
    alert = next((a for a in alerts_data if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # Update assignment (in-memory for now)
    alert['assigned_to'] = analyst_id
    alert['assigned_at'] = datetime.utcnow().isoformat() + 'Z'
    
    # Log action
    log_action(user['user_id'], user['username'], 'alert_assigned', 'alert', alert_id,
               {'analyst_id': analyst_id})
    
    return jsonify({
        'alert_id': alert_id,
        'assigned_to': analyst_id,
        'assigned_at': alert['assigned_at']
    })

@app.route('/api/alerts/<int:alert_id>/sla')
@requires_role('view_alerts')
def get_alert_sla(alert_id):
    """Get SLA status for an alert"""
    alert = next((a for a in alerts_data if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # SLA definitions
    sla_times = {
        'critical': 15,  # 15 minutes
        'high': 60,      # 1 hour
        'medium': 240,   # 4 hours
        'low': 1440      # 24 hours
    }
    
    severity = alert.get('severity', 'medium')
    sla_minutes = sla_times.get(severity, 240)
    
    # Calculate time elapsed
    timestamp = alert.get('timestamp', datetime.now().isoformat())
    alert_time = datetime.fromisoformat(timestamp.replace('Z', ''))
    elapsed = (datetime.now() - alert_time).total_seconds() / 60
    
    remaining = sla_minutes - elapsed
    is_breached = remaining < 0
    
    # Calculate percentage
    percentage = min(100, (elapsed / sla_minutes) * 100)
    
    return jsonify({
        'alert_id': alert_id,
        'severity': severity,
        'sla_minutes': sla_minutes,
        'elapsed_minutes': int(elapsed),
        'remaining_minutes': int(remaining),
        'is_breached': is_breached,
        'percentage': round(percentage, 2),
        'status': 'breached' if is_breached else ('warning' if percentage > 75 else 'normal')
    })

# ===== CORRELATION ENGINE ENDPOINTS =====

@app.route('/api/correlations')
@requires_role('view_alerts')
def get_correlations():
    """Get all correlation groups with optional filters"""
    correlations = load_correlations()
    
    # Apply filters
    status = request.args.get('status')
    risk_level = request.args.get('risk_level')
    min_score = request.args.get('min_score', type=int)
    
    if status:
        correlations = [c for c in correlations if c.get('status') == status]
    if risk_level:
        correlations = [c for c in correlations if c.get('risk_level') == risk_level]
    if min_score:
        correlations = [c for c in correlations if c.get('correlation_score', 0) >= min_score]
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'viewed_correlations', 'correlation', None, {})
    
    return jsonify(correlations)

@app.route('/api/correlations/<int:correlation_id>')
@requires_role('view_alerts')
def get_correlation_detail(correlation_id):
    """Get detailed correlation group with full kill chain and alert details"""
    correlations = load_correlations()
    correlation = next((c for c in correlations if c['id'] == correlation_id), None)
    
    if not correlation:
        return jsonify({'error': 'Correlation not found'}), 404
    
    # Enrich with full alert details
    alert_ids = correlation.get('alert_ids', [])
    alerts = [a for a in alerts_data if a['id'] in alert_ids]
    correlation['alerts'] = alerts
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'viewed_correlation', 'correlation', correlation_id, {})
    
    return jsonify(correlation)

@app.route('/api/correlations/analyze', methods=['POST'])
@requires_role('investigate_alerts')
def analyze_correlations():
    """Trigger correlation analysis on current alerts"""
    # Get all active alerts
    active_alerts = [a for a in alerts_data if a.get('status') in ['active', 'monitoring']]
    
    # Run correlation analysis
    groups = correlation_engine.group_alerts(active_alerts)
    
    # Create correlation objects
    correlations = []
    for i, group in enumerate(groups):
        correlation = correlation_engine.create_correlation_group(i + 1, group)
        correlations.append(correlation)
    
    # Save correlations
    save_correlations(correlations)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'analyzed_correlations', 'correlation', None, {
                'groups_found': len(correlations)
            })
    
    return jsonify({
        'success': True,
        'groups_found': len(correlations),
        'correlations': correlations
    })

@app.route('/api/correlations/stats')
@requires_role('view_alerts')
def get_correlation_stats():
    """Get correlation statistics"""
    correlations = load_correlations()
    
    if not correlations:
        return jsonify({
            'total_groups': 0,
            'average_score': 0,
            'deduplication_rate': 0,
            'alerts_correlated': 0,
            'alerts_uncorrelated': len(alerts_data)
        })
    
    # Calculate stats
    total_groups = len(correlations)
    avg_score = sum(c.get('correlation_score', 0) for c in correlations) / total_groups if total_groups > 0 else 0
    
    # Get all correlated alert IDs
    correlated_alert_ids = set()
    for c in correlations:
        correlated_alert_ids.update(c.get('alert_ids', []))
    
    alerts_correlated = len(correlated_alert_ids)
    alerts_uncorrelated = len(alerts_data) - alerts_correlated
    
    # De-duplication analysis
    duplicates = correlation_engine.find_duplicates(alerts_data)
    total_duplicates = sum(d['count'] - 1 for d in duplicates)
    deduplication_rate = (total_duplicates / len(alerts_data) * 100) if len(alerts_data) > 0 else 0
    
    return jsonify({
        'total_groups': total_groups,
        'average_score': round(avg_score, 1),
        'deduplication_rate': round(deduplication_rate, 1),
        'alerts_correlated': alerts_correlated,
        'alerts_uncorrelated': alerts_uncorrelated,
        'by_risk_level': {
            'critical': len([c for c in correlations if c.get('risk_level') == 'critical']),
            'high': len([c for c in correlations if c.get('risk_level') == 'high']),
            'medium': len([c for c in correlations if c.get('risk_level') == 'medium']),
            'low': len([c for c in correlations if c.get('risk_level') == 'low'])
        }
    })

@app.route('/api/alerts/<int:alert_id>/related')
@requires_role('view_alerts')
def get_related_alerts(alert_id):
    """Get related alerts for a specific alert with similarity scores"""
    alert = next((a for a in alerts_data if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # Find related alerts
    related = correlation_engine.find_related_alerts(alert, alerts_data, top_n=10)
    
    # Format response
    related_alerts = []
    for item in related:
        related_alerts.append({
            'alert': item['alert'],
            'similarity_score': item['similarity']['similarity_score'],
            'entity_similarity': item['similarity']['entity_similarity'],
            'time_proximity': item['similarity']['time_proximity'],
            'shared_entities': item['similarity']['shared_entities']
        })
    
    return jsonify({
        'alert_id': alert_id,
        'related_alerts': related_alerts
    })

@app.route('/api/alerts/<int:alert_id>/kill-chain')
@requires_role('view_alerts')
def get_alert_kill_chain(alert_id):
    """Get the kill chain context for an alert"""
    # Find correlation group containing this alert
    correlations = load_correlations()
    correlation = next((c for c in correlations if alert_id in c.get('alert_ids', [])), None)
    
    if not correlation:
        return jsonify({
            'alert_id': alert_id,
            'in_correlation': False,
            'kill_chain_position': None
        })
    
    # Find position in kill chain
    kill_chain_item = next((k for k in correlation.get('kill_chain', []) if k['alert_id'] == alert_id), None)
    
    return jsonify({
        'alert_id': alert_id,
        'in_correlation': True,
        'correlation_id': correlation['id'],
        'correlation_name': correlation['name'],
        'kill_chain_position': kill_chain_item,
        'kill_chain_coverage': correlation.get('kill_chain_coverage'),
        'risk_level': correlation.get('risk_level')
    })

@app.route('/api/alerts/duplicates')
@requires_role('view_alerts')
def get_duplicate_alerts():
    """List all identified duplicate alert groups"""
    duplicates = correlation_engine.find_duplicates(alerts_data, time_threshold_minutes=30)
    
    # Enrich with alert details
    for dup_group in duplicates:
        primary_id = dup_group['primary_alert_id']
        dup_group['primary_alert'] = next((a for a in alerts_data if a['id'] == primary_id), None)
        dup_group['duplicate_alerts'] = [
            next((a for a in alerts_data if a['id'] == dup_id), None)
            for dup_id in dup_group['duplicate_alert_ids']
        ]
    
    return jsonify({
        'duplicate_groups': duplicates,
        'total_duplicates': sum(d['count'] - 1 for d in duplicates)
    })

@app.route('/api/alerts/deduplicate', methods=['POST'])
@requires_role('investigate_alerts')
def deduplicate_alerts():
    """Run de-duplication analysis"""
    duplicates = correlation_engine.find_duplicates(alerts_data)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'deduplication_analysis', 'alert', None, {
                'groups_found': len(duplicates)
            })
    
    return jsonify({
        'success': True,
        'duplicate_groups': duplicates,
        'total_duplicates': sum(d['count'] - 1 for d in duplicates),
        'deduplication_rate': round((sum(d['count'] - 1 for d in duplicates) / len(alerts_data) * 100), 1) if len(alerts_data) > 0 else 0
    })

# ===== NOTIFICATION ENGINE ENDPOINTS =====

@app.route('/api/notifications')
@requires_role('view_alerts')
def get_notifications():
    """Get current user's notifications with optional filters"""
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    notifications = load_notifications()
    
    # Filter by user
    user_notifications = [n for n in notifications if n.get('user_id') == user['id']]
    
    # Apply filters
    read_status = request.args.get('read')
    notification_type = request.args.get('type')
    severity = request.args.get('severity')
    
    if read_status is not None:
        is_read = read_status.lower() == 'true'
        user_notifications = [n for n in user_notifications if n.get('read') == is_read]
    if notification_type:
        user_notifications = [n for n in user_notifications if n.get('type') == notification_type]
    if severity:
        user_notifications = [n for n in user_notifications if n.get('severity') == severity]
    
    return jsonify(user_notifications)

@app.route('/api/notifications/count')
@requires_role('view_alerts')
def get_notification_count():
    """Get unread notification count for current user"""
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    notifications = load_notifications()
    unread_count = len([n for n in notifications if n.get('user_id') == user['id'] and not n.get('read')])
    
    return jsonify({'unread_count': unread_count})

@app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
@requires_role('view_alerts')
def mark_notification_read(notification_id):
    """Mark notification as read"""
    notifications = load_notifications()
    notification = next((n for n in notifications if n['id'] == notification_id), None)
    
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404
    
    notification['read'] = True
    save_notifications(notifications)
    
    return jsonify({'success': True, 'notification': notification})

@app.route('/api/notifications/read-all', methods=['PUT'])
@requires_role('view_alerts')
def mark_all_notifications_read():
    """Mark all notifications as read for current user"""
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    notifications = load_notifications()
    
    # Mark all user's notifications as read
    for n in notifications:
        if n.get('user_id') == user['id']:
            n['read'] = True
    
    save_notifications(notifications)
    
    return jsonify({'success': True, 'message': 'All notifications marked as read'})

@app.route('/api/notifications/test', methods=['POST'])
@requires_role('admin')
def send_test_notification():
    """Send a test notification (admin only)"""
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    # Create test notification
    notification = notification_engine.create_notification(
        user_id=user['id'],
        notification_type='system_alert',
        title='Test Notification',
        message='This is a test notification from the SOC Automation Platform',
        severity='medium',
        resource_type='system',
        resource_id=None
    )
    
    # Add to notifications
    notifications = load_notifications()
    notifications.insert(0, notification)
    save_notifications(notifications)
    
    return jsonify({'success': True, 'notification': notification})

# ===== ESCALATION POLICY ENDPOINTS =====

@app.route('/api/escalation-policies')
@requires_role('view_alerts')
def get_escalation_policies():
    """List all escalation policies"""
    policies = load_escalation_policies()
    return jsonify(policies)

@app.route('/api/escalation-policies/<int:policy_id>')
@requires_role('view_alerts')
def get_escalation_policy(policy_id):
    """Get policy details"""
    policies = load_escalation_policies()
    policy = next((p for p in policies if p['id'] == policy_id), None)
    
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404
    
    return jsonify(policy)

@app.route('/api/escalation-policies/<int:policy_id>', methods=['PUT'])
@requires_role('soc_manager')
def update_escalation_policy(policy_id):
    """Update an escalation policy (soc_manager+ only)"""
    policies = load_escalation_policies()
    policy = next((p for p in policies if p['id'] == policy_id), None)
    
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404
    
    data = request.get_json()
    
    # Update allowed fields
    if 'name' in data:
        policy['name'] = data['name']
    if 'description' in data:
        policy['description'] = data['description']
    if 'enabled' in data:
        policy['enabled'] = data['enabled']
    if 'levels' in data:
        policy['levels'] = data['levels']
    
    save_escalation_policies(policies)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'updated_escalation_policy', 'escalation_policy', policy_id, data)
    
    return jsonify({'success': True, 'policy': policy})

@app.route('/api/escalation-policies/<int:policy_id>/toggle', methods=['PUT'])
@requires_role('soc_manager')
def toggle_escalation_policy(policy_id):
    """Enable/disable an escalation policy"""
    policies = load_escalation_policies()
    policy = next((p for p in policies if p['id'] == policy_id), None)
    
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404
    
    policy['enabled'] = not policy.get('enabled', True)
    save_escalation_policies(policies)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'toggled_escalation_policy', 'escalation_policy', policy_id, {
                'enabled': policy['enabled']
            })
    
    return jsonify({'success': True, 'policy': policy})

@app.route('/api/alerts/<int:alert_id>/escalation-status')
@requires_role('view_alerts')
def get_alert_escalation_status(alert_id):
    """Get current escalation level and timeline for an alert"""
    alert = next((a for a in alerts_data if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # Calculate alert age
    timestamp = alert.get('timestamp', datetime.now().isoformat())
    alert_time = datetime.fromisoformat(timestamp.replace('Z', ''))
    alert_age_minutes = (datetime.now() - alert_time).total_seconds() / 60
    
    # Get escalation status
    escalation_status = notification_engine.calculate_escalation_level(alert, alert_age_minutes)
    
    return jsonify({
        'alert_id': alert_id,
        'alert_age_minutes': int(alert_age_minutes),
        'escalation': escalation_status
    })

# ===== ON-CALL ENDPOINTS =====

@app.route('/api/oncall')
@requires_role('view_alerts')
def get_current_oncall():
    """Get current on-call rotation"""
    schedule = load_oncall_schedule()
    return jsonify(schedule.get('current_oncall', {}))

@app.route('/api/oncall/schedule')
@requires_role('view_alerts')
def get_oncall_schedule():
    """Get full rotation schedule"""
    schedule = load_oncall_schedule()
    return jsonify(schedule)

@app.route('/api/oncall/override', methods=['PUT'])
@requires_role('soc_manager')
def set_oncall_override():
    """Set a temporary on-call override (soc_manager+ only)"""
    data = request.get_json()
    
    required_fields = ['primary_user_id', 'secondary_user_id', 'start', 'end', 'reason']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    schedule = load_oncall_schedule()
    schedule['override'] = {
        'primary_user_id': data['primary_user_id'],
        'secondary_user_id': data['secondary_user_id'],
        'start': data['start'],
        'end': data['end'],
        'reason': data['reason'],
        'set_by': 'system',
        'set_at': datetime.now().isoformat() + 'Z'
    }
    
    save_oncall_schedule(schedule)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'set_oncall_override', 'oncall', None, data)
    
    return jsonify({'success': True, 'schedule': schedule})

# ===== WEBHOOK ENDPOINTS =====

@app.route('/api/webhooks')
@requires_role('admin')
def get_webhooks():
    """List configured webhooks (admin only)"""
    webhooks = load_webhook_config()
    return jsonify(webhooks)

@app.route('/api/webhooks/<int:webhook_id>/test', methods=['POST'])
@requires_role('admin')
def test_webhook(webhook_id):
    """Send test webhook (returns simulated success)"""
    webhooks = load_webhook_config()
    webhook = next((w for w in webhooks if w['id'] == webhook_id), None)
    
    if not webhook:
        return jsonify({'error': 'Webhook not found'}), 404
    
    # Simulate webhook trigger
    result = notification_engine.simulate_webhook_trigger(
        webhook,
        'test',
        {'message': 'This is a test webhook'}
    )
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'tested_webhook', 'webhook', webhook_id, result)
    
    return jsonify(result)

@app.route('/api/webhooks/<int:webhook_id>/toggle', methods=['PUT'])
@requires_role('admin')
def toggle_webhook(webhook_id):
    """Enable/disable a webhook"""
    webhooks = load_webhook_config()
    webhook = next((w for w in webhooks if w['id'] == webhook_id), None)
    
    if not webhook:
        return jsonify({'error': 'Webhook not found'}), 404
    
    webhook['enabled'] = not webhook.get('enabled', True)
    save_webhook_config(webhooks)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'toggled_webhook', 'webhook', webhook_id, {
                'enabled': webhook['enabled']
            })
    
    return jsonify({'success': True, 'webhook': webhook})

# ============= COMPLIANCE & EXECUTIVE REPORTING ENDPOINTS =============

@app.route('/api/compliance/frameworks')
@requires_role('view_alerts')
def get_compliance_frameworks():
    """Get list of all supported compliance frameworks"""
    frameworks = compliance_engine.get_frameworks()
    return jsonify(frameworks)

@app.route('/api/compliance/posture')
@requires_role('view_alerts')
def get_compliance_posture():
    """Get overall compliance posture score across all frameworks"""
    # Load playbook data for coverage analysis
    playbooks = [
        {'id': 1, 'name': 'Malware Detection Response'},
        {'id': 2, 'name': 'Phishing Email Investigation'},
        {'id': 3, 'name': 'Brute Force Attack Mitigation'},
        {'id': 4, 'name': 'Data Exfiltration Prevention'},
        {'id': 5, 'name': 'Insider Threat Investigation'}
    ]
    
    posture = compliance_engine.calculate_posture(alerts_data, playbooks, iocs_data)
    return jsonify(posture)

@app.route('/api/compliance/coverage/<framework_id>')
@requires_role('view_alerts')
def get_compliance_coverage(framework_id):
    """Get detailed coverage matrix for a specific framework"""
    playbooks = [
        {'id': 1, 'name': 'Malware Detection Response'},
        {'id': 2, 'name': 'Phishing Email Investigation'},
        {'id': 3, 'name': 'Brute Force Attack Mitigation'},
        {'id': 4, 'name': 'Data Exfiltration Prevention'},
        {'id': 5, 'name': 'Insider Threat Investigation'}
    ]
    
    coverage = compliance_engine.get_coverage_matrix(framework_id, alerts_data, playbooks, iocs_data)
    return jsonify(coverage)

@app.route('/api/compliance/gaps')
@requires_role('view_alerts')
def get_compliance_gaps():
    """Get coverage gap analysis across all frameworks"""
    playbooks = [
        {'id': 1, 'name': 'Malware Detection Response'},
        {'id': 2, 'name': 'Phishing Email Investigation'},
        {'id': 3, 'name': 'Brute Force Attack Mitigation'},
        {'id': 4, 'name': 'Data Exfiltration Prevention'},
        {'id': 5, 'name': 'Insider Threat Investigation'}
    ]
    
    gaps = compliance_engine.get_gaps(alerts_data, playbooks, iocs_data)
    return jsonify(gaps)

@app.route('/api/mitre/heatmap')
@requires_role('view_alerts')
def get_mitre_heatmap():
    """Get MITRE ATT&CK heatmap showing tactics x techniques coverage"""
    playbooks = [
        {'id': 1, 'name': 'Malware Detection Response'},
        {'id': 2, 'name': 'Phishing Email Investigation'},
        {'id': 3, 'name': 'Brute Force Attack Mitigation'},
        {'id': 4, 'name': 'Data Exfiltration Prevention'},
        {'id': 5, 'name': 'Insider Threat Investigation'}
    ]
    
    heatmap = compliance_engine.get_mitre_heatmap(alerts_data, playbooks, iocs_data)
    return jsonify(heatmap)

@app.route('/api/reports')
@requires_role('view_alerts')
def get_reports():
    """Get list of all generated reports"""
    reports_file = os.path.join(data_dir, 'reports.json')
    try:
        with open(reports_file, 'r') as f:
            reports = json.load(f)
        return jsonify(reports)
    except FileNotFoundError:
        return jsonify([])

@app.route('/api/reports/generate', methods=['POST'])
@requires_role('t2_analyst')
def generate_report():
    """Generate a new compliance report on-demand"""
    data = request.get_json()
    report_type = data.get('type', 'daily')
    
    if report_type not in ['daily', 'weekly', 'monthly', 'posture']:
        return jsonify({'error': 'Invalid report type'}), 400
    
    playbooks = [
        {'id': 1, 'name': 'Malware Detection Response'},
        {'id': 2, 'name': 'Phishing Email Investigation'},
        {'id': 3, 'name': 'Brute Force Attack Mitigation'},
        {'id': 4, 'name': 'Data Exfiltration Prevention'},
        {'id': 5, 'name': 'Insider Threat Investigation'}
    ]
    
    report = compliance_engine.generate_report(report_type, alerts_data, playbooks, iocs_data, incidents_data)
    
    # Save report to file
    reports_file = os.path.join(data_dir, 'reports.json')
    try:
        with open(reports_file, 'r') as f:
            reports = json.load(f)
    except FileNotFoundError:
        reports = []
    
    reports.insert(0, report)  # Add to beginning of list
    reports = reports[:50]  # Keep only last 50 reports
    
    with open(reports_file, 'w') as f:
        json.dump(reports, f, indent=2)
    
    # Log action
    token = get_token_from_request()
    if token:
        user = verify_token(token)
        if user:
            log_action(user['id'], user['username'], 'generated_report', 'report', report['id'], data)
    
    return jsonify(report)

# ============= THREAT HUNTING ENDPOINTS =============

@app.route('/api/hunts')
@requires_role('view_alerts')
def get_hunts():
    """Get all threat hunts, optionally filtered by status"""
    status = request.args.get('status')
    hunts = hunting_engine.get_all_hunts(status)
    return jsonify(hunts)

@app.route('/api/hunts', methods=['POST'])
@requires_role('t2_analyst')
def create_hunt():
    """Start a new hunt from hunt library"""
    data = request.get_json()
    hunt_package_id = data.get('hunt_package_id')
    
    if not hunt_package_id:
        return jsonify({'error': 'hunt_package_id required'}), 400
    
    # Get user info
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    hunt = hunting_engine.create_hunt(hunt_package_id, user['id'], user['username'])
    
    if 'error' in hunt:
        return jsonify(hunt), 404
    
    # Log action
    log_action(user['id'], user['username'], 'started_hunt', 'hunt', hunt['id'], data)
    
    return jsonify(hunt)

@app.route('/api/hunts/<int:hunt_id>')
@requires_role('view_alerts')
def get_hunt(hunt_id):
    """Get hunt details including query, findings, and journal"""
    hunt = hunting_engine.get_hunt_by_id(hunt_id)
    
    if not hunt:
        return jsonify({'error': 'Hunt not found'}), 404
    
    return jsonify(hunt)

@app.route('/api/hunts/<int:hunt_id>/query', methods=['PUT'])
@requires_role('t2_analyst')
def update_hunt_query(hunt_id):
    """Edit and run hunt query"""
    data = request.get_json()
    query = data.get('query')
    
    if not query:
        return jsonify({'error': 'query required'}), 400
    
    # Get user info
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    result = hunting_engine.update_hunt_query(hunt_id, query, user['username'])
    
    if 'error' in result:
        return jsonify(result), 404
    
    # Log action
    log_action(user['id'], user['username'], 'updated_hunt_query', 'hunt', hunt_id, data)
    
    return jsonify(result)

@app.route('/api/hunts/<int:hunt_id>/findings')
@requires_role('view_alerts')
def get_hunt_findings(hunt_id):
    """Get findings for a hunt"""
    findings = hunting_engine.get_findings(hunt_id)
    return jsonify(findings)

@app.route('/api/hunts/<int:hunt_id>/findings', methods=['POST'])
@requires_role('t2_analyst')
def add_hunt_finding(hunt_id):
    """Add a finding to a hunt"""
    data = request.get_json()
    
    required_fields = ['title', 'description', 'severity']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} required'}), 400
    
    # Get user info
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    finding = hunting_engine.add_finding(hunt_id, data, user['username'])
    
    if 'error' in finding:
        return jsonify(finding), 404
    
    # Log action
    log_action(user['id'], user['username'], 'added_hunt_finding', 'hunt', hunt_id, data)
    
    return jsonify(finding)

@app.route('/api/hunts/<int:hunt_id>/journal')
@requires_role('view_alerts')
def get_hunt_journal(hunt_id):
    """Get hunt journal timeline"""
    journal = hunting_engine.get_journal(hunt_id)
    return jsonify(journal)

@app.route('/api/hunts/<int:hunt_id>/journal', methods=['POST'])
@requires_role('t2_analyst')
def add_hunt_journal_entry(hunt_id):
    """Add an entry to the hunt journal"""
    data = request.get_json()
    
    entry_type = data.get('entry_type', 'observation')
    content = data.get('content')
    
    if not content:
        return jsonify({'error': 'content required'}), 400
    
    # Get user info
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    entry = hunting_engine.add_journal_entry(hunt_id, user['username'], entry_type, content)
    
    if 'error' in entry:
        return jsonify(entry), 404
    
    return jsonify(entry)

@app.route('/api/hunt-library')
@requires_role('view_alerts')
def get_hunt_library():
    """Get available hunt packages"""
    library = hunting_engine.get_hunt_library()
    return jsonify(library)

@app.route('/api/hunt-metrics')
@requires_role('view_alerts')
def get_hunt_metrics():
    """Get hunt statistics and tracking"""
    metrics = hunting_engine.get_hunt_metrics()
    return jsonify(metrics)

@app.route('/api/hunts/<int:hunt_id>/complete', methods=['PUT'])
@requires_role('t2_analyst')
def complete_hunt(hunt_id):
    """Mark a hunt as completed"""
    data = request.get_json()
    summary = data.get('summary', '')
    
    # Get user info
    token = get_token_from_request()
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    user = verify_token(token)
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    hunt = hunting_engine.complete_hunt(hunt_id, user['username'], summary)
    
    if 'error' in hunt:
        return jsonify(hunt), 404
    
    # Log action
    log_action(user['id'], user['username'], 'completed_hunt', 'hunt', hunt_id, data)
    
    return jsonify(hunt)

if __name__ == '__main__':
    import os
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
