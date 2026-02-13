"""
SOC Automation Dashboard - Backend API
A production-ready Flask application for security operations automation
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import random
import os

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# Load dummy security data
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
    return alerts, threats, incidents, iocs

alerts_data, threats_data, incidents_data, iocs_data = load_data()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

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
def investigate_alert(alert_id):
    """Trigger automated investigation playbook"""
    alert = next((a for a in alerts_data if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
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
    
    return jsonify(investigation)

@app.route('/api/alerts/<int:alert_id>/respond', methods=['POST'])
def respond_to_alert(alert_id):
    """Execute automated response playbook"""
    action = request.json.get('action')
    
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

if __name__ == '__main__':
    import os
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
