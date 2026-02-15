#!/usr/bin/env python3
"""
Generate comprehensive security data for SOC Automation Dashboard
Creates realistic alerts, threats, incidents, and IOCs
"""

import json
import random
from datetime import datetime, timedelta

# Configuration
NUM_ALERTS = 50
NUM_THREATS = 35
NUM_INCIDENTS = 25
NUM_IOCS = 150

# Alert templates with realistic scenarios
ALERT_TEMPLATES = [
    {
        "title": "Suspicious PowerShell Execution Detected",
        "severity": "high",
        "source": "EDR",
        "description": "Encoded PowerShell command detected with base64 obfuscation",
        "indicators": ["powershell.exe", "base64", "network_connection"],
        "mitre_tactics": ["T1059.001", "T1027"]
    },
    {
        "title": "Multiple Failed Login Attempts",
        "severity": "medium",
        "source": "SIEM",
        "description": "Multiple failed authentication attempts from suspicious IP",
        "indicators": ["brute_force", "failed_auth", "external_ip"],
        "mitre_tactics": ["T1110"]
    },
    {
        "title": "Malware Signature Detected",
        "severity": "critical",
        "source": "Antivirus",
        "description": "Known malware signature detected in downloaded file",
        "indicators": ["malware_detected", "trojan", "suspicious_download"],
        "mitre_tactics": ["T1204.002"]
    },
    {
        "title": "Unusual Outbound Network Traffic",
        "severity": "high",
        "source": "Firewall",
        "description": "Large data transfer to unknown external IP",
        "indicators": ["data_exfiltration", "unusual_traffic", "external_connection"],
        "mitre_tactics": ["T1041"]
    },
    {
        "title": "Privilege Escalation Attempt",
        "severity": "critical",
        "source": "EDR",
        "description": "Unauthorized attempt to escalate privileges detected",
        "indicators": ["privilege_escalation", "unauthorized_access", "system_tampering"],
        "mitre_tactics": ["T1068"]
    },
    {
        "title": "Suspicious Registry Modification",
        "severity": "high",
        "source": "EDR",
        "description": "Registry persistence mechanism detected",
        "indicators": ["registry_modification", "persistence", "auto_start"],
        "mitre_tactics": ["T1547.001"]
    },
    {
        "title": "Credential Dumping Detected",
        "severity": "critical",
        "source": "EDR",
        "description": "Mimikatz-like behavior detected",
        "indicators": ["credential_access", "lsass_access", "memory_dump"],
        "mitre_tactics": ["T1003.001"]
    },
    {
        "title": "SQL Injection Attempt",
        "severity": "high",
        "source": "WAF",
        "description": "SQL injection patterns detected in web request",
        "indicators": ["sql_injection", "web_attack", "malicious_payload"],
        "mitre_tactics": ["T1190"]
    },
    {
        "title": "Lateral Movement Detected",
        "severity": "high",
        "source": "EDR",
        "description": "Unauthorized network share access detected",
        "indicators": ["lateral_movement", "smb_enumeration", "remote_access"],
        "mitre_tactics": ["T1021.002"]
    },
    {
        "title": "Suspicious Process Injection",
        "severity": "critical",
        "source": "EDR",
        "description": "Code injection into legitimate process detected",
        "indicators": ["process_injection", "code_injection", "evasion"],
        "mitre_tactics": ["T1055"]
    }
]

HOSTNAMES = [
    "WKSTN-1247", "WKSTN-0892", "WKSTN-2341", "WKSTN-5612", "WKSTN-7834",
    "WEB-SERVER-01", "WEB-SERVER-02", "APP-SERVER-01", "APP-SERVER-02",
    "DB-SERVER-01", "DB-SERVER-02", "DB-SERVER-03", "FILE-SERVER-01",
    "DC-01", "DC-02", "MAIL-01", "PROXY-01", "LOAD-BALANCER-01"
]

USERS = [
    "john.doe", "jane.smith", "mike.johnson", "sarah.williams", "chris.brown",
    "admin", "system", "webservice", "dbadmin", "backup_service",
    "emily.davis", "robert.wilson", "lisa.anderson", "david.martinez",
    "jennifer.garcia", "kevin.rodriguez", "amanda.lee", "brian.taylor"
]

STATUSES = ["active", "investigating", "resolved", "contained", "monitoring"]

def generate_alerts(count):
    alerts = []
    now = datetime.now()
    
    for i in range(count):
        template = random.choice(ALERT_TEMPLATES)
        hours_ago = random.randint(0, 168)  # Last 7 days
        timestamp = (now - timedelta(hours=hours_ago)).isoformat() + 'Z'
        
        risk_score = random.randint(60, 99) if template["severity"] in ["critical", "high"] else random.randint(30, 70)
        
        alert = {
            "id": i + 1,
            "title": template["title"],
            "severity": template["severity"],
            "status": random.choice(STATUSES),
            "source": template["source"],
            "timestamp": timestamp,
            "host": random.choice(HOSTNAMES),
            "user": random.choice(USERS),
            "description": template["description"],
            "indicators": template["indicators"],
            "mitre_tactics": template["mitre_tactics"],
            "risk_score": risk_score
        }
        alerts.append(alert)
    
    return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)

def generate_threats(count):
    threat_types = ["malware", "ransomware", "apt", "phishing", "botnet", "exploit", "backdoor", "cryptominer", "spyware", "web_attack"]
    threat_names = [
        "Emotet Trojan", "LockBit 3.0", "APT29 (Cozy Bear)", "APT28 (Fancy Bear)", 
        "Credential Harvesting Campaign", "Mirai Botnet", "Log4Shell Exploitation",
        "Cobalt Strike Beacon", "XMRig Miner", "Agent Tesla", "SQL Injection Campaign",
        "TrickBot", "Ryuk Ransomware", "BlackCat", "Conti", "REvil", "DarkSide",
        "APT41", "Lazarus Group", "FIN7", "TA505", "Qakbot", "BazarLoader",
        "IcedID", "Dridex", "Zeus", "Remcos RAT", "AsyncRAT", "njRAT",
        "Metasploit Framework", "Empire", "PoshC2", "Sliver", "Havoc C2"
    ]
    
    actions = ["blocked", "contained", "investigating", "quarantined"]
    countries = ["Russia", "China", "United States", "Brazil", "Germany", "India", 
                "United Kingdom", "France", "Netherlands", "Romania", "Ukraine"]
    
    threats = []
    now = datetime.now()
    
    for i in range(count):
        hours_ago = random.randint(0, 168)
        timestamp = (now - timedelta(hours=hours_ago)).isoformat() + 'Z'
        
        threat = {
            "id": i + 1,
            "type": random.choice(threat_types),
            "name": random.choice(threat_names),
            "severity": random.choice(["critical", "high", "medium"]),
            "action": random.choice(actions),
            "timestamp": timestamp,
            "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "destination_ip": f"10.0.{random.randint(1,10)}.{random.randint(1,255)}",
            "country": random.choice(countries),
            "description": f"Threat actor activity detected",
            "indicators": random.randint(5, 25),
            "confidence": random.randint(85, 99)
        }
        threats.append(threat)
    
    return sorted(threats, key=lambda x: x['timestamp'], reverse=True)

def generate_incidents(count):
    incident_types = [
        "Ransomware Attack", "APT Intrusion Attempt", "Credential Dumping",
        "DDoS Attack", "Phishing Campaign", "Malware Infection", "Data Exfiltration",
        "Insider Threat", "Web Application Attack", "Supply Chain Attack",
        "Zero-Day Exploitation", "Business Email Compromise", "Cryptojacking",
        "DNS Tunneling", "Living Off the Land Attack"
    ]
    
    severities = ["critical", "high", "medium"]
    statuses_inc = ["investigating", "contained", "mitigating", "resolved"]
    
    analysts = [
        "Tier 1 SOC Analyst", "Tier 2 SOC Analyst", "Tier 3 SOC Analyst",
        "Senior SOC Analyst", "Incident Responder", "Threat Hunter",
        "Security Engineer", "SOC Manager", "CISO"
    ]
    
    incidents = []
    now = datetime.now()
    
    for i in range(count):
        hours_ago = random.randint(0, 336)  # Last 2 weeks
        created = (now - timedelta(hours=hours_ago)).isoformat() + 'Z'
        updated = (now - timedelta(hours=max(0, hours_ago - random.randint(1, 24)))).isoformat() + 'Z'
        
        incident_type = random.choice(incident_types)
        severity = random.choice(severities)
        
        affected_systems = random.sample(HOSTNAMES, random.randint(1, 5))
        
        incident = {
            "id": i + 1,
            "title": f"{incident_type} on {affected_systems[0]}",
            "severity": severity,
            "status": random.choice(statuses_inc),
            "created": created,
            "updated": updated,
            "assignee": random.choice(analysts),
            "affected_systems": affected_systems,
            "description": f"{incident_type} detected and under investigation",
            "impact": f"{'Critical' if severity == 'critical' else 'High'} - Business impact assessment ongoing",
            "response_actions": [
                "Host isolated from network" if random.random() > 0.5 else "Enhanced monitoring enabled",
                "Forensic analysis in progress",
                "Incident ticket created",
                "Stakeholders notified"
            ],
            "timeline": [
                {"time": created.split('T')[1][:5], "event": "Initial detection"},
                {"time": updated.split('T')[1][:5], "event": "Investigation ongoing"}
            ]
        }
        incidents.append(incident)
    
    return sorted(incidents, key=lambda x: x['created'], reverse=True)

def generate_iocs(count):
    ioc_types = ["ip", "domain", "hash", "url", "email"]
    threat_types_ioc = ["malware_c2", "phishing", "apt", "ransomware", "botnet", "exploit", "spam"]
    
    # Real-looking malicious domains and IPs
    tlds = [".com", ".net", ".org", ".xyz", ".top", ".ru", ".cn"]
    suspicious_words = ["update", "secure", "login", "verify", "account", "payment", "bank", "admin"]
    
    iocs = []
    now = datetime.now()
    
    for i in range(count):
        ioc_type = random.choice(ioc_types)
        days_ago = random.randint(0, 30)
        first_seen = (now - timedelta(days=days_ago)).isoformat() + 'Z'
        last_seen = (now - timedelta(days=random.randint(0, days_ago))).isoformat() + 'Z'
        
        if ioc_type == "ip":
            value = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        elif ioc_type == "domain":
            value = f"{random.choice(suspicious_words)}-{random.choice(suspicious_words)}{random.choice(tlds)}"
        elif ioc_type == "hash":
            value = ''.join(random.choices('0123456789abcdef', k=64))
        elif ioc_type == "url":
            value = f"http://{random.choice(suspicious_words)}-site{random.choice(tlds)}/malicious"
        else:  # email
            value = f"noreply@{random.choice(suspicious_words)}{random.choice(tlds)}"
        
        ioc = {
            "id": i + 1,
            "type": ioc_type,
            "value": value,
            "threat_type": random.choice(threat_types_ioc),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "threat_actor": random.choice(["Unknown", "APT29", "FIN7", "Lazarus", "TA505", "Emotet Group"]),
            "severity": random.choice(["critical", "high", "medium"]),
            "status": random.choice(["active", "monitoring", "blocked"]),
            "tags": random.sample(["trojan", "c2_server", "phishing", "malware", "exploit"], k=random.randint(1, 3)),
            "description": f"Malicious {ioc_type} associated with threat activity"
        }
        iocs.append(ioc)
    
    return iocs

# Generate all data
print("Generating comprehensive security data...")
print(f"Creating {NUM_ALERTS} alerts...")
alerts = generate_alerts(NUM_ALERTS)

print(f"Creating {NUM_THREATS} threats...")
threats = generate_threats(NUM_THREATS)

print(f"Creating {NUM_INCIDENTS} incidents...")
incidents = generate_incidents(NUM_INCIDENTS)

print(f"Creating {NUM_IOCS} IOCs...")
iocs = generate_iocs(NUM_IOCS)

# Generate users
print("Generating users...")
from werkzeug.security import generate_password_hash

users = [
    {
        'id': 1,
        'username': 'admin',
        'password_hash': generate_password_hash('SOCdemo2026!'),
        'role': 'admin',
        'display_name': 'SOC Admin',
        'email': 'admin@soc.local'
    },
    {
        'id': 2,
        'username': 'sarah.chen',
        'password_hash': generate_password_hash('SOCdemo2026!'),
        'role': 'soc_manager',
        'display_name': 'Sarah Chen',
        'email': 'sarah.chen@soc.local'
    },
    {
        'id': 3,
        'username': 'mike.ross',
        'password_hash': generate_password_hash('SOCdemo2026!'),
        'role': 't3_analyst',
        'display_name': 'Mike Ross',
        'email': 'mike.ross@soc.local'
    },
    {
        'id': 4,
        'username': 'emily.zhang',
        'password_hash': generate_password_hash('SOCdemo2026!'),
        'role': 't2_analyst',
        'display_name': 'Emily Zhang',
        'email': 'emily.zhang@soc.local'
    },
    {
        'id': 5,
        'username': 'jake.miller',
        'password_hash': generate_password_hash('SOCdemo2026!'),
        'role': 't1_analyst',
        'display_name': 'Jake Miller',
        'email': 'jake.miller@soc.local'
    },
    {
        'id': 6,
        'username': 'viewer',
        'password_hash': generate_password_hash('SOCdemo2026!'),
        'role': 'read_only',
        'display_name': 'SOC Viewer',
        'email': 'viewer@soc.local'
    }
]

# Generate case notes
print("Generating case notes...")
analysts = [
    {'id': 3, 'name': 'Mike Ross'},
    {'id': 4, 'name': 'Emily Zhang'},
    {'id': 5, 'name': 'Jake Miller'}
]

note_templates = [
    {
        'content': 'Initial triage completed. PowerShell execution appears to be encoded command downloading second-stage payload. Recommending host isolation.',
        'type': 'investigation_note',
        'tags': ['malware', 'powershell', 'triage']
    },
    {
        'content': 'Confirmed C2 communication to suspicious IP. VirusTotal shows multiple detections. Escalating to Tier 3.',
        'type': 'escalation_note',
        'tags': ['c2', 'escalation', 'virustotal']
    },
    {
        'content': 'Brute force attack blocked at firewall. Source IP added to blocklist. Monitoring for additional attempts.',
        'type': 'investigation_note',
        'tags': ['brute_force', 'blocked', 'firewall']
    },
    {
        'content': 'Phishing email quarantined. Malicious attachment contains known payload. Scanning for additional instances.',
        'type': 'investigation_note',
        'tags': ['phishing', 'email', 'malware']
    },
    {
        'content': 'Incident response team activated. Legal and PR teams notified. Recovery procedures initiated.',
        'type': 'response_note',
        'tags': ['incident_response', 'recovery']
    }
]

case_notes = []
for i, alert in enumerate(alerts[:15]):  # Add notes to first 15 alerts
    num_notes = random.randint(1, 3)
    for j in range(num_notes):
        analyst = random.choice(analysts)
        template = random.choice(note_templates)
        note = {
            'id': len(case_notes) + 1,
            'alert_id': alert['id'],
            'incident_id': None,
            'author_id': analyst['id'],
            'author_name': analyst['name'],
            'content': template['content'],
            'type': template['type'],
            'created_at': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat() + 'Z',
            'updated_at': (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat() + 'Z',
            'is_pinned': random.choice([True, False, False]),
            'tags': template['tags']
        }
        case_notes.append(note)

# Generate evidence
print("Generating evidence...")
evidence_templates = [
    {
        'type': 'file_hash',
        'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'hash_type': 'SHA-256',
        'description': 'Suspicious file hash',
        'tags': ['malware', 'file']
    },
    {
        'type': 'ip_address',
        'value': '185.220.101.45',
        'hash_type': None,
        'description': 'C2 server IP address',
        'tags': ['c2', 'network']
    },
    {
        'type': 'domain',
        'value': 'malicious-domain.com',
        'hash_type': None,
        'description': 'Known malicious domain',
        'tags': ['domain', 'c2']
    },
    {
        'type': 'email',
        'value': 'phishing@malicious.com',
        'hash_type': None,
        'description': 'Phishing email address',
        'tags': ['phishing', 'email']
    }
]

evidence_list = []
for i, alert in enumerate(alerts[:20]):  # Add evidence to first 20 alerts
    num_evidence = random.randint(1, 2)
    for j in range(num_evidence):
        analyst = random.choice(analysts)
        template = random.choice(evidence_templates)
        evidence = {
            'id': len(evidence_list) + 1,
            'alert_id': alert['id'],
            'incident_id': None,
            'type': template['type'],
            'value': template['value'],
            'hash_type': template['hash_type'],
            'description': template['description'],
            'collected_by_id': analyst['id'],
            'collected_by_name': analyst['name'],
            'collected_at': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat() + 'Z',
            'chain_of_custody': [
                {
                    'action': 'collected',
                    'by': analyst['name'],
                    'at': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat() + 'Z',
                    'notes': 'Extracted from security logs'
                }
            ],
            'tags': template['tags'],
            'status': random.choice(['verified', 'collected', 'analyzed'])
        }
        evidence_list.append(evidence)

# Generate sample audit log
print("Generating sample audit log...")
actions = [
    'login', 'logout', 'alert_investigated', 'alert_response_executed',
    'playbook_executed', 'note_added', 'evidence_added'
]

audit_log = []
for i in range(50):  # Generate 50 sample audit entries
    user = random.choice(users)
    action = random.choice(actions)
    audit_log.append({
        'id': i + 1,
        'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 72))).isoformat() + 'Z',
        'user_id': user['id'],
        'username': user['username'],
        'action': action,
        'resource_type': 'alert' if 'alert' in action else ('playbook' if 'playbook' in action else 'auth'),
        'resource_id': random.randint(1, 50) if action != 'login' and action != 'logout' else None,
        'details': {},
        'ip_address': f'192.168.1.{random.randint(1, 255)}'
    })

# Sort audit log by timestamp descending
audit_log.sort(key=lambda x: x['timestamp'], reverse=True)

# Generate correlations
print("Generating alert correlations...")
correlations = []

# Correlation 1: Coordinated Attack on WKSTN-1247
wkstn_alerts = [a for a in alerts if a['host'] == 'WKSTN-1247'][:4]
if len(wkstn_alerts) >= 2:
    correlations.append({
        'id': 1,
        'name': 'Coordinated Attack on WKSTN-1247',
        'description': 'Multiple indicators suggest a coordinated attack targeting workstation WKSTN-1247, progressing from initial access through lateral movement.',
        'correlation_score': 92,
        'created_at': (datetime.now() - timedelta(hours=6)).isoformat() + 'Z',
        'updated_at': (datetime.now() - timedelta(hours=2)).isoformat() + 'Z',
        'status': 'active',
        'alert_ids': [a['id'] for a in wkstn_alerts],
        'shared_entities': {
            'hosts': ['WKSTN-1247'],
            'users': list(set([a['user'] for a in wkstn_alerts])),
            'ips': ['185.220.101.45'],
            'mitre_tactics': list(set([t for a in wkstn_alerts for t in a.get('mitre_tactics', [])]))
        },
        'kill_chain': [
            {'stage': 'Initial Access', 'alert_id': wkstn_alerts[0]['id'], 'technique': 'T1566.001', 'timestamp': wkstn_alerts[0]['timestamp']},
            {'stage': 'Execution', 'alert_id': wkstn_alerts[1]['id'], 'technique': 'T1059.001', 'timestamp': wkstn_alerts[1]['timestamp']}
        ] if len(wkstn_alerts) >= 2 else [],
        'kill_chain_coverage': min(4, len(wkstn_alerts)),
        'total_kill_chain_stages': 14,
        'risk_level': 'critical',
        'recommended_action': 'Immediate host isolation and full forensic investigation'
    })

# Correlation 2: Brute Force Campaign
brute_force_alerts = [a for a in alerts if 'brute_force' in ' '.join(a.get('indicators', [])).lower() or 'failed' in a['title'].lower()][:3]
if len(brute_force_alerts) >= 2:
    correlations.append({
        'id': 2,
        'name': 'Brute Force Attack Campaign',
        'description': 'Coordinated brute force attempts detected across multiple hosts from suspicious IP addresses.',
        'correlation_score': 78,
        'created_at': (datetime.now() - timedelta(hours=8)).isoformat() + 'Z',
        'updated_at': (datetime.now() - timedelta(hours=4)).isoformat() + 'Z',
        'status': 'active',
        'alert_ids': [a['id'] for a in brute_force_alerts],
        'shared_entities': {
            'hosts': list(set([a['host'] for a in brute_force_alerts])),
            'users': list(set([a['user'] for a in brute_force_alerts])),
            'ips': ['192.168.1.100', '10.0.0.50'],
            'mitre_tactics': ['T1110']
        },
        'kill_chain': [
            {'stage': 'Credential Access', 'alert_id': brute_force_alerts[0]['id'], 'technique': 'T1110', 'timestamp': brute_force_alerts[0]['timestamp']}
        ],
        'kill_chain_coverage': 1,
        'total_kill_chain_stages': 14,
        'risk_level': 'high',
        'recommended_action': 'Block source IPs and enforce account lockout policies'
    })

# Correlation 3: Malware Propagation
malware_alerts = [a for a in alerts if a['severity'] == 'critical' and ('malware' in a['title'].lower() or 'suspicious' in a['title'].lower())][:4]
if len(malware_alerts) >= 2:
    correlations.append({
        'id': 3,
        'name': 'Malware Propagation Pattern',
        'description': 'Malware activity detected across multiple systems indicating potential propagation or coordinated infection.',
        'correlation_score': 85,
        'created_at': (datetime.now() - timedelta(hours=5)).isoformat() + 'Z',
        'updated_at': (datetime.now() - timedelta(hours=1)).isoformat() + 'Z',
        'status': 'active',
        'alert_ids': [a['id'] for a in malware_alerts],
        'shared_entities': {
            'hosts': list(set([a['host'] for a in malware_alerts])),
            'users': list(set([a['user'] for a in malware_alerts])),
            'ips': [],
            'mitre_tactics': list(set([t for a in malware_alerts for t in a.get('mitre_tactics', [])]))
        },
        'kill_chain': [
            {'stage': 'Execution', 'alert_id': malware_alerts[0]['id'], 'technique': 'T1204.002', 'timestamp': malware_alerts[0]['timestamp']},
            {'stage': 'Defense Evasion', 'alert_id': malware_alerts[1]['id'], 'technique': 'T1055', 'timestamp': malware_alerts[1]['timestamp']}
        ] if len(malware_alerts) >= 2 else [],
        'kill_chain_coverage': 2,
        'total_kill_chain_stages': 14,
        'risk_level': 'critical',
        'recommended_action': 'Isolate infected systems and perform malware analysis'
    })

# Correlation 4: Privilege Escalation Chain
priv_esc_alerts = [a for a in alerts if 'privilege' in a['title'].lower() or 'escalation' in a['title'].lower()][:3]
if len(priv_esc_alerts) >= 2:
    correlations.append({
        'id': 4,
        'name': 'Privilege Escalation Campaign',
        'description': 'Multiple privilege escalation attempts detected, indicating attacker attempting to gain elevated access.',
        'correlation_score': 81,
        'created_at': (datetime.now() - timedelta(hours=7)).isoformat() + 'Z',
        'updated_at': (datetime.now() - timedelta(hours=3)).isoformat() + 'Z',
        'status': 'active',
        'alert_ids': [a['id'] for a in priv_esc_alerts],
        'shared_entities': {
            'hosts': list(set([a['host'] for a in priv_esc_alerts])),
            'users': list(set([a['user'] for a in priv_esc_alerts])),
            'ips': [],
            'mitre_tactics': ['T1068', 'T1134']
        },
        'kill_chain': [
            {'stage': 'Privilege Escalation', 'alert_id': priv_esc_alerts[0]['id'], 'technique': 'T1068', 'timestamp': priv_esc_alerts[0]['timestamp']}
        ],
        'kill_chain_coverage': 1,
        'total_kill_chain_stages': 14,
        'risk_level': 'high',
        'recommended_action': 'Review access controls and patch known vulnerabilities'
    })

# Correlation 5: Data Exfiltration Pattern
exfil_alerts = [a for a in alerts if 'outbound' in a['title'].lower() or 'traffic' in a['title'].lower() or 'exfiltration' in ' '.join(a.get('indicators', [])).lower()][:3]
if len(exfil_alerts) >= 2:
    correlations.append({
        'id': 5,
        'name': 'Potential Data Exfiltration',
        'description': 'Unusual network traffic patterns suggesting data exfiltration attempts.',
        'correlation_score': 74,
        'created_at': (datetime.now() - timedelta(hours=4)).isoformat() + 'Z',
        'updated_at': (datetime.now() - timedelta(hours=1)).isoformat() + 'Z',
        'status': 'active',
        'alert_ids': [a['id'] for a in exfil_alerts],
        'shared_entities': {
            'hosts': list(set([a['host'] for a in exfil_alerts])),
            'users': list(set([a['user'] for a in exfil_alerts])),
            'ips': ['185.220.101.45', '203.0.113.42'],
            'mitre_tactics': ['T1041', 'T1048']
        },
        'kill_chain': [
            {'stage': 'Exfiltration', 'alert_id': exfil_alerts[0]['id'], 'technique': 'T1041', 'timestamp': exfil_alerts[0]['timestamp']}
        ],
        'kill_chain_coverage': 1,
        'total_kill_chain_stages': 14,
        'risk_level': 'high',
        'recommended_action': 'Block suspicious connections and investigate data access logs'
    })

# Correlation 6: Persistence Mechanism
persistence_alerts = [a for a in alerts if 'persistence' in ' '.join(a.get('indicators', [])).lower() or 'registry' in a['title'].lower()][:3]
if len(persistence_alerts) >= 2:
    correlations.append({
        'id': 6,
        'name': 'Persistence Establishment',
        'description': 'Multiple persistence mechanisms detected across systems.',
        'correlation_score': 69,
        'created_at': (datetime.now() - timedelta(hours=9)).isoformat() + 'Z',
        'updated_at': (datetime.now() - timedelta(hours=5)).isoformat() + 'Z',
        'status': 'monitoring',
        'alert_ids': [a['id'] for a in persistence_alerts],
        'shared_entities': {
            'hosts': list(set([a['host'] for a in persistence_alerts])),
            'users': list(set([a['user'] for a in persistence_alerts])),
            'ips': [],
            'mitre_tactics': ['T1547.001']
        },
        'kill_chain': [
            {'stage': 'Persistence', 'alert_id': persistence_alerts[0]['id'], 'technique': 'T1547.001', 'timestamp': persistence_alerts[0]['timestamp']}
        ],
        'kill_chain_coverage': 1,
        'total_kill_chain_stages': 14,
        'risk_level': 'medium',
        'recommended_action': 'Remove persistence mechanisms and monitor for reinfection'
    })

# Generate notifications
print("Generating notifications...")
notifications = []
notification_types = [
    ('alert_assigned', 'New Critical Alert Assigned', 'A critical alert has been assigned to you', 'critical'),
    ('alert_escalated', 'Alert Escalated to Level 2', 'Alert requires immediate attention', 'high'),
    ('sla_breach', 'SLA Breach Warning', 'Alert is approaching SLA threshold', 'high'),
    ('playbook_completed', 'Playbook Execution Completed', 'Automated playbook has finished execution', 'medium'),
    ('correlation_detected', 'New Alert Correlation Detected', 'Multiple related alerts have been grouped', 'high'),
    ('system_alert', 'System Notification', 'SOC platform update available', 'low')
]

for i, (n_type, title, message, severity) in enumerate(notification_types):
    for j in range(random.randint(2, 4)):
        user = random.choice(users)
        notifications.append({
            'id': len(notifications) + 1,
            'user_id': user['id'],
            'type': n_type,
            'title': title,
            'message': message,
            'severity': severity,
            'resource_type': 'alert' if 'alert' in n_type or 'sla' in n_type else ('playbook' if 'playbook' in n_type else 'correlation' if 'correlation' in n_type else 'system'),
            'resource_id': random.randint(1, 50) if 'system' not in n_type else None,
            'read': random.choice([True, False, False]),
            'acknowledged_at': None,
            'created_at': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat() + 'Z'
        })

# Sort notifications by created_at descending
notifications.sort(key=lambda x: x['created_at'], reverse=True)

# Generate escalation policies
print("Generating escalation policies...")
escalation_policies = [
    {
        'id': 1,
        'name': 'Critical Alert Escalation',
        'description': 'Escalation path for critical severity alerts',
        'trigger_severity': 'critical',
        'enabled': True,
        'levels': [
            {
                'level': 1,
                'escalate_after_minutes': 5,
                'notify_roles': ['t1_analyst', 't2_analyst'],
                'action': 'notify'
            },
            {
                'level': 2,
                'escalate_after_minutes': 15,
                'notify_roles': ['t3_analyst'],
                'action': 'notify_and_assign'
            },
            {
                'level': 3,
                'escalate_after_minutes': 30,
                'notify_roles': ['soc_manager'],
                'action': 'notify_and_escalate'
            },
            {
                'level': 4,
                'escalate_after_minutes': 60,
                'notify_roles': ['admin'],
                'action': 'emergency_page'
            }
        ]
    },
    {
        'id': 2,
        'name': 'High Alert Escalation',
        'description': 'Escalation path for high severity alerts',
        'trigger_severity': 'high',
        'enabled': True,
        'levels': [
            {
                'level': 1,
                'escalate_after_minutes': 15,
                'notify_roles': ['t1_analyst'],
                'action': 'notify'
            },
            {
                'level': 2,
                'escalate_after_minutes': 60,
                'notify_roles': ['t2_analyst'],
                'action': 'notify_and_assign'
            },
            {
                'level': 3,
                'escalate_after_minutes': 120,
                'notify_roles': ['soc_manager'],
                'action': 'notify_and_escalate'
            }
        ]
    },
    {
        'id': 3,
        'name': 'Medium Alert Escalation',
        'description': 'Escalation path for medium severity alerts',
        'trigger_severity': 'medium',
        'enabled': True,
        'levels': [
            {
                'level': 1,
                'escalate_after_minutes': 60,
                'notify_roles': ['t1_analyst'],
                'action': 'notify'
            },
            {
                'level': 2,
                'escalate_after_minutes': 240,
                'notify_roles': ['t2_analyst'],
                'action': 'notify_and_assign'
            }
        ]
    }
]

# Generate on-call schedule
print("Generating on-call schedule...")
oncall_schedule = {
    'current_oncall': {
        'primary': {
            'user_id': 4,
            'name': 'Emily Zhang',
            'role': 't2_analyst',
            'start': (datetime.now() - timedelta(days=5)).isoformat() + 'Z',
            'end': (datetime.now() + timedelta(days=2)).isoformat() + 'Z'
        },
        'secondary': {
            'user_id': 3,
            'name': 'Mike Ross',
            'role': 't3_analyst',
            'start': (datetime.now() - timedelta(days=5)).isoformat() + 'Z',
            'end': (datetime.now() + timedelta(days=2)).isoformat() + 'Z'
        }
    },
    'schedule': [
        {
            'week_start': (datetime.now() - timedelta(days=5)).strftime('%Y-%m-%d'),
            'primary_user_id': 4,
            'secondary_user_id': 3
        },
        {
            'week_start': (datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d'),
            'primary_user_id': 5,
            'secondary_user_id': 4
        },
        {
            'week_start': (datetime.now() + timedelta(days=9)).strftime('%Y-%m-%d'),
            'primary_user_id': 3,
            'secondary_user_id': 5
        },
        {
            'week_start': (datetime.now() + timedelta(days=16)).strftime('%Y-%m-%d'),
            'primary_user_id': 4,
            'secondary_user_id': 3
        }
    ],
    'override': None
}

# Generate webhook config
print("Generating webhook configuration...")
webhook_config = [
    {
        'id': 1,
        'name': 'Slack SOC Channel',
        'type': 'slack',
        'url': 'https://hooks.slack.com/services/SIMULATED/WEBHOOK/URL',
        'enabled': True,
        'trigger_severity': ['critical', 'high'],
        'events': ['new_alert', 'sla_breach', 'escalation']
    },
    {
        'id': 2,
        'name': 'Teams Security Channel',
        'type': 'teams',
        'url': 'https://outlook.office.com/webhook/SIMULATED/URL',
        'enabled': True,
        'trigger_severity': ['critical'],
        'events': ['new_alert', 'escalation']
    },
    {
        'id': 3,
        'name': 'PagerDuty Integration',
        'type': 'pagerduty',
        'url': 'https://events.pagerduty.com/v2/enqueue',
        'enabled': True,
        'trigger_severity': ['critical'],
        'events': ['sla_breach', 'escalation']
    },
    {
        'id': 4,
        'name': 'Email Notifications',
        'type': 'email',
        'url': 'smtp://mail.soc.local:587',
        'enabled': True,
        'trigger_severity': ['critical', 'high', 'medium'],
        'events': ['new_alert', 'assignment', 'sla_breach']
    }
]

# Save to files
with open('alerts.json', 'w') as f:
    json.dump(alerts, f, indent=2)

with open('threats.json', 'w') as f:
    json.dump(threats, f, indent=2)

with open('incidents.json', 'w') as f:
    json.dump(incidents, f, indent=2)

with open('iocs.json', 'w') as f:
    json.dump(iocs, f, indent=2)

with open('users.json', 'w') as f:
    json.dump(users, f, indent=2)

with open('case_notes.json', 'w') as f:
    json.dump(case_notes, f, indent=2)

with open('evidence.json', 'w') as f:
    json.dump(evidence_list, f, indent=2)

with open('audit_log.json', 'w') as f:
    json.dump(audit_log, f, indent=2)

with open('correlations.json', 'w') as f:
    json.dump(correlations, f, indent=2)

with open('notifications.json', 'w') as f:
    json.dump(notifications, f, indent=2)

with open('escalation_policies.json', 'w') as f:
    json.dump(escalation_policies, f, indent=2)

with open('oncall_schedule.json', 'w') as f:
    json.dump(oncall_schedule, f, indent=2)

with open('webhook_config.json', 'w') as f:
    json.dump(webhook_config, f, indent=2)

print("\nData generation complete!")
print(f"- {len(alerts)} alerts")
print(f"- {len(threats)} threats")
print(f"- {len(incidents)} incidents")
print(f"- {len(iocs)} IOCs")
print(f"- {len(users)} users")
print(f"- {len(case_notes)} case notes")
print(f"- {len(evidence_list)} evidence items")
print(f"- {len(audit_log)} audit log entries")
print(f"- {len(correlations)} correlation groups")
print(f"- {len(notifications)} notifications")
print(f"- {len(escalation_policies)} escalation policies")
print(f"- {len(webhook_config)} webhook configurations")
