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

# Save to files
with open('alerts.json', 'w') as f:
    json.dump(alerts, f, indent=2)

with open('threats.json', 'w') as f:
    json.dump(threats, f, indent=2)

with open('incidents.json', 'w') as f:
    json.dump(incidents, f, indent=2)

with open('iocs.json', 'w') as f:
    json.dump(iocs, f, indent=2)

print("\nData generation complete!")
print(f"- {len(alerts)} alerts")
print(f"- {len(threats)} threats")
print(f"- {len(incidents)} incidents")
print(f"- {len(iocs)} IOCs")
