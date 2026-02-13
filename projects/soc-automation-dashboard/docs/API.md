# SOC Automation Dashboard - API Documentation

## Base URL
```
http://localhost:5000/api
```

---

## Endpoints

### Dashboard

#### Get Dashboard Statistics
```
GET /api/dashboard/stats
```

**Response:**
```json
{
  "total_alerts": 12,
  "active_alerts": 7,
  "total_incidents": 6,
  "critical_incidents": 3,
  "blocked_threats": 8,
  "iocs_detected": 15,
  "mttr": "45 min",
  "automation_rate": "87%"
}
```

#### Get Timeline Data
```
GET /api/timeline?hours=24
```

**Query Parameters:**
- `hours` (optional): Number of hours to retrieve (default: 24)

**Response:**
```json
[
  {
    "timestamp": "2026-02-13T14:00:00Z",
    "alerts": 15,
    "threats_blocked": 8,
    "incidents": 2
  }
]
```

#### Get Threat Map
```
GET /api/threat-map
```

**Response:**
```json
[
  {
    "country": "United States",
    "lat": 37.0902,
    "lon": -95.7129,
    "count": 1247
  }
]
```

---

### Alerts

#### List Alerts
```
GET /api/alerts
```

**Query Parameters:**
- `status` (optional): Filter by status (active, investigating, resolved)
- `severity` (optional): Filter by severity (critical, high, medium, low)

**Response:**
```json
[
  {
    "id": 1,
    "title": "Suspicious PowerShell Execution Detected",
    "severity": "high",
    "status": "active",
    "source": "EDR",
    "timestamp": "2026-02-13T14:45:22Z",
    "host": "WKSTN-1247",
    "user": "john.doe",
    "description": "Encoded PowerShell command detected",
    "indicators": ["powershell.exe", "base64"],
    "mitre_tactics": ["T1059.001", "T1027"],
    "risk_score": 85
  }
]
```

#### Investigate Alert
```
POST /api/alerts/{alert_id}/investigate
```

**Response:**
```json
{
  "alert_id": 1,
  "status": "investigating",
  "steps_completed": [
    "IOC enrichment completed",
    "Threat intelligence lookup completed"
  ],
  "findings": {
    "ioc_matches": 3,
    "threat_score": 85,
    "recommended_action": "isolate",
    "confidence": 92
  },
  "timestamp": "2026-02-13T15:00:00Z"
}
```

#### Execute Response
```
POST /api/alerts/{alert_id}/respond
```

**Request Body:**
```json
{
  "action": "isolate"
}
```

**Valid Actions:** isolate, block, monitor

**Response:**
```json
{
  "alert_id": 1,
  "action": "isolate",
  "status": "executed",
  "actions_taken": [
    "Host isolated from network",
    "Active connections terminated"
  ],
  "timestamp": "2026-02-13T15:05:00Z"
}
```

---

### Threats

#### List Threats
```
GET /api/threats
```

**Response:**
```json
[
  {
    "id": 1,
    "type": "malware",
    "name": "Emotet Trojan",
    "severity": "critical",
    "action": "blocked",
    "timestamp": "2026-02-13T14:18:45Z",
    "source_ip": "185.220.101.45",
    "destination_ip": "10.0.1.142",
    "country": "Russia",
    "description": "Banking trojan",
    "indicators": 15,
    "confidence": 98
  }
]
```

---

### Incidents

#### List Incidents
```
GET /api/incidents
```

**Query Parameters:**
- `status` (optional): Filter by status

**Response:**
```json
[
  {
    "id": 1,
    "title": "Ransomware Attack on File Server",
    "severity": "critical",
    "status": "contained",
    "created": "2026-02-13T10:33:21Z",
    "updated": "2026-02-13T11:15:44Z",
    "assignee": "Tier 2 SOC Analyst",
    "affected_systems": ["FILE-SERVER-01"],
    "description": "LockBit 3.0 detected",
    "impact": "High - Critical files encrypted",
    "response_actions": ["Host isolated"],
    "timeline": []
  }
]
```

---

### IOCs

#### List Indicators of Compromise
```
GET /api/iocs
```

**Query Parameters:**
- `type` (optional): Filter by type (ip, domain, hash, url, email)

**Response:**
```json
[
  {
    "id": 1,
    "type": "ip",
    "value": "185.220.101.45",
    "threat_type": "malware_c2",
    "first_seen": "2026-02-10T08:15:22Z",
    "last_seen": "2026-02-13T14:18:45Z",
    "threat_actor": "Emotet Group",
    "severity": "critical",
    "status": "active",
    "tags": ["trojan", "c2_server"],
    "description": "Known C2 server"
  }
]
```

---

### Playbooks

#### List Playbooks
```
GET /api/playbooks
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "Malware Detection Response",
    "description": "Automated response to malware",
    "steps": 6,
    "avg_execution_time": "2 min",
    "success_rate": "94%",
    "triggers": ["malware_detected"]
  }
]
```

---

### Metrics

#### Get Performance Metrics
```
GET /api/metrics/performance
```

**Response:**
```json
{
  "alert_processing": {
    "avg_time": "1.2 min",
    "automated": "87%"
  },
  "incident_resolution": {
    "avg_time": "45 min",
    "within_sla": "92%"
  },
  "threat_detection": {
    "true_positive_rate": "94%"
  },
  "automation_impact": {
    "time_saved": "156 hours/week"
  }
}
```

---

## Error Handling

All endpoints return standard HTTP status codes:
- `200 OK`: Successful request
- `400 Bad Request`: Invalid parameters
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

**Error Response Format:**
```json
{
  "error": "Error message description"
}
```

---

## Rate Limiting

No rate limiting is currently implemented for this demo application.

---

## Authentication

No authentication is required for this demo application. In production, implement OAuth 2.0 or JWT authentication.
