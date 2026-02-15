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

## Authentication

### JWT-Based Authentication

All API endpoints (except `/api/auth/login`) require a valid JWT token in the Authorization header.

**Header Format:**
```
Authorization: Bearer <JWT_TOKEN>
```

---

## Authentication Endpoints

### Login

```
POST /api/auth/login
```

**Request Body:**
```json
{
  "username": "admin",
  "password": "SOCdemo2026!"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "display_name": "SOC Admin",
    "email": "admin@soc.local"
  }
}
```

**Error Responses:**
- `400` - Missing username or password
- `401` - Invalid credentials

### Logout

```
POST /api/auth/logout
```

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

### Get Current User

```
GET /api/auth/me
```

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "role": "admin",
  "display_name": "SOC Admin",
  "email": "admin@soc.local"
}
```

### Change Password

```
POST /api/auth/change-password
```

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Request Body:**
```json
{
  "current_password": "SOCdemo2026!",
  "new_password": "NewSecurePassword123!"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

**Error Responses:**
- `400` - Missing required fields
- `401` - Current password is incorrect

---

## Case Notes Endpoints

### Get Alert Notes

```
GET /api/alerts/{alert_id}/notes
```

**Required Permission:** `view_alerts`

**Response:**
```json
[
  {
    "id": 1,
    "alert_id": 1,
    "incident_id": null,
    "author_id": 3,
    "author_name": "Mike Ross",
    "content": "Initial triage completed...",
    "type": "investigation_note",
    "created_at": "2026-02-15T09:30:00Z",
    "updated_at": "2026-02-15T09:30:00Z",
    "is_pinned": true,
    "tags": ["malware", "powershell"]
  }
]
```

### Add Alert Note

```
POST /api/alerts/{alert_id}/notes
```

**Required Permission:** `add_notes`

**Request Body:**
```json
{
  "content": "Suspicious activity confirmed...",
  "type": "investigation_note",
  "tags": ["malware", "investigation"],
  "is_pinned": false
}
```

**Response:**
```json
{
  "id": 10,
  "alert_id": 1,
  "author_id": 3,
  "author_name": "Mike Ross",
  "content": "Suspicious activity confirmed...",
  "type": "investigation_note",
  "created_at": "2026-02-15T12:30:00Z",
  "updated_at": "2026-02-15T12:30:00Z",
  "is_pinned": false,
  "tags": ["malware", "investigation"]
}
```

### Get Incident Notes

```
GET /api/incidents/{incident_id}/notes
```

**Required Permission:** `view_alerts`

### Add Incident Note

```
POST /api/incidents/{incident_id}/notes
```

**Required Permission:** `add_notes`

### Update Note

```
PUT /api/notes/{note_id}
```

**Required Permission:** `add_notes` (author or admin only)

**Request Body:**
```json
{
  "content": "Updated content...",
  "type": "investigation_note",
  "is_pinned": true,
  "tags": ["updated", "tags"]
}
```

### Delete Note

```
DELETE /api/notes/{note_id}
```

**Required Permission:** `add_notes` (author or admin only)

---

## Evidence Endpoints

### Get Alert Evidence

```
GET /api/alerts/{alert_id}/evidence
```

**Required Permission:** `view_alerts`

**Response:**
```json
[
  {
    "id": 1,
    "alert_id": 1,
    "incident_id": null,
    "type": "file_hash",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hash_type": "SHA-256",
    "description": "Suspicious PowerShell script hash",
    "collected_by_id": 3,
    "collected_by_name": "Mike Ross",
    "collected_at": "2026-02-15T09:35:00Z",
    "chain_of_custody": [
      {
        "action": "collected",
        "by": "Mike Ross",
        "at": "2026-02-15T09:35:00Z",
        "notes": "Extracted from endpoint WKSTN-1247"
      }
    ],
    "tags": ["malware", "script"],
    "status": "verified"
  }
]
```

### Add Alert Evidence

```
POST /api/alerts/{alert_id}/evidence
```

**Required Permission:** `add_evidence`

**Request Body:**
```json
{
  "type": "ip_address",
  "value": "192.168.1.100",
  "description": "Suspicious connection attempt",
  "tags": ["network", "suspicious"],
  "initial_notes": "Detected in firewall logs"
}
```

**Response:**
```json
{
  "id": 20,
  "alert_id": 1,
  "type": "ip_address",
  "value": "192.168.1.100",
  "description": "Suspicious connection attempt",
  "collected_by_id": 3,
  "collected_by_name": "Mike Ross",
  "collected_at": "2026-02-15T14:00:00Z",
  "chain_of_custody": [
    {
      "action": "collected",
      "by": "Mike Ross",
      "at": "2026-02-15T14:00:00Z",
      "notes": "Detected in firewall logs"
    }
  ],
  "tags": ["network", "suspicious"],
  "status": "collected"
}
```

### Get Incident Evidence

```
GET /api/incidents/{incident_id}/evidence
```

**Required Permission:** `view_alerts`

### Add Incident Evidence

```
POST /api/incidents/{incident_id}/evidence
```

**Required Permission:** `add_evidence`

### Update Chain of Custody

```
PUT /api/evidence/{evidence_id}/custody
```

**Required Permission:** `add_evidence`

**Request Body:**
```json
{
  "action": "analyzed",
  "notes": "Submitted to malware sandbox",
  "status": "analyzed"
}
```

---

## Analyst Assignment & SLA Endpoints

### Assign Alert

```
POST /api/alerts/{alert_id}/assign
```

**Required Permission:** `assign_analyst`

**Request Body:**
```json
{
  "analyst_id": 3
}
```

**Response:**
```json
{
  "alert_id": 1,
  "assigned_to": 3,
  "assigned_at": "2026-02-15T15:00:00Z"
}
```

### Get Alert SLA

```
GET /api/alerts/{alert_id}/sla
```

**Required Permission:** `view_alerts`

**Response:**
```json
{
  "alert_id": 1,
  "severity": "critical",
  "sla_minutes": 15,
  "elapsed_minutes": 10,
  "remaining_minutes": 5,
  "is_breached": false,
  "percentage": 66.67,
  "status": "warning"
}
```

**Status Values:**
- `normal` - Less than 75% of SLA time elapsed
- `warning` - 75-100% of SLA time elapsed
- `breached` - SLA time exceeded

---

## Audit Log Endpoints

### Get Audit Log

```
GET /api/audit-log?user_id=3&action=login&page=1&per_page=50
```

**Required Permission:** `view_audit_log` (admin or soc_manager only)

**Query Parameters:**
- `user_id` (optional): Filter by user ID
- `action` (optional): Filter by action type
- `resource_type` (optional): Filter by resource type
- `start_date` (optional): Filter by start date (ISO 8601)
- `end_date` (optional): Filter by end date (ISO 8601)
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Results per page (default: 50)

**Response:**
```json
{
  "entries": [
    {
      "id": 1,
      "timestamp": "2026-02-15T10:00:00Z",
      "user_id": 1,
      "username": "admin",
      "action": "login",
      "resource_type": "auth",
      "resource_id": null,
      "details": {},
      "ip_address": "192.168.1.100"
    }
  ],
  "total": 150,
  "page": 1,
  "per_page": 50,
  "total_pages": 3
}
```

**Action Types:**
- `login` - User logged in
- `logout` - User logged out
- `login_failed` - Failed login attempt
- `password_changed` - Password changed
- `alert_investigated` - Alert investigation triggered
- `alert_response_executed` - Response action executed
- `playbook_executed` - Playbook executed
- `note_added` - Case note added
- `note_updated` - Case note updated
- `note_deleted` - Case note deleted
- `evidence_added` - Evidence added
- `custody_updated` - Chain of custody updated
- `alert_assigned` - Alert assigned to analyst

---

## Rate Limiting

No rate limiting is currently implemented for this demo application. In production, implement rate limiting to prevent abuse.

---

## Permissions Reference

### Permission Matrix

| Permission | Admin | SOC Manager | T3 Analyst | T2 Analyst | T1 Analyst | Read Only |
|-----------|-------|-------------|------------|------------|------------|-----------|
| `view_alerts` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `investigate` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `execute_response` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `manage_playbooks` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| `manage_team` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `admin_settings` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `view_audit_log` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `add_notes` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| `add_evidence` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| `assign_analyst` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
