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
| `t2_analyst` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |

---

## Phase 3 Endpoints

### Compliance & Executive Reporting

#### Get Compliance Frameworks

```
GET /api/compliance/frameworks
```

**Required Permission:** `view_alerts`

**Response:**
```json
[
  {
    "id": "nist_csf",
    "name": "NIST Cybersecurity Framework",
    "version": "1.1",
    "description": "Framework for improving critical infrastructure cybersecurity",
    "categories": 5,
    "controls": 23,
    "coverage": 87.5,
    "status": "active",
    "last_assessed": "2026-02-15T10:00:00Z"
  },
  {
    "id": "iso_27001",
    "name": "ISO/IEC 27001",
    "version": "2022",
    "description": "Information security management systems",
    "categories": 14,
    "controls": 114,
    "coverage": 92.1,
    "status": "active",
    "last_assessed": "2026-02-14T08:30:00Z"
  },
  {
    "id": "cis_controls",
    "name": "CIS Controls",
    "version": "8.0",
    "description": "Critical Security Controls for Effective Cyber Defense",
    "categories": 18,
    "controls": 153,
    "coverage": 78.4,
    "status": "active",
    "last_assessed": "2026-02-13T14:15:00Z"
  }
]
```

**Error Responses:**
- `401` - Unauthorized (invalid or missing token)
- `403` - Forbidden (insufficient permissions)

#### Get Compliance Posture

```
GET /api/compliance/posture
```

**Required Permission:** `view_alerts`

**Response:**
```json
{
  "overall_score": 84.6,
  "status": "compliant",
  "last_updated": "2026-02-15T10:00:00Z",
  "frameworks": [
    {
      "id": "nist_csf",
      "name": "NIST CSF",
      "score": 87.5,
      "status": "compliant",
      "controls_met": 20,
      "controls_total": 23,
      "gaps": 3
    },
    {
      "id": "iso_27001",
      "name": "ISO 27001",
      "score": 92.1,
      "status": "compliant",
      "controls_met": 105,
      "controls_total": 114,
      "gaps": 9
    },
    {
      "id": "cis_controls",
      "name": "CIS Controls",
      "score": 78.4,
      "status": "partial",
      "controls_met": 120,
      "controls_total": 153,
      "gaps": 33
    }
  ],
  "trend": {
    "direction": "up",
    "change": 2.3
  },
  "risk_summary": {
    "high_risk_gaps": 4,
    "medium_risk_gaps": 18,
    "low_risk_gaps": 23
  }
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `500` - Internal server error

#### Get Framework Coverage

```
GET /api/compliance/coverage/{framework_id}
```

**Required Permission:** `view_alerts`

**URL Parameters:**
- `framework_id`: Framework identifier (e.g., `nist_csf`, `iso_27001`, `cis_controls`)

**Response:**
```json
{
  "framework_id": "nist_csf",
  "framework_name": "NIST Cybersecurity Framework",
  "overall_coverage": 87.5,
  "categories": [
    {
      "id": "identify",
      "name": "Identify",
      "coverage": 90.0,
      "controls_met": 9,
      "controls_total": 10,
      "controls": [
        {
          "id": "ID.AM",
          "name": "Asset Management",
          "description": "Inventory and manage hardware and software assets",
          "status": "met",
          "evidence_count": 5,
          "last_verified": "2026-02-15T09:00:00Z"
        },
        {
          "id": "ID.RA",
          "name": "Risk Assessment",
          "description": "Identify and prioritize cybersecurity risks",
          "status": "partial",
          "evidence_count": 2,
          "last_verified": "2026-02-14T15:30:00Z",
          "gap_notes": "Formal risk assessment process needs documentation"
        }
      ]
    },
    {
      "id": "protect",
      "name": "Protect",
      "coverage": 85.0,
      "controls_met": 4,
      "controls_total": 5,
      "controls": []
    }
  ]
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Framework not found

#### Get Compliance Gaps

```
GET /api/compliance/gaps
```

**Required Permission:** `view_alerts`

**Query Parameters:**
- `framework_id` (optional): Filter by specific framework
- `severity` (optional): Filter by severity (high, medium, low)

**Response:**
```json
[
  {
    "id": 1,
    "framework_id": "nist_csf",
    "framework_name": "NIST CSF",
    "control_id": "ID.RA",
    "control_name": "Risk Assessment",
    "category": "Identify",
    "severity": "high",
    "description": "Formal risk assessment process needs documentation",
    "impact": "Unable to demonstrate systematic risk management",
    "remediation": "Document and implement formal risk assessment procedures",
    "assigned_to": "SOC Manager",
    "target_date": "2026-03-15T00:00:00Z",
    "status": "open",
    "created_at": "2026-02-10T10:00:00Z"
  },
  {
    "id": 2,
    "framework_id": "cis_controls",
    "framework_name": "CIS Controls",
    "control_id": "4.1",
    "control_name": "Establish and Maintain Secure Configuration Process",
    "category": "Protect",
    "severity": "medium",
    "description": "Configuration management baseline incomplete for cloud assets",
    "impact": "Inconsistent security configurations across cloud infrastructure",
    "remediation": "Extend configuration management to include all cloud resources",
    "assigned_to": "Cloud Security Team",
    "target_date": "2026-03-01T00:00:00Z",
    "status": "in_progress",
    "created_at": "2026-02-08T14:20:00Z"
  }
]
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `400` - Invalid query parameters

#### Get MITRE ATT&CK Heatmap

```
GET /api/mitre/heatmap
```

**Required Permission:** `view_alerts`

**Query Parameters:**
- `days` (optional): Number of days to analyze (default: 30)

**Response:**
```json
{
  "period_days": 30,
  "generated_at": "2026-02-15T12:00:00Z",
  "total_techniques": 82,
  "techniques_detected": 18,
  "coverage": 21.95,
  "tactics": [
    {
      "id": "TA0001",
      "name": "Initial Access",
      "techniques": [
        {
          "id": "T1566",
          "name": "Phishing",
          "detections": 23,
          "severity": "high",
          "last_seen": "2026-02-15T10:30:00Z",
          "alerts": [1, 5, 12, 18]
        },
        {
          "id": "T1078",
          "name": "Valid Accounts",
          "detections": 8,
          "severity": "medium",
          "last_seen": "2026-02-14T16:45:00Z",
          "alerts": [3, 9]
        }
      ]
    },
    {
      "id": "TA0002",
      "name": "Execution",
      "techniques": [
        {
          "id": "T1059.001",
          "name": "PowerShell",
          "detections": 45,
          "severity": "critical",
          "last_seen": "2026-02-15T11:20:00Z",
          "alerts": [1, 4, 7, 11, 15]
        }
      ]
    }
  ],
  "top_techniques": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "count": 45
    },
    {
      "id": "T1566",
      "name": "Phishing",
      "tactic": "Initial Access",
      "count": 23
    }
  ]
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `400` - Invalid days parameter

#### Get Reports

```
GET /api/reports
```

**Required Permission:** `view_alerts`

**Query Parameters:**
- `type` (optional): Filter by report type (executive, compliance, incident, threat_intelligence)
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Results per page (default: 20)

**Response:**
```json
{
  "reports": [
    {
      "id": 1,
      "title": "Weekly SOC Operations Summary",
      "type": "executive",
      "description": "Executive summary of SOC activities for week of Feb 8-14, 2026",
      "generated_at": "2026-02-15T08:00:00Z",
      "generated_by": "admin",
      "period_start": "2026-02-08T00:00:00Z",
      "period_end": "2026-02-14T23:59:59Z",
      "format": "pdf",
      "size_bytes": 245678,
      "status": "ready",
      "download_url": "/api/reports/1/download"
    },
    {
      "id": 2,
      "title": "NIST CSF Compliance Report Q1 2026",
      "type": "compliance",
      "description": "Quarterly compliance assessment against NIST Cybersecurity Framework",
      "generated_at": "2026-02-14T16:30:00Z",
      "generated_by": "soc_manager",
      "period_start": "2026-01-01T00:00:00Z",
      "period_end": "2026-02-14T23:59:59Z",
      "format": "pdf",
      "size_bytes": 512340,
      "status": "ready",
      "download_url": "/api/reports/2/download",
      "metadata": {
        "framework": "nist_csf",
        "overall_score": 87.5
      }
    }
  ],
  "total": 15,
  "page": 1,
  "per_page": 20,
  "total_pages": 1
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden

#### Generate Report

```
POST /api/reports/generate
```

**Required Permission:** `view_alerts`

**Request Body:**
```json
{
  "type": "executive",
  "title": "Monthly Executive Summary - February 2026",
  "description": "Comprehensive monthly summary of SOC operations",
  "period_start": "2026-02-01T00:00:00Z",
  "period_end": "2026-02-28T23:59:59Z",
  "format": "pdf",
  "options": {
    "include_metrics": true,
    "include_incidents": true,
    "include_compliance": true,
    "include_mitre": false
  }
}
```

**Valid Report Types:**
- `executive` - Executive summary with key metrics and trends
- `compliance` - Compliance posture and framework assessments
- `incident` - Detailed incident analysis and response
- `threat_intelligence` - Threat landscape and IOC analysis

**Valid Formats:**
- `pdf`
- `html`
- `json`

**Response:**
```json
{
  "id": 3,
  "title": "Monthly Executive Summary - February 2026",
  "type": "executive",
  "status": "generating",
  "progress": 0,
  "generated_at": "2026-02-15T12:30:00Z",
  "generated_by": "admin",
  "estimated_completion": "2026-02-15T12:35:00Z"
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `400` - Invalid request body or date range

---

### Threat Hunting

#### List Hunts

```
GET /api/hunts
```

**Required Permission:** `t2_analyst`

**Query Parameters:**
- `status` (optional): Filter by status (planning, active, completed, archived)
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Results per page (default: 20)

**Response:**
```json
{
  "hunts": [
    {
      "id": 1,
      "name": "Suspicious PowerShell Activity",
      "description": "Hunt for obfuscated PowerShell commands and download cradles",
      "status": "active",
      "priority": "high",
      "created_at": "2026-02-15T09:00:00Z",
      "created_by": "Mike Ross",
      "started_at": "2026-02-15T09:30:00Z",
      "completed_at": null,
      "hypothesis": "Adversaries using PowerShell for initial access and C2 communication",
      "hunt_package_id": "hp_001",
      "findings_count": 3,
      "total_queries": 5,
      "queries_executed": 3,
      "tags": ["powershell", "malware", "initial_access"]
    },
    {
      "id": 2,
      "name": "Lateral Movement Detection",
      "description": "Identify potential lateral movement using WMI and PsExec",
      "status": "completed",
      "priority": "medium",
      "created_at": "2026-02-10T14:00:00Z",
      "created_by": "Sarah Chen",
      "started_at": "2026-02-10T14:30:00Z",
      "completed_at": "2026-02-12T16:45:00Z",
      "hypothesis": "Threat actors using built-in Windows tools for lateral movement",
      "hunt_package_id": "hp_003",
      "findings_count": 2,
      "total_queries": 8,
      "queries_executed": 8,
      "tags": ["lateral_movement", "wmi", "psexec"],
      "summary": "Identified 2 instances of suspicious WMI activity. Created 2 incidents for further investigation."
    }
  ],
  "total": 12,
  "page": 1,
  "per_page": 20,
  "total_pages": 1
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden (insufficient permissions)

#### Create Hunt

```
POST /api/hunts
```

**Required Permission:** `t2_analyst`

**Request Body:**
```json
{
  "hunt_package_id": "hp_002"
}
```

**Response:**
```json
{
  "id": 3,
  "name": "DNS Tunneling Detection",
  "description": "Hunt for DNS queries indicating data exfiltration",
  "status": "planning",
  "priority": "high",
  "created_at": "2026-02-15T13:00:00Z",
  "created_by": "Mike Ross",
  "started_at": null,
  "completed_at": null,
  "hypothesis": "Adversaries may use DNS tunneling for C2 and data exfiltration",
  "hunt_package_id": "hp_002",
  "findings_count": 0,
  "total_queries": 6,
  "queries_executed": 0,
  "tags": ["dns", "exfiltration", "c2"],
  "queries": [
    {
      "id": 1,
      "title": "Detect Excessive DNS Query Volume",
      "query": "SELECT src_ip, COUNT(*) as query_count FROM dns_logs WHERE timestamp > now() - INTERVAL 1 HOUR GROUP BY src_ip HAVING query_count > 100",
      "status": "pending"
    }
  ]
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `400` - Missing hunt_package_id
- `404` - Hunt package not found

#### Get Hunt Details

```
GET /api/hunts/{id}
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Response:**
```json
{
  "id": 1,
  "name": "Suspicious PowerShell Activity",
  "description": "Hunt for obfuscated PowerShell commands and download cradles",
  "status": "active",
  "priority": "high",
  "created_at": "2026-02-15T09:00:00Z",
  "created_by": "Mike Ross",
  "started_at": "2026-02-15T09:30:00Z",
  "completed_at": null,
  "hypothesis": "Adversaries using PowerShell for initial access and C2 communication",
  "hunt_package_id": "hp_001",
  "findings_count": 3,
  "total_queries": 5,
  "queries_executed": 3,
  "tags": ["powershell", "malware", "initial_access"],
  "queries": [
    {
      "id": 1,
      "title": "Base64 Encoded PowerShell",
      "query": "SELECT * FROM process_logs WHERE command_line LIKE '%powershell%' AND command_line LIKE '%-enc%'",
      "status": "completed",
      "executed_at": "2026-02-15T09:35:00Z",
      "results_count": 12
    },
    {
      "id": 2,
      "title": "PowerShell Download Cradles",
      "query": "SELECT * FROM process_logs WHERE command_line LIKE '%Invoke-WebRequest%' OR command_line LIKE '%DownloadString%'",
      "status": "completed",
      "executed_at": "2026-02-15T09:42:00Z",
      "results_count": 5
    },
    {
      "id": 3,
      "title": "Suspicious Execution Policy Changes",
      "query": "SELECT * FROM process_logs WHERE command_line LIKE '%Set-ExecutionPolicy%Bypass%'",
      "status": "active",
      "executed_at": "2026-02-15T10:15:00Z",
      "results_count": 3
    }
  ],
  "mitre_techniques": ["T1059.001", "T1027", "T1140"]
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found

#### Update Hunt Query

```
PUT /api/hunts/{id}/query
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Request Body:**
```json
{
  "query": "SELECT * FROM process_logs WHERE command_line LIKE '%powershell%' AND command_line LIKE '%-w hidden%' AND timestamp > '2026-02-15T00:00:00Z'"
}
```

**Response:**
```json
{
  "hunt_id": 1,
  "query_updated": true,
  "executed_at": "2026-02-15T13:30:00Z",
  "results_count": 7,
  "status": "completed"
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found
- `400` - Invalid or empty query

#### Get Hunt Findings

```
GET /api/hunts/{id}/findings
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Response:**
```json
[
  {
    "id": 1,
    "hunt_id": 1,
    "title": "Base64 Encoded Malicious Script",
    "description": "Detected PowerShell execution with base64 encoded payload attempting to download additional malware",
    "severity": "high",
    "created_at": "2026-02-15T10:00:00Z",
    "created_by": "Mike Ross",
    "status": "validated",
    "affected_hosts": ["WKSTN-1247", "WKSTN-1502"],
    "indicators": [
      "powershell.exe -enc aQBlAHgAIAAoAG4AZQB3AC...",
      "185.220.101.45"
    ],
    "mitre_techniques": ["T1059.001", "T1027"],
    "recommended_action": "Isolate affected hosts and conduct forensic analysis",
    "evidence": [
      {
        "type": "process_log",
        "value": "Full command line captured",
        "timestamp": "2026-02-15T09:35:22Z"
      }
    ]
  },
  {
    "id": 2,
    "hunt_id": 1,
    "title": "Invoke-Expression with Obfuscation",
    "description": "Multiple instances of IEX being used with character substitution obfuscation",
    "severity": "medium",
    "created_at": "2026-02-15T10:30:00Z",
    "created_by": "Mike Ross",
    "status": "investigating",
    "affected_hosts": ["WKSTN-0892"],
    "indicators": [
      "IEX (New-Object Net.WebClient).DownloadString"
    ],
    "mitre_techniques": ["T1059.001", "T1140"],
    "recommended_action": "Monitor for additional suspicious activity",
    "evidence": []
  }
]
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found

#### Add Hunt Finding

```
POST /api/hunts/{id}/findings
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Request Body:**
```json
{
  "title": "Suspicious Registry Modification",
  "description": "PowerShell script modified Run key for persistence",
  "severity": "high",
  "affected_hosts": ["WKSTN-3341"],
  "indicators": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
  "mitre_techniques": ["T1547.001"],
  "recommended_action": "Remove malicious registry entry and investigate source",
  "evidence": [
    {
      "type": "registry_log",
      "value": "Registry modification logged in Sysmon Event ID 13",
      "timestamp": "2026-02-15T11:22:00Z"
    }
  ]
}
```

**Response:**
```json
{
  "id": 3,
  "hunt_id": 1,
  "title": "Suspicious Registry Modification",
  "description": "PowerShell script modified Run key for persistence",
  "severity": "high",
  "created_at": "2026-02-15T14:00:00Z",
  "created_by": "Mike Ross",
  "status": "new",
  "affected_hosts": ["WKSTN-3341"],
  "indicators": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
  "mitre_techniques": ["T1547.001"],
  "recommended_action": "Remove malicious registry entry and investigate source",
  "evidence": [
    {
      "type": "registry_log",
      "value": "Registry modification logged in Sysmon Event ID 13",
      "timestamp": "2026-02-15T11:22:00Z"
    }
  ]
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found
- `400` - Missing required fields (title, description, severity)

#### Get Hunt Journal

```
GET /api/hunts/{id}/journal
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Response:**
```json
[
  {
    "id": 1,
    "hunt_id": 1,
    "entry_type": "note",
    "content": "Initiated hunt based on increased PowerShell alerts in past 48 hours",
    "created_at": "2026-02-15T09:00:00Z",
    "created_by": "Mike Ross",
    "created_by_id": 3
  },
  {
    "id": 2,
    "hunt_id": 1,
    "entry_type": "query_executed",
    "content": "Executed query: Base64 Encoded PowerShell - Found 12 results",
    "created_at": "2026-02-15T09:35:00Z",
    "created_by": "System",
    "created_by_id": null
  },
  {
    "id": 3,
    "hunt_id": 1,
    "entry_type": "finding",
    "content": "Added finding: Base64 Encoded Malicious Script (HIGH severity)",
    "created_at": "2026-02-15T10:00:00Z",
    "created_by": "Mike Ross",
    "created_by_id": 3
  },
  {
    "id": 4,
    "hunt_id": 1,
    "entry_type": "note",
    "content": "Coordinating with IR team on affected hosts WKSTN-1247 and WKSTN-1502",
    "created_at": "2026-02-15T10:45:00Z",
    "created_by": "Mike Ross",
    "created_by_id": 3
  }
]
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found

#### Add Journal Entry

```
POST /api/hunts/{id}/journal
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Request Body:**
```json
{
  "entry_type": "note",
  "content": "Expanded search scope to include last 7 days based on initial findings"
}
```

**Valid Entry Types:**
- `note` - General hunt note
- `observation` - Observation during hunt
- `query_executed` - Query execution (auto-generated)
- `finding` - Finding added (auto-generated)
- `pivot` - Hunt pivot or direction change

**Response:**
```json
{
  "id": 5,
  "hunt_id": 1,
  "entry_type": "note",
  "content": "Expanded search scope to include last 7 days based on initial findings",
  "created_at": "2026-02-15T14:30:00Z",
  "created_by": "Mike Ross",
  "created_by_id": 3
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found
- `400` - Missing or invalid entry_type or content

#### Get Hunt Library

```
GET /api/hunt-library
```

**Required Permission:** `t2_analyst`

**Query Parameters:**
- `category` (optional): Filter by category
- `search` (optional): Search in name and description

**Response:**
```json
[
  {
    "id": "hp_001",
    "name": "PowerShell Abuse Detection",
    "description": "Comprehensive hunt package for detecting PowerShell-based attacks",
    "category": "Execution",
    "difficulty": "intermediate",
    "estimated_time": "2-4 hours",
    "mitre_tactics": ["Execution", "Defense Evasion"],
    "mitre_techniques": ["T1059.001", "T1027", "T1140"],
    "queries_count": 5,
    "tags": ["powershell", "malware", "obfuscation"],
    "created_at": "2026-01-15T10:00:00Z",
    "author": "SOC Team",
    "times_used": 12,
    "avg_findings": 2.4
  },
  {
    "id": "hp_002",
    "name": "DNS Tunneling Detection",
    "description": "Identify DNS queries indicating data exfiltration or C2 communication",
    "category": "Exfiltration",
    "difficulty": "advanced",
    "estimated_time": "4-6 hours",
    "mitre_tactics": ["Command and Control", "Exfiltration"],
    "mitre_techniques": ["T1071.004", "T1048.003"],
    "queries_count": 6,
    "tags": ["dns", "exfiltration", "c2"],
    "created_at": "2026-01-20T14:30:00Z",
    "author": "Threat Intel Team",
    "times_used": 8,
    "avg_findings": 1.2
  },
  {
    "id": "hp_003",
    "name": "Lateral Movement via WMI",
    "description": "Hunt for lateral movement using Windows Management Instrumentation",
    "category": "Lateral Movement",
    "difficulty": "intermediate",
    "estimated_time": "3-5 hours",
    "mitre_tactics": ["Lateral Movement", "Execution"],
    "mitre_techniques": ["T1021.006", "T1047"],
    "queries_count": 8,
    "tags": ["lateral_movement", "wmi", "windows"],
    "created_at": "2026-01-25T09:00:00Z",
    "author": "SOC Team",
    "times_used": 15,
    "avg_findings": 1.8
  }
]
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden

#### Get Hunt Metrics

```
GET /api/hunt-metrics
```

**Required Permission:** `t2_analyst`

**Query Parameters:**
- `days` (optional): Number of days to analyze (default: 30)

**Response:**
```json
{
  "period_days": 30,
  "total_hunts": 12,
  "active_hunts": 3,
  "completed_hunts": 8,
  "archived_hunts": 1,
  "total_findings": 28,
  "high_severity_findings": 9,
  "medium_severity_findings": 12,
  "low_severity_findings": 7,
  "avg_hunt_duration_hours": 18.5,
  "hunts_by_status": {
    "planning": 1,
    "active": 3,
    "completed": 8,
    "archived": 1
  },
  "hunts_by_priority": {
    "critical": 2,
    "high": 5,
    "medium": 4,
    "low": 1
  },
  "top_hunters": [
    {
      "name": "Mike Ross",
      "hunts": 5,
      "findings": 12
    },
    {
      "name": "Sarah Chen",
      "hunts": 4,
      "findings": 10
    }
  ],
  "most_used_packages": [
    {
      "id": "hp_003",
      "name": "Lateral Movement via WMI",
      "times_used": 4
    },
    {
      "id": "hp_001",
      "name": "PowerShell Abuse Detection",
      "times_used": 3
    }
  ],
  "findings_trend": [
    {
      "date": "2026-02-08",
      "count": 2
    },
    {
      "date": "2026-02-15",
      "count": 5
    }
  ]
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `400` - Invalid days parameter

#### Complete Hunt

```
PUT /api/hunts/{id}/complete
```

**Required Permission:** `t2_analyst`

**URL Parameters:**
- `id`: Hunt ID

**Request Body:**
```json
{
  "summary": "Hunt successfully identified 3 instances of malicious PowerShell activity. All affected hosts have been isolated and incidents created for remediation. Recommended updating detection rules to catch similar patterns proactively."
}
```

**Response:**
```json
{
  "id": 1,
  "name": "Suspicious PowerShell Activity",
  "status": "completed",
  "completed_at": "2026-02-15T15:00:00Z",
  "summary": "Hunt successfully identified 3 instances of malicious PowerShell activity. All affected hosts have been isolated and incidents created for remediation. Recommended updating detection rules to catch similar patterns proactively.",
  "findings_count": 3,
  "duration_hours": 5.5,
  "queries_executed": 5,
  "affected_hosts_count": 3
}
```

**Error Responses:**
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Hunt not found
- `400` - Missing summary or hunt not in active status
