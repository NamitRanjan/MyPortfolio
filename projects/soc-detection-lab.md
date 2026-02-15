# Project: SOC Detection Lab (End-to-End Monitoring Pipeline)

## Objective
Build a practical SOC environment to simulate enterprise monitoring workflows: telemetry collection, detection engineering, triage, and incident documentation.

## Environment
- Windows endpoints instrumented with Sysmon.
- Network visibility through Zeek/Suricata.
- SIEM stack for centralized log ingestion and search.

## Implementation
1. Forwarded host and network logs into centralized SIEM.
2. Created ATT&CK-mapped detections for suspicious process behavior, PowerShell misuse, and lateral movement signals.
3. Established triage runbooks for severity classification, false-positive handling, and escalation.
4. Performed repeatable incident simulations to validate analyst procedures.

## Analyst Deliverables
- Detection rules and alert tuning notes.
- Incident tickets with timeline, affected assets, and containment decisions.
- Playbooks for common SOC alert categories.

## Security Outcomes
- Increased visibility across endpoint and network telemetry.
- Improved triage consistency through standardized procedures.
- Reduced alert noise by iteratively tuning detections.

## Skills Demonstrated
`SIEM Engineering` · `Log Analysis` · `Incident Response` · `MITRE ATT&CK Mapping`
