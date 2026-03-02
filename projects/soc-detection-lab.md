# Project: SOC Detection Lab (Enterprise-Style Home Lab)

## Overview
This project documents my **SOC Detection Home Lab** built to simulate a real analyst workflow from data onboarding to incident closure. The design follows a practical homelab model: isolated virtual network, multi-source telemetry, SIEM correlation, ATT&CK-aligned detections, and repeatable triage playbooks.

The goal was to create a portfolio project that is not only technically strong, but also **reproducible and GitHub-ready**.

---

## 1) Lab Objectives
- Build an isolated blue-team lab that mirrors SOC operations.
- Collect endpoint + network telemetry in one analysis platform.
- Create and tune detections mapped to MITRE ATT&CK.
- Validate detections through controlled attack simulation.
- Produce analyst-ready documentation for triage and escalation.

---

## 2) Lab Topology

```text
Attacker VM (Kali)
        |
        |  (Internal vSwitch / Host-only Network)
        v
Victim Endpoint (Windows 10 + Sysmon)  --->  SIEM Stack (Wazuh/Elastic)
        |                                      |
        |                                      +--> Dashboards + Alerts + Rule Tuning
        |
        +-------------------------------------> Network Sensor (Suricata/Zeek)
```

### Core Components
| Layer | Tooling | Purpose |
|---|---|---|
| Virtualization | VirtualBox / VMware Workstation | Isolated SOC test environment |
| Endpoint Telemetry | Sysmon + Windows Event Logs | Process, command-line, and network activity visibility |
| Network Telemetry | Suricata / Zeek | IDS signals and protocol-level behavior |
| SIEM + Analytics | Wazuh + Elastic / Kibana | Centralized detection, search, alerting |
| Adversary Simulation | Kali Linux + Atomic/Manual commands | Controlled attack emulation |

---

## 3) Build Process

### Phase A — Environment Provisioning
1. Created separate VMs for attacker, victim endpoint, and monitoring stack.
2. Configured host-only/internal network for safe offensive simulation.
3. Hardened baseline images and snapshotted clean states for repeatability.

### Phase B — Telemetry Onboarding
1. Installed Sysmon on Windows endpoint using a tuned configuration.
2. Enabled forwarding of Sysmon and Security logs to SIEM collector.
3. Deployed Suricata/Zeek sensor and integrated alerts/events into SIEM.
4. Normalized fields to improve endpoint-network correlation during investigations.

### Phase C — Detection Engineering
Implemented ATT&CK-aligned detections for common SOC scenarios:
- **PowerShell abuse** (EncodedCommand, obfuscation patterns)
- **Suspicious process chains** (Office/Script host spawning admin tools)
- **Credential access signals** (dumping-tool patterns / anomalous auth activity)
- **Lateral movement indicators** (remote service / SMB / RDP anomalies)
- **Network IOC behavior** (known bad IP/domain matching and unusual egress)

### Phase D — Triage Workflow and Playbooks
- Built severity model: `Low / Medium / High / Critical`.
- Added triage checklist:
  - Confirm alert validity
  - Scope impacted host/user
  - Correlate endpoint + network timeline
  - Classify false positive vs malicious
  - Escalate and document containment actions
- Standardized case notes with timeline + evidence + analyst decision.

### Phase E — Validation & Tuning
- Ran controlled test activity to trigger each major detection category.
- Measured detection quality (signal-to-noise and triage time).
- Updated thresholds, exclusions, and enrichment notes after each simulation cycle.

---

## 4) ATT&CK Coverage Snapshot

| Detection Theme | ATT&CK Tactic | Technique (Example) | Telemetry Source |
|---|---|---|---|
| Encoded PowerShell execution | Execution | T1059.001 – PowerShell | Sysmon ProcessCreate + command-line |
| Script-host to admin-tool chain | Defense Evasion / Execution | T1218 – Signed Binary Proxy Execution (pattern-based) | Sysmon parent-child process lineage |
| Credential dump behavior | Credential Access | T1003 – OS Credential Dumping | Sysmon process + Security logs |
| Remote service / lateral movement | Lateral Movement | T1021 – Remote Services | Security logs + Suricata alerts |
| Suspicious outbound C2-like traffic | Command and Control | T1071 – Application Layer Protocol | Sysmon network events + Zeek/Suricata |

> Note: Technique IDs are mapped at detection-design level and validated in simulation rounds before being finalized in rule notes.

---

## 5) Example Detection Use Cases

| Use Case | Data Source | Expected Signal |
|---|---|---|
| Obfuscated PowerShell | Sysmon Event ID 1 | Encoded execution flag and suspicious command-line |
| Suspicious parent-child process | Sysmon ProcessCreate | Office/Script parent launching unusual child process |
| Brute-force attempts | Windows Security Logs + IDS | Repeated failures from single source with burst pattern |
| Unusual outbound behavior | Sysmon NetConn + Suricata | Non-browser process reaching external destination |

---

## 6) Sample Incident Timeline (Lab Simulation)

| Time (UTC) | Event | Analyst Action |
|---|---|---|
| 10:02 | Encoded PowerShell alert fired on endpoint | Opened case, validated source host and user context |
| 10:05 | Child process spawned from script host | Pulled process tree + command-line evidence |
| 10:08 | Same host made abnormal outbound connection | Correlated endpoint and network telemetry in SIEM |
| 10:12 | IOC check returned suspicious reputation | Elevated severity to High and initiated containment checklist |
| 10:18 | Host isolated in lab workflow | Documented actions, impact, and next investigation tasks |
| 10:30 | Case updated with final triage verdict | Logged tuning note to reduce future false positives |

---

## 7) Analyst Deliverables (GitHub-Ready Artifacts)
- SOC lab architecture and implementation notes.
- Detection catalog with ATT&CK mapping and tuning history.
- Triage SOP and incident case template.
- Sample incident reports with evidence timeline.
- Lessons learned and roadmap for next lab iteration.

---

## 8) Reproducibility Checklist
- [ ] Build isolated VM network (attacker, victim, SIEM, sensor).
- [ ] Install and tune Sysmon on Windows endpoint.
- [ ] Enable endpoint log forwarding to SIEM.
- [ ] Deploy Suricata/Zeek and confirm ingestion.
- [ ] Create ATT&CK-tagged detection rules.
- [ ] Configure severity model and triage SOP template.
- [ ] Run controlled simulations and capture evidence.
- [ ] Tune detections and record false-positive rationale.
- [ ] Publish dashboard snapshots + incident sample in repository docs.

---

## 9) Outcomes
- Improved practical understanding of full SOC lifecycle, not just alert writing.
- Increased consistency in triage through structured playbooks.
- Reduced noise through iterative tuning and source correlation.
- Built a reusable lab blueprint for future cloud/SOAR integrations.

---

## 10) Skills Demonstrated
`SOC Operations` · `Detection Engineering` · `SIEM Administration` · `Sysmon Telemetry Analysis` · `Network Threat Monitoring` · `MITRE ATT&CK Mapping` · `Incident Triage & Reporting`

---

## 11) Next Improvements
- Add Sigma-based rules and automated rule conversion pipeline.
- Integrate TheHive for case management + responder workflow.
- Add SOAR enrichment for IOC reputation and asset criticality scoring.
- Extend lab to cloud telemetry (Azure/M365 audit signals).

## Further Reading
- Medium blog: [Creating a SOC Analyst Home Lab](https://medium.com/@namit.ranjan/creating-a-soc-analyst-home-lab-c288bcf237f9)
