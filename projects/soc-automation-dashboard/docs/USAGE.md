# User Guide - SOC Automation Dashboard

## Getting Started

The SOC Automation Dashboard is your central hub for security operations, providing real-time visibility into threats, alerts, and incidents.

---

## Dashboard Overview

### Main Statistics
The dashboard displays four key metrics:

1. **Critical Alerts**: Number of active high-priority security alerts
2. **Active Threats**: Count of currently detected and blocked threats
3. **Automation Rate**: Percentage of alerts handled automatically
4. **MTTR**: Mean Time To Respond - average response time

### Security Events Timeline
Interactive chart showing:
- Alerts over time (yellow line)
- Threats blocked (green line)
- Incidents (red line)

### Alert Distribution
Pie chart breaking down alerts by severity:
- Critical (dark red)
- High (red)
- Medium (yellow)
- Low (blue)

### Real-Time Activity Feed
Live stream of security events including:
- Alert detection
- Threat blocking
- Incident creation
- Response execution

### Global Threat Map
Geographic distribution of threat origins with attack counts by country.

---

## Working with Alerts

### Viewing Alerts

1. Click **Alerts** in the top navigation
2. Browse the list of security alerts
3. Each alert shows:
   - Title and description
   - Severity badge (Critical/High/Medium/Low)
   - Status (Active/Investigating/Resolved)
   - Host and user information
   - Indicators and MITRE ATT&CK tactics
   - Risk score

### Filtering Alerts

Use the dropdown filters to:
- **Filter by Severity**: Show only Critical, High, Medium, or Low alerts
- **Filter by Status**: Show Active, Investigating, or Resolved alerts

### Investigating an Alert

1. Click on any alert to open the details modal
2. Review the alert information:
   - Full description
   - Affected systems
   - User account
   - MITRE ATT&CK tactics
   - Indicators of compromise
3. Click **Investigate** to trigger automated investigation
4. Review investigation findings:
   - IOC matches found
   - Calculated threat score
   - Recommended action
   - Confidence level

### Responding to Alerts

After investigation, execute automated response:

1. Click **Execute Response**
2. Choose action type:
   - **Isolate**: Disconnect host from network
   - **Block**: Block malicious IPs/domains
   - **Monitor**: Enable enhanced monitoring
3. Review automated actions taken
4. Actions are logged in the incident timeline

---

## Threat Intelligence

### Viewing Threats

The Threats page shows detected threats including:
- Threat name and type
- Severity level
- Action taken (Blocked/Investigating/Quarantined)
- Source and destination IPs
- Country of origin
- Number of indicators
- Confidence score

### Understanding Threat Types

- **Malware**: Malicious software detected
- **Ransomware**: Encryption-based attacks
- **APT**: Advanced Persistent Threats (nation-state actors)
- **Phishing**: Credential theft attempts
- **Botnet**: Compromised device networks
- **Exploit**: Vulnerability exploitation
- **Backdoor**: Unauthorized access tools
- **Cryptominer**: Cryptocurrency mining malware
- **Spyware**: Information stealing software
- **Web Attack**: Web application attacks

---

## Incident Management

### Viewing Incidents

The Incidents page displays:
- Incident title and description
- Severity and status
- Assigned analyst
- Creation and update timestamps
- Affected systems
- Impact assessment
- Response actions taken
- Incident timeline

### Incident Statuses

- **Investigating**: Initial investigation underway
- **Contained**: Threat contained, investigation continues
- **Mitigating**: Actively mitigating impact
- **Resolved**: Incident fully resolved

### Understanding Impact Levels

- **Critical**: Severe business impact, immediate action required
- **High**: Significant impact, urgent response needed
- **Medium**: Moderate impact, prioritized response
- **Low**: Minor impact, standard response timeline

---

## Automation Playbooks

### Viewing Playbooks

The Playbooks page shows automated response procedures:
- Playbook name and description
- Number of steps
- Average execution time
- Success rate
- Trigger conditions

### Available Playbooks

1. **Malware Detection Response**
   - Isolate infected host
   - Collect forensic artifacts
   - Block C2 communications
   - Scan related systems

2. **Phishing Email Investigation**
   - Quarantine emails
   - Block sender domains
   - Notify affected users
   - Update email filters

3. **Brute Force Attack Mitigation**
   - Block attacker IPs
   - Lock affected accounts
   - Enable MFA
   - Alert user

4. **Data Exfiltration Prevention**
   - Block outbound connections
   - Isolate source system
   - Preserve evidence
   - Notify data owner

5. **Insider Threat Investigation**
   - Enable enhanced logging
   - Review access history
   - Collect user activity
   - Engage HR/Legal

---

## Best Practices

### Alert Triage

1. **Prioritize by Severity**: Handle Critical and High alerts first
2. **Review Context**: Check user, host, and network context
3. **Correlate Events**: Look for related alerts
4. **Validate**: Confirm alert is not false positive
5. **Document**: Add notes to incident timeline

### Incident Response

1. **Contain**: Prevent further damage
2. **Investigate**: Determine root cause
3. **Remediate**: Remove threat and restore systems
4. **Document**: Record all actions
5. **Learn**: Update playbooks and procedures

### Security Monitoring

1. **Regular Review**: Check dashboard daily
2. **Trend Analysis**: Monitor patterns over time
3. **Fine-Tune**: Adjust alert thresholds
4. **Update IOCs**: Keep threat intelligence current
5. **Test Playbooks**: Regularly validate automation

---

## Keyboard Shortcuts

- `Ctrl/Cmd + D`: Dashboard
- `Ctrl/Cmd + A`: Alerts
- `Ctrl/Cmd + T`: Threats
- `Ctrl/Cmd + I`: Incidents
- `Ctrl/Cmd + P`: Playbooks
- `Esc`: Close modal

---

## Understanding Metrics

### Alert Processing Time
Time from alert generation to initial triage completion.

### Automation Rate
Percentage of alerts handled without manual intervention.

### Mean Time to Respond (MTTR)
Average time from alert detection to response action execution.

### True Positive Rate
Percentage of alerts that represent real security threats.

### False Positive Rate
Percentage of alerts that are not actual threats.

---

## Reporting

### Dashboard Export
- Screenshot dashboard for reports
- Export charts as PNG
- Copy metrics for documentation

### Incident Reports
Each incident includes:
- Executive summary
- Technical details
- Timeline of events
- Response actions
- Lessons learned

---

## Tips for New Users

1. **Start with Dashboard**: Get familiar with the overview
2. **Explore Alerts**: Click on different alerts to see details
3. **Try Investigation**: Use the automated investigation feature
4. **Review Playbooks**: Understand available automations
5. **Check Metrics**: Monitor your SOC's performance

---

## Common Workflows

### Daily SOC Operations
1. Check dashboard for new alerts
2. Review critical and high severity alerts
3. Investigate suspicious activity
4. Execute responses as needed
5. Update incident status
6. Review metrics and trends

### Alert Investigation
1. Open alert details
2. Review MITRE ATT&CK tactics
3. Check related IOCs
4. Run automated investigation
5. Execute appropriate response
6. Document findings

### Incident Handling
1. Receive alert or notification
2. Create incident ticket
3. Contain the threat
4. Collect evidence
5. Remediate affected systems
6. Document and close incident

---

## Troubleshooting

### Dashboard Not Loading
- Check network connection
- Verify backend is running
- Clear browser cache
- Check browser console for errors

### Alerts Not Updating
- Refresh the page
- Check API connectivity
- Verify data files are accessible

### Investigation Failed
- Check alert ID is valid
- Verify backend is responding
- Review server logs

---

## Support

For questions or issues:
- Email: namit.ranjan@example.com
- LinkedIn: [namit-ranjan-cybersecurity](https://linkedin.com/in/namit-ranjan-cybersecurity)
- GitHub: Open an issue

---

## Additional Resources

- [API Documentation](API.md)
- [Deployment Guide](DEPLOYMENT.md)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST CSF](https://www.nist.gov/cyberframework)
