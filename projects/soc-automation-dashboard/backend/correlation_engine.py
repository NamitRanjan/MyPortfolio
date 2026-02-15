"""
SOC Automation Dashboard - AI-Powered Alert Correlation Engine
Automatically groups related alerts, reconstructs kill chains, and eliminates alert fatigue
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple
from collections import defaultdict
import os

# MITRE ATT&CK Kill Chain Stages (in order)
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

# Mapping of MITRE Techniques to Kill Chain Stages
TECHNIQUE_TO_STAGE = {
    "T1595": "Reconnaissance",
    "T1592": "Reconnaissance",
    "T1589": "Reconnaissance",
    "T1590": "Reconnaissance",
    "T1591": "Reconnaissance",
    "T1598": "Reconnaissance",
    "T1597": "Reconnaissance",
    "T1596": "Reconnaissance",
    "T1593": "Reconnaissance",
    "T1594": "Reconnaissance",
    
    "T1583": "Resource Development",
    "T1586": "Resource Development",
    "T1584": "Resource Development",
    "T1587": "Resource Development",
    "T1588": "Resource Development",
    "T1608": "Resource Development",
    
    "T1189": "Initial Access",
    "T1190": "Initial Access",
    "T1133": "Initial Access",
    "T1200": "Initial Access",
    "T1566": "Initial Access",
    "T1091": "Initial Access",
    "T1195": "Initial Access",
    "T1199": "Initial Access",
    
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1204": "Execution",
    "T1204.002": "Execution",
    "T1106": "Execution",
    
    "T1547": "Persistence",
    "T1547.001": "Persistence",
    "T1053": "Persistence",
    "T1136": "Persistence",
    "T1078": "Persistence",
    
    "T1068": "Privilege Escalation",
    "T1134": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    
    "T1027": "Defense Evasion",
    "T1055": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1112": "Defense Evasion",
    "T1222": "Defense Evasion",
    
    "T1003": "Credential Access",
    "T1003.001": "Credential Access",
    "T1110": "Credential Access",
    "T1555": "Credential Access",
    "T1552": "Credential Access",
    
    "T1087": "Discovery",
    "T1083": "Discovery",
    "T1046": "Discovery",
    "T1135": "Discovery",
    "T1018": "Discovery",
    
    "T1021": "Lateral Movement",
    "T1021.002": "Lateral Movement",
    "T1080": "Lateral Movement",
    "T1550": "Lateral Movement",
    
    "T1005": "Collection",
    "T1039": "Collection",
    "T1074": "Collection",
    "T1114": "Collection",
    
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1095": "Command and Control",
    "T1572": "Command and Control",
    
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1567": "Exfiltration",
    
    "T1485": "Impact",
    "T1486": "Impact",
    "T1490": "Impact",
    "T1491": "Impact",
    "T1561": "Impact"
}


class CorrelationEngine:
    """AI-Powered Alert Correlation Engine"""
    
    def __init__(self, time_window_hours=4):
        """
        Initialize the correlation engine
        
        Args:
            time_window_hours: Time window for alert grouping (default: 4 hours)
        """
        self.time_window = timedelta(hours=time_window_hours)
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse ISO 8601 timestamp string"""
        # Handle both with and without microseconds
        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ']:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        return datetime.now()
    
    def calculate_time_proximity_score(self, alert1: Dict, alert2: Dict) -> float:
        """Calculate similarity score based on time proximity (0-1)"""
        try:
            time1 = self.parse_timestamp(alert1['timestamp'])
            time2 = self.parse_timestamp(alert2['timestamp'])
            time_diff = abs((time1 - time2).total_seconds() / 3600)  # hours
            
            # Within time window: score decreases linearly with time
            if time_diff <= self.time_window.total_seconds() / 3600:
                return 1.0 - (time_diff / (self.time_window.total_seconds() / 3600))
            return 0.0
        except:
            return 0.0
    
    def calculate_entity_similarity(self, alert1: Dict, alert2: Dict) -> Tuple[float, Dict]:
        """Calculate similarity based on shared entities"""
        shared_entities = {
            'hosts': [],
            'users': [],
            'ips': [],
            'mitre_tactics': [],
            'indicators': []
        }
        
        score = 0.0
        max_score = 5.0  # Total possible points
        
        # Host match (weight: 1.5)
        if alert1.get('host') == alert2.get('host') and alert1.get('host'):
            score += 1.5
            shared_entities['hosts'].append(alert1['host'])
        
        # User match (weight: 1.2)
        if alert1.get('user') == alert2.get('user') and alert1.get('user'):
            score += 1.2
            shared_entities['users'].append(alert1['user'])
        
        # Source IP match (if available, weight: 1.0)
        alert1_ip = alert1.get('source_ip') or alert1.get('ip')
        alert2_ip = alert2.get('source_ip') or alert2.get('ip')
        if alert1_ip and alert2_ip and alert1_ip == alert2_ip:
            score += 1.0
            shared_entities['ips'].append(alert1_ip)
        
        # MITRE tactics overlap (weight: 0.8)
        tactics1 = set(alert1.get('mitre_tactics', []))
        tactics2 = set(alert2.get('mitre_tactics', []))
        if tactics1 and tactics2:
            overlap = tactics1.intersection(tactics2)
            if overlap:
                score += 0.8
                shared_entities['mitre_tactics'].extend(list(overlap))
        
        # Indicators overlap (weight: 0.5)
        indicators1 = set(alert1.get('indicators', []))
        indicators2 = set(alert2.get('indicators', []))
        if indicators1 and indicators2:
            overlap = indicators1.intersection(indicators2)
            if overlap:
                score += 0.5
                shared_entities['indicators'].extend(list(overlap))
        
        return score / max_score, shared_entities
    
    def calculate_severity_escalation_score(self, alerts: List[Dict]) -> float:
        """Calculate score based on severity escalation pattern"""
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        severities = [severity_order.get(a.get('severity', 'low'), 1) for a in alerts]
        
        # Check if there's an escalation pattern
        is_escalating = all(severities[i] <= severities[i+1] for i in range(len(severities)-1))
        if is_escalating and len(set(severities)) > 1:
            return 0.3  # Bonus for escalation
        return 0.0
    
    def get_kill_chain_stage(self, mitre_technique: str) -> str:
        """Map MITRE technique to kill chain stage"""
        # Try exact match first
        if mitre_technique in TECHNIQUE_TO_STAGE:
            return TECHNIQUE_TO_STAGE[mitre_technique]
        
        # Try base technique (remove sub-technique)
        base_technique = mitre_technique.split('.')[0]
        if base_technique in TECHNIQUE_TO_STAGE:
            return TECHNIQUE_TO_STAGE[base_technique]
        
        return None
    
    def calculate_kill_chain_progression_score(self, alerts: List[Dict]) -> float:
        """Calculate score based on kill chain progression"""
        stages = set()
        for alert in alerts:
            for technique in alert.get('mitre_tactics', []):
                stage = self.get_kill_chain_stage(technique)
                if stage:
                    stages.add(stage)
        
        if len(stages) > 1:
            # Check if stages follow kill chain order
            stage_indices = sorted([KILL_CHAIN_STAGES.index(s) for s in stages if s in KILL_CHAIN_STAGES])
            if len(stage_indices) > 1:
                # Bonus for sequential progression
                is_sequential = all(stage_indices[i] < stage_indices[i+1] for i in range(len(stage_indices)-1))
                if is_sequential:
                    return 0.4  # Strong bonus for proper kill chain progression
                return 0.2  # Partial bonus for multiple stages
        return 0.0
    
    def calculate_correlation_score(self, alerts: List[Dict]) -> int:
        """Calculate overall correlation score (0-100)"""
        if len(alerts) < 2:
            return 0
        
        # Base score from number of alerts
        base_score = min(20, len(alerts) * 4)
        
        # Calculate pairwise entity similarity (average)
        entity_scores = []
        for i in range(len(alerts)):
            for j in range(i+1, len(alerts)):
                entity_score, _ = self.calculate_entity_similarity(alerts[i], alerts[j])
                entity_scores.append(entity_score)
        avg_entity_score = sum(entity_scores) / len(entity_scores) if entity_scores else 0
        entity_points = avg_entity_score * 30
        
        # Time proximity (average)
        time_scores = []
        for i in range(len(alerts)):
            for j in range(i+1, len(alerts)):
                time_scores.append(self.calculate_time_proximity_score(alerts[i], alerts[j]))
        avg_time_score = sum(time_scores) / len(time_scores) if time_scores else 0
        time_points = avg_time_score * 20
        
        # Severity escalation
        escalation_points = self.calculate_severity_escalation_score(alerts) * 15
        
        # Kill chain progression
        kill_chain_points = self.calculate_kill_chain_progression_score(alerts) * 15
        
        total_score = base_score + entity_points + time_points + escalation_points + kill_chain_points
        return min(100, int(total_score))
    
    def group_alerts(self, alerts: List[Dict]) -> List[List[Dict]]:
        """Group alerts into correlation clusters"""
        groups = []
        ungrouped = alerts.copy()
        
        while ungrouped:
            # Start a new group with the first ungrouped alert
            current_group = [ungrouped.pop(0)]
            
            # Try to add related alerts to this group
            changed = True
            while changed:
                changed = False
                remaining = []
                
                for alert in ungrouped:
                    # Check if alert should be in current group
                    should_add = False
                    for group_alert in current_group:
                        # Calculate similarity
                        entity_score, _ = self.calculate_entity_similarity(alert, group_alert)
                        time_score = self.calculate_time_proximity_score(alert, group_alert)
                        
                        # Add if sufficiently similar
                        if entity_score >= 0.3 or time_score >= 0.5:
                            should_add = True
                            break
                    
                    if should_add:
                        current_group.append(alert)
                        changed = True
                    else:
                        remaining.append(alert)
                
                ungrouped = remaining
            
            # Only keep groups with 2+ alerts
            if len(current_group) >= 2:
                groups.append(current_group)
        
        return groups
    
    def build_kill_chain_timeline(self, alerts: List[Dict]) -> List[Dict]:
        """Build kill chain timeline from correlated alerts"""
        timeline = []
        
        for alert in alerts:
            for technique in alert.get('mitre_tactics', []):
                stage = self.get_kill_chain_stage(technique)
                if stage:
                    timeline.append({
                        'stage': stage,
                        'alert_id': alert['id'],
                        'technique': technique,
                        'timestamp': alert['timestamp']
                    })
        
        # Sort by kill chain order, then by timestamp
        timeline.sort(key=lambda x: (
            KILL_CHAIN_STAGES.index(x['stage']) if x['stage'] in KILL_CHAIN_STAGES else 999,
            x['timestamp']
        ))
        
        return timeline
    
    def get_shared_entities(self, alerts: List[Dict]) -> Dict:
        """Extract all shared entities from alert group"""
        shared = {
            'hosts': set(),
            'users': set(),
            'ips': set(),
            'mitre_tactics': set(),
            'indicators': set()
        }
        
        for alert in alerts:
            if alert.get('host'):
                shared['hosts'].add(alert['host'])
            if alert.get('user'):
                shared['users'].add(alert['user'])
            if alert.get('source_ip'):
                shared['ips'].add(alert['source_ip'])
            if alert.get('ip'):
                shared['ips'].add(alert['ip'])
            shared['mitre_tactics'].update(alert.get('mitre_tactics', []))
            shared['indicators'].update(alert.get('indicators', []))
        
        # Convert sets to lists and filter to only shared items
        result = {}
        for key in shared:
            items = list(shared[key])
            # Consider "shared" if appears in multiple alerts OR if only one unique value
            if len(items) > 0:
                result[key] = items
        
        return result
    
    def determine_risk_level(self, correlation_score: int, kill_chain_coverage: int) -> str:
        """Determine risk level based on correlation score and kill chain coverage"""
        if correlation_score >= 80 or kill_chain_coverage >= 5:
            return 'critical'
        elif correlation_score >= 60 or kill_chain_coverage >= 3:
            return 'high'
        elif correlation_score >= 40 or kill_chain_coverage >= 2:
            return 'medium'
        return 'low'
    
    def generate_correlation_name(self, alerts: List[Dict], shared_entities: Dict) -> str:
        """Generate a descriptive name for the correlation group"""
        # Priority: specific host > user > general pattern
        if len(shared_entities.get('hosts', [])) == 1:
            host = list(shared_entities['hosts'])[0]
            return f"Coordinated Attack on {host}"
        elif len(shared_entities.get('users', [])) == 1:
            user = list(shared_entities['users'])[0]
            return f"Suspicious Activity by {user}"
        elif len(shared_entities.get('ips', [])) == 1:
            ip = list(shared_entities['ips'])[0]
            return f"Attack Campaign from {ip}"
        elif any('brute' in str(a.get('title', '')).lower() for a in alerts):
            return "Brute Force Attack Campaign"
        elif any('ransomware' in str(a.get('title', '')).lower() or 'malware' in str(a.get('title', '')).lower() for a in alerts):
            return "Malware/Ransomware Propagation"
        elif any('phish' in str(a.get('title', '')).lower() for a in alerts):
            return "Phishing Attack Chain"
        else:
            return f"Multi-Stage Attack Campaign"
    
    def generate_correlation_description(self, alerts: List[Dict], kill_chain_timeline: List[Dict]) -> str:
        """Generate a detailed description of the correlation"""
        stages = set(item['stage'] for item in kill_chain_timeline)
        num_stages = len(stages)
        
        if num_stages >= 4:
            return f"Advanced multi-stage attack detected with {len(alerts)} correlated alerts spanning {num_stages} kill chain stages. Indicates sophisticated threat actor activity requiring immediate investigation."
        elif num_stages >= 2:
            return f"Multiple indicators suggest a coordinated attack with {len(alerts)} related alerts across {num_stages} attack stages. Requires investigation and potential containment."
        else:
            return f"{len(alerts)} related security alerts detected. Common indicators suggest coordinated activity."
    
    def recommend_action(self, risk_level: str, kill_chain_coverage: int) -> str:
        """Recommend action based on risk assessment"""
        if risk_level == 'critical':
            return "Immediate host isolation and full forensic investigation required. Escalate to incident response team."
        elif risk_level == 'high':
            if kill_chain_coverage >= 3:
                return "Isolate affected systems and conduct thorough investigation. Check for lateral movement."
            return "Investigate immediately and prepare for containment. Monitor for escalation."
        elif risk_level == 'medium':
            return "Investigate alert cluster and correlate with other security data. Monitor for progression."
        return "Review alerts and assess if further investigation is needed."
    
    def create_correlation_group(self, group_id: int, alerts: List[Dict]) -> Dict:
        """Create a correlation group object from alerts"""
        # Calculate metrics
        correlation_score = self.calculate_correlation_score(alerts)
        kill_chain_timeline = self.build_kill_chain_timeline(alerts)
        kill_chain_coverage = len(set(item['stage'] for item in kill_chain_timeline))
        shared_entities = self.get_shared_entities(alerts)
        risk_level = self.determine_risk_level(correlation_score, kill_chain_coverage)
        
        # Generate descriptive information
        name = self.generate_correlation_name(alerts, shared_entities)
        description = self.generate_correlation_description(alerts, kill_chain_timeline)
        recommended_action = self.recommend_action(risk_level, kill_chain_coverage)
        
        # Get timestamps
        timestamps = [self.parse_timestamp(a['timestamp']) for a in alerts]
        created_at = min(timestamps).isoformat() + 'Z'
        updated_at = max(timestamps).isoformat() + 'Z'
        
        return {
            'id': group_id,
            'name': name,
            'description': description,
            'correlation_score': correlation_score,
            'created_at': created_at,
            'updated_at': updated_at,
            'status': 'active',
            'alert_ids': [a['id'] for a in alerts],
            'shared_entities': {k: list(v) for k, v in shared_entities.items()},
            'kill_chain': kill_chain_timeline,
            'kill_chain_coverage': kill_chain_coverage,
            'total_kill_chain_stages': len(KILL_CHAIN_STAGES),
            'risk_level': risk_level,
            'recommended_action': recommended_action
        }
    
    def find_duplicates(self, alerts: List[Dict], time_threshold_minutes=30) -> List[Dict]:
        """Identify duplicate alerts"""
        duplicates = []
        seen = set()
        
        for i, alert in enumerate(alerts):
            if i in seen:
                continue
            
            # Look for duplicates
            duplicate_group = []
            for j, other in enumerate(alerts[i+1:], start=i+1):
                if j in seen:
                    continue
                
                # Check if duplicate
                same_title = alert.get('title') == other.get('title')
                same_host = alert.get('host') == other.get('host')
                same_source = alert.get('source') == other.get('source')
                
                # Check time proximity
                time_diff = abs((
                    self.parse_timestamp(alert['timestamp']) - 
                    self.parse_timestamp(other['timestamp'])
                ).total_seconds() / 60)
                
                if same_title and same_host and same_source and time_diff <= time_threshold_minutes:
                    duplicate_group.append(other['id'])
                    seen.add(j)
            
            if duplicate_group:
                duplicates.append({
                    'primary_alert_id': alert['id'],
                    'duplicate_alert_ids': duplicate_group,
                    'count': len(duplicate_group) + 1
                })
        
        return duplicates
    
    def calculate_similarity(self, alert1: Dict, alert2: Dict) -> Dict:
        """Calculate detailed similarity between two alerts"""
        entity_score, shared_entities = self.calculate_entity_similarity(alert1, alert2)
        time_score = self.calculate_time_proximity_score(alert1, alert2)
        
        # Overall similarity
        overall_similarity = (entity_score * 0.7 + time_score * 0.3)
        
        return {
            'similarity_score': int(overall_similarity * 100),
            'entity_similarity': int(entity_score * 100),
            'time_proximity': int(time_score * 100),
            'shared_entities': shared_entities
        }
    
    def find_related_alerts(self, target_alert: Dict, all_alerts: List[Dict], top_n=5) -> List[Dict]:
        """Find the most similar alerts to a given alert"""
        related = []
        
        for alert in all_alerts:
            if alert['id'] == target_alert['id']:
                continue
            
            similarity = self.calculate_similarity(target_alert, alert)
            if similarity['similarity_score'] > 10:  # Threshold
                related.append({
                    'alert': alert,
                    'similarity': similarity
                })
        
        # Sort by similarity and return top N
        related.sort(key=lambda x: x['similarity']['similarity_score'], reverse=True)
        return related[:top_n]
