"""
Compliance Engine - Framework Mapping and Coverage Analysis
Maps detections, playbooks, and IOCs to compliance frameworks
Supports: NIST CSF, ISO 27001, SOC 2, CIS Controls, MITRE ATT&CK
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any

class ComplianceEngine:
    """
    Engine for compliance framework mapping and coverage analysis
    """
    
    FRAMEWORKS = {
        'NIST_CSF': {
            'name': 'NIST Cybersecurity Framework',
            'version': '1.1',
            'categories': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
        },
        'ISO_27001': {
            'name': 'ISO/IEC 27001:2013',
            'version': '2013',
            'domains': ['A.5-A.18']
        },
        'SOC_2': {
            'name': 'SOC 2 Type II',
            'version': '2017',
            'criteria': ['CC1-CC9']
        },
        'CIS_CONTROLS': {
            'name': 'CIS Critical Security Controls',
            'version': 'v8',
            'controls': ['CIS-1 to CIS-18']
        },
        'MITRE_ATTACK': {
            'name': 'MITRE ATT&CK',
            'version': 'v13',
            'tactics': [
                'Reconnaissance', 'Resource Development', 'Initial Access',
                'Execution', 'Persistence', 'Privilege Escalation',
                'Defense Evasion', 'Credential Access', 'Discovery',
                'Lateral Movement', 'Collection', 'Command and Control',
                'Exfiltration', 'Impact'
            ]
        }
    }
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.mappings = self._load_mappings()
        
    def _load_mappings(self) -> Dict:
        """Load compliance mappings from JSON file"""
        mappings_file = os.path.join(self.data_dir, 'compliance_mappings.json')
        try:
            with open(mappings_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def get_frameworks(self) -> List[Dict]:
        """Get list of all supported frameworks"""
        return [
            {
                'id': fid,
                'name': info['name'],
                'version': info['version']
            }
            for fid, info in self.FRAMEWORKS.items()
        ]
    
    def calculate_posture(self, alerts: List[Dict], playbooks: List[Dict], iocs: List[Dict]) -> Dict:
        """
        Calculate overall compliance posture score
        Returns posture metrics across all frameworks
        """
        framework_scores = {}
        
        for framework_id, framework_info in self.FRAMEWORKS.items():
            coverage = self._calculate_framework_coverage(
                framework_id, alerts, playbooks, iocs
            )
            framework_scores[framework_id] = {
                'name': framework_info['name'],
                'score': coverage['score'],
                'covered': coverage['covered'],
                'total': coverage['total'],
                'percentage': round((coverage['covered'] / coverage['total']) * 100, 1) if coverage['total'] > 0 else 0
            }
        
        # Calculate overall posture score (average of all frameworks)
        avg_score = sum(f['score'] for f in framework_scores.values()) / len(framework_scores)
        
        return {
            'overall_score': round(avg_score, 1),
            'overall_percentage': round(sum(f['percentage'] for f in framework_scores.values()) / len(framework_scores), 1),
            'frameworks': framework_scores,
            'last_updated': datetime.now().isoformat()
        }
    
    def _calculate_framework_coverage(self, framework_id: str, alerts: List[Dict], 
                                     playbooks: List[Dict], iocs: List[Dict]) -> Dict:
        """Calculate coverage for a specific framework"""
        if framework_id not in self.mappings:
            return {'score': 0, 'covered': 0, 'total': 100}
        
        framework_mapping = self.mappings.get(framework_id, {})
        controls = framework_mapping.get('controls', {})
        
        if not controls:
            return {'score': 0, 'covered': 0, 'total': 100}
        
        total_controls = len(controls)
        covered_controls = sum(1 for c in controls.values() if c.get('covered', False))
        
        score = (covered_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'score': round(score, 1),
            'covered': covered_controls,
            'total': total_controls
        }
    
    def get_coverage_matrix(self, framework_id: str, alerts: List[Dict], 
                          playbooks: List[Dict], iocs: List[Dict]) -> Dict:
        """
        Get detailed coverage matrix for a specific framework
        Shows which controls are covered by which detections
        """
        if framework_id not in self.FRAMEWORKS:
            return {'error': 'Framework not found'}
        
        framework_mapping = self.mappings.get(framework_id, {})
        controls = framework_mapping.get('controls', {})
        
        coverage_data = []
        for control_id, control_info in controls.items():
            coverage_data.append({
                'control_id': control_id,
                'control_name': control_info.get('name', ''),
                'description': control_info.get('description', ''),
                'covered': control_info.get('covered', False),
                'coverage_sources': control_info.get('coverage_sources', []),
                'mapped_alerts': control_info.get('mapped_alerts', []),
                'mapped_playbooks': control_info.get('mapped_playbooks', []),
                'mapped_iocs': control_info.get('mapped_iocs', []),
                'gap': not control_info.get('covered', False)
            })
        
        return {
            'framework': self.FRAMEWORKS[framework_id],
            'coverage': coverage_data,
            'summary': {
                'total': len(controls),
                'covered': sum(1 for c in coverage_data if c['covered']),
                'gaps': sum(1 for c in coverage_data if c['gap'])
            }
        }
    
    def get_gaps(self, alerts: List[Dict], playbooks: List[Dict], iocs: List[Dict]) -> Dict:
        """
        Identify coverage gaps across all frameworks
        Returns prioritized list of gaps
        """
        all_gaps = []
        
        for framework_id in self.FRAMEWORKS.keys():
            framework_mapping = self.mappings.get(framework_id, {})
            controls = framework_mapping.get('controls', {})
            
            for control_id, control_info in controls.items():
                if not control_info.get('covered', False):
                    all_gaps.append({
                        'framework': self.FRAMEWORKS[framework_id]['name'],
                        'framework_id': framework_id,
                        'control_id': control_id,
                        'control_name': control_info.get('name', ''),
                        'description': control_info.get('description', ''),
                        'priority': control_info.get('priority', 'medium'),
                        'remediation': control_info.get('remediation', '')
                    })
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_gaps.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return {
            'total_gaps': len(all_gaps),
            'by_priority': {
                'critical': sum(1 for g in all_gaps if g['priority'] == 'critical'),
                'high': sum(1 for g in all_gaps if g['priority'] == 'high'),
                'medium': sum(1 for g in all_gaps if g['priority'] == 'medium'),
                'low': sum(1 for g in all_gaps if g['priority'] == 'low')
            },
            'gaps': all_gaps[:50]  # Return top 50 gaps
        }
    
    def get_mitre_heatmap(self, alerts: List[Dict], playbooks: List[Dict], iocs: List[Dict]) -> Dict:
        """
        Generate MITRE ATT&CK heatmap showing coverage
        Returns tactics x techniques grid with coverage status
        """
        mitre_mapping = self.mappings.get('MITRE_ATTACK', {})
        tactics = mitre_mapping.get('tactics', {})
        
        heatmap_data = []
        
        for tactic_name in self.FRAMEWORKS['MITRE_ATTACK']['tactics']:
            tactic_data = tactics.get(tactic_name, {})
            techniques = tactic_data.get('techniques', [])
            
            for technique in techniques:
                heatmap_data.append({
                    'tactic': tactic_name,
                    'technique_id': technique.get('id', ''),
                    'technique_name': technique.get('name', ''),
                    'covered': technique.get('covered', False),
                    'coverage_count': len(technique.get('coverage_sources', [])),
                    'mapped_alerts': technique.get('mapped_alerts', []),
                    'mapped_playbooks': technique.get('mapped_playbooks', [])
                })
        
        # Calculate coverage by tactic
        tactic_coverage = {}
        for tactic in self.FRAMEWORKS['MITRE_ATTACK']['tactics']:
            tactic_techniques = [t for t in heatmap_data if t['tactic'] == tactic]
            if tactic_techniques:
                covered = sum(1 for t in tactic_techniques if t['covered'])
                total = len(tactic_techniques)
                tactic_coverage[tactic] = {
                    'covered': covered,
                    'total': total,
                    'percentage': round((covered / total) * 100, 1) if total > 0 else 0
                }
        
        return {
            'heatmap': heatmap_data,
            'tactic_coverage': tactic_coverage,
            'summary': {
                'total_techniques': len(heatmap_data),
                'covered_techniques': sum(1 for t in heatmap_data if t['covered']),
                'coverage_percentage': round((sum(1 for t in heatmap_data if t['covered']) / len(heatmap_data)) * 100, 1) if heatmap_data else 0
            }
        }
    
    def generate_report(self, report_type: str, alerts: List[Dict], 
                       playbooks: List[Dict], iocs: List[Dict], 
                       incidents: List[Dict]) -> Dict:
        """
        Generate compliance report
        Types: daily, weekly, monthly, posture
        """
        posture = self.calculate_posture(alerts, playbooks, iocs)
        gaps = self.get_gaps(alerts, playbooks, iocs)
        mitre = self.get_mitre_heatmap(alerts, playbooks, iocs)
        
        report = {
            'id': f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'type': report_type,
            'generated_at': datetime.now().isoformat(),
            'period': self._get_report_period(report_type),
            'executive_summary': {
                'overall_posture': posture['overall_score'],
                'total_alerts': len([a for a in alerts if a.get('status') != 'resolved']),
                'critical_incidents': len([i for i in incidents if i.get('severity') == 'critical']),
                'compliance_gaps': gaps['total_gaps'],
                'mitre_coverage': mitre['summary']['coverage_percentage']
            },
            'posture': posture,
            'top_gaps': gaps['gaps'][:10],
            'mitre_summary': mitre['summary'],
            'trends': self._generate_trends(report_type),
            'recommendations': self._generate_recommendations(gaps, posture)
        }
        
        return report
    
    def _get_report_period(self, report_type: str) -> Dict:
        """Calculate report period based on type"""
        now = datetime.now()
        if report_type == 'daily':
            return {
                'start': (now.replace(hour=0, minute=0, second=0)).isoformat(),
                'end': now.isoformat()
            }
        elif report_type == 'weekly':
            start = now - timedelta(days=7)
            return {'start': start.isoformat(), 'end': now.isoformat()}
        elif report_type == 'monthly':
            start = now - timedelta(days=30)
            return {'start': start.isoformat(), 'end': now.isoformat()}
        else:
            return {'start': now.isoformat(), 'end': now.isoformat()}
    
    def _generate_trends(self, report_type: str) -> List[Dict]:
        """Generate trend data for reports"""
        # Mock trend data - in production, this would analyze historical data
        return [
            {'metric': 'Compliance Score', 'trend': 'up', 'change': '+5.2%'},
            {'metric': 'Coverage Gaps', 'trend': 'down', 'change': '-8 gaps'},
            {'metric': 'MITRE Coverage', 'trend': 'up', 'change': '+12.3%'},
            {'metric': 'Critical Incidents', 'trend': 'down', 'change': '-3 incidents'}
        ]
    
    def _generate_recommendations(self, gaps: Dict, posture: Dict) -> List[str]:
        """Generate actionable recommendations based on gaps and posture"""
        recommendations = []
        
        # Check for critical gaps
        critical_gaps = gaps['by_priority'].get('critical', 0)
        if critical_gaps > 0:
            recommendations.append(f"Address {critical_gaps} critical compliance gaps immediately")
        
        # Check framework scores
        for fw_id, fw_data in posture['frameworks'].items():
            if fw_data['percentage'] < 70:
                recommendations.append(f"Improve {fw_data['name']} coverage (currently {fw_data['percentage']}%)")
        
        # Generic recommendations if no specific issues
        if not recommendations:
            recommendations.append("Maintain current compliance posture through regular reviews")
            recommendations.append("Consider expanding detection coverage for emerging threats")
        
        return recommendations[:5]  # Return top 5 recommendations
