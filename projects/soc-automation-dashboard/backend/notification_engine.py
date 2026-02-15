"""
SOC Automation Dashboard - Real-Time Notification & Escalation Engine
Ensures critical alerts never go unnoticed with escalation policies and on-call rotations
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import os


class NotificationEngine:
    """Real-Time Notification & Escalation Engine"""
    
    def __init__(self, data_dir='../data'):
        """Initialize the notification engine"""
        self.data_dir = data_dir
    
    def create_notification(
        self,
        user_id: int,
        notification_type: str,
        title: str,
        message: str,
        severity: str,
        resource_type: str = None,
        resource_id: int = None
    ) -> Dict:
        """
        Create a new notification
        
        Args:
            user_id: ID of the user to notify
            notification_type: Type of notification (alert_assigned, alert_escalated, etc.)
            title: Notification title
            message: Notification message
            severity: Severity level (critical, high, medium, low)
            resource_type: Type of resource (alert, incident, playbook, etc.)
            resource_id: ID of the related resource
        
        Returns:
            Notification dictionary
        """
        notification = {
            'id': self._generate_notification_id(),
            'user_id': user_id,
            'type': notification_type,
            'title': title,
            'message': message,
            'severity': severity,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'read': False,
            'acknowledged_at': None,
            'created_at': datetime.now().isoformat() + 'Z'
        }
        
        return notification
    
    def _generate_notification_id(self) -> int:
        """Generate a unique notification ID"""
        try:
            notifications = self.load_notifications()
            if notifications:
                return max(n['id'] for n in notifications) + 1
            return 1
        except:
            return 1
    
    def load_notifications(self) -> List[Dict]:
        """Load notifications from file"""
        try:
            notifications_file = os.path.join(self.data_dir, 'notifications.json')
            with open(notifications_file, 'r') as f:
                return json.load(f)
        except:
            return []
    
    def save_notifications(self, notifications: List[Dict]):
        """Save notifications to file"""
        notifications_file = os.path.join(self.data_dir, 'notifications.json')
        with open(notifications_file, 'w') as f:
            json.dump(notifications, f, indent=2)
    
    def auto_generate_alert_notification(self, alert: Dict) -> Optional[Dict]:
        """
        Auto-generate notification for new high/critical alert
        
        Args:
            alert: Alert dictionary
        
        Returns:
            Notification if alert is high/critical severity, None otherwise
        """
        if alert.get('severity') not in ['high', 'critical']:
            return None
        
        # Find on-call analyst to notify
        oncall = self.get_current_oncall()
        if not oncall or 'primary' not in oncall:
            return None
        
        user_id = oncall['primary']['user_id']
        severity_emoji = '🔴' if alert['severity'] == 'critical' else '🟠'
        
        notification = self.create_notification(
            user_id=user_id,
            notification_type='alert_assigned',
            title=f"{severity_emoji} New {alert['severity'].title()} Alert",
            message=f"{alert['title']} - {alert.get('host', 'Unknown host')}",
            severity=alert['severity'],
            resource_type='alert',
            resource_id=alert['id']
        )
        
        return notification
    
    def generate_sla_warning_notification(self, alert: Dict, sla_percentage: float) -> Dict:
        """Generate notification for SLA warning (75% threshold)"""
        oncall = self.get_current_oncall()
        user_id = oncall['primary']['user_id'] if oncall and 'primary' in oncall else 1
        
        notification = self.create_notification(
            user_id=user_id,
            notification_type='sla_breach',
            title='⚠️ SLA Warning',
            message=f"Alert #{alert['id']} is at {int(sla_percentage)}% of SLA time",
            severity='high',
            resource_type='alert',
            resource_id=alert['id']
        )
        
        return notification
    
    def generate_sla_breach_notification(self, alert: Dict) -> Dict:
        """Generate notification for SLA breach"""
        oncall = self.get_current_oncall()
        user_id = oncall['secondary']['user_id'] if oncall and 'secondary' in oncall else 1
        
        notification = self.create_notification(
            user_id=user_id,
            notification_type='sla_breach',
            title='🚨 SLA Breach',
            message=f"Alert #{alert['id']} has breached SLA - {alert['title']}",
            severity='critical',
            resource_type='alert',
            resource_id=alert['id']
        )
        
        return notification
    
    def generate_playbook_completion_notification(self, playbook_id: int, success: bool) -> Dict:
        """Generate notification for playbook completion"""
        oncall = self.get_current_oncall()
        user_id = oncall['primary']['user_id'] if oncall and 'primary' in oncall else 1
        
        status = '✅ completed' if success else '❌ failed'
        
        notification = self.create_notification(
            user_id=user_id,
            notification_type='playbook_completed',
            title=f"Playbook {status}",
            message=f"Playbook #{playbook_id} has {status}",
            severity='medium' if success else 'high',
            resource_type='playbook',
            resource_id=playbook_id
        )
        
        return notification
    
    def generate_correlation_notification(self, correlation: Dict) -> Dict:
        """Generate notification for new correlation detected"""
        oncall = self.get_current_oncall()
        user_id = oncall['primary']['user_id'] if oncall and 'primary' in oncall else 1
        
        notification = self.create_notification(
            user_id=user_id,
            notification_type='correlation_detected',
            title='🧠 New Alert Correlation Detected',
            message=f"{correlation['name']} - {len(correlation['alert_ids'])} alerts correlated",
            severity=correlation.get('risk_level', 'medium'),
            resource_type='correlation',
            resource_id=correlation['id']
        )
        
        return notification
    
    def load_escalation_policies(self) -> List[Dict]:
        """Load escalation policies from file"""
        try:
            policies_file = os.path.join(self.data_dir, 'escalation_policies.json')
            with open(policies_file, 'r') as f:
                return json.load(f)
        except:
            return []
    
    def get_escalation_policy_for_severity(self, severity: str) -> Optional[Dict]:
        """Get the appropriate escalation policy for a given severity"""
        policies = self.load_escalation_policies()
        
        for policy in policies:
            if policy.get('trigger_severity') == severity and policy.get('enabled'):
                return policy
        
        return None
    
    def calculate_escalation_level(
        self,
        alert: Dict,
        alert_age_minutes: float
    ) -> Optional[Dict]:
        """
        Calculate current escalation level for an alert
        
        Args:
            alert: Alert dictionary
            alert_age_minutes: Age of alert in minutes
        
        Returns:
            Dictionary with escalation info or None
        """
        policy = self.get_escalation_policy_for_severity(alert.get('severity'))
        if not policy:
            return None
        
        current_level = None
        for level_info in policy['levels']:
            if alert_age_minutes >= level_info['escalate_after_minutes']:
                current_level = level_info
        
        if not current_level:
            return None
        
        # Find next level
        next_level = None
        for level_info in policy['levels']:
            if level_info['level'] > current_level['level']:
                next_level = level_info
                break
        
        return {
            'policy_id': policy['id'],
            'policy_name': policy['name'],
            'current_level': current_level['level'],
            'current_action': current_level['action'],
            'notified_roles': current_level['notify_roles'],
            'next_escalation_in_minutes': (
                next_level['escalate_after_minutes'] - alert_age_minutes
                if next_level else None
            ),
            'next_level': next_level['level'] if next_level else None
        }
    
    def generate_escalation_notification(
        self,
        alert: Dict,
        escalation_level: int,
        roles: List[str]
    ) -> List[Dict]:
        """Generate notifications for alert escalation"""
        notifications = []
        
        # In a real system, would look up user IDs by role
        # For now, use oncall
        oncall = self.get_current_oncall()
        
        # Determine recipients based on escalation level
        if escalation_level == 1:
            user_ids = [oncall['primary']['user_id']] if oncall and 'primary' in oncall else [1]
        elif escalation_level == 2:
            user_ids = [oncall['secondary']['user_id']] if oncall and 'secondary' in oncall else [2]
        else:
            user_ids = [oncall['primary']['user_id'], oncall['secondary']['user_id']] if oncall else [1, 2]
        
        for user_id in user_ids:
            notification = self.create_notification(
                user_id=user_id,
                notification_type='alert_escalated',
                title=f'🔺 Alert Escalated to Level {escalation_level}',
                message=f"Alert #{alert['id']} - {alert['title']} requires attention",
                severity='critical' if escalation_level >= 3 else 'high',
                resource_type='alert',
                resource_id=alert['id']
            )
            notifications.append(notification)
        
        return notifications
    
    def get_current_oncall(self) -> Optional[Dict]:
        """Get current on-call rotation"""
        try:
            oncall_file = os.path.join(self.data_dir, 'oncall_schedule.json')
            with open(oncall_file, 'r') as f:
                data = json.load(f)
            return data.get('current_oncall')
        except:
            return None
    
    def get_oncall_schedule(self) -> Dict:
        """Get full on-call schedule"""
        try:
            oncall_file = os.path.join(self.data_dir, 'oncall_schedule.json')
            with open(oncall_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def set_oncall_override(
        self,
        primary_user_id: int,
        secondary_user_id: int,
        start_time: str,
        end_time: str,
        reason: str
    ) -> Dict:
        """Set a temporary on-call override"""
        schedule = self.get_oncall_schedule()
        
        schedule['override'] = {
            'primary_user_id': primary_user_id,
            'secondary_user_id': secondary_user_id,
            'start': start_time,
            'end': end_time,
            'reason': reason,
            'set_by': 'system',
            'set_at': datetime.now().isoformat() + 'Z'
        }
        
        # Save updated schedule
        oncall_file = os.path.join(self.data_dir, 'oncall_schedule.json')
        with open(oncall_file, 'w') as f:
            json.dump(schedule, f, indent=2)
        
        return schedule
    
    def load_webhook_config(self) -> List[Dict]:
        """Load webhook configuration"""
        try:
            webhook_file = os.path.join(self.data_dir, 'webhook_config.json')
            with open(webhook_file, 'r') as f:
                return json.load(f)
        except:
            return []
    
    def save_webhook_config(self, webhooks: List[Dict]):
        """Save webhook configuration"""
        webhook_file = os.path.join(self.data_dir, 'webhook_config.json')
        with open(webhook_file, 'w') as f:
            json.dump(webhooks, f, indent=2)
    
    def should_trigger_webhook(
        self,
        webhook: Dict,
        event_type: str,
        severity: str
    ) -> bool:
        """Determine if a webhook should be triggered"""
        if not webhook.get('enabled'):
            return False
        
        if event_type not in webhook.get('events', []):
            return False
        
        if severity not in webhook.get('trigger_severity', []):
            return False
        
        return True
    
    def simulate_webhook_trigger(
        self,
        webhook: Dict,
        event_type: str,
        payload: Dict
    ) -> Dict:
        """
        Simulate triggering a webhook (for demo purposes)
        In production, this would make actual HTTP requests
        """
        return {
            'success': True,
            'webhook_id': webhook['id'],
            'webhook_name': webhook['name'],
            'webhook_type': webhook['type'],
            'url': webhook['url'],
            'event': event_type,
            'timestamp': datetime.now().isoformat() + 'Z',
            'simulated': True,
            'message': f"Simulated {webhook['type']} webhook trigger successful"
        }
    
    def get_notification_statistics(self, user_id: Optional[int] = None) -> Dict:
        """Get notification statistics"""
        notifications = self.load_notifications()
        
        if user_id:
            notifications = [n for n in notifications if n.get('user_id') == user_id]
        
        total = len(notifications)
        unread = len([n for n in notifications if not n.get('read')])
        by_type = {}
        by_severity = {}
        
        for n in notifications:
            n_type = n.get('type', 'unknown')
            n_severity = n.get('severity', 'medium')
            
            by_type[n_type] = by_type.get(n_type, 0) + 1
            by_severity[n_severity] = by_severity.get(n_severity, 0) + 1
        
        return {
            'total': total,
            'unread': unread,
            'read': total - unread,
            'by_type': by_type,
            'by_severity': by_severity
        }
