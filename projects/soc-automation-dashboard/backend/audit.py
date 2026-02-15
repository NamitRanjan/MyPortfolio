"""
SOC Automation Dashboard - Audit Logging Module
Track all security-significant actions
"""

import json
import os
from datetime import datetime
from flask import request

def load_audit_log():
    """Load audit log from file"""
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    audit_file = os.path.join(data_dir, 'audit_log.json')
    
    if not os.path.exists(audit_file):
        return []
    
    with open(audit_file, 'r') as f:
        return json.load(f)

def save_audit_log(log_entries):
    """Save audit log to file"""
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    audit_file = os.path.join(data_dir, 'audit_log.json')
    
    with open(audit_file, 'w') as f:
        json.dump(log_entries, f, indent=2)

def get_next_id():
    """Get next audit log entry ID"""
    log_entries = load_audit_log()
    if not log_entries:
        return 1
    return max(entry['id'] for entry in log_entries) + 1

def log_action(user_id, username, action, resource_type, resource_id, details=None):
    """Log an action to the audit log"""
    log_entries = load_audit_log()
    
    # Get client IP (handle proxies)
    if request:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip_address and ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
    else:
        ip_address = 'system'
    
    entry = {
        'id': get_next_id(),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'user_id': user_id,
        'username': username,
        'action': action,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'details': details or {},
        'ip_address': ip_address
    }
    
    log_entries.append(entry)
    save_audit_log(log_entries)
    
    return entry

def filter_audit_log(user_id=None, action=None, resource_type=None, start_date=None, end_date=None, page=1, per_page=50):
    """Filter and paginate audit log"""
    log_entries = load_audit_log()
    
    # Apply filters
    filtered = log_entries
    
    if user_id:
        filtered = [e for e in filtered if e['user_id'] == user_id]
    
    if action:
        filtered = [e for e in filtered if e['action'] == action]
    
    if resource_type:
        filtered = [e for e in filtered if e['resource_type'] == resource_type]
    
    if start_date:
        filtered = [e for e in filtered if e['timestamp'] >= start_date]
    
    if end_date:
        filtered = [e for e in filtered if e['timestamp'] <= end_date]
    
    # Sort by timestamp descending (newest first)
    filtered.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Paginate
    total = len(filtered)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated = filtered[start_idx:end_idx]
    
    return {
        'entries': paginated,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    }
