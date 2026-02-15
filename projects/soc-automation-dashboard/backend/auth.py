"""
SOC Automation Dashboard - Authentication Module
JWT-based authentication with role-based access control
"""

import jwt
import json
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from werkzeug.security import check_password_hash

# JWT Configuration
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'soc-dashboard-secret-key-change-in-production')
TOKEN_EXPIRY_HOURS = 8  # Match SOC shift duration

# Token blacklist (in-memory for now, use Redis in production)
token_blacklist = set()

def load_users():
    """Load users from data file"""
    data_dir = os.path.join(os.path.dirname(__file__), '../data')
    users_file = os.path.join(data_dir, 'users.json')
    
    if not os.path.exists(users_file):
        return []
    
    with open(users_file, 'r') as f:
        return json.load(f)

def get_user_by_username(username):
    """Get user by username"""
    users = load_users()
    return next((u for u in users if u['username'] == username), None)

def get_user_by_id(user_id):
    """Get user by ID"""
    users = load_users()
    return next((u for u in users if u['id'] == user_id), None)

def generate_token(user):
    """Generate JWT token for user"""
    payload = {
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'display_name': user['display_name'],
        'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def verify_token(token):
    """Verify JWT token and return payload"""
    try:
        # Check if token is blacklisted
        if token in token_blacklist:
            return None
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def authenticate(username, password):
    """Authenticate user with username and password"""
    user = get_user_by_username(username)
    
    if not user:
        return None
    
    # Check password
    if check_password_hash(user['password_hash'], password):
        return user
    
    return None

def get_token_from_request():
    """Extract token from Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    
    return None

def invalidate_token(token):
    """Add token to blacklist"""
    token_blacklist.add(token)

# Role hierarchy and permissions
ROLE_PERMISSIONS = {
    'admin': {
        'view_alerts': True,
        'investigate': True,
        'execute_response': True,
        'manage_playbooks': True,
        'manage_team': True,
        'admin_settings': True,
        'view_audit_log': True,
        'add_notes': True,
        'add_evidence': True,
        'assign_analyst': True
    },
    'soc_manager': {
        'view_alerts': True,
        'investigate': True,
        'execute_response': True,
        'manage_playbooks': True,
        'manage_team': True,
        'admin_settings': False,
        'view_audit_log': True,
        'add_notes': True,
        'add_evidence': True,
        'assign_analyst': True
    },
    't3_analyst': {
        'view_alerts': True,
        'investigate': True,
        'execute_response': True,
        'manage_playbooks': True,
        'manage_team': False,
        'admin_settings': False,
        'view_audit_log': False,
        'add_notes': True,
        'add_evidence': True,
        'assign_analyst': True
    },
    't2_analyst': {
        'view_alerts': True,
        'investigate': True,
        'execute_response': True,
        'manage_playbooks': False,
        'manage_team': False,
        'admin_settings': False,
        'view_audit_log': False,
        'add_notes': True,
        'add_evidence': True,
        'assign_analyst': True
    },
    't1_analyst': {
        'view_alerts': True,
        'investigate': True,
        'execute_response': False,
        'manage_playbooks': False,
        'manage_team': False,
        'admin_settings': False,
        'view_audit_log': False,
        'add_notes': True,
        'add_evidence': False,
        'assign_analyst': False
    },
    'read_only': {
        'view_alerts': True,
        'investigate': False,
        'execute_response': False,
        'manage_playbooks': False,
        'manage_team': False,
        'admin_settings': False,
        'view_audit_log': False,
        'add_notes': False,
        'add_evidence': False,
        'assign_analyst': False
    }
}

def check_permission(role, permission):
    """Check if role has permission"""
    role_perms = ROLE_PERMISSIONS.get(role, {})
    return role_perms.get(permission, False)

def requires_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token_from_request()
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Add user info to request context
        request.current_user = payload
        
        return f(*args, **kwargs)
    
    return decorated_function

def requires_role(*required_permissions):
    """Decorator to require specific permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = get_token_from_request()
            
            if not token:
                return jsonify({'error': 'Authentication required'}), 401
            
            payload = verify_token(token)
            
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Check permissions
            user_role = payload.get('role')
            
            for permission in required_permissions:
                if not check_permission(user_role, permission):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'required_permission': permission,
                        'user_role': user_role
                    }), 403
            
            # Add user info to request context
            request.current_user = payload
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator
