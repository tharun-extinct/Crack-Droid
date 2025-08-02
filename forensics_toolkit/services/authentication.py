"""
Authentication and authorization service implementation
"""

import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

from ..interfaces import (
    IAuthenticationService, IUserManager, IAuditLogger,
    User, Session, AuditLog, UserRole, Permission,
    AuthenticationException, AuthorizationException
)


class RolePermissionManager:
    """Manages role-based permissions"""
    
    ROLE_PERMISSIONS = {
        UserRole.ADMIN: [
            Permission.DEVICE_ACCESS,
            Permission.ATTACK_EXECUTION,
            Permission.EVIDENCE_MANAGEMENT,
            Permission.USER_MANAGEMENT,
            Permission.SYSTEM_CONFIG,
            Permission.REPORT_GENERATION
        ],
        UserRole.INVESTIGATOR: [
            Permission.DEVICE_ACCESS,
            Permission.ATTACK_EXECUTION,
            Permission.EVIDENCE_MANAGEMENT,
            Permission.REPORT_GENERATION
        ],
        UserRole.ANALYST: [
            Permission.DEVICE_ACCESS,
            Permission.EVIDENCE_MANAGEMENT,
            Permission.REPORT_GENERATION
        ],
        UserRole.VIEWER: [
            Permission.REPORT_GENERATION
        ]
    }
    
    @classmethod
    def get_permissions_for_role(cls, role: UserRole) -> List[Permission]:
        """Get permissions for a specific role"""
        return cls.ROLE_PERMISSIONS.get(role, [])
    
    @classmethod
    def has_permission(cls, role: UserRole, permission: Permission) -> bool:
        """Check if role has specific permission"""
        return permission in cls.get_permissions_for_role(role)


class UserManager(IUserManager):
    """User management implementation"""
    
    def __init__(self, users_file: str = "config/users.json"):
        self.users_file = Path(users_file)
        self.users_file.parent.mkdir(exist_ok=True)
        self._users: Dict[str, Dict] = self._load_users()
    
    def _load_users(self) -> Dict[str, Dict]:
        """Load users from file"""
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}
    
    def _save_users(self) -> None:
        """Save users to file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self._users, f, indent=2, default=str)
        except IOError as e:
            raise AuthenticationException(f"Failed to save users: {e}", "USER_SAVE_ERROR")
    
    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return password_hash.hex(), salt
    
    def create_user(self, username: str, password: str, role: UserRole) -> User:
        """Create new user"""
        if username in self._users:
            raise AuthenticationException(f"User {username} already exists", "USER_EXISTS")
        
        password_hash, salt = self._hash_password(password)
        permissions = RolePermissionManager.get_permissions_for_role(role)
        
        user_data = {
            'username': username,
            'password_hash': password_hash,
            'salt': salt,
            'role': role.value,
            'permissions': [p.value for p in permissions],
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'session_timeout': 3600,
            'is_active': True
        }
        
        self._users[username] = user_data
        self._save_users()
        
        return User(
            username=username,
            role=role,
            permissions=permissions,
            created_at=datetime.fromisoformat(user_data['created_at']),
            last_login=None,
            session_timeout=user_data['session_timeout'],
            is_active=user_data['is_active']
        )
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        user_data = self._users.get(username)
        if not user_data:
            return None
        
        return User(
            username=user_data['username'],
            role=UserRole(user_data['role']),
            permissions=[Permission(p) for p in user_data['permissions']],
            created_at=datetime.fromisoformat(user_data['created_at']),
            last_login=datetime.fromisoformat(user_data['last_login']) if user_data['last_login'] else None,
            session_timeout=user_data['session_timeout'],
            is_active=user_data['is_active']
        )
    
    def update_user(self, username: str, **kwargs) -> bool:
        """Update user information"""
        if username not in self._users:
            return False
        
        user_data = self._users[username]
        
        # Update allowed fields
        if 'role' in kwargs:
            role = kwargs['role']
            if isinstance(role, UserRole):
                user_data['role'] = role.value
                user_data['permissions'] = [p.value for p in RolePermissionManager.get_permissions_for_role(role)]
        
        if 'is_active' in kwargs:
            user_data['is_active'] = kwargs['is_active']
        
        if 'session_timeout' in kwargs:
            user_data['session_timeout'] = kwargs['session_timeout']
        
        if 'password' in kwargs:
            password_hash, salt = self._hash_password(kwargs['password'])
            user_data['password_hash'] = password_hash
            user_data['salt'] = salt
        
        self._save_users()
        return True
    
    def delete_user(self, username: str) -> bool:
        """Delete user"""
        if username in self._users:
            del self._users[username]
            self._save_users()
            return True
        return False
    
    def list_users(self) -> List[User]:
        """List all users"""
        users = []
        for username in self._users:
            user = self.get_user(username)
            if user:
                users.append(user)
        return users
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password"""
        user_data = self._users.get(username)
        if not user_data or not user_data['is_active']:
            return False
        
        password_hash, _ = self._hash_password(password, user_data['salt'])
        return password_hash == user_data['password_hash']


class AuditLogger(IAuditLogger):
    """Audit logging implementation"""
    
    def __init__(self, audit_file: str = "logs/audit.log"):
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(exist_ok=True)
    
    def _write_log(self, log_entry: AuditLog) -> None:
        """Write log entry to file"""
        try:
            with open(self.audit_file, 'a') as f:
                log_data = {
                    'timestamp': log_entry.timestamp.isoformat(),
                    'user': log_entry.user,
                    'action': log_entry.action,
                    'resource': log_entry.resource,
                    'result': log_entry.result,
                    'ip_address': log_entry.ip_address,
                    'details': log_entry.details
                }
                f.write(json.dumps(log_data) + '\n')
        except IOError as e:
            # Log to system log if audit log fails
            print(f"Failed to write audit log: {e}")
    
    def log_access_attempt(self, username: str, success: bool, ip_address: str = None) -> None:
        """Log authentication attempt"""
        log_entry = AuditLog(
            timestamp=datetime.now(),
            user=username,
            action="LOGIN_ATTEMPT",
            resource="AUTHENTICATION",
            result="SUCCESS" if success else "FAILURE",
            ip_address=ip_address
        )
        self._write_log(log_entry)
    
    def log_operation(self, user: str, action: str, resource: str, result: str, **kwargs) -> None:
        """Log user operation"""
        log_entry = AuditLog(
            timestamp=datetime.now(),
            user=user,
            action=action,
            resource=resource,
            result=result,
            ip_address=kwargs.get('ip_address'),
            details=kwargs.get('details')
        )
        self._write_log(log_entry)
    
    def get_audit_logs(self, start_date: datetime = None, end_date: datetime = None) -> List[AuditLog]:
        """Retrieve audit logs"""
        logs = []
        
        if not self.audit_file.exists():
            return logs
        
        try:
            with open(self.audit_file, 'r') as f:
                for line in f:
                    try:
                        log_data = json.loads(line.strip())
                        log_timestamp = datetime.fromisoformat(log_data['timestamp'])
                        
                        # Filter by date range if specified
                        if start_date and log_timestamp < start_date:
                            continue
                        if end_date and log_timestamp > end_date:
                            continue
                        
                        log_entry = AuditLog(
                            timestamp=log_timestamp,
                            user=log_data['user'],
                            action=log_data['action'],
                            resource=log_data['resource'],
                            result=log_data['result'],
                            ip_address=log_data.get('ip_address'),
                            details=log_data.get('details')
                        )
                        logs.append(log_entry)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except IOError:
            pass
        
        return logs


class AuthenticationService(IAuthenticationService):
    """Authentication service implementation"""
    
    def __init__(self, user_manager: UserManager = None, audit_logger: AuditLogger = None):
        self.user_manager = user_manager or UserManager()
        self.audit_logger = audit_logger or AuditLogger()
        self._sessions: Dict[str, Session] = {}
        
        # Create default admin user if no users exist
        if not self.user_manager.list_users():
            self._create_default_admin()
    
    def _create_default_admin(self) -> None:
        """Create default admin user"""
        try:
            self.user_manager.create_user("admin", "forensics123", UserRole.ADMIN)
            self.audit_logger.log_operation(
                "SYSTEM", "CREATE_DEFAULT_ADMIN", "USER_MANAGEMENT", "SUCCESS"
            )
        except AuthenticationException:
            pass  # Admin already exists
    
    def _generate_session_id(self) -> str:
        """Generate secure session ID"""
        return secrets.token_urlsafe(32)
    
    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions"""
        current_time = datetime.now()
        expired_sessions = [
            session_id for session_id, session in self._sessions.items()
            if current_time > session.expires_at or not session.is_active
        ]
        
        for session_id in expired_sessions:
            del self._sessions[session_id]
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials"""
        try:
            # Verify credentials
            if not self.user_manager.verify_password(username, password):
                self.audit_logger.log_access_attempt(username, False)
                return None
            
            # Get user
            user = self.user_manager.get_user(username)
            if not user or not user.is_active:
                self.audit_logger.log_access_attempt(username, False)
                return None
            
            # Update last login
            self.user_manager.update_user(username, last_login=datetime.now())
            self.audit_logger.log_access_attempt(username, True)
            
            return user
            
        except Exception as e:
            self.audit_logger.log_access_attempt(username, False)
            raise AuthenticationException(f"Authentication failed: {e}", "AUTH_ERROR")
    
    def create_session(self, user: User) -> Session:
        """Create user session"""
        self._cleanup_expired_sessions()
        
        session_id = self._generate_session_id()
        current_time = datetime.now()
        expires_at = current_time + timedelta(seconds=user.session_timeout)
        
        session = Session(
            session_id=session_id,
            user=user,
            created_at=current_time,
            last_activity=current_time,
            expires_at=expires_at,
            is_active=True
        )
        
        self._sessions[session_id] = session
        
        self.audit_logger.log_operation(
            user.username, "CREATE_SESSION", "AUTHENTICATION", "SUCCESS",
            details={'session_id': session_id}
        )
        
        return session
    
    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate and refresh session"""
        self._cleanup_expired_sessions()
        
        session = self._sessions.get(session_id)
        if not session or not session.is_active:
            return None
        
        current_time = datetime.now()
        if current_time > session.expires_at:
            session.is_active = False
            return None
        
        # Refresh session
        session.last_activity = current_time
        session.expires_at = current_time + timedelta(seconds=session.user.session_timeout)
        
        return session
    
    def logout_user(self, session_id: str) -> bool:
        """Logout user and invalidate session"""
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            self.audit_logger.log_operation(
                session.user.username, "LOGOUT", "AUTHENTICATION", "SUCCESS",
                details={'session_id': session_id}
            )
            del self._sessions[session_id]
            return True
        return False
    
    def check_permission(self, session_id: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        session = self.validate_session(session_id)
        if not session:
            return False
        
        has_permission = permission in session.user.permissions
        
        self.audit_logger.log_operation(
            session.user.username, "PERMISSION_CHECK", permission.value,
            "SUCCESS" if has_permission else "DENIED",
            details={'session_id': session_id}
        )
        
        return has_permission