"""
Authentication and authorization decorators
"""

from functools import wraps
from typing import Callable, Any, Optional
from ..interfaces import Permission, AuthorizationException


def require_permission(permission: Permission):
    """Decorator to require specific permission for method execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs) -> Any:
            # Get session_id from method arguments or instance
            session_id = kwargs.get('session_id')
            if not session_id and hasattr(self, '_current_session_id'):
                session_id = self._current_session_id
            
            if not session_id:
                raise AuthorizationException(
                    "No active session found", "NO_SESSION"
                )
            
            # Check permission using authentication service
            auth_service = getattr(self, '_auth_service', None)
            if not auth_service:
                raise AuthorizationException(
                    "Authentication service not available", "NO_AUTH_SERVICE"
                )
            
            if not auth_service.check_permission(session_id, permission):
                raise AuthorizationException(
                    f"Permission {permission.value} required", "PERMISSION_DENIED"
                )
            
            return func(self, *args, **kwargs)
        return wrapper
    return decorator


def require_authentication(func: Callable) -> Callable:
    """Decorator to require valid authentication for method execution"""
    @wraps(func)
    def wrapper(self, *args, **kwargs) -> Any:
        # Get session_id from method arguments or instance
        session_id = kwargs.get('session_id')
        if not session_id and hasattr(self, '_current_session_id'):
            session_id = self._current_session_id
        
        if not session_id:
            raise AuthorizationException(
                "Authentication required", "NO_SESSION"
            )
        
        # Validate session using authentication service
        auth_service = getattr(self, '_auth_service', None)
        if not auth_service:
            raise AuthorizationException(
                "Authentication service not available", "NO_AUTH_SERVICE"
            )
        
        session = auth_service.validate_session(session_id)
        if not session:
            raise AuthorizationException(
                "Invalid or expired session", "INVALID_SESSION"
            )
        
        return func(self, *args, **kwargs)
    return wrapper


class AuthenticationMixin:
    """Mixin class to add authentication capabilities to services"""
    
    def __init__(self, auth_service=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_service = auth_service
        self._current_session_id: Optional[str] = None
    
    def set_session(self, session_id: str) -> None:
        """Set current session ID"""
        self._current_session_id = session_id
    
    def get_current_user(self):
        """Get current authenticated user"""
        if not self._current_session_id or not self._auth_service:
            return None
        
        session = self._auth_service.validate_session(self._current_session_id)
        return session.user if session else None
    
    def check_permission(self, permission: Permission) -> bool:
        """Check if current user has permission"""
        if not self._current_session_id or not self._auth_service:
            return False
        
        return self._auth_service.check_permission(self._current_session_id, permission)