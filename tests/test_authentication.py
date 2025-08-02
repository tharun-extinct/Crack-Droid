"""
Unit tests for authentication and authorization system
"""

import unittest
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path

from forensics_toolkit.interfaces import (
    UserRole, Permission, AuthenticationException, AuthorizationException
)
from forensics_toolkit.services.authentication import (
    RolePermissionManager, UserManager, AuditLogger, AuthenticationService
)
from forensics_toolkit.services.auth_decorators import (
    require_permission, require_authentication, AuthenticationMixin
)


class TestRolePermissionManager(unittest.TestCase):
    """Test role-based permission management"""
    
    def test_admin_permissions(self):
        """Test admin role has all permissions"""
        permissions = RolePermissionManager.get_permissions_for_role(UserRole.ADMIN)
        expected_permissions = [
            Permission.DEVICE_ACCESS,
            Permission.ATTACK_EXECUTION,
            Permission.EVIDENCE_MANAGEMENT,
            Permission.USER_MANAGEMENT,
            Permission.SYSTEM_CONFIG,
            Permission.REPORT_GENERATION
        ]
        self.assertEqual(set(permissions), set(expected_permissions))
    
    def test_investigator_permissions(self):
        """Test investigator role permissions"""
        permissions = RolePermissionManager.get_permissions_for_role(UserRole.INVESTIGATOR)
        expected_permissions = [
            Permission.DEVICE_ACCESS,
            Permission.ATTACK_EXECUTION,
            Permission.EVIDENCE_MANAGEMENT,
            Permission.REPORT_GENERATION
        ]
        self.assertEqual(set(permissions), set(expected_permissions))
        self.assertNotIn(Permission.USER_MANAGEMENT, permissions)
        self.assertNotIn(Permission.SYSTEM_CONFIG, permissions)
    
    def test_analyst_permissions(self):
        """Test analyst role permissions"""
        permissions = RolePermissionManager.get_permissions_for_role(UserRole.ANALYST)
        expected_permissions = [
            Permission.DEVICE_ACCESS,
            Permission.EVIDENCE_MANAGEMENT,
            Permission.REPORT_GENERATION
        ]
        self.assertEqual(set(permissions), set(expected_permissions))
        self.assertNotIn(Permission.ATTACK_EXECUTION, permissions)
    
    def test_viewer_permissions(self):
        """Test viewer role permissions"""
        permissions = RolePermissionManager.get_permissions_for_role(UserRole.VIEWER)
        self.assertEqual(permissions, [Permission.REPORT_GENERATION])
    
    def test_has_permission(self):
        """Test permission checking"""
        self.assertTrue(
            RolePermissionManager.has_permission(UserRole.ADMIN, Permission.USER_MANAGEMENT)
        )
        self.assertFalse(
            RolePermissionManager.has_permission(UserRole.VIEWER, Permission.ATTACK_EXECUTION)
        )


class TestUserManager(unittest.TestCase):
    """Test user management functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.users_file = os.path.join(self.temp_dir, "test_users.json")
        self.user_manager = UserManager(self.users_file)
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.users_file):
            os.remove(self.users_file)
        os.rmdir(self.temp_dir)
    
    def test_create_user(self):
        """Test user creation"""
        user = self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.role, UserRole.INVESTIGATOR)
        self.assertIn(Permission.DEVICE_ACCESS, user.permissions)
        self.assertTrue(user.is_active)
        self.assertIsInstance(user.created_at, datetime)
    
    def test_create_duplicate_user(self):
        """Test creating duplicate user raises exception"""
        self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        with self.assertRaises(AuthenticationException):
            self.user_manager.create_user("testuser", "password456", UserRole.ADMIN)
    
    def test_get_user(self):
        """Test retrieving user"""
        created_user = self.user_manager.create_user("testuser", "password123", UserRole.ANALYST)
        retrieved_user = self.user_manager.get_user("testuser")
        
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(retrieved_user.username, created_user.username)
        self.assertEqual(retrieved_user.role, created_user.role)
    
    def test_get_nonexistent_user(self):
        """Test retrieving non-existent user returns None"""
        user = self.user_manager.get_user("nonexistent")
        self.assertIsNone(user)
    
    def test_update_user(self):
        """Test updating user information"""
        self.user_manager.create_user("testuser", "password123", UserRole.VIEWER)
        
        success = self.user_manager.update_user("testuser", role=UserRole.ADMIN, is_active=False)
        self.assertTrue(success)
        
        updated_user = self.user_manager.get_user("testuser")
        self.assertEqual(updated_user.role, UserRole.ADMIN)
        self.assertFalse(updated_user.is_active)
        self.assertIn(Permission.USER_MANAGEMENT, updated_user.permissions)
    
    def test_delete_user(self):
        """Test user deletion"""
        self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        success = self.user_manager.delete_user("testuser")
        self.assertTrue(success)
        
        user = self.user_manager.get_user("testuser")
        self.assertIsNone(user)
    
    def test_list_users(self):
        """Test listing all users"""
        self.user_manager.create_user("user1", "password123", UserRole.ADMIN)
        self.user_manager.create_user("user2", "password456", UserRole.INVESTIGATOR)
        
        users = self.user_manager.list_users()
        self.assertEqual(len(users), 2)
        usernames = [user.username for user in users]
        self.assertIn("user1", usernames)
        self.assertIn("user2", usernames)
    
    def test_verify_password(self):
        """Test password verification"""
        self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        self.assertTrue(self.user_manager.verify_password("testuser", "password123"))
        self.assertFalse(self.user_manager.verify_password("testuser", "wrongpassword"))
        self.assertFalse(self.user_manager.verify_password("nonexistent", "password123"))


class TestAuditLogger(unittest.TestCase):
    """Test audit logging functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_file = os.path.join(self.temp_dir, "test_audit.log")
        self.audit_logger = AuditLogger(self.audit_file)
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.audit_file):
            os.remove(self.audit_file)
        os.rmdir(self.temp_dir)
    
    def test_log_access_attempt(self):
        """Test logging access attempts"""
        self.audit_logger.log_access_attempt("testuser", True, "192.168.1.1")
        self.audit_logger.log_access_attempt("baduser", False, "192.168.1.2")
        
        logs = self.audit_logger.get_audit_logs()
        self.assertEqual(len(logs), 2)
        
        success_log = next(log for log in logs if log.user == "testuser")
        self.assertEqual(success_log.action, "LOGIN_ATTEMPT")
        self.assertEqual(success_log.result, "SUCCESS")
        self.assertEqual(success_log.ip_address, "192.168.1.1")
        
        failure_log = next(log for log in logs if log.user == "baduser")
        self.assertEqual(failure_log.result, "FAILURE")
    
    def test_log_operation(self):
        """Test logging user operations"""
        self.audit_logger.log_operation(
            "testuser", "DEVICE_ACCESS", "ANDROID_DEVICE", "SUCCESS",
            ip_address="192.168.1.1", details={"device_id": "ABC123"}
        )
        
        logs = self.audit_logger.get_audit_logs()
        self.assertEqual(len(logs), 1)
        
        log = logs[0]
        self.assertEqual(log.user, "testuser")
        self.assertEqual(log.action, "DEVICE_ACCESS")
        self.assertEqual(log.resource, "ANDROID_DEVICE")
        self.assertEqual(log.result, "SUCCESS")
        self.assertEqual(log.details["device_id"], "ABC123")
    
    def test_get_audit_logs_with_date_filter(self):
        """Test retrieving audit logs with date filtering"""
        # Log entries at different times
        self.audit_logger.log_operation("user1", "ACTION1", "RESOURCE1", "SUCCESS")
        
        # Get logs from future date (should be empty)
        future_date = datetime.now() + timedelta(days=1)
        logs = self.audit_logger.get_audit_logs(start_date=future_date)
        self.assertEqual(len(logs), 0)
        
        # Get logs from past date (should include all)
        past_date = datetime.now() - timedelta(days=1)
        logs = self.audit_logger.get_audit_logs(start_date=past_date)
        self.assertEqual(len(logs), 1)


class TestAuthenticationService(unittest.TestCase):
    """Test authentication service functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.users_file = os.path.join(self.temp_dir, "test_users.json")
        self.audit_file = os.path.join(self.temp_dir, "test_audit.log")
        
        self.user_manager = UserManager(self.users_file)
        self.audit_logger = AuditLogger(self.audit_file)
        self.auth_service = AuthenticationService(self.user_manager, self.audit_logger)
    
    def tearDown(self):
        """Clean up test environment"""
        for file in [self.users_file, self.audit_file]:
            if os.path.exists(file):
                os.remove(file)
        os.rmdir(self.temp_dir)
    
    def test_default_admin_creation(self):
        """Test default admin user is created"""
        admin_user = self.user_manager.get_user("admin")
        self.assertIsNotNone(admin_user)
        self.assertEqual(admin_user.role, UserRole.ADMIN)
    
    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        user = self.auth_service.authenticate_user("testuser", "password123")
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "testuser")
    
    def test_authenticate_user_failure(self):
        """Test failed user authentication"""
        self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        user = self.auth_service.authenticate_user("testuser", "wrongpassword")
        self.assertIsNone(user)
        
        user = self.auth_service.authenticate_user("nonexistent", "password123")
        self.assertIsNone(user)
    
    def test_create_and_validate_session(self):
        """Test session creation and validation"""
        user = self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        
        session = self.auth_service.create_session(user)
        self.assertIsNotNone(session.session_id)
        self.assertEqual(session.user.username, "testuser")
        self.assertTrue(session.is_active)
        
        # Validate session
        validated_session = self.auth_service.validate_session(session.session_id)
        self.assertIsNotNone(validated_session)
        self.assertEqual(validated_session.session_id, session.session_id)
    
    def test_session_expiration(self):
        """Test session expiration"""
        user = self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        user.session_timeout = 1  # 1 second timeout
        
        session = self.auth_service.create_session(user)
        
        # Wait for session to expire
        import time
        time.sleep(2)
        
        validated_session = self.auth_service.validate_session(session.session_id)
        self.assertIsNone(validated_session)
    
    def test_logout_user(self):
        """Test user logout"""
        user = self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        session = self.auth_service.create_session(user)
        
        success = self.auth_service.logout_user(session.session_id)
        self.assertTrue(success)
        
        # Session should be invalid after logout
        validated_session = self.auth_service.validate_session(session.session_id)
        self.assertIsNone(validated_session)
    
    def test_check_permission(self):
        """Test permission checking"""
        user = self.user_manager.create_user("testuser", "password123", UserRole.INVESTIGATOR)
        session = self.auth_service.create_session(user)
        
        # Investigator should have device access
        has_permission = self.auth_service.check_permission(
            session.session_id, Permission.DEVICE_ACCESS
        )
        self.assertTrue(has_permission)
        
        # Investigator should not have user management permission
        has_permission = self.auth_service.check_permission(
            session.session_id, Permission.USER_MANAGEMENT
        )
        self.assertFalse(has_permission)


class TestAuthenticationDecorators(unittest.TestCase):
    """Test authentication decorators"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.users_file = os.path.join(self.temp_dir, "test_users.json")
        self.audit_file = os.path.join(self.temp_dir, "test_audit.log")
        
        self.user_manager = UserManager(self.users_file)
        self.audit_logger = AuditLogger(self.audit_file)
        self.auth_service = AuthenticationService(self.user_manager, self.audit_logger)
    
    def tearDown(self):
        """Clean up test environment"""
        for file in [self.users_file, self.audit_file]:
            if os.path.exists(file):
                os.remove(file)
        os.rmdir(self.temp_dir)
    
    def test_authentication_mixin(self):
        """Test authentication mixin functionality"""
        
        class TestService(AuthenticationMixin):
            @require_authentication
            def protected_method(self):
                return "success"
            
            @require_permission(Permission.USER_MANAGEMENT)
            def admin_method(self):
                return "admin_success"
        
        service = TestService(auth_service=self.auth_service)
        
        # Test without authentication
        with self.assertRaises(AuthorizationException):
            service.protected_method()
        
        # Test with authentication
        user = self.user_manager.create_user("testuser", "password123", UserRole.ADMIN)
        session = self.auth_service.create_session(user)
        service.set_session(session.session_id)
        
        result = service.protected_method()
        self.assertEqual(result, "success")
        
        result = service.admin_method()
        self.assertEqual(result, "admin_success")
        
        # Test with insufficient permissions
        user2 = self.user_manager.create_user("viewer", "password123", UserRole.VIEWER)
        session2 = self.auth_service.create_session(user2)
        service.set_session(session2.session_id)
        
        with self.assertRaises(AuthorizationException):
            service.admin_method()


if __name__ == '__main__':
    unittest.main()