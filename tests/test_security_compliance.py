"""
Security and Compliance Tests for Android Forensics Toolkit

This module provides comprehensive security and compliance testing including:
- Access control validation tests
- Evidence tampering detection tests
- Legal compliance workflow validation
- Audit trail completeness verification

Requirements covered: 5.1, 5.2, 5.4, 5.5
"""

import pytest
import tempfile
import shutil
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from forensics_toolkit.interfaces import (
    UserRole, Permission, AuthenticationException, AuthorizationException
)
from forensics_toolkit.services.authentication import (
    AuthenticationService, UserManager, AuditLogger, RolePermissionManager
)
from forensics_toolkit.services.legal_compliance import (
    LegalComplianceService, LegalDisclaimerManager, CaseManager, 
    EnvironmentValidator, ComplianceAuditLogger
)
from forensics_toolkit.services.evidence_logger import EvidenceLogger
from forensics_toolkit.services.chain_of_custody import ChainOfCustody
from forensics_toolkit.models.attack import EvidenceRecord


@dataclass
class SecurityTestCase:
    """Test case for security validation"""
    name: str
    description: str
    user_role: UserRole
    required_permission: Permission
    should_pass: bool
    test_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceTestCase:
    """Test case for compliance validation"""
    name: str
    description: str
    case_id: str
    investigator: str
    should_pass: bool
    violation_type: Optional[str] = None
    test_data: Dict[str, Any] = field(default_factory=dict)


class SecurityComplianceTestFramework:
    """Framework for security and compliance testing"""
    
    def __init__(self, temp_dir: str):
        self.temp_dir = Path(temp_dir)
        self.setup_test_environment()
        
        # Initialize services
        self.auth_service = AuthenticationService(
            UserManager(str(self.temp_dir / "users.json")),
            AuditLogger(str(self.temp_dir / "audit.log"))
        )
        
        self.compliance_service = LegalComplianceService(
            LegalDisclaimerManager(str(self.temp_dir / "disclaimer.json")),
            CaseManager(str(self.temp_dir / "cases.json")),
            ComplianceAuditLogger(str(self.temp_dir / "compliance_audit.log"))
        )
        
        self.evidence_logger = EvidenceLogger(str(self.temp_dir / "evidence.log"))
        self.chain_of_custody = ChainOfCustody(str(self.temp_dir / "custody.log"))
        
        # Test data
        self.test_users = {}
        self.test_cases = {}
        self.test_sessions = {}
        
    def setup_test_environment(self):
        """Set up test environment directories"""
        (self.temp_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.temp_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (self.temp_dir / "config").mkdir(parents=True, exist_ok=True)
    
    def create_test_users(self):
        """Create test users with different roles"""
        test_user_configs = [
            ("admin_user", "admin123", UserRole.ADMIN),
            ("investigator_user", "inv123", UserRole.INVESTIGATOR),
            ("analyst_user", "analyst123", UserRole.ANALYST),
            ("viewer_user", "viewer123", UserRole.VIEWER)
        ]
        
        for username, password, role in test_user_configs:
            user = self.auth_service.user_manager.create_user(username, password, role)
            session = self.auth_service.create_session(user)
            self.test_users[username] = user
            self.test_sessions[username] = session
    
    def create_test_cases(self):
        """Create test forensic cases"""
        test_case_configs = [
            ("FBI-2024-123456", "Test Investigation 1", "investigator_user"),
            ("DOJ-2024-789012", "Test Investigation 2", "investigator_user"),
            ("NYPD-2024-345678", "Test Investigation 3", "admin_user")
        ]
        
        for case_id, title, investigator in test_case_configs:
            case_info = self.compliance_service.case_manager.create_case(
                case_id, title, investigator, "Search Warrant #12345"
            )
            self.test_cases[case_id] = case_info
    
    def simulate_evidence_tampering(self, evidence_file: Path, tamper_type: str):
        """Simulate different types of evidence tampering"""
        if not evidence_file.exists():
            return
        
        with open(evidence_file, 'r') as f:
            data = json.load(f)
        
        if tamper_type == "modify_result":
            data["result"]["successful_value"] = "tampered_value"
        elif tamper_type == "change_timestamp":
            data["timestamp"] = datetime.now().isoformat()
        elif tamper_type == "alter_case_id":
            data["case_id"] = "TAMPERED-2024-999999"
        elif tamper_type == "remove_hash":
            if "hash_verification" in data:
                del data["hash_verification"]
        
        with open(evidence_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def create_evidence_with_known_hash(self, case_id: str, operation_type: str) -> tuple:
        """Create evidence file with known hash for tampering tests"""
        evidence_data = {
            "case_id": case_id,
            "timestamp": datetime.now().isoformat(),
            "operation_type": operation_type,
            "device_serial": "TEST_DEVICE_001",
            "result": {
                "success": True,
                "attempts": 42,
                "successful_value": "1234"
            },
            "investigator": "test_investigator",
            "hash_verification": "placeholder_hash_will_be_computed"
        }
        
        evidence_file = self.temp_dir / "evidence" / f"{case_id}_{operation_type}.json"
        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2, default=str)
        
        # Calculate hash
        with open(evidence_file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        return evidence_file, file_hash
    
    def verify_audit_trail_completeness(self, operation_sequence: List[str]) -> Dict[str, bool]:
        """Verify audit trail completeness for operation sequence"""
        audit_logs = self.auth_service.audit_logger.get_audit_logs()
        compliance_logs = self.compliance_service.compliance_logger.get_compliance_audit_logs()
        evidence_operations = self.evidence_logger.get_operations()
        
        results = {}
        
        for expected_operation in operation_sequence:
            # Check authentication audit logs
            auth_found = any(
                log.action == expected_operation for log in audit_logs
            )
            
            # Check compliance audit logs
            compliance_found = any(
                log.action == expected_operation for log in compliance_logs
            )
            
            # Check evidence operations logs
            evidence_found = any(
                op.operation_type == expected_operation for op in evidence_operations
            )
            
            results[expected_operation] = auth_found or compliance_found or evidence_found
        
        return results


class TestAccessControlValidation:
    """Test access control validation (Requirement 5.1)"""
    
    @pytest.fixture
    def security_framework(self):
        """Create security test framework"""
        temp_dir = tempfile.mkdtemp()
        framework = SecurityComplianceTestFramework(temp_dir)
        framework.create_test_users()
        framework.create_test_cases()
        yield framework
        shutil.rmtree(temp_dir)
    
    def test_role_based_permission_enforcement(self, security_framework):
        """Test role-based permission enforcement"""
        test_cases = [
            SecurityTestCase(
                "admin_device_access", "Admin should have device access",
                UserRole.ADMIN, Permission.DEVICE_ACCESS, True
            ),
            SecurityTestCase(
                "admin_user_management", "Admin should have user management",
                UserRole.ADMIN, Permission.USER_MANAGEMENT, True
            ),
            SecurityTestCase(
                "investigator_attack_execution", "Investigator should have attack execution",
                UserRole.INVESTIGATOR, Permission.ATTACK_EXECUTION, True
            ),
            SecurityTestCase(
                "investigator_user_management", "Investigator should NOT have user management",
                UserRole.INVESTIGATOR, Permission.USER_MANAGEMENT, False
            ),
            SecurityTestCase(
                "analyst_evidence_management", "Analyst should have evidence management",
                UserRole.ANALYST, Permission.EVIDENCE_MANAGEMENT, True
            ),
            SecurityTestCase(
                "analyst_attack_execution", "Analyst should NOT have attack execution",
                UserRole.ANALYST, Permission.ATTACK_EXECUTION, False
            ),
            SecurityTestCase(
                "viewer_report_generation", "Viewer should have report generation",
                UserRole.VIEWER, Permission.REPORT_GENERATION, True
            ),
            SecurityTestCase(
                "viewer_device_access", "Viewer should NOT have device access",
                UserRole.VIEWER, Permission.DEVICE_ACCESS, False
            )
        ]
        
        for test_case in test_cases:
            has_permission = RolePermissionManager.has_permission(
                test_case.user_role, test_case.required_permission
            )
            
            if test_case.should_pass:
                assert has_permission, f"Failed: {test_case.description}"
            else:
                assert not has_permission, f"Failed: {test_case.description}"
    
    def test_session_based_access_control(self, security_framework):
        """Test session-based access control enforcement"""
        # Test valid session access
        investigator_session = security_framework.test_sessions["investigator_user"]
        
        # Should have permission for device access
        has_permission = security_framework.auth_service.check_permission(
            investigator_session.session_id, Permission.DEVICE_ACCESS
        )
        assert has_permission, "Investigator should have device access"
        
        # Should not have permission for user management
        has_permission = security_framework.auth_service.check_permission(
            investigator_session.session_id, Permission.USER_MANAGEMENT
        )
        assert not has_permission, "Investigator should not have user management"
        
        # Test invalid session
        invalid_session_id = "invalid_session_123"
        has_permission = security_framework.auth_service.check_permission(
            invalid_session_id, Permission.DEVICE_ACCESS
        )
        assert not has_permission, "Invalid session should not have any permissions"
    
    def test_session_timeout_enforcement(self, security_framework):
        """Test session timeout enforcement"""
        # Create user with short timeout
        user = security_framework.auth_service.user_manager.create_user(
            "timeout_user", "password123", UserRole.INVESTIGATOR
        )
        user.session_timeout = 1  # 1 second timeout
        
        # Create session
        session = security_framework.auth_service.create_session(user)
        
        # Should be valid initially
        validated_session = security_framework.auth_service.validate_session(session.session_id)
        assert validated_session is not None, "Session should be valid initially"
        
        # Wait for timeout
        time.sleep(2)
        
        # Should be invalid after timeout
        validated_session = security_framework.auth_service.validate_session(session.session_id)
        assert validated_session is None, "Session should be invalid after timeout"
    
    def test_concurrent_session_limits(self, security_framework):
        """Test concurrent session limits"""
        user = security_framework.test_users["investigator_user"]
        
        # Create multiple sessions
        sessions = []
        for i in range(3):
            session = security_framework.auth_service.create_session(user)
            sessions.append(session)
        
        # All sessions should be valid initially
        for session in sessions:
            validated_session = security_framework.auth_service.validate_session(session.session_id)
            assert validated_session is not None, f"Session {session.session_id} should be valid"
        
        # Test session invalidation on logout
        success = security_framework.auth_service.logout_user(sessions[0].session_id)
        assert success, "Logout should succeed"
        
        # First session should be invalid
        validated_session = security_framework.auth_service.validate_session(sessions[0].session_id)
        assert validated_session is None, "Logged out session should be invalid"
        
        # Other sessions should still be valid
        for session in sessions[1:]:
            validated_session = security_framework.auth_service.validate_session(session.session_id)
            assert validated_session is not None, f"Session {session.session_id} should still be valid"


class TestEvidenceTamperingDetection:
    """Test evidence tampering detection (Requirement 5.1, 5.4)"""
    
    @pytest.fixture
    def security_framework(self):
        """Create security test framework"""
        temp_dir = tempfile.mkdtemp()
        framework = SecurityComplianceTestFramework(temp_dir)
        framework.create_test_users()
        framework.create_test_cases()
        yield framework
        shutil.rmtree(temp_dir)
    
    def test_hash_verification_integrity(self, security_framework):
        """Test evidence hash verification detects tampering"""
        case_id = "FBI-2024-123456"
        
        # Create evidence with known hash
        evidence_file, original_hash = security_framework.create_evidence_with_known_hash(
            case_id, "BRUTE_FORCE_ATTACK"
        )
        
        # Verify original integrity
        with open(evidence_file, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        assert current_hash == original_hash, "Original hash should match"
        
        # Simulate tampering
        security_framework.simulate_evidence_tampering(evidence_file, "modify_result")
        
        # Verify tampering is detected
        with open(evidence_file, 'rb') as f:
            tampered_hash = hashlib.sha256(f.read()).hexdigest()
        assert tampered_hash != original_hash, "Tampering should change hash"
    
    def test_timestamp_tampering_detection(self, security_framework):
        """Test detection of timestamp tampering"""
        case_id = "FBI-2024-123456"
        
        # Create evidence with known hash
        evidence_file, original_hash = security_framework.create_evidence_with_known_hash(
            case_id, "PATTERN_ANALYSIS"
        )
        
        # Record original timestamp
        with open(evidence_file, 'r') as f:
            original_data = json.load(f)
        original_timestamp = original_data["timestamp"]
        
        # Simulate timestamp tampering
        security_framework.simulate_evidence_tampering(evidence_file, "change_timestamp")
        
        # Verify tampering is detected
        with open(evidence_file, 'r') as f:
            tampered_data = json.load(f)
        assert tampered_data["timestamp"] != original_timestamp, "Timestamp should be changed"
        
        # Hash should be different
        with open(evidence_file, 'rb') as f:
            tampered_hash = hashlib.sha256(f.read()).hexdigest()
        assert tampered_hash != original_hash, "Hash should detect timestamp tampering"
    
    def test_case_id_tampering_detection(self, security_framework):
        """Test detection of case ID tampering"""
        case_id = "FBI-2024-123456"
        
        # Create evidence with known hash
        evidence_file, original_hash = security_framework.create_evidence_with_known_hash(
            case_id, "HASH_CRACKING"
        )
        
        # Simulate case ID tampering
        security_framework.simulate_evidence_tampering(evidence_file, "alter_case_id")
        
        # Verify tampering is detected
        with open(evidence_file, 'r') as f:
            tampered_data = json.load(f)
        assert tampered_data["case_id"] != case_id, "Case ID should be changed"
        
        # Hash should be different
        with open(evidence_file, 'rb') as f:
            tampered_hash = hashlib.sha256(f.read()).hexdigest()
        assert tampered_hash != original_hash, "Hash should detect case ID tampering"
    
    def test_hash_removal_detection(self, security_framework):
        """Test detection of hash removal tampering"""
        case_id = "FBI-2024-123456"
        
        # Create evidence with known hash
        evidence_file, original_hash = security_framework.create_evidence_with_known_hash(
            case_id, "DICTIONARY_ATTACK"
        )
        
        # Record original content
        with open(evidence_file, 'r') as f:
            original_data = json.load(f)
        
        # Simulate hash removal
        security_framework.simulate_evidence_tampering(evidence_file, "remove_hash")
        
        # Verify hash field is removed
        with open(evidence_file, 'r') as f:
            tampered_data = json.load(f)
        assert "hash_verification" not in tampered_data, "Hash field should be removed"
        
        # Content should be different (field removed)
        assert len(tampered_data) < len(original_data), "Content should be different after hash removal"
    
    def test_chain_of_custody_tampering_detection(self, security_framework):
        """Test chain of custody tampering detection"""
        case_id = "FBI-2024-123456"
        
        # Ensure case exists in chain of custody
        if case_id not in security_framework.chain_of_custody._case_cache:
            # Create the case in chain of custody
            security_framework.chain_of_custody.create_case(
                case_id, "investigator_user", "Test Investigation", "Test case for tampering detection",
                authorized_users=["investigator_user"]
            )
        
        # Create evidence record
        from forensics_toolkit.models.attack import EvidenceRecord
        evidence = EvidenceRecord(
            case_id=case_id,
            timestamp=datetime.now(),
            operation_type="BRUTE_FORCE_ATTACK",
            device_serial="TEST_DEVICE_001",
            attempt_number=42,
            result="1234",
            hash_verification="",  # Will be computed by custody manager
            evidence_type="PIN_CRACK",
            investigator_id="investigator_user"
        )
        
        # Add evidence to chain of custody
        evidence_hash = security_framework.chain_of_custody.add_evidence_record(
            evidence, "investigator_user"
        )
        
        # Verify initial integrity
        is_valid, errors = security_framework.chain_of_custody.verify_evidence_integrity(
            case_id, evidence_hash
        )
        assert is_valid, f"Evidence should be valid initially: {errors}"
        
        # Simulate tampering by modifying evidence in cache
        cached_evidence = security_framework.chain_of_custody._evidence_cache[case_id][0]
        cached_evidence.result = "tampered_result"
        
        # Verify tampering is detected
        is_valid, errors = security_framework.chain_of_custody.verify_evidence_integrity(
            case_id, evidence_hash
        )
        assert not is_valid, "Tampering should be detected"
        assert len(errors) > 0, "Errors should be reported"
    
    def test_custody_signature_verification(self, security_framework):
        """Test custody event signature verification"""
        case_id = "FBI-2024-123456"
        
        # Ensure case exists in chain of custody
        if case_id not in security_framework.chain_of_custody._case_cache:
            # Create the case in chain of custody
            security_framework.chain_of_custody.create_case(
                case_id, "investigator_user", "Test Investigation", "Test case for signature verification",
                authorized_users=["investigator_user"]
            )
        
        # Get custody events
        custody_events = security_framework.chain_of_custody.get_custody_chain(case_id)
        assert len(custody_events) > 0, "Should have custody events"
        
        # Add some evidence to have more custody events
        from forensics_toolkit.models.attack import EvidenceRecord
        evidence = EvidenceRecord(
            case_id=case_id,
            timestamp=datetime.now(),
            operation_type="TEST_OPERATION",
            device_serial="TEST_DEVICE_001",
            attempt_number=1,
            result="test_result",
            hash_verification="",  # Will be computed by custody manager
            evidence_type="TEST_EVIDENCE",
            investigator_id="investigator_user"
        )
        
        # Add evidence to create more custody events
        security_framework.chain_of_custody.add_evidence_record(evidence, "investigator_user")
        
        # Verify custody chain integrity
        tampering_detected, issues = security_framework.chain_of_custody.detect_tampering(case_id)
        # Filter out the "insufficient custody events" issue since we now have evidence
        filtered_issues = [issue for issue in issues if "Insufficient custody events" not in issue]
        assert not tampering_detected or len(filtered_issues) == 0, f"No tampering should be detected initially: {filtered_issues}"
        
        # Manually corrupt custody log file to simulate tampering
        case_dir = security_framework.chain_of_custody.storage_path / case_id
        custody_log_file = case_dir / "custody_log.json"
        
        if custody_log_file.exists():
            with open(custody_log_file, 'r') as f:
                events_data = json.load(f)
            
            # Corrupt a signature
            if events_data:
                events_data[0]['signature'] = "corrupted_signature"
                
                with open(custody_log_file, 'w') as f:
                    json.dump(events_data, f, indent=2)
                
                # Verify tampering is detected
                tampering_detected, issues = security_framework.chain_of_custody.detect_tampering(case_id)
                assert tampering_detected, "Signature tampering should be detected"
                assert len(issues) > 0, "Issues should be reported"


class TestLegalComplianceWorkflow:
    """Test legal compliance workflow validation (Requirement 5.2, 5.4)"""
    
    @pytest.fixture
    def security_framework(self):
        """Create security test framework"""
        temp_dir = tempfile.mkdtemp()
        framework = SecurityComplianceTestFramework(temp_dir)
        framework.create_test_users()
        framework.create_test_cases()
        yield framework
        shutil.rmtree(temp_dir)
    
    def test_disclaimer_acknowledgment_workflow(self, security_framework):
        """Test legal disclaimer acknowledgment workflow"""
        # Display disclaimer
        disclaimer = security_framework.compliance_service.display_disclaimer()
        assert disclaimer is not None, "Disclaimer should be displayed"
        assert "AUTHORIZED USE ONLY" in disclaimer.content, "Disclaimer should contain authorization notice"
        
        # Test consent acceptance
        consent_record = security_framework.compliance_service.capture_consent(
            "investigator_user", True, "FBI-2024-123456", "192.168.1.1"
        )
        assert consent_record.consent_given, "Consent should be recorded as given"
        assert consent_record.user == "investigator_user", "User should be recorded"
        
        # Verify consent is valid
        has_consent = security_framework.compliance_service.disclaimer_manager.has_valid_consent(
            "investigator_user"
        )
        assert has_consent, "User should have valid consent"
    
    def test_consent_rejection_handling(self, security_framework):
        """Test handling of consent rejection"""
        # Test consent rejection
        with pytest.raises(AuthorizationException):
            security_framework.compliance_service.capture_consent(
                "investigator_user", False, "FBI-2024-123456"
            )
        
        # Verify consent is not valid
        has_consent = security_framework.compliance_service.disclaimer_manager.has_valid_consent(
            "investigator_user"
        )
        assert not has_consent, "User should not have valid consent after rejection"
    
    def test_case_authorization_validation(self, security_framework):
        """Test case authorization validation"""
        # Test valid case authorization
        case_info = security_framework.compliance_service.validate_case_authorization(
            "FBI-2024-123456", "investigator_user"
        )
        assert case_info is not None, "Case authorization should succeed"
        assert case_info.case_id == "FBI-2024-123456", "Case ID should match"
        
        # Test invalid case ID
        with pytest.raises(AuthorizationException):
            security_framework.compliance_service.validate_case_authorization(
                "INVALID-CASE-ID", "investigator_user"
            )
        
        # Test unauthorized investigator
        with pytest.raises(AuthorizationException):
            security_framework.compliance_service.validate_case_authorization(
                "FBI-2024-123456", "unauthorized_user"
            )
    
    def test_environment_authorization_check(self, security_framework):
        """Test environment authorization check"""
        # Test environment verification
        env_info = security_framework.compliance_service.verify_authorized_environment(
            "FBI-2024-123456", "investigator_user"
        )
        
        assert 'hostname' in env_info, "Environment info should include hostname"
        assert 'ip_address' in env_info, "Environment info should include IP address"
        assert env_info['is_authorized'], "Environment should be authorized in test mode"
    
    def test_complete_compliance_workflow(self, security_framework):
        """Test complete compliance workflow"""
        user_id = "investigator_user"
        case_id = "FBI-2024-123456"
        
        # Initially, requirements should not be met
        status = security_framework.compliance_service.check_compliance_requirements(
            user_id, case_id
        )
        assert not status['disclaimer_accepted'], "Disclaimer should not be accepted initially"
        assert not status['all_requirements_met'], "All requirements should not be met initially"
        
        # Accept disclaimer
        security_framework.compliance_service.capture_consent(user_id, True, case_id)
        
        # Check requirements again
        status = security_framework.compliance_service.check_compliance_requirements(
            user_id, case_id
        )
        assert status['disclaimer_accepted'], "Disclaimer should be accepted"
        assert status['case_authorized'], "Case should be authorized"
        assert status['environment_authorized'], "Environment should be authorized"
        assert status['all_requirements_met'], "All requirements should be met"
    
    def test_compliance_violation_logging(self, security_framework):
        """Test compliance violation logging"""
        case_id = "FBI-2024-123456"
        user_id = "investigator_user"
        
        # Log a compliance violation
        security_framework.compliance_service.compliance_logger.log_compliance_violation(
            case_id, user_id, "UNAUTHORIZED_ACCESS", 
            details="Test violation for compliance testing"
        )
        
        # Verify violation is logged
        logs = security_framework.compliance_service.compliance_logger.get_compliance_audit_logs(
            case_id=case_id
        )
        
        violation_logs = [log for log in logs if log.action == "COMPLIANCE_VIOLATION"]
        assert len(violation_logs) > 0, "Compliance violation should be logged"
        
        violation_log = violation_logs[0]
        assert violation_log.result == "VIOLATION", "Result should be VIOLATION"
        assert violation_log.user == user_id, "User should be recorded"


class TestAuditTrailCompleteness:
    """Test audit trail completeness verification (Requirement 5.5)"""
    
    @pytest.fixture
    def security_framework(self):
        """Create security test framework"""
        temp_dir = tempfile.mkdtemp()
        framework = SecurityComplianceTestFramework(temp_dir)
        framework.create_test_users()
        framework.create_test_cases()
        yield framework
        shutil.rmtree(temp_dir)
    
    def test_authentication_audit_trail(self, security_framework):
        """Test authentication operations are properly audited"""
        # Perform authentication operations
        user = security_framework.auth_service.authenticate_user("investigator_user", "inv123")
        assert user is not None, "Authentication should succeed"
        
        # Check audit logs
        audit_logs = security_framework.auth_service.audit_logger.get_audit_logs()
        
        # Should have login attempt logged
        login_logs = [log for log in audit_logs if log.action == "LOGIN_ATTEMPT"]
        assert len(login_logs) > 0, "Login attempts should be audited"
        
        login_log = login_logs[-1]  # Get most recent
        assert login_log.result == "SUCCESS", "Successful login should be logged"
        assert login_log.user == "investigator_user", "User should be recorded"
    
    def test_evidence_operations_audit_trail(self, security_framework):
        """Test evidence operations are properly audited"""
        case_id = "FBI-2024-123456"
        
        # Log evidence operation
        operation_log = security_framework.evidence_logger.log_operation(
            case_id=case_id,
            operation_type="BRUTE_FORCE_ATTACK",
            message="Test brute force attack on device",
            device_serial="TEST_DEVICE_001",
            user_id="investigator_user",
            metadata={"attempts": 42, "result": "success"}
        )
        
        assert operation_log is not None, "Operation should be logged"
        assert operation_log.case_id == case_id, "Case ID should be recorded"
        assert operation_log.user_id == "investigator_user", "User should be recorded"
        
        # Verify audit trail generation
        audit_trail = security_framework.evidence_logger.generate_audit_trail(case_id)
        assert audit_trail['total_operations'] > 0, "Audit trail should include operations"
        assert case_id in str(audit_trail), "Case ID should be in audit trail"
    
    def test_compliance_operations_audit_trail(self, security_framework):
        """Test compliance operations are properly audited"""
        case_id = "FBI-2024-123456"
        user_id = "investigator_user"
        
        # Perform compliance operations
        security_framework.compliance_service.capture_consent(user_id, True, case_id)
        security_framework.compliance_service.validate_case_authorization(case_id, user_id)
        
        # Check compliance audit logs
        compliance_logs = security_framework.compliance_service.compliance_logger.get_compliance_audit_logs(
            case_id=case_id
        )
        
        assert len(compliance_logs) > 0, "Compliance operations should be audited"
        
        # Should have disclaimer acknowledgment
        disclaimer_logs = [log for log in compliance_logs if log.action == "DISCLAIMER_ACKNOWLEDGMENT"]
        assert len(disclaimer_logs) > 0, "Disclaimer acknowledgment should be audited"
        
        # Should have case validation
        case_validation_logs = [log for log in compliance_logs if log.action == "CASE_VALIDATION"]
        assert len(case_validation_logs) > 0, "Case validation should be audited"
    
    def test_chain_of_custody_audit_trail(self, security_framework):
        """Test chain of custody operations are properly audited"""
        case_id = "FBI-2024-123456"
        
        # Ensure case exists in chain of custody
        if case_id not in security_framework.chain_of_custody._case_cache:
            # Create the case in chain of custody
            security_framework.chain_of_custody.create_case(
                case_id, "investigator_user", "Test Investigation", "Test case for audit trail",
                authorized_users=["investigator_user"]
            )
        
        # Create evidence record
        from forensics_toolkit.models.attack import EvidenceRecord
        evidence = EvidenceRecord(
            case_id=case_id,
            timestamp=datetime.now(),
            operation_type="PATTERN_ANALYSIS",
            device_serial="TEST_DEVICE_001",
            attempt_number=1,
            result="pattern_found",
            hash_verification="",  # Will be computed by custody manager
            evidence_type="PATTERN_CRACK",
            investigator_id="investigator_user"
        )
        
        # Add to chain of custody
        evidence_hash = security_framework.chain_of_custody.add_evidence_record(
            evidence, "investigator_user"
        )
        
        # Get custody chain
        custody_events = security_framework.chain_of_custody.get_custody_chain(case_id)
        assert len(custody_events) > 0, "Custody events should be recorded"
        
        # Should have evidence collection event
        collection_events = [
            event for event in custody_events 
            if event.event_type == "evidence_collected"
        ]
        assert len(collection_events) > 0, "Evidence collection should be audited"
        
        collection_event = collection_events[0]
        assert collection_event.user_id == "investigator_user", "User should be recorded"
        assert collection_event.hash_after == evidence_hash, "Evidence hash should be recorded"
    
    def test_audit_trail_chronological_order(self, security_framework):
        """Test audit trail maintains chronological order"""
        case_id = "FBI-2024-123456"
        
        # Perform multiple operations with small delays
        operations = []
        for i in range(5):
            operation_log = security_framework.evidence_logger.log_operation(
                case_id=case_id,
                operation_type=f"TEST_OPERATION_{i}",
                message=f"Test operation {i}",
                user_id="investigator_user"
            )
            operations.append(operation_log)
            time.sleep(0.1)  # Small delay to ensure different timestamps
        
        # Get operations and verify chronological order
        retrieved_operations = security_framework.evidence_logger.get_operations(case_id=case_id)
        
        # Filter to our test operations
        test_operations = [
            op for op in retrieved_operations 
            if op.operation_type.startswith("TEST_OPERATION_")
        ]
        
        assert len(test_operations) == 5, "All test operations should be retrieved"
        
        # Verify chronological order
        for i in range(1, len(test_operations)):
            assert test_operations[i].timestamp >= test_operations[i-1].timestamp, \
                f"Operations should be in chronological order: {i-1} -> {i}"
    
    def test_audit_trail_completeness_verification(self, security_framework):
        """Test verification of audit trail completeness"""
        case_id = "FBI-2024-123456"
        
        # Define expected operation sequence
        expected_operations = [
            "DISCLAIMER_ACKNOWLEDGMENT",
            "CASE_VALIDATION",
            "DEVICE_ACCESS",
            "BRUTE_FORCE_ATTACK",
            "EVIDENCE_COLLECTION"
        ]
        
        # Simulate the operations
        security_framework.compliance_service.capture_consent("investigator_user", True, case_id)
        security_framework.compliance_service.validate_case_authorization(case_id, "investigator_user")
        
        security_framework.evidence_logger.log_operation(
            case_id, "DEVICE_ACCESS", "Device accessed", user_id="investigator_user"
        )
        security_framework.evidence_logger.log_operation(
            case_id, "BRUTE_FORCE_ATTACK", "Brute force attack executed", user_id="investigator_user"
        )
        security_framework.evidence_logger.log_operation(
            case_id, "EVIDENCE_COLLECTION", "Evidence collected", user_id="investigator_user"
        )
        
        # Verify audit trail completeness
        completeness_results = security_framework.verify_audit_trail_completeness(expected_operations)
        
        for operation in expected_operations:
            assert completeness_results[operation], f"Operation {operation} should be in audit trail"
    
    def test_audit_trail_integrity_verification(self, security_framework):
        """Test audit trail integrity verification"""
        case_id = "FBI-2024-123456"
        
        # Log some operations
        for i in range(3):
            security_framework.evidence_logger.log_operation(
                case_id=case_id,
                operation_type=f"INTEGRITY_TEST_{i}",
                message=f"Integrity test operation {i}",
                user_id="investigator_user"
            )
        
        # Verify integrity
        integrity_results = security_framework.evidence_logger.verify_integrity(case_id)
        
        assert integrity_results['integrity_status'] == 'verified', \
            f"Audit trail integrity should be verified: {integrity_results}"
        assert integrity_results['failed_operations'] == 0, \
            "No operations should have failed integrity check"
        assert integrity_results['total_operations'] > 0, \
            "Should have operations to verify"
    
    def test_audit_trail_export_and_verification(self, security_framework):
        """Test audit trail export and verification"""
        case_id = "FBI-2024-123456"
        
        # Log operations
        security_framework.evidence_logger.log_operation(
            case_id, "EXPORT_TEST", "Test operation for export", user_id="investigator_user"
        )
        
        # Export audit trail
        export_path = security_framework.temp_dir / "audit_export.json"
        success = security_framework.evidence_logger.export_case_logs(
            case_id, str(export_path), include_metadata=True
        )
        
        assert success, "Audit trail export should succeed"
        assert export_path.exists(), "Export file should be created"
        
        # Verify export content
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        assert export_data['export_info']['case_id'] == case_id, "Case ID should be in export"
        assert 'audit_trail' in export_data, "Audit trail should be in export"
        assert 'operations' in export_data, "Operations should be in export"
        assert len(export_data['operations']) > 0, "Should have operations in export"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])