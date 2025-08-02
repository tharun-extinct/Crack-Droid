"""
Unit tests for legal compliance workflow
"""

import unittest
import tempfile
import os
import json
from datetime import datetime, timedelta
from pathlib import Path

from forensics_toolkit.interfaces import AuthorizationException
from forensics_toolkit.services.legal_compliance import (
    LegalDisclaimerManager, CaseManager, EnvironmentValidator,
    ComplianceAuditLogger, LegalComplianceService,
    LegalDisclaimer, ConsentRecord, CaseInfo, ComplianceAuditEntry
)


class TestLegalDisclaimerManager(unittest.TestCase):
    """Test legal disclaimer management"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.disclaimer_file = os.path.join(self.temp_dir, "test_disclaimer.json")
        self.disclaimer_manager = LegalDisclaimerManager(self.disclaimer_file)
    
    def tearDown(self):
        """Clean up test environment"""
        for file in [self.disclaimer_file, 
                    os.path.join(self.temp_dir, "consent_records.json")]:
            if os.path.exists(file):
                os.remove(file)
        os.rmdir(self.temp_dir)
    
    def test_default_disclaimer_creation(self):
        """Test default disclaimer is created"""
        disclaimer = self.disclaimer_manager.get_disclaimer()
        self.assertIsNotNone(disclaimer)
        self.assertEqual(disclaimer.version, "1.0")
        self.assertTrue(disclaimer.requires_acknowledgment)
        self.assertIn("AUTHORIZED USE ONLY", disclaimer.content)
    
    def test_update_disclaimer(self):
        """Test updating disclaimer"""
        new_disclaimer = self.disclaimer_manager.update_disclaimer(
            "Updated Legal Notice",
            "Updated content for testing",
            "2.0"
        )
        
        self.assertEqual(new_disclaimer.title, "Updated Legal Notice")
        self.assertEqual(new_disclaimer.version, "2.0")
        self.assertEqual(new_disclaimer.content, "Updated content for testing")
    
    def test_record_consent(self):
        """Test recording user consent"""
        consent_record = self.disclaimer_manager.record_consent(
            "testuser", True, "192.168.1.1", "TestAgent/1.0"
        )
        
        self.assertEqual(consent_record.user, "testuser")
        self.assertTrue(consent_record.consent_given)
        self.assertEqual(consent_record.ip_address, "192.168.1.1")
        self.assertEqual(consent_record.disclaimer_version, "1.0")
    
    def test_has_valid_consent(self):
        """Test checking valid consent"""
        # No consent initially
        self.assertFalse(self.disclaimer_manager.has_valid_consent("testuser"))
        
        # Record consent
        self.disclaimer_manager.record_consent("testuser", True)
        self.assertTrue(self.disclaimer_manager.has_valid_consent("testuser"))
        
        # Record rejection
        self.disclaimer_manager.record_consent("testuser2", False)
        self.assertFalse(self.disclaimer_manager.has_valid_consent("testuser2"))
    
    def test_consent_version_tracking(self):
        """Test consent tracking across disclaimer versions"""
        # Give consent for version 1.0
        self.disclaimer_manager.record_consent("testuser", True)
        self.assertTrue(self.disclaimer_manager.has_valid_consent("testuser"))
        
        # Update disclaimer to version 2.0
        self.disclaimer_manager.update_disclaimer(
            "New Disclaimer", "New content", "2.0"
        )
        
        # Old consent should not be valid for new version
        self.assertFalse(self.disclaimer_manager.has_valid_consent("testuser"))
        
        # Give consent for new version
        self.disclaimer_manager.record_consent("testuser", True)
        self.assertTrue(self.disclaimer_manager.has_valid_consent("testuser"))
    
    def test_consent_history(self):
        """Test getting consent history"""
        self.disclaimer_manager.record_consent("testuser", False)
        self.disclaimer_manager.record_consent("testuser", True)
        
        history = self.disclaimer_manager.get_consent_history("testuser")
        self.assertEqual(len(history), 2)
        self.assertFalse(history[0].consent_given)
        self.assertTrue(history[1].consent_given)


class TestCaseManager(unittest.TestCase):
    """Test case management functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.cases_file = os.path.join(self.temp_dir, "test_cases.json")
        self.case_manager = CaseManager(self.cases_file)
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.cases_file):
            os.remove(self.cases_file)
        os.rmdir(self.temp_dir)
    
    def test_validate_case_id_format(self):
        """Test case ID format validation"""
        valid_ids = ["FBI-2024-123456", "DOJ-2023-987654", "NYPD-2024-111111"]
        invalid_ids = ["invalid", "FBI-24-123", "FBI-2024-12345", "fbi-2024-123456"]
        
        for case_id in valid_ids:
            self.assertTrue(self.case_manager.validate_case_id_format(case_id))
        
        for case_id in invalid_ids:
            self.assertFalse(self.case_manager.validate_case_id_format(case_id))
    
    def test_create_case(self):
        """Test case creation"""
        case_info = self.case_manager.create_case(
            "FBI-2024-123456",
            "Test Investigation",
            "Agent Smith",
            "Search Warrant #12345",
            warrant_number="SW-12345"
        )
        
        self.assertEqual(case_info.case_id, "FBI-2024-123456")
        self.assertEqual(case_info.case_title, "Test Investigation")
        self.assertEqual(case_info.investigator, "Agent Smith")
        self.assertEqual(case_info.warrant_number, "SW-12345")
        self.assertEqual(case_info.status, "ACTIVE")
    
    def test_create_case_invalid_id(self):
        """Test creating case with invalid ID raises exception"""
        with self.assertRaises(AuthorizationException):
            self.case_manager.create_case(
                "invalid-id", "Test", "Agent", "Authority"
            )
    
    def test_create_duplicate_case(self):
        """Test creating duplicate case raises exception"""
        self.case_manager.create_case(
            "FBI-2024-123456", "Test", "Agent", "Authority"
        )
        
        with self.assertRaises(AuthorizationException):
            self.case_manager.create_case(
                "FBI-2024-123456", "Test2", "Agent2", "Authority2"
            )
    
    def test_get_case(self):
        """Test retrieving case"""
        created_case = self.case_manager.create_case(
            "FBI-2024-123456", "Test", "Agent", "Authority"
        )
        
        retrieved_case = self.case_manager.get_case("FBI-2024-123456")
        self.assertIsNotNone(retrieved_case)
        self.assertEqual(retrieved_case.case_id, created_case.case_id)
        
        # Non-existent case
        self.assertIsNone(self.case_manager.get_case("FBI-2024-999999"))
    
    def test_validate_case(self):
        """Test case validation"""
        self.case_manager.create_case(
            "FBI-2024-123456", "Test", "Agent Smith", "Authority"
        )
        
        # Valid case and investigator
        self.assertTrue(self.case_manager.validate_case("FBI-2024-123456", "Agent Smith"))
        
        # Wrong investigator
        self.assertFalse(self.case_manager.validate_case("FBI-2024-123456", "Agent Jones"))
        
        # Non-existent case
        self.assertFalse(self.case_manager.validate_case("FBI-2024-999999", "Agent Smith"))
    
    def test_list_cases(self):
        """Test listing cases"""
        self.case_manager.create_case("FBI-2024-111111", "Case1", "Agent1", "Auth1")
        self.case_manager.create_case("FBI-2024-222222", "Case2", "Agent2", "Auth2")
        self.case_manager.create_case("FBI-2024-333333", "Case3", "Agent1", "Auth3")
        
        # List all cases
        all_cases = self.case_manager.list_cases()
        self.assertEqual(len(all_cases), 3)
        
        # List cases for specific investigator
        agent1_cases = self.case_manager.list_cases("Agent1")
        self.assertEqual(len(agent1_cases), 2)
        
        agent2_cases = self.case_manager.list_cases("Agent2")
        self.assertEqual(len(agent2_cases), 1)
    
    def test_update_case_status(self):
        """Test updating case status"""
        self.case_manager.create_case("FBI-2024-123456", "Test", "Agent", "Authority")
        
        success = self.case_manager.update_case_status("FBI-2024-123456", "CLOSED")
        self.assertTrue(success)
        
        case = self.case_manager.get_case("FBI-2024-123456")
        self.assertEqual(case.status, "CLOSED")
        
        # Non-existent case
        success = self.case_manager.update_case_status("FBI-2024-999999", "CLOSED")
        self.assertFalse(success)


class TestEnvironmentValidator(unittest.TestCase):
    """Test environment validation"""
    
    def test_get_system_info(self):
        """Test getting system information"""
        system_info = EnvironmentValidator.get_system_info()
        self.assertIn('hostname', system_info)
        self.assertIn('ip_address', system_info)
        self.assertIsInstance(system_info['hostname'], str)
        self.assertIsInstance(system_info['ip_address'], str)
    
    def test_is_authorized_environment(self):
        """Test environment authorization check"""
        # For testing, this should return True (development mode)
        self.assertTrue(EnvironmentValidator.is_authorized_environment())
    
    def test_validate_environment(self):
        """Test environment validation"""
        env_info = EnvironmentValidator.validate_environment()
        
        required_keys = ['hostname', 'ip_address', 'is_authorized', 'timestamp']
        for key in required_keys:
            self.assertIn(key, env_info)
        
        self.assertIsInstance(env_info['is_authorized'], bool)


class TestComplianceAuditLogger(unittest.TestCase):
    """Test compliance audit logging"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_file = os.path.join(self.temp_dir, "test_compliance_audit.log")
        self.audit_logger = ComplianceAuditLogger(self.audit_file)
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.audit_file):
            os.remove(self.audit_file)
        os.rmdir(self.temp_dir)
    
    def test_log_disclaimer_acknowledgment(self):
        """Test logging disclaimer acknowledgment"""
        self.audit_logger.log_disclaimer_acknowledgment(
            "FBI-2024-123456", "testuser", True, ip_address="192.168.1.1"
        )
        
        logs = self.audit_logger.get_compliance_audit_logs()
        self.assertEqual(len(logs), 1)
        
        log = logs[0]
        self.assertEqual(log.case_id, "FBI-2024-123456")
        self.assertEqual(log.user, "testuser")
        self.assertEqual(log.action, "DISCLAIMER_ACKNOWLEDGMENT")
        self.assertEqual(log.result, "ACCEPTED")
    
    def test_log_case_validation(self):
        """Test logging case validation"""
        self.audit_logger.log_case_validation(
            "FBI-2024-123456", "testuser", True, reason="Valid case"
        )
        
        logs = self.audit_logger.get_compliance_audit_logs()
        self.assertEqual(len(logs), 1)
        
        log = logs[0]
        self.assertEqual(log.action, "CASE_VALIDATION")
        self.assertEqual(log.result, "VALID")
        self.assertEqual(log.details["reason"], "Valid case")
    
    def test_log_environment_check(self):
        """Test logging environment check"""
        self.audit_logger.log_environment_check(
            "FBI-2024-123456", "testuser", True, hostname="forensic-lab"
        )
        
        logs = self.audit_logger.get_compliance_audit_logs()
        self.assertEqual(len(logs), 1)
        
        log = logs[0]
        self.assertEqual(log.action, "ENVIRONMENT_CHECK")
        self.assertEqual(log.result, "AUTHORIZED")
    
    def test_log_compliance_violation(self):
        """Test logging compliance violation"""
        self.audit_logger.log_compliance_violation(
            "FBI-2024-123456", "testuser", "UNAUTHORIZED_ACCESS", 
            details="Attempted access without proper authorization"
        )
        
        logs = self.audit_logger.get_compliance_audit_logs()
        self.assertEqual(len(logs), 1)
        
        log = logs[0]
        self.assertEqual(log.action, "COMPLIANCE_VIOLATION")
        self.assertEqual(log.result, "VIOLATION")
    
    def test_get_compliance_audit_logs_filtered(self):
        """Test getting filtered compliance audit logs"""
        # Log entries for different cases
        self.audit_logger.log_case_validation("FBI-2024-111111", "user1", True)
        self.audit_logger.log_case_validation("FBI-2024-222222", "user2", True)
        self.audit_logger.log_case_validation("FBI-2024-111111", "user1", False)
        
        # Get all logs
        all_logs = self.audit_logger.get_compliance_audit_logs()
        self.assertEqual(len(all_logs), 3)
        
        # Get logs for specific case
        case_logs = self.audit_logger.get_compliance_audit_logs(case_id="FBI-2024-111111")
        self.assertEqual(len(case_logs), 2)
        
        # Get logs with date filter
        future_date = datetime.now() + timedelta(days=1)
        future_logs = self.audit_logger.get_compliance_audit_logs(start_date=future_date)
        self.assertEqual(len(future_logs), 0)


class TestLegalComplianceService(unittest.TestCase):
    """Test legal compliance service"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        disclaimer_file = os.path.join(self.temp_dir, "disclaimer.json")
        cases_file = os.path.join(self.temp_dir, "cases.json")
        audit_file = os.path.join(self.temp_dir, "compliance_audit.log")
        
        self.disclaimer_manager = LegalDisclaimerManager(disclaimer_file)
        self.case_manager = CaseManager(cases_file)
        self.compliance_logger = ComplianceAuditLogger(audit_file)
        
        self.compliance_service = LegalComplianceService(
            self.disclaimer_manager, self.case_manager, self.compliance_logger
        )
        
        # Create test case
        self.case_manager.create_case(
            "FBI-2024-123456", "Test Case", "Agent Smith", "Search Warrant"
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_display_disclaimer(self):
        """Test displaying disclaimer"""
        disclaimer = self.compliance_service.display_disclaimer()
        self.assertIsInstance(disclaimer, LegalDisclaimer)
        self.assertIn("AUTHORIZED USE ONLY", disclaimer.content)
    
    def test_capture_consent_accepted(self):
        """Test capturing accepted consent"""
        consent_record = self.compliance_service.capture_consent(
            "testuser", True, "FBI-2024-123456", "192.168.1.1"
        )
        
        self.assertTrue(consent_record.consent_given)
        self.assertEqual(consent_record.user, "testuser")
    
    def test_capture_consent_rejected(self):
        """Test capturing rejected consent raises exception"""
        with self.assertRaises(AuthorizationException):
            self.compliance_service.capture_consent(
                "testuser", False, "FBI-2024-123456"
            )
    
    def test_validate_case_authorization_success(self):
        """Test successful case authorization validation"""
        case_info = self.compliance_service.validate_case_authorization(
            "FBI-2024-123456", "Agent Smith"
        )
        
        self.assertEqual(case_info.case_id, "FBI-2024-123456")
        self.assertEqual(case_info.investigator, "Agent Smith")
    
    def test_validate_case_authorization_failure(self):
        """Test failed case authorization validation"""
        # Non-existent case
        with self.assertRaises(AuthorizationException):
            self.compliance_service.validate_case_authorization(
                "FBI-2024-999999", "Agent Smith"
            )
        
        # Wrong investigator
        with self.assertRaises(AuthorizationException):
            self.compliance_service.validate_case_authorization(
                "FBI-2024-123456", "Agent Jones"
            )
    
    def test_verify_authorized_environment(self):
        """Test environment verification"""
        env_info = self.compliance_service.verify_authorized_environment(
            "FBI-2024-123456", "Agent Smith"
        )
        
        self.assertIn('hostname', env_info)
        self.assertIn('ip_address', env_info)
        self.assertTrue(env_info['is_authorized'])
    
    def test_check_compliance_requirements(self):
        """Test checking all compliance requirements"""
        # Initially, no requirements met
        status = self.compliance_service.check_compliance_requirements(
            "Agent Smith", "FBI-2024-123456"
        )
        
        self.assertFalse(status['disclaimer_accepted'])
        self.assertTrue(status['case_authorized'])  # Case exists and investigator matches
        self.assertTrue(status['environment_authorized'])  # Development environment
        self.assertFalse(status['all_requirements_met'])  # Disclaimer not accepted
        
        # Accept disclaimer
        self.compliance_service.capture_consent("Agent Smith", True, "FBI-2024-123456")
        
        status = self.compliance_service.check_compliance_requirements(
            "Agent Smith", "FBI-2024-123456"
        )
        
        self.assertTrue(status['disclaimer_accepted'])
        self.assertTrue(status['case_authorized'])
        self.assertTrue(status['environment_authorized'])
        self.assertTrue(status['all_requirements_met'])


if __name__ == '__main__':
    unittest.main()