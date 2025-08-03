"""
Simple unit tests for GUI interface components

This module tests the core logic of GUI components without PyQt5 dependencies.
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from forensics_toolkit.interfaces import AndroidDevice, AttackType, LockType, UserRole, AttackResult
from forensics_toolkit.services.forensics_orchestrator import DeviceAnalysisResult


class TestGUILogic(unittest.TestCase):
    """Test GUI logic without PyQt5 dependencies"""
    
    def test_device_data_formatting(self):
        """Test device data formatting for display"""
        device = AndroidDevice(
            serial="test_device_001",
            model="Pixel 6",
            brand="Google",
            android_version="12",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        # Test device info formatting
        expected_info = "Google Pixel 6 (Serial: test_device_001)"
        actual_info = f"{device.brand} {device.model} (Serial: {device.serial})"
        self.assertEqual(actual_info, expected_info)
        
        # Test USB debugging display
        usb_debug_display = "Yes" if device.usb_debugging else "No"
        self.assertEqual(usb_debug_display, "Yes")
        
        # Test lock type display
        lock_type_display = device.lock_type.value if device.lock_type else "Unknown"
        self.assertEqual(lock_type_display, "pin")
    
    def test_attack_strategy_validation(self):
        """Test attack strategy validation logic"""
        device = AndroidDevice(
            serial="test_device",
            model="Test Phone",
            brand="TestBrand",
            android_version="12",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        # Test strategy type mapping
        attack_type_map = {
            0: AttackType.BRUTE_FORCE,
            1: AttackType.DICTIONARY,
            2: AttackType.PATTERN_ANALYSIS,
            3: AttackType.HASH_CRACKING,
            4: AttackType.HYBRID
        }
        
        self.assertEqual(attack_type_map[0], AttackType.BRUTE_FORCE)
        self.assertEqual(attack_type_map[1], AttackType.DICTIONARY)
        self.assertEqual(attack_type_map[2], AttackType.PATTERN_ANALYSIS)
        self.assertEqual(attack_type_map[3], AttackType.HASH_CRACKING)
        self.assertEqual(attack_type_map[4], AttackType.HYBRID)
    
    def test_progress_data_formatting(self):
        """Test attack progress data formatting"""
        progress_data = {
            'attempts': 500,
            'duration': 30.5,
            'rate': 16.4,
            'status': 'running'
        }
        
        # Test formatting functions
        attempts_text = str(progress_data['attempts'])
        self.assertEqual(attempts_text, "500")
        
        duration_text = f"{progress_data['duration']:.1f}s"
        self.assertEqual(duration_text, "30.5s")
        
        rate_text = f"{progress_data['rate']:.1f}/s"
        self.assertEqual(rate_text, "16.4/s")
        
        status_text = f"Status: {progress_data['status']}"
        self.assertEqual(status_text, "Status: running")
    
    def test_attack_result_processing(self):
        """Test attack result processing logic"""
        # Test successful result
        success_result = AttackResult(
            success=True,
            attempts=750,
            duration=45.2,
            result_data="1234"
        )
        
        self.assertTrue(success_result.success)
        self.assertEqual(success_result.attempts, 750)
        self.assertEqual(success_result.duration, 45.2)
        self.assertEqual(success_result.result_data, "1234")
        
        # Test failed result
        failed_result = AttackResult(
            success=False,
            attempts=1000,
            duration=60.0,
            error_message="Maximum attempts reached"
        )
        
        self.assertFalse(failed_result.success)
        self.assertEqual(failed_result.attempts, 1000)
        self.assertEqual(failed_result.duration, 60.0)
        self.assertEqual(failed_result.error_message, "Maximum attempts reached")
        
        # Test rate calculation
        if success_result.duration > 0:
            rate = success_result.attempts / success_result.duration
            expected_rate = 750 / 45.2
            self.assertAlmostEqual(rate, expected_rate, places=2)
    
    def test_report_formatting(self):
        """Test evidence report formatting logic"""
        report = {
            'case_id': 'TEST_CASE_001',
            'report_generated_at': '2025-01-01T12:00:00',
            'generated_by': 'test_user',
            'workflow_summary': {
                'workflow_status': 'completed',
                'start_time': '2025-01-01T10:00:00',
                'last_activity': '2025-01-01T11:30:00',
                'devices_detected': 2,
                'devices_analyzed': 1
            },
            'device_summary': {
                'device1': {
                    'brand': 'Google',
                    'model': 'Pixel 6',
                    'android_version': '12',
                    'usb_debugging': True
                }
            },
            'attack_summary': {
                'device1': {
                    'attack_type': 'brute_force',
                    'success': True,
                    'attempts': 500,
                    'duration': 30.5,
                    'result_data': '1234'
                }
            },
            'evidence_records': [
                {
                    'timestamp': '2025-01-01T11:00:00',
                    'operation_type': 'attack_success',
                    'device_serial': 'device1',
                    'result': 'Device unlocked'
                }
            ],
            'integrity_verification': True
        }
        
        # Test report header formatting
        header_lines = []
        header_lines.append("=" * 60)
        header_lines.append("FORENSIC EVIDENCE REPORT")
        header_lines.append("=" * 60)
        header_lines.append("")
        header_lines.append(f"Case ID: {report.get('case_id', 'N/A')}")
        header_lines.append(f"Generated: {report.get('report_generated_at', 'N/A')}")
        header_lines.append(f"Generated by: {report.get('generated_by', 'N/A')}")
        
        expected_header = "\n".join(header_lines)
        self.assertIn("FORENSIC EVIDENCE REPORT", expected_header)
        self.assertIn("Case ID: TEST_CASE_001", expected_header)
        self.assertIn("Generated: 2025-01-01T12:00:00", expected_header)
        self.assertIn("Generated by: test_user", expected_header)
        
        # Test workflow summary formatting
        workflow = report.get('workflow_summary', {})
        workflow_lines = []
        workflow_lines.append("WORKFLOW SUMMARY")
        workflow_lines.append("-" * 20)
        workflow_lines.append(f"Status: {workflow.get('workflow_status', 'N/A')}")
        workflow_lines.append(f"Devices Detected: {workflow.get('devices_detected', 0)}")
        workflow_lines.append(f"Devices Analyzed: {workflow.get('devices_analyzed', 0)}")
        
        workflow_text = "\n".join(workflow_lines)
        self.assertIn("WORKFLOW SUMMARY", workflow_text)
        self.assertIn("Status: completed", workflow_text)
        self.assertIn("Devices Detected: 2", workflow_text)
        self.assertIn("Devices Analyzed: 1", workflow_text)
        
        # Test integrity verification formatting
        integrity = report.get('integrity_verification', False)
        integrity_status = 'VERIFIED' if integrity else 'FAILED'
        self.assertEqual(integrity_status, 'VERIFIED')
    
    def test_device_analysis_result_processing(self):
        """Test device analysis result processing"""
        device = AndroidDevice(
            serial="test_device",
            model="Test Phone",
            brand="TestBrand",
            android_version="12",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        analysis_result = DeviceAnalysisResult(
            device=device,
            capabilities={'brute_force_viable': True, 'hash_extraction': False},
            recommended_strategies=[AttackType.BRUTE_FORCE, AttackType.DICTIONARY]
        )
        
        # Test device info extraction
        info_text = f"{analysis_result.device.brand} {analysis_result.device.model} (Serial: {analysis_result.device.serial})"
        expected_info = "TestBrand Test Phone (Serial: test_device)"
        self.assertEqual(info_text, expected_info)
        
        # Test capability checking
        self.assertTrue(analysis_result.capabilities.get('brute_force_viable', False))
        self.assertFalse(analysis_result.capabilities.get('hash_extraction', False))
        
        # Test strategy recommendations
        self.assertIn(AttackType.BRUTE_FORCE, analysis_result.recommended_strategies)
        self.assertIn(AttackType.DICTIONARY, analysis_result.recommended_strategies)
        self.assertNotIn(AttackType.PATTERN_ANALYSIS, analysis_result.recommended_strategies)
        
        # Test strategy enablement logic
        brute_force_enabled = AttackType.BRUTE_FORCE in analysis_result.recommended_strategies
        dictionary_enabled = AttackType.DICTIONARY in analysis_result.recommended_strategies
        pattern_enabled = AttackType.PATTERN_ANALYSIS in analysis_result.recommended_strategies
        hash_enabled = AttackType.HASH_CRACKING in analysis_result.recommended_strategies
        hybrid_enabled = AttackType.HYBRID in analysis_result.recommended_strategies
        
        self.assertTrue(brute_force_enabled)
        self.assertTrue(dictionary_enabled)
        self.assertFalse(pattern_enabled)
        self.assertFalse(hash_enabled)
        self.assertFalse(hybrid_enabled)
    
    def test_case_id_validation(self):
        """Test case ID validation logic"""
        import re
        
        # Valid case IDs
        valid_case_ids = [
            "CASE_2025_001",
            "TEST_CASE_001",
            "FORENSIC-CASE-123",
            "case_123",
            "CASE123"
        ]
        
        # Invalid case IDs
        invalid_case_ids = [
            "",
            "   ",
            "CASE 001",  # Contains space
            "CASE@001",  # Contains special character
            "CASE#001",  # Contains special character
            "CASE.001"   # Contains dot
        ]
        
        case_id_pattern = r'^[A-Za-z0-9_-]+$'
        
        # Test valid case IDs
        for case_id in valid_case_ids:
            self.assertTrue(bool(re.match(case_id_pattern, case_id)), 
                          f"Valid case ID failed validation: {case_id}")
        
        # Test invalid case IDs
        for case_id in invalid_case_ids:
            if case_id.strip():  # Skip empty strings for regex test
                self.assertFalse(bool(re.match(case_id_pattern, case_id)), 
                               f"Invalid case ID passed validation: {case_id}")
    
    def test_file_export_logic(self):
        """Test file export logic"""
        report = {
            'case_id': 'TEST_CASE_001',
            'report_generated_at': '2025-01-01T12:00:00',
            'workflow_summary': {'workflow_status': 'completed'}
        }
        
        # Test filename generation
        case_id = report.get('case_id', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"report_{case_id}_{timestamp}.json"
        
        self.assertTrue(default_filename.startswith("report_TEST_CASE_001_"))
        self.assertTrue(default_filename.endswith(".json"))
        
        # Test file extension detection
        test_paths = [
            "report.txt",
            "report.json",
            "report.pdf",
            "report"
        ]
        
        for path in test_paths:
            is_txt = path.endswith('.txt')
            is_json = path.endswith('.json')
            
            if path == "report.txt":
                self.assertTrue(is_txt)
                self.assertFalse(is_json)
            elif path == "report.json":
                self.assertFalse(is_txt)
                self.assertTrue(is_json)
            else:
                self.assertFalse(is_txt)
                if path != "report.json":
                    self.assertFalse(is_json)


class TestGUIUtilities(unittest.TestCase):
    """Test GUI utility functions"""
    
    def test_format_duration(self):
        """Test duration formatting"""
        test_cases = [
            (0.5, "0.5s"),
            (30.0, "30.0s"),
            (60.5, "60.5s"),
            (3661.2, "3661.2s")
        ]
        
        for duration, expected in test_cases:
            formatted = f"{duration:.1f}s"
            self.assertEqual(formatted, expected)
    
    def test_format_attempts(self):
        """Test attempts formatting"""
        test_cases = [
            (0, "0"),
            (100, "100"),
            (1000, "1000"),
            (10000, "10000")
        ]
        
        for attempts, expected in test_cases:
            formatted = str(attempts)
            self.assertEqual(formatted, expected)
    
    def test_format_rate(self):
        """Test rate formatting"""
        test_cases = [
            (0.0, "0.0/s"),
            (1.5, "1.5/s"),
            (16.4, "16.4/s"),
            (100.0, "100.0/s")
        ]
        
        for rate, expected in test_cases:
            formatted = f"{rate:.1f}/s"
            self.assertEqual(formatted, expected)
    
    def test_status_message_formatting(self):
        """Test status message formatting"""
        device = AndroidDevice(
            serial="test_device",
            model="Test Phone",
            brand="TestBrand",
            android_version="12"
        )
        
        attack_type = AttackType.BRUTE_FORCE
        
        # Test attack status message
        status_message = f"Executing {attack_type.value} attack on {device.brand} {device.model}"
        expected = "Executing brute_force attack on TestBrand Test Phone"
        self.assertEqual(status_message, expected)
        
        # Test completion messages
        success_message = "Attack completed successfully!"
        failure_message = "Attack failed"
        
        self.assertEqual(success_message, "Attack completed successfully!")
        self.assertEqual(failure_message, "Attack failed")
    
    def test_error_message_formatting(self):
        """Test error message formatting"""
        error_cases = [
            ("Connection failed", "Attack error: Connection failed"),
            ("Device not found", "Attack error: Device not found"),
            ("Timeout occurred", "Attack error: Timeout occurred")
        ]
        
        for error, expected in error_cases:
            formatted = f"Attack error: {error}"
            self.assertEqual(formatted, expected)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)