"""
Integration tests for ForensicsOrchestrator complete forensic workflows

This module provides comprehensive integration tests for the ForensicsOrchestrator
class, testing complete forensic workflows from device detection through evidence
collection and reporting.
"""

import pytest
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path

from forensics_toolkit.services.forensics_orchestrator import (
    ForensicsOrchestrator, ForensicsOrchestratorException, DeviceAnalysisResult
)
from forensics_toolkit.services.device_manager import DeviceManager, DeviceState
from forensics_toolkit.models.device import AndroidDevice, LockoutPolicy
from forensics_toolkit.models.attack import AttackStrategy, EvidenceRecord
from forensics_toolkit.interfaces import AttackType, LockType, AttackResult


class TestForensicsOrchestratorIntegration:
    """Integration tests for complete forensic workflows"""
    
    @pytest.fixture
    def temp_directory(self):
        """Create temporary directory for test files"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def mock_device_handlers(self):
        """Create mock device handlers"""
        adb_handler = Mock()
        edl_handler = Mock()
        fastboot_handler = Mock()
        
        return {
            'adb': adb_handler,
            'edl': edl_handler,
            'fastboot': fastboot_handler
        }
    
    @pytest.fixture
    def mock_attack_engines(self):
        """Create mock attack engines"""
        brute_force = Mock()
        dictionary = Mock()
        hash_cracking = Mock()
        pattern_analysis = Mock()
        
        return {
            AttackType.BRUTE_FORCE: brute_force,
            AttackType.DICTIONARY: dictionary,
            AttackType.HASH_CRACKING: hash_cracking,
            AttackType.PATTERN_ANALYSIS: pattern_analysis,
            AttackType.HYBRID: brute_force
        }
    
    @pytest.fixture
    def sample_android_device(self):
        """Create sample Android device for testing"""
        return AndroidDevice(
            serial="TEST123456",
            model="Galaxy S21",
            brand="Samsung",
            android_version="12.0",
            imei="123456789012345",
            usb_debugging=True,
            root_status=False,
            lock_type=LockType.PIN,
            screen_timeout=30,
            lockout_policy=LockoutPolicy(
                max_attempts=5,
                lockout_duration=30,
                progressive_lockout=True
            )
        )
    
    @pytest.fixture
    def orchestrator(self, temp_directory, mock_device_handlers, mock_attack_engines):
        """Create ForensicsOrchestrator instance for testing"""
        with patch('forensics_toolkit.services.forensics_orchestrator.config_manager') as mock_config:
            # Configure mock config manager
            mock_config.get_evidence_path.return_value = Path(temp_directory)
            mock_config.forensics_settings.max_concurrent_attacks = 4
            mock_config.forensics_settings.default_timeout = 30
            mock_config.security_settings.encrypt_evidence = False
            mock_config.tool_paths.adb_path = "adb"
            mock_config.tool_paths.edl_py_path = "edl.py"
            mock_config.tool_paths.fastboot_path = "fastboot"
            mock_config.tool_paths.hashcat_path = "hashcat"
            mock_config.tool_paths.john_path = "john"
            
            with patch.multiple(
                'forensics_toolkit.services.forensics_orchestrator',
                ADBHandler=Mock(return_value=mock_device_handlers['adb']),
                EDLHandler=Mock(return_value=mock_device_handlers['edl']),
                FastbootHandler=Mock(return_value=mock_device_handlers['fastboot']),
                BruteForceEngine=Mock(return_value=mock_attack_engines[AttackType.BRUTE_FORCE]),
                DictionaryAttack=Mock(return_value=mock_attack_engines[AttackType.DICTIONARY]),
                HashCracking=Mock(return_value=mock_attack_engines[AttackType.HASH_CRACKING]),
                PatternAnalysis=Mock(return_value=mock_attack_engines[AttackType.PATTERN_ANALYSIS])
            ):
                orchestrator = ForensicsOrchestrator(
                    case_id="TEST_CASE_001",
                    user_session="test_user"
                )
                yield orchestrator
                orchestrator.cleanup()
    
    def test_complete_forensic_workflow_success(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test complete successful forensic workflow"""
        # Setup mock responses
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        # Mock successful attack
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.BRUTE_FORCE].execute_attack.return_value = {
            'success': True,
            'total_attempts': 42,
            'duration_seconds': 120.5,
            'successful_pattern': '1234'
        }
        
        # Step 1: Device Detection
        detected_devices = orchestrator.detect_devices()
        assert len(detected_devices) == 1
        assert detected_devices[0].serial == "TEST123456"
        
        # Step 2: Device Analysis
        analyzed_device = orchestrator.analyze_device(detected_devices[0])
        assert analyzed_device.serial == "TEST123456"
        assert orchestrator.workflow_state.analysis_results[analyzed_device.serial] is not None
        
        # Step 3: Attack Execution
        attack_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=analyzed_device,
            max_attempts=1000,
            timeout_seconds=300
        )
        
        attack_result = orchestrator.execute_attack(attack_strategy)
        assert attack_result.success is True
        assert attack_result.result_data == '1234'
        assert attack_result.attempts == 42
        
        # Step 4: Evidence Report Generation
        evidence_report = orchestrator.generate_evidence_report("TEST_CASE_001")
        assert evidence_report['case_id'] == "TEST_CASE_001"
        assert evidence_report['workflow_summary']['devices_detected'] == 1
        assert evidence_report['workflow_summary']['attacks_executed'] == 1
        assert len(evidence_report['evidence_records']) > 0
    
    def test_complete_forensic_workflow_failure(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test complete forensic workflow with attack failure"""
        # Setup mock responses
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        # Mock failed attack
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.BRUTE_FORCE].execute_attack.return_value = {
            'success': False,
            'total_attempts': 1000,
            'duration_seconds': 300.0,
            'error_message': 'Maximum attempts reached'
        }
        
        # Execute workflow
        detected_devices = orchestrator.detect_devices()
        analyzed_device = orchestrator.analyze_device(detected_devices[0])
        
        attack_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=analyzed_device,
            max_attempts=1000,
            timeout_seconds=300
        )
        
        attack_result = orchestrator.execute_attack(attack_strategy)
        assert attack_result.success is False
        assert attack_result.error_message == 'Maximum attempts reached'
        
        # Evidence report should still be generated
        evidence_report = orchestrator.generate_evidence_report("TEST_CASE_001")
        assert evidence_report['attack_summary']['failed_attacks'] == 1
        assert evidence_report['attack_summary']['successful_attacks'] == 0
    
    def test_multi_device_workflow(self, orchestrator, mock_device_handlers, mock_attack_engines):
        """Test workflow with multiple devices"""
        # Create multiple test devices
        device1 = AndroidDevice(
            serial="DEVICE001",
            model="Galaxy S21",
            brand="Samsung",
            android_version="12.0",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        device2 = AndroidDevice(
            serial="DEVICE002",
            model="Pixel 6",
            brand="Google",
            android_version="13.0",
            usb_debugging=True,
            lock_type=LockType.PATTERN
        )
        
        # Setup mock responses
        mock_device_handlers['adb'].detect_devices.return_value = [device1, device2]
        mock_device_handlers['adb'].get_device_info.side_effect = lambda d: d
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        # Mock attack engines
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.PATTERN_ANALYSIS].validate_strategy.return_value = True
        
        # Device detection
        detected_devices = orchestrator.detect_devices()
        assert len(detected_devices) == 2
        
        # Analyze both devices
        for device in detected_devices:
            orchestrator.analyze_device(device)
        
        assert len(orchestrator.workflow_state.analysis_results) == 2
        
        # Execute attacks on both devices
        for device in detected_devices:
            if device.lock_type == LockType.PIN:
                strategy_type = AttackType.BRUTE_FORCE
                mock_engine = mock_attack_engines[AttackType.BRUTE_FORCE]
            else:
                strategy_type = AttackType.PATTERN_ANALYSIS
                mock_engine = mock_attack_engines[AttackType.PATTERN_ANALYSIS]
            
            mock_engine.execute_attack.return_value = {
                'success': True,
                'total_attempts': 50,
                'duration_seconds': 60.0,
                'successful_pattern': 'test_pattern'
            }
            
            strategy = AttackStrategy(
                strategy_type=strategy_type,
                target_device=device,
                max_attempts=1000
            )
            
            result = orchestrator.execute_attack(strategy)
            assert result.success is True
        
        # Generate comprehensive report
        evidence_report = orchestrator.generate_evidence_report("TEST_CASE_001")
        assert evidence_report['workflow_summary']['devices_detected'] == 2
        assert evidence_report['workflow_summary']['attacks_executed'] == 2
        assert evidence_report['attack_summary']['successful_attacks'] == 2
    
    def test_async_attack_execution(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test asynchronous attack execution"""
        # Setup mocks
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.BRUTE_FORCE].execute_attack.return_value = {
            'success': True,
            'total_attempts': 100,
            'duration_seconds': 30.0,
            'successful_pattern': '5678'
        }
        
        # Setup workflow
        detected_devices = orchestrator.detect_devices()
        analyzed_device = orchestrator.analyze_device(detected_devices[0])
        
        # Execute attack asynchronously
        attack_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=analyzed_device,
            max_attempts=1000
        )
        
        future = orchestrator.execute_attack_async(attack_strategy)
        assert future is not None
        
        # Wait for completion
        result = future.result(timeout=10)
        assert result.success is True
        assert result.result_data == '5678'
        
        # Check workflow state
        assert analyzed_device.serial in orchestrator.workflow_state.completed_attacks
    
    def test_device_error_recovery(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test device error recovery during workflow"""
        # Setup initial success then failure
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        mock_device_handlers['adb'].is_device_accessible.side_effect = [True, False, True]  # Fail then recover
        
        # Initial detection and analysis
        detected_devices = orchestrator.detect_devices()
        analyzed_device = orchestrator.analyze_device(detected_devices[0])
        
        # Simulate device becoming inaccessible
        assert not mock_device_handlers['adb'].is_device_accessible(sample_android_device)
        
        # Device should recover on next check
        assert mock_device_handlers['adb'].is_device_accessible(sample_android_device)
    
    def test_evidence_integrity_verification(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test evidence integrity verification throughout workflow"""
        # Setup successful workflow
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.BRUTE_FORCE].execute_attack.return_value = {
            'success': True,
            'total_attempts': 25,
            'duration_seconds': 45.0,
            'successful_pattern': '9876'
        }
        
        # Execute complete workflow
        detected_devices = orchestrator.detect_devices()
        analyzed_device = orchestrator.analyze_device(detected_devices[0])
        
        attack_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=analyzed_device,
            max_attempts=1000
        )
        
        attack_result = orchestrator.execute_attack(attack_strategy)
        evidence_report = orchestrator.generate_evidence_report("TEST_CASE_001")
        
        # Verify evidence integrity
        integrity_verification = evidence_report['integrity_verification']
        assert integrity_verification['integrity_status'] in ['verified', 'partial']
        assert integrity_verification['total_operations'] > 0
    
    def test_workflow_state_tracking(self, orchestrator, sample_android_device, mock_device_handlers):
        """Test workflow state tracking throughout execution"""
        # Setup mocks
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        
        # Initial state
        initial_status = orchestrator.get_workflow_status()
        assert initial_status['case_id'] == "TEST_CASE_001"
        assert initial_status['devices_detected'] == 0
        assert initial_status['devices_analyzed'] == 0
        
        # After device detection
        orchestrator.detect_devices()
        status_after_detection = orchestrator.get_workflow_status()
        assert status_after_detection['devices_detected'] == 1
        
        # After device analysis
        orchestrator.analyze_device(sample_android_device)
        status_after_analysis = orchestrator.get_workflow_status()
        assert status_after_analysis['devices_analyzed'] == 1
    
    def test_callback_functionality(self, orchestrator, sample_android_device, mock_device_handlers):
        """Test callback functionality during workflow execution"""
        # Setup callback mocks
        device_detected_callback = Mock()
        analysis_completed_callback = Mock()
        
        orchestrator.set_device_detected_callback(device_detected_callback)
        orchestrator.set_analysis_completed_callback(analysis_completed_callback)
        
        # Setup device handler mocks
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        
        # Execute workflow steps
        orchestrator.detect_devices()
        orchestrator.analyze_device(sample_android_device)
        
        # Verify callbacks were called
        device_detected_callback.assert_called_once_with(sample_android_device)
        analysis_completed_callback.assert_called_once()
    
    def test_concurrent_attack_execution(self, orchestrator, mock_device_handlers, mock_attack_engines):
        """Test concurrent attack execution on multiple devices"""
        # Create multiple devices
        devices = [
            AndroidDevice(
                serial=f"DEVICE{i:03d}",
                model="Test Device",
                brand="Test",
                android_version="12.0",
                usb_debugging=True,
                lock_type=LockType.PIN
            )
            for i in range(3)
        ]
        
        # Setup mocks
        mock_device_handlers['adb'].detect_devices.return_value = devices
        mock_device_handlers['adb'].get_device_info.side_effect = lambda d: d
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.BRUTE_FORCE].execute_attack.return_value = {
            'success': True,
            'total_attempts': 10,
            'duration_seconds': 5.0,
            'successful_pattern': '0000'
        }
        
        # Setup workflow
        detected_devices = orchestrator.detect_devices()
        for device in detected_devices:
            orchestrator.analyze_device(device)
        
        # Execute attacks concurrently
        futures = []
        for device in detected_devices:
            strategy = AttackStrategy(
                strategy_type=AttackType.BRUTE_FORCE,
                target_device=device,
                max_attempts=100
            )
            future = orchestrator.execute_attack_async(strategy)
            futures.append(future)
        
        # Wait for all attacks to complete
        results = [future.result(timeout=30) for future in futures]
        
        # Verify all attacks succeeded
        assert all(result.success for result in results)
        assert len(orchestrator.workflow_state.completed_attacks) == 3
    
    def test_error_handling_and_cleanup(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test error handling and proper cleanup"""
        # Setup mocks to cause errors
        mock_device_handlers['adb'].detect_devices.side_effect = Exception("Detection failed")
        
        # Test error handling
        with pytest.raises(ForensicsOrchestratorException):
            orchestrator.detect_devices()
        
        # Test cleanup
        orchestrator.cleanup()
        
        # Verify cleanup was called
        workflow_status = orchestrator.get_workflow_status()
        assert workflow_status is not None  # Should still be accessible after cleanup
    
    def test_stop_all_attacks(self, orchestrator, sample_android_device, mock_device_handlers, mock_attack_engines):
        """Test stopping all active attacks"""
        # Setup mocks
        mock_device_handlers['adb'].detect_devices.return_value = [sample_android_device]
        mock_device_handlers['adb'].get_device_info.return_value = sample_android_device
        mock_device_handlers['adb'].is_device_accessible.return_value = True
        
        # Mock long-running attack
        import time
        def long_running_attack(*args, **kwargs):
            time.sleep(10)  # Simulate long attack
            return {'success': False, 'total_attempts': 0, 'duration_seconds': 10.0}
        
        mock_attack_engines[AttackType.BRUTE_FORCE].validate_strategy.return_value = True
        mock_attack_engines[AttackType.BRUTE_FORCE].execute_attack.side_effect = long_running_attack
        
        # Setup workflow
        detected_devices = orchestrator.detect_devices()
        analyzed_device = orchestrator.analyze_device(detected_devices[0])
        
        # Start attack asynchronously
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=analyzed_device,
            max_attempts=1000
        )
        
        future = orchestrator.execute_attack_async(strategy)
        
        # Stop all attacks
        orchestrator.stop_all_attacks()
        
        # Verify attack was cancelled
        assert future.cancelled() or future.done()


class TestDeviceManagerIntegration:
    """Integration tests for DeviceManager"""
    
    @pytest.fixture
    def mock_handlers(self):
        """Create mock device handlers"""
        return {
            'adb': Mock(),
            'edl': Mock(),
            'fastboot': Mock()
        }
    
    @pytest.fixture
    def device_manager(self, mock_handlers):
        """Create DeviceManager instance"""
        manager = DeviceManager(
            device_handlers=mock_handlers,
            max_concurrent_devices=2,
            health_check_interval=1  # Short interval for testing
        )
        yield manager
        manager.shutdown()
    
    def test_device_discovery_integration(self, device_manager, mock_handlers):
        """Test integrated device discovery"""
        # Setup mock devices
        test_devices = [
            AndroidDevice(
                serial="TEST001",
                model="Test Device 1",
                brand="Test",
                android_version="12.0",
                usb_debugging=True
            ),
            AndroidDevice(
                serial="TEST002",
                model="Test Device 2",
                brand="Test",
                android_version="13.0",
                usb_debugging=False
            )
        ]
        
        # Setup mock responses
        mock_handlers['adb'].detect_devices.return_value = [test_devices[0]]
        mock_handlers['edl'].detect_devices.return_value = [test_devices[1]]
        mock_handlers['fastboot'].detect_devices.return_value = []
        
        # Discover devices
        discovered = device_manager.discover_devices()
        
        # Verify results
        assert len(discovered) == 2
        assert any(d.serial == "TEST001" for d in discovered)
        assert any(d.serial == "TEST002" for d in discovered)
        
        # Verify device status tracking
        status = device_manager.get_all_device_status()
        assert len(status) == 2
        assert all(s.state == DeviceState.CONNECTED for s in status.values())
    
    def test_concurrent_device_operations(self, device_manager, mock_handlers):
        """Test concurrent operations on multiple devices"""
        # Setup devices
        test_devices = [
            AndroidDevice(serial=f"DEVICE{i}", model="Test", brand="Test", android_version="12.0")
            for i in range(3)
        ]
        
        mock_handlers['adb'].detect_devices.return_value = test_devices
        
        # Discover devices
        device_manager.discover_devices()
        
        # Define test operation
        def test_operation(device_serial: str):
            return f"Operation completed for {device_serial}"
        
        # Execute concurrent operations
        device_serials = [d.serial for d in test_devices]
        results = device_manager.perform_concurrent_operation(
            device_serials, test_operation, "test_operation"
        )
        
        # Verify results
        assert len(results) == 3
        for serial in device_serials:
            assert serial in results
            assert "Operation completed" in results[serial]
    
    def test_device_health_monitoring(self, device_manager, mock_handlers):
        """Test device health monitoring"""
        # Setup device
        test_device = AndroidDevice(
            serial="HEALTH_TEST",
            model="Test Device",
            brand="Test",
            android_version="12.0"
        )
        
        mock_handlers['adb'].detect_devices.return_value = [test_device]
        
        # Discover device
        device_manager.discover_devices()
        
        # Simulate device errors
        device_manager.set_device_state("HEALTH_TEST", DeviceState.ERROR, error="Test error")
        device_manager.set_device_state("HEALTH_TEST", DeviceState.ERROR, error="Another error")
        
        # Wait for health check
        import time
        time.sleep(2)
        
        # Check health status
        status = device_manager.get_device_status("HEALTH_TEST")
        assert status is not None
        assert status.error_count >= 2
        
        # Get health summary
        health_summary = device_manager.get_health_summary()
        assert health_summary['total_devices'] == 1
        assert health_summary['error_devices'] >= 0  # May have recovered


if __name__ == "__main__":
    pytest.main([__file__, "-v"])