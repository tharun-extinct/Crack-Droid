"""
Unit tests for GUI interface components

This module tests the PyQt5 GUI interface including:
- Main application window functionality
- Device selection and configuration panels
- Attack progress monitoring
- Evidence report viewing and export
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock PyQt5 before importing GUI modules
sys.modules['PyQt5'] = Mock()
sys.modules['PyQt5.QtWidgets'] = Mock()
sys.modules['PyQt5.QtCore'] = Mock()
sys.modules['PyQt5.QtGui'] = Mock()

from forensics_toolkit.interfaces import AndroidDevice, AttackType, LockType, UserRole, AttackResult
from forensics_toolkit.services.forensics_orchestrator import DeviceAnalysisResult


class MockQApplication:
    """Mock QApplication for testing"""
    
    def __init__(self, args):
        pass
    
    def exec_(self):
        return 0
    
    def setApplicationName(self, name):
        pass
    
    def setApplicationVersion(self, version):
        pass
    
    def setOrganizationName(self, org):
        pass


class MockQWidget:
    """Mock QWidget base class"""
    
    def __init__(self, parent=None):
        self.parent = parent
        self.layout_widget = None
        self.visible = True
        self.enabled = True
    
    def setLayout(self, layout):
        self.layout_widget = layout
    
    def setVisible(self, visible):
        self.visible = visible
    
    def setEnabled(self, enabled):
        self.enabled = enabled
    
    def show(self):
        self.visible = True
    
    def hide(self):
        self.visible = False


class MockQDialog(MockQWidget):
    """Mock QDialog for testing"""
    
    Accepted = 1
    Rejected = 0
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.modal = False
        self.result_code = self.Rejected
    
    def setModal(self, modal):
        self.modal = modal
    
    def exec_(self):
        return self.result_code
    
    def accept(self):
        self.result_code = self.Accepted
    
    def reject(self):
        self.result_code = self.Rejected


class TestLoginDialog(unittest.TestCase):
    """Test login dialog functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.mock_auth_service = Mock()
        
        # Mock PyQt5 components
        with patch('forensics_toolkit.ui.gui.QDialog', MockQDialog):
            with patch('forensics_toolkit.ui.gui.QVBoxLayout', Mock):
                with patch('forensics_toolkit.ui.gui.QFormLayout', Mock):
                    with patch('forensics_toolkit.ui.gui.QLineEdit', Mock):
                        with patch('forensics_toolkit.ui.gui.QPushButton', Mock):
                            with patch('forensics_toolkit.ui.gui.QLabel', Mock):
                                from forensics_toolkit.ui.gui import LoginDialog
                                self.dialog = LoginDialog(self.mock_auth_service)
    
    def test_login_dialog_initialization(self):
        """Test login dialog initialization"""
        self.assertIsNotNone(self.dialog)
        self.assertEqual(self.dialog.auth_service, self.mock_auth_service)
        self.assertIsNone(self.dialog.user)
        self.assertIsNone(self.dialog.session)
    
    @patch('forensics_toolkit.ui.gui.QLineEdit')
    def test_successful_login(self, mock_line_edit):
        """Test successful user login"""
        # Setup mocks
        mock_username_edit = Mock()
        mock_username_edit.text.return_value = "test_user"
        mock_password_edit = Mock()
        mock_password_edit.text.return_value = "test_password"
        
        self.dialog.username_edit = mock_username_edit
        self.dialog.password_edit = mock_password_edit
        self.dialog.status_label = Mock()
        self.dialog.login_button = Mock()
        
        # Mock successful authentication
        mock_user = Mock()
        mock_user.username = "test_user"
        mock_session = Mock()
        
        self.mock_auth_service.authenticate_user.return_value = mock_user
        self.mock_auth_service.create_session.return_value = mock_session
        
        # Test login attempt
        self.dialog.attempt_login()
        
        # Verify authentication was called
        self.mock_auth_service.authenticate_user.assert_called_once_with("test_user", "test_password")
        self.mock_auth_service.create_session.assert_called_once_with(mock_user)
        
        # Verify dialog state
        self.assertEqual(self.dialog.user, mock_user)
        self.assertEqual(self.dialog.session, mock_session)
    
    def test_failed_login(self):
        """Test failed user login"""
        # Setup mocks
        mock_username_edit = Mock()
        mock_username_edit.text.return_value = "invalid_user"
        mock_password_edit = Mock()
        mock_password_edit.text.return_value = "invalid_password"
        
        self.dialog.username_edit = mock_username_edit
        self.dialog.password_edit = mock_password_edit
        self.dialog.status_label = Mock()
        self.dialog.login_button = Mock()
        
        # Mock failed authentication
        self.mock_auth_service.authenticate_user.return_value = None
        
        # Test login attempt
        self.dialog.attempt_login()
        
        # Verify authentication was called
        self.mock_auth_service.authenticate_user.assert_called_once_with("invalid_user", "invalid_password")
        
        # Verify dialog state
        self.assertIsNone(self.dialog.user)
        self.assertIsNone(self.dialog.session)
        self.dialog.status_label.setText.assert_called_with("Invalid credentials")


class TestDeviceListWidget(unittest.TestCase):
    """Test device list widget functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        with patch('forensics_toolkit.ui.gui.QWidget', MockQWidget):
            with patch('forensics_toolkit.ui.gui.QVBoxLayout', Mock):
                with patch('forensics_toolkit.ui.gui.QTableWidget', Mock):
                    with patch('forensics_toolkit.ui.gui.QPushButton', Mock):
                        with patch('forensics_toolkit.ui.gui.QLabel', Mock):
                            from forensics_toolkit.ui.gui import DeviceListWidget
                            self.widget = DeviceListWidget()
    
    def test_device_list_initialization(self):
        """Test device list widget initialization"""
        self.assertIsNotNone(self.widget)
        self.assertEqual(len(self.widget.devices), 0)
    
    def test_update_devices(self):
        """Test updating device list"""
        # Create test devices
        device1 = AndroidDevice(
            serial="device1",
            model="Pixel 6",
            brand="Google",
            android_version="12",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        device2 = AndroidDevice(
            serial="device2",
            model="Galaxy S21",
            brand="Samsung",
            android_version="11",
            usb_debugging=False,
            lock_type=LockType.PATTERN
        )
        
        devices = [device1, device2]
        
        # Mock table widget
        self.widget.device_table = Mock()
        
        # Update devices
        self.widget.update_devices(devices)
        
        # Verify devices were stored
        self.assertEqual(len(self.widget.devices), 2)
        self.assertEqual(self.widget.devices[0].serial, "device1")
        self.assertEqual(self.widget.devices[1].serial, "device2")
        
        # Verify table was updated
        self.widget.device_table.setRowCount.assert_called_once_with(2)


class TestAttackConfigWidget(unittest.TestCase):
    """Test attack configuration widget functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        with patch('forensics_toolkit.ui.gui.QWidget', MockQWidget):
            with patch('forensics_toolkit.ui.gui.QVBoxLayout', Mock):
                with patch('forensics_toolkit.ui.gui.QGroupBox', Mock):
                    with patch('forensics_toolkit.ui.gui.QRadioButton', Mock):
                        with patch('forensics_toolkit.ui.gui.QSpinBox', Mock):
                            with patch('forensics_toolkit.ui.gui.QPushButton', Mock):
                                with patch('forensics_toolkit.ui.gui.QLabel', Mock):
                                    from forensics_toolkit.ui.gui import AttackConfigWidget
                                    self.widget = AttackConfigWidget()
    
    def test_attack_config_initialization(self):
        """Test attack config widget initialization"""
        self.assertIsNotNone(self.widget)
        self.assertIsNone(self.widget.analysis_result)
    
    def test_set_analysis_result(self):
        """Test setting device analysis result"""
        # Create test device and analysis result
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
        
        # Mock UI components
        self.widget.device_info_label = Mock()
        self.widget.brute_force_radio = Mock()
        self.widget.dictionary_radio = Mock()
        self.widget.pattern_radio = Mock()
        self.widget.hash_radio = Mock()
        self.widget.hybrid_radio = Mock()
        self.widget.execute_button = Mock()
        
        # Set analysis result
        self.widget.set_analysis_result(analysis_result)
        
        # Verify analysis result was stored
        self.assertEqual(self.widget.analysis_result, analysis_result)
        
        # Verify UI was updated
        expected_info = "TestBrand Test Phone (Serial: test_device)"
        self.widget.device_info_label.setText.assert_called_with(expected_info)
        
        # Verify attack types were enabled/disabled appropriately
        self.widget.brute_force_radio.setEnabled.assert_called_with(True)
        self.widget.dictionary_radio.setEnabled.assert_called_with(True)
        self.widget.pattern_radio.setEnabled.assert_called_with(False)
        self.widget.hash_radio.setEnabled.assert_called_with(False)
        self.widget.hybrid_radio.setEnabled.assert_called_with(False)
        
        # Verify execute button was enabled
        self.widget.execute_button.setEnabled.assert_called_with(True)


class TestAttackProgressWidget(unittest.TestCase):
    """Test attack progress widget functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        with patch('forensics_toolkit.ui.gui.QWidget', MockQWidget):
            with patch('forensics_toolkit.ui.gui.QVBoxLayout', Mock):
                with patch('forensics_toolkit.ui.gui.QProgressBar', Mock):
                    with patch('forensics_toolkit.ui.gui.QPushButton', Mock):
                        with patch('forensics_toolkit.ui.gui.QLabel', Mock):
                            from forensics_toolkit.ui.gui import AttackProgressWidget
                            self.widget = AttackProgressWidget()
    
    def test_attack_progress_initialization(self):
        """Test attack progress widget initialization"""
        self.assertIsNotNone(self.widget)
    
    def test_start_attack(self):
        """Test starting attack progress display"""
        # Create test strategy
        device = AndroidDevice(
            serial="test_device",
            model="Test Phone",
            brand="TestBrand",
            android_version="12"
        )
        
        from forensics_toolkit.models.attack import AttackStrategy
        strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=device,
            max_attempts=1000
        )
        
        # Mock UI components
        self.widget.status_label = Mock()
        self.widget.progress_bar = Mock()
        self.widget.stop_button = Mock()
        self.widget.attempts_label = Mock()
        self.widget.duration_label = Mock()
        self.widget.rate_label = Mock()
        
        # Start attack
        self.widget.start_attack(strategy)
        
        # Verify UI was updated
        expected_status = "Executing brute_force attack on TestBrand Test Phone"
        self.widget.status_label.setText.assert_called_with(expected_status)
        self.widget.progress_bar.setVisible.assert_called_with(True)
        self.widget.progress_bar.setRange.assert_called_with(0, 1000)
        self.widget.stop_button.setEnabled.assert_called_with(True)
    
    def test_update_progress(self):
        """Test updating attack progress"""
        # Mock UI components
        self.widget.attempts_label = Mock()
        self.widget.duration_label = Mock()
        self.widget.rate_label = Mock()
        self.widget.status_label = Mock()
        self.widget.progress_bar = Mock()
        
        # Update progress
        progress_data = {
            'attempts': 500,
            'duration': 30.5,
            'rate': 16.4,
            'status': 'running'
        }
        
        self.widget.update_progress(progress_data)
        
        # Verify UI was updated
        self.widget.attempts_label.setText.assert_called_with("500")
        self.widget.duration_label.setText.assert_called_with("30.5s")
        self.widget.rate_label.setText.assert_called_with("16.4/s")
        self.widget.status_label.setText.assert_called_with("Status: running")
        self.widget.progress_bar.setValue.assert_called_with(500)
    
    def test_attack_completed_success(self):
        """Test handling successful attack completion"""
        # Mock UI components
        self.widget.status_label = Mock()
        self.widget.progress_bar = Mock()
        self.widget.stop_button = Mock()
        self.widget.attempts_label = Mock()
        self.widget.duration_label = Mock()
        self.widget.rate_label = Mock()
        
        # Create successful result
        result = AttackResult(
            success=True,
            attempts=750,
            duration=45.2,
            result_data="1234"
        )
        
        # Handle completion
        self.widget.attack_completed(result)
        
        # Verify UI was updated
        self.widget.status_label.setText.assert_called_with("Attack completed successfully!")
        self.widget.progress_bar.setVisible.assert_called_with(False)
        self.widget.stop_button.setEnabled.assert_called_with(False)
        self.widget.attempts_label.setText.assert_called_with("750")
        self.widget.duration_label.setText.assert_called_with("45.2s")
    
    def test_attack_completed_failure(self):
        """Test handling failed attack completion"""
        # Mock UI components
        self.widget.status_label = Mock()
        self.widget.progress_bar = Mock()
        self.widget.stop_button = Mock()
        self.widget.attempts_label = Mock()
        self.widget.duration_label = Mock()
        
        # Create failed result
        result = AttackResult(
            success=False,
            attempts=1000,
            duration=60.0,
            error_message="Maximum attempts reached"
        )
        
        # Handle completion
        self.widget.attack_completed(result)
        
        # Verify UI was updated
        self.widget.status_label.setText.assert_called_with("Attack failed")
        self.widget.progress_bar.setVisible.assert_called_with(False)
        self.widget.stop_button.setEnabled.assert_called_with(False)


class TestEvidenceReportWidget(unittest.TestCase):
    """Test evidence report widget functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        with patch('forensics_toolkit.ui.gui.QWidget', MockQWidget):
            with patch('forensics_toolkit.ui.gui.QVBoxLayout', Mock):
                with patch('forensics_toolkit.ui.gui.QTextEdit', Mock):
                    with patch('forensics_toolkit.ui.gui.QPushButton', Mock):
                        with patch('forensics_toolkit.ui.gui.QLabel', Mock):
                            from forensics_toolkit.ui.gui import EvidenceReportWidget
                            self.widget = EvidenceReportWidget()
    
    def test_evidence_report_initialization(self):
        """Test evidence report widget initialization"""
        self.assertIsNotNone(self.widget)
        self.assertIsNone(self.widget.current_report)
    
    def test_set_report(self):
        """Test setting evidence report"""
        # Create test report
        report = {
            'case_id': 'TEST_CASE_001',
            'report_generated_at': '2025-01-01T12:00:00',
            'generated_by': 'test_user',
            'workflow_summary': {
                'workflow_status': 'completed',
                'devices_detected': 2,
                'devices_analyzed': 1
            },
            'evidence_records': [],
            'integrity_verification': True
        }
        
        # Mock UI components
        self.widget.report_text = Mock()
        self.widget.export_button = Mock()
        
        # Set report
        self.widget.set_report(report)
        
        # Verify report was stored
        self.assertEqual(self.widget.current_report, report)
        
        # Verify UI was updated
        self.widget.export_button.setEnabled.assert_called_with(True)
        self.widget.report_text.setPlainText.assert_called_once()
    
    def test_format_report(self):
        """Test report formatting"""
        # Create test report
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
        
        # Format report
        formatted_report = self.widget.format_report(report)
        
        # Verify report contains expected sections
        self.assertIn("FORENSIC EVIDENCE REPORT", formatted_report)
        self.assertIn("Case ID: TEST_CASE_001", formatted_report)
        self.assertIn("WORKFLOW SUMMARY", formatted_report)
        self.assertIn("DEVICE SUMMARY", formatted_report)
        self.assertIn("ATTACK SUMMARY", formatted_report)
        self.assertIn("EVIDENCE RECORDS", formatted_report)
        self.assertIn("INTEGRITY VERIFICATION", formatted_report)
        self.assertIn("Status: VERIFIED", formatted_report)


class TestForensicsMainWindow(unittest.TestCase):
    """Test main application window functionality"""
    
    def setUp(self):
        """Setup test fixtures"""
        # Mock all PyQt5 components
        with patch('forensics_toolkit.ui.gui.QMainWindow', MockQWidget):
            with patch('forensics_toolkit.ui.gui.QTabWidget', Mock):
                with patch('forensics_toolkit.ui.gui.QMenuBar', Mock):
                    with patch('forensics_toolkit.ui.gui.QStatusBar', Mock):
                        with patch('forensics_toolkit.ui.gui.DeviceListWidget', Mock):
                            with patch('forensics_toolkit.ui.gui.AttackConfigWidget', Mock):
                                with patch('forensics_toolkit.ui.gui.AttackProgressWidget', Mock):
                                    with patch('forensics_toolkit.ui.gui.EvidenceReportWidget', Mock):
                                        # Mock authentication and legal compliance
                                        with patch('forensics_toolkit.ui.gui.LoginDialog') as mock_login:
                                            with patch('forensics_toolkit.ui.gui.LegalComplianceDialog') as mock_legal:
                                                with patch('forensics_toolkit.ui.gui.CaseSetupDialog') as mock_case:
                                                    # Setup successful authentication
                                                    mock_login_instance = Mock()
                                                    mock_login_instance.exec_.return_value = MockQDialog.Accepted
                                                    mock_login_instance.session = Mock()
                                                    mock_login_instance.user = Mock()
                                                    mock_login_instance.user.username = "test_user"
                                                    mock_login_instance.user.role = UserRole.INVESTIGATOR
                                                    mock_login.return_value = mock_login_instance
                                                    
                                                    # Setup successful legal compliance
                                                    mock_legal_instance = Mock()
                                                    mock_legal_instance.exec_.return_value = MockQDialog.Accepted
                                                    mock_legal.return_value = mock_legal_instance
                                                    
                                                    # Setup successful case setup
                                                    mock_case_instance = Mock()
                                                    mock_case_instance.exec_.return_value = MockQDialog.Accepted
                                                    mock_case_instance.case_id = "TEST_CASE_001"
                                                    mock_case.return_value = mock_case_instance
                                                    
                                                    # Mock orchestrator
                                                    with patch('forensics_toolkit.ui.gui.ForensicsOrchestrator') as mock_orchestrator:
                                                        mock_orchestrator_instance = Mock()
                                                        mock_orchestrator.return_value = mock_orchestrator_instance
                                                        
                                                        from forensics_toolkit.ui.gui import ForensicsMainWindow
                                                        self.window = ForensicsMainWindow()
    
    def test_main_window_initialization(self):
        """Test main window initialization"""
        self.assertIsNotNone(self.window)
        self.assertIsNotNone(self.window.current_session)
        self.assertIsNotNone(self.window.current_orchestrator)


class TestGUIIntegration(unittest.TestCase):
    """Test GUI integration scenarios"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.mock_app = Mock()
    
    @patch('forensics_toolkit.ui.gui.QApplication')
    @patch('forensics_toolkit.ui.gui.ForensicsMainWindow')
    def test_main_function(self, mock_window, mock_app):
        """Test main function execution"""
        # Setup mocks
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        mock_app_instance.exec_.return_value = 0
        
        mock_window_instance = Mock()
        mock_window.return_value = mock_window_instance
        
        # Import and run main function
        from forensics_toolkit.ui.gui import main
        
        # Mock sys.argv
        with patch('sys.argv', ['gui.py']):
            with patch('sys.exit') as mock_exit:
                main()
                
                # Verify application was created and run
                mock_app.assert_called_once()
                mock_window.assert_called_once()
                mock_window_instance.show.assert_called_once()
                mock_app_instance.exec_.assert_called_once()
                mock_exit.assert_called_once_with(0)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)