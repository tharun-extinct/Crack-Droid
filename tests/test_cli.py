"""
Unit tests for CLI interface functionality
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import io
from datetime import datetime

from forensics_toolkit.ui.cli import ForensicsCLI, ProgressDisplay, CLIColors
from forensics_toolkit.interfaces import (
    AndroidDevice, AttackStrategy, AttackResult, AttackType, LockType,
    UserRole, Permission, User, Session
)
from forensics_toolkit.models.device import AndroidDevice as DeviceModel
from forensics_toolkit.models.attack import AttackStrategy as StrategyModel


class TestProgressDisplay(unittest.TestCase):
    """Test progress display functionality"""
    
    def setUp(self):
        self.progress = ProgressDisplay("Test operation")
    
    def test_progress_display_initialization(self):
        """Test progress display initialization"""
        self.assertEqual(self.progress.description, "Test operation")
        self.assertFalse(self.progress.is_running)
        self.assertEqual(self.progress._progress_data, {})
    
    def test_progress_update(self):
        """Test progress data update"""
        self.progress.update(attempts=100, duration=5.5, status="running")
        
        expected_data = {
            'attempts': 100,
            'duration': 5.5,
            'status': 'running'
        }
        self.assertEqual(self.progress._progress_data, expected_data)
    
    def test_format_progress_data(self):
        """Test progress data formatting"""
        self.progress.update(attempts=100, duration=5.5, status="running")
        formatted = self.progress._format_progress_data()
        
        self.assertIn("Attempts: 100", formatted)
        self.assertIn("Duration: 5.5s", formatted)
        self.assertIn("Status: running", formatted)
    
    def test_start_stop_progress(self):
        """Test starting and stopping progress display"""
        # Mock threading to avoid actual thread creation in tests
        with patch('threading.Thread') as mock_thread:
            mock_thread_instance = Mock()
            mock_thread.return_value = mock_thread_instance
            
            self.progress.start()
            self.assertTrue(self.progress.is_running)
            mock_thread.assert_called_once()
            mock_thread_instance.start.assert_called_once()
            
            self.progress.stop()
            self.assertFalse(self.progress.is_running)
            mock_thread_instance.join.assert_called_once_with(timeout=1)


class TestForensicsCLI(unittest.TestCase):
    """Test CLI interface functionality"""
    
    def setUp(self):
        """Setup test environment"""
        # Mock external dependencies
        with patch('forensics_toolkit.ui.cli.AuthenticationService'), \
             patch('forensics_toolkit.ui.cli.UserManager'), \
             patch('forensics_toolkit.ui.cli.LegalComplianceService'):
            self.cli = ForensicsCLI()
        
        # Create mock user and session
        self.mock_user = User(
            username="test_user",
            role=UserRole.INVESTIGATOR,
            permissions=[Permission.DEVICE_ACCESS, Permission.ATTACK_EXECUTION],
            created_at=datetime.now()
        )
        
        self.mock_session = Session(
            session_id="test_session_123",
            user=self.mock_user,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            expires_at=datetime.now(),
            is_active=True
        )
    
    def test_cli_initialization(self):
        """Test CLI initialization"""
        self.assertIsNotNone(self.cli.parser)
        self.assertIsNone(self.cli.current_session)
        self.assertIsNone(self.cli.current_orchestrator)
    
    def test_argument_parser_setup(self):
        """Test argument parser configuration"""
        parser = self.cli.parser
        
        # Test help output contains expected commands
        help_output = parser.format_help()
        self.assertIn("interactive", help_output)
        self.assertIn("detect", help_output)
        self.assertIn("analyze", help_output)
        self.assertIn("attack", help_output)
        self.assertIn("report", help_output)
        self.assertIn("config", help_output)
    
    def test_parse_interactive_command(self):
        """Test parsing interactive command"""
        args = self.cli.parser.parse_args(['interactive'])
        self.assertEqual(args.command, 'interactive')
    
    def test_parse_detect_command(self):
        """Test parsing detect command"""
        args = self.cli.parser.parse_args(['detect'])
        self.assertEqual(args.command, 'detect')
    
    def test_parse_analyze_command(self):
        """Test parsing analyze command"""
        args = self.cli.parser.parse_args(['analyze', '--device', 'ABC123'])
        self.assertEqual(args.command, 'analyze')
        self.assertEqual(args.device, 'ABC123')
    
    def test_parse_attack_command(self):
        """Test parsing attack command"""
        args = self.cli.parser.parse_args([
            'attack', '--case', 'CASE001', '--device', 'ABC123', 
            '--type', 'brute_force', '--max-attempts', '5000'
        ])
        self.assertEqual(args.command, 'attack')
        self.assertEqual(args.case, 'CASE001')
        self.assertEqual(args.device, 'ABC123')
        self.assertEqual(args.type, 'brute_force')
        self.assertEqual(args.max_attempts, 5000)
    
    def test_parse_report_command(self):
        """Test parsing report command"""
        args = self.cli.parser.parse_args(['report', '--case', 'CASE001', '--format', 'pdf'])
        self.assertEqual(args.command, 'report')
        self.assertEqual(args.case, 'CASE001')
        self.assertEqual(args.format, 'pdf')
    
    def test_parse_config_commands(self):
        """Test parsing config commands"""
        # Test config show
        args = self.cli.parser.parse_args(['config', 'show'])
        self.assertEqual(args.command, 'config')
        self.assertEqual(args.config_command, 'show')
        
        # Test config validate
        args = self.cli.parser.parse_args(['config', 'validate'])
        self.assertEqual(args.config_command, 'validate')
        
        # Test config set
        args = self.cli.parser.parse_args(['config', 'set', 'max_attempts', '1000'])
        self.assertEqual(args.config_command, 'set')
        self.assertEqual(args.key, 'max_attempts')
        self.assertEqual(args.value, '1000')
    
    @patch('sys.stdout', new_callable=io.StringIO)
    def test_run_no_command_shows_help(self, mock_stdout):
        """Test that running with no command shows help"""
        result = self.cli.run([])
        self.assertEqual(result, 0)
        output = mock_stdout.getvalue()
        self.assertIn("usage:", output)
    
    @patch('builtins.input', side_effect=['q'])
    @patch('forensics_toolkit.ui.cli.ForensicsCLI._authenticate_user', return_value=True)
    @patch('forensics_toolkit.ui.cli.ForensicsCLI._handle_legal_compliance', return_value=True)
    def test_interactive_mode_quit(self, mock_legal, mock_auth, mock_input):
        """Test interactive mode quit functionality"""
        self.cli.current_session = self.mock_session
        result = self.cli._run_interactive_mode()
        self.assertEqual(result, 0)
    
    @patch('builtins.input', side_effect=['test_user'])
    @patch('getpass.getpass', return_value='password123')
    def test_authenticate_user_success(self, mock_getpass, mock_input):
        """Test successful user authentication"""
        # Mock authentication service
        self.cli.auth_service.authenticate_user.return_value = self.mock_user
        self.cli.auth_service.create_session.return_value = self.mock_session
        
        result = self.cli._authenticate_user()
        
        self.assertTrue(result)
        self.assertEqual(self.cli.current_session, self.mock_session)
        self.cli.auth_service.authenticate_user.assert_called_once_with('test_user', 'password123')
    
    @patch('builtins.input', side_effect=['wrong_user', 'wrong_user', 'wrong_user'])
    @patch('getpass.getpass', return_value='wrong_password')
    def test_authenticate_user_failure(self, mock_getpass, mock_input):
        """Test failed user authentication"""
        # Mock authentication service to return None (failed auth)
        self.cli.auth_service.authenticate_user.return_value = None
        
        result = self.cli._authenticate_user()
        
        self.assertFalse(result)
        self.assertIsNone(self.cli.current_session)
        self.assertEqual(self.cli.auth_service.authenticate_user.call_count, 3)
    
    @patch('builtins.input', return_value='yes')
    def test_handle_legal_compliance_accept(self, mock_input):
        """Test legal compliance acceptance"""
        # Mock legal compliance service
        disclaimer = {'content': 'Legal disclaimer text'}
        self.cli.legal_compliance.get_legal_disclaimer.return_value = disclaimer
        self.cli.legal_compliance.record_consent.return_value = True
        self.cli.current_session = self.mock_session
        
        result = self.cli._handle_legal_compliance()
        
        self.assertTrue(result)
        self.cli.legal_compliance.record_consent.assert_called_once()
    
    @patch('builtins.input', return_value='no')
    def test_handle_legal_compliance_reject(self, mock_input):
        """Test legal compliance rejection"""
        disclaimer = {'content': 'Legal disclaimer text'}
        self.cli.legal_compliance.get_legal_disclaimer.return_value = disclaimer
        self.cli.current_session = self.mock_session
        
        result = self.cli._handle_legal_compliance()
        
        self.assertFalse(result)
    
    def test_validate_case_id_valid(self):
        """Test case ID validation with valid IDs"""
        valid_ids = ['CASE001', 'TEST_CASE_123', 'forensics-case-2024']
        
        for case_id in valid_ids:
            with self.subTest(case_id=case_id):
                self.assertTrue(self.cli._validate_case_id(case_id))
    
    def test_validate_case_id_invalid(self):
        """Test case ID validation with invalid IDs"""
        invalid_ids = ['', 'case with spaces', 'case@special', 'case#123']
        
        for case_id in invalid_ids:
            with self.subTest(case_id=case_id):
                self.assertFalse(self.cli._validate_case_id(case_id))
    
    @patch('builtins.input', return_value='CASE001')
    @patch('forensics_toolkit.ui.cli.ForensicsOrchestrator')
    def test_interactive_case_setup_success(self, mock_orchestrator, mock_input):
        """Test successful interactive case setup"""
        self.cli.current_session = self.mock_session
        mock_orchestrator_instance = Mock()
        mock_orchestrator.return_value = mock_orchestrator_instance
        
        self.cli._interactive_case_setup()
        
        mock_orchestrator.assert_called_once_with(
            case_id='CASE001',
            user_session=self.mock_session.session_id
        )
        self.assertEqual(self.cli.current_orchestrator, mock_orchestrator_instance)
    
    @patch('builtins.input', return_value='')
    def test_interactive_case_setup_empty_case_id(self, mock_input):
        """Test interactive case setup with empty case ID"""
        self.cli.current_session = self.mock_session
        
        # Should not create orchestrator with empty case ID
        self.cli._interactive_case_setup()
        self.assertIsNone(self.cli.current_orchestrator)
    
    def test_check_orchestrator_with_orchestrator(self):
        """Test orchestrator check when orchestrator exists"""
        self.cli.current_orchestrator = Mock()
        result = self.cli._check_orchestrator()
        self.assertTrue(result)
    
    def test_check_orchestrator_without_orchestrator(self):
        """Test orchestrator check when orchestrator doesn't exist"""
        self.cli.current_orchestrator = None
        result = self.cli._check_orchestrator()
        self.assertFalse(result)
    
    def test_select_device_valid_choice(self):
        """Test device selection with valid choice"""
        devices = [
            DeviceModel(
                serial='ABC123',
                model='Pixel 6',
                brand='Google',
                android_version='12'
            ),
            DeviceModel(
                serial='DEF456',
                model='Galaxy S21',
                brand='Samsung',
                android_version='11'
            )
        ]
        
        with patch('builtins.input', return_value='1'):
            selected = self.cli._select_device(devices)
            self.assertEqual(selected, devices[0])
    
    def test_select_device_invalid_choice(self):
        """Test device selection with invalid choice"""
        devices = [
            DeviceModel(
                serial='ABC123',
                model='Pixel 6',
                brand='Google',
                android_version='12'
            )
        ]
        
        with patch('builtins.input', return_value='5'):  # Invalid choice
            selected = self.cli._select_device(devices)
            self.assertIsNone(selected)
    
    def test_get_int_input_with_valid_input(self):
        """Test integer input with valid value"""
        with patch('builtins.input', return_value='1000'):
            result = self.cli._get_int_input("Test prompt", 500)
            self.assertEqual(result, 1000)
    
    def test_get_int_input_with_empty_input(self):
        """Test integer input with empty value (should use default)"""
        with patch('builtins.input', return_value=''):
            result = self.cli._get_int_input("Test prompt", 500)
            self.assertEqual(result, 500)
    
    def test_get_int_input_with_invalid_input(self):
        """Test integer input with invalid value (should use default)"""
        with patch('builtins.input', return_value='not_a_number'):
            result = self.cli._get_int_input("Test prompt", 500)
            self.assertEqual(result, 500)
    
    @patch('forensics_toolkit.ui.cli.config_manager')
    def test_show_configuration(self, mock_config):
        """Test configuration display"""
        # Mock configuration values
        mock_config.tool_paths.adb_path = '/usr/bin/adb'
        mock_config.tool_paths.fastboot_path = '/usr/bin/fastboot'
        mock_config.forensics_settings.max_concurrent_attacks = 4
        mock_config.security_settings.require_case_id = True
        
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.cli._show_configuration()
            output = mock_stdout.getvalue()
            
            self.assertIn('/usr/bin/adb', output)
            self.assertIn('/usr/bin/fastboot', output)
            self.assertIn('4', output)  # max_concurrent_attacks
            self.assertIn('True', output)  # require_case_id
    
    @patch('forensics_toolkit.ui.cli.config_manager')
    def test_validate_tool_paths(self, mock_config):
        """Test tool path validation"""
        mock_config.validate_tool_paths.return_value = {
            'adb': True,
            'fastboot': False,
            'hashcat': True,
            'john': False
        }
        
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.cli._validate_tool_paths()
            output = mock_stdout.getvalue()
            
            # Should show validation results
            self.assertIn('adb', output)
            self.assertIn('fastboot', output)
            self.assertIn('hashcat', output)
            self.assertIn('john', output)
    
    def test_display_attack_results_success(self):
        """Test display of successful attack results"""
        result = AttackResult(
            success=True,
            attempts=150,
            duration=45.5,
            result_data="1234",
            timestamp=datetime.now()
        )
        
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.cli._display_attack_results(result)
            output = mock_stdout.getvalue()
            
            self.assertIn("successfully", output)
            self.assertIn("150", output)  # attempts
            self.assertIn("45.50", output)  # duration
            self.assertIn("1234", output)  # result_data
    
    def test_display_attack_results_failure(self):
        """Test display of failed attack results"""
        result = AttackResult(
            success=False,
            attempts=1000,
            duration=300.0,
            error_message="Maximum attempts reached",
            timestamp=datetime.now()
        )
        
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.cli._display_attack_results(result)
            output = mock_stdout.getvalue()
            
            self.assertIn("failed", output)
            self.assertIn("1000", output)  # attempts
            self.assertIn("300.00", output)  # duration
            self.assertIn("Maximum attempts reached", output)  # error_message
    
    def test_color_output_methods(self):
        """Test colored output methods"""
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            self.cli._print_success("Success message")
            self.cli._print_error("Error message")
            self.cli._print_warning("Warning message")
            self.cli._print_info("Info message")
            
            output = mock_stdout.getvalue()
            
            self.assertIn("Success message", output)
            self.assertIn("Error message", output)
            self.assertIn("Warning message", output)
            self.assertIn("Info message", output)
            
            # Check for prefixes
            self.assertIn("[SUCCESS]", output)
            self.assertIn("[ERROR]", output)
            self.assertIn("[WARNING]", output)
            self.assertIn("[INFO]", output)
            
            # Check for color codes
            self.assertIn(CLIColors.OKGREEN, output)
            self.assertIn(CLIColors.FAIL, output)
            self.assertIn(CLIColors.WARNING, output)
            self.assertIn(CLIColors.OKBLUE, output)
    
    def test_run_with_keyboard_interrupt(self):
        """Test handling of keyboard interrupt"""
        with patch.object(self.cli.parser, 'parse_args', side_effect=KeyboardInterrupt):
            result = self.cli.run(['interactive'])
            self.assertEqual(result, 130)  # Standard exit code for SIGINT
    
    def test_run_with_forensics_exception(self):
        """Test handling of forensics exceptions"""
        from forensics_toolkit.interfaces import ForensicsException
        
        with patch.object(self.cli.parser, 'parse_args', 
                         side_effect=ForensicsException("Test error", "TEST_ERROR")):
            result = self.cli.run(['interactive'])
            self.assertEqual(result, 1)
    
    def test_run_with_unexpected_exception(self):
        """Test handling of unexpected exceptions"""
        with patch.object(self.cli.parser, 'parse_args', 
                         side_effect=RuntimeError("Unexpected error")):
            result = self.cli.run(['interactive'])
            self.assertEqual(result, 1)


class TestCLIIntegration(unittest.TestCase):
    """Integration tests for CLI functionality"""
    
    def setUp(self):
        """Setup integration test environment"""
        with patch('forensics_toolkit.ui.cli.AuthenticationService'), \
             patch('forensics_toolkit.ui.cli.UserManager'), \
             patch('forensics_toolkit.ui.cli.LegalComplianceService'):
            self.cli = ForensicsCLI()
    
    def test_full_command_parsing_workflow(self):
        """Test complete command parsing workflow"""
        test_commands = [
            ['--version'],
            ['interactive'],
            ['detect'],
            ['analyze', '--device', 'ABC123'],
            ['attack', '--case', 'CASE001', '--device', 'ABC123', '--type', 'brute_force'],
            ['report', '--case', 'CASE001'],
            ['config', 'show'],
            ['config', 'validate'],
            ['auth', 'whoami']
        ]
        
        for cmd in test_commands:
            with self.subTest(command=cmd):
                try:
                    if cmd[0] == '--version':
                        # Version command exits, so we expect SystemExit
                        with self.assertRaises(SystemExit):
                            self.cli.parser.parse_args(cmd)
                    else:
                        args = self.cli.parser.parse_args(cmd)
                        self.assertIsNotNone(args)
                except SystemExit as e:
                    # Version command is expected to exit
                    if cmd[0] != '--version':
                        self.fail(f"Unexpected SystemExit for command {cmd}: {e}")


if __name__ == '__main__':
    unittest.main()