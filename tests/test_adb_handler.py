"""
Unit tests for ADB Handler with mocked ADB responses
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import subprocess
from datetime import datetime
from typing import List

from forensics_toolkit.services.adb_handler import ADBHandler, ADBException, ADBCommand
from forensics_toolkit.interfaces import LockType
from forensics_toolkit.models.device import AndroidDevice, LockoutPolicy


class TestADBHandler(unittest.TestCase):
    """Test cases for ADB Handler"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.adb_path = "/usr/bin/adb"
        
        # Mock successful ADB version check
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Android Debug Bridge version 1.0.41",
                stderr=""
            )
            self.handler = ADBHandler(adb_path=self.adb_path, timeout=10)
    
    def test_init_success(self):
        """Test successful ADB handler initialization"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Android Debug Bridge version 1.0.41",
                stderr=""
            )
            
            handler = ADBHandler()
            self.assertEqual(handler.adb_path, "adb")
            self.assertEqual(handler.timeout, 30)
            self.assertEqual(len(handler.connected_devices), 0)
    
    def test_init_adb_not_found(self):
        """Test initialization when ADB is not found"""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            with self.assertRaises(ADBException) as context:
                ADBHandler(adb_path="/invalid/path/adb")
            
            self.assertIn("ADB executable not found", str(context.exception))
    
    def test_init_adb_not_working(self):
        """Test initialization when ADB is not working properly"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="command not found"
            )
            
            with self.assertRaises(ADBException) as context:
                ADBHandler()
            
            self.assertIn("ADB not properly installed", str(context.exception))
    
    @patch('subprocess.run')
    @patch('time.time')
    def test_execute_adb_command_success(self, mock_time, mock_run):
        """Test successful ADB command execution"""
        mock_time.side_effect = [1000.0, 1000.1]  # Start and end times
        mock_run.return_value = Mock(
            returncode=0,
            stdout="test output",
            stderr=""
        )
        
        result = self.handler._execute_adb_command(["devices"])
        
        self.assertIsInstance(result, ADBCommand)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "test output")
        self.assertEqual(result.stderr, "")
        self.assertIsInstance(result.timestamp, datetime)
        self.assertGreater(result.execution_time, 0)
    
    @patch('subprocess.run')
    def test_execute_adb_command_with_device_serial(self, mock_run):
        """Test ADB command execution with device serial"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="test output",
            stderr=""
        )
        
        result = self.handler._execute_adb_command(
            ["shell", "echo", "test"], 
            device_serial="ABC123"
        )
        
        # Verify command was called with device serial
        mock_run.assert_called_once()
        called_args = mock_run.call_args[0][0]
        self.assertIn("-s", called_args)
        self.assertIn("ABC123", called_args)
    
    @patch('subprocess.run')
    def test_execute_adb_command_timeout(self, mock_run):
        """Test ADB command timeout handling"""
        mock_run.side_effect = subprocess.TimeoutExpired("adb", 5)
        
        with self.assertRaises(ADBException) as context:
            self.handler._execute_adb_command(["devices"], timeout=5)
        
        self.assertIn("timed out", str(context.exception))
    
    @patch('subprocess.run')
    def test_detect_devices_success(self, mock_run):
        """Test successful device detection"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""List of devices attached
ABC123\tdevice model:SM_G973F device:beyond1lte
DEF456\tdevice model:Pixel_4 device:flame
""",
            stderr=""
        )
        
        devices = self.handler.detect_devices()
        
        self.assertEqual(len(devices), 2)
        
        # Check first device
        device1 = devices[0]
        self.assertEqual(device1.serial, "ABC123")
        self.assertEqual(device1.model, "SM_G973F")
        self.assertTrue(device1.usb_debugging)
        
        # Check second device
        device2 = devices[1]
        self.assertEqual(device2.serial, "DEF456")
        self.assertEqual(device2.model, "Pixel_4")
        self.assertTrue(device2.usb_debugging)
    
    @patch('subprocess.run')
    def test_detect_devices_no_devices(self, mock_run):
        """Test device detection with no devices"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="List of devices attached\n",
            stderr=""
        )
        
        devices = self.handler.detect_devices()
        self.assertEqual(len(devices), 0)
    
    @patch('subprocess.run')
    def test_detect_devices_unauthorized(self, mock_run):
        """Test device detection with unauthorized devices"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""List of devices attached
ABC123\tunauthorized
DEF456\tdevice model:Pixel_4
""",
            stderr=""
        )
        
        devices = self.handler.detect_devices()
        
        # Should only return authorized devices
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].serial, "DEF456")
    
    @patch('subprocess.run')
    def test_connect_device_success(self, mock_run):
        """Test successful device connection"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="test",
            stderr=""
        )
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11"
        )
        
        result = self.handler.connect_device(device)
        
        self.assertTrue(result)
        self.assertIn("ABC123", self.handler.connected_devices)
    
    @patch('subprocess.run')
    def test_connect_device_failure(self, mock_run):
        """Test device connection failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="device not found"
        )
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test Model",
            brand="Test Brand",
            android_version="11"
        )
        
        with self.assertRaises(ADBException) as context:
            self.handler.connect_device(device)
        
        self.assertIn("Failed to connect", str(context.exception))
    
    @patch('subprocess.run')
    def test_get_system_properties(self, mock_run):
        """Test system properties retrieval"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""[ro.product.model]: [SM-G973F]
[ro.product.brand]: [samsung]
[ro.build.version.release]: [11]
[ro.build.display.id]: [RP1A.200720.012]
[ro.build.version.security_patch]: [2021-10-01]
""",
            stderr=""
        )
        
        props = self.handler._get_system_properties("ABC123")
        
        self.assertEqual(props["ro.product.model"], "SM-G973F")
        self.assertEqual(props["ro.product.brand"], "samsung")
        self.assertEqual(props["ro.build.version.release"], "11")
        self.assertEqual(props["ro.build.display.id"], "RP1A.200720.012")
        self.assertEqual(props["ro.build.version.security_patch"], "2021-10-01")
    
    @patch('subprocess.run')
    def test_get_imei_success(self, mock_run):
        """Test successful IMEI retrieval"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Result: Parcel(00000000 00000000 00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 '123456789012345')",
            stderr=""
        )
        
        imei = self.handler._get_imei("ABC123")
        self.assertEqual(imei, "123456789012345")
    
    @patch('subprocess.run')
    def test_get_imei_failure(self, mock_run):
        """Test IMEI retrieval failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Permission denied"
        )
        
        imei = self.handler._get_imei("ABC123")
        self.assertIsNone(imei)
    
    @patch('subprocess.run')
    def test_check_root_status_rooted(self, mock_run):
        """Test root status check for rooted device"""
        # First call for 'which su'
        # Second call for 'su -c id'
        mock_run.side_effect = [
            Mock(returncode=0, stdout="/system/bin/su", stderr=""),
            Mock(returncode=0, stdout="uid=0(root) gid=0(root)", stderr="")
        ]
        
        is_rooted = self.handler._check_root_status("ABC123")
        self.assertTrue(is_rooted)
    
    @patch('subprocess.run')
    def test_check_root_status_not_rooted(self, mock_run):
        """Test root status check for non-rooted device"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="not found"
        )
        
        is_rooted = self.handler._check_root_status("ABC123")
        self.assertFalse(is_rooted)
    
    @patch('subprocess.run')
    def test_identify_lock_type_pin(self, mock_run):
        """Test lock type identification for PIN"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="2",
            stderr=""
        )
        
        lock_type = self.handler._identify_lock_type("ABC123")
        self.assertEqual(lock_type, LockType.PIN)
    
    @patch('subprocess.run')
    def test_identify_lock_type_pattern(self, mock_run):
        """Test lock type identification for pattern"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="1",
            stderr=""
        )
        
        lock_type = self.handler._identify_lock_type("ABC123")
        self.assertEqual(lock_type, LockType.PATTERN)
    
    @patch('subprocess.run')
    def test_identify_lock_type_password(self, mock_run):
        """Test lock type identification for password"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="3",
            stderr=""
        )
        
        lock_type = self.handler._identify_lock_type("ABC123")
        self.assertEqual(lock_type, LockType.PASSWORD)
    
    @patch('subprocess.run')
    def test_identify_lock_type_none(self, mock_run):
        """Test lock type identification for no lock"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="0",
            stderr=""
        )
        
        lock_type = self.handler._identify_lock_type("ABC123")
        self.assertEqual(lock_type, LockType.NONE)
    
    @patch('subprocess.run')
    def test_get_screen_timeout(self, mock_run):
        """Test screen timeout retrieval"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="60000",  # 60 seconds in milliseconds
            stderr=""
        )
        
        timeout = self.handler._get_screen_timeout("ABC123")
        self.assertEqual(timeout, 60)
    
    @patch('subprocess.run')
    def test_get_screen_timeout_default(self, mock_run):
        """Test screen timeout with default value"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="not found"
        )
        
        timeout = self.handler._get_screen_timeout("ABC123")
        self.assertEqual(timeout, 30)  # Default value
    
    @patch('subprocess.run')
    def test_get_lockout_policy(self, mock_run):
        """Test lockout policy retrieval"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="10", stderr=""),  # max attempts
            Mock(returncode=0, stdout="30000", stderr="")  # lockout duration in ms
        ]
        
        policy = self.handler._get_lockout_policy("ABC123")
        
        self.assertIsInstance(policy, LockoutPolicy)
        self.assertEqual(policy.max_attempts, 10)
        self.assertEqual(policy.lockout_duration, 30)
        self.assertTrue(policy.progressive_lockout)
        self.assertEqual(policy.wipe_after_attempts, 20)
    
    def test_get_device_info_comprehensive(self):
        """Test comprehensive device information retrieval"""
        basic_device = AndroidDevice(
            serial="ABC123",
            model="Unknown",
            brand="Unknown",
            android_version="Unknown"
        )
        
        # Mock each method individually for more control
        with patch.object(self.handler, '_get_system_properties') as mock_props, \
             patch.object(self.handler, '_get_imei') as mock_imei, \
             patch.object(self.handler, '_check_root_status') as mock_root, \
             patch.object(self.handler, '_identify_lock_type') as mock_lock, \
             patch.object(self.handler, '_get_screen_timeout') as mock_timeout, \
             patch.object(self.handler, '_get_lockout_policy') as mock_policy, \
             patch.object(self.handler, '_check_bootloader_status') as mock_bootloader, \
             patch.object(self.handler, '_check_encryption_status') as mock_encryption, \
             patch.object(self.handler, '_check_developer_options') as mock_dev_options:
            
            # Set up mock returns
            mock_props.return_value = {
                'ro.product.model': 'SM-G973F',
                'ro.product.brand': 'samsung',
                'ro.build.version.release': '11',
                'ro.build.display.id': 'RP1A.200720.012',
                'ro.build.version.security_patch': '2021-10-01'
            }
            mock_imei.return_value = "123456789012345"
            mock_root.return_value = True
            mock_lock.return_value = LockType.PIN
            mock_timeout.return_value = 60
            mock_policy.return_value = LockoutPolicy(max_attempts=5, lockout_duration=30)
            mock_bootloader.return_value = True
            mock_encryption.return_value = True
            mock_dev_options.return_value = True
            
            enhanced_device = self.handler.get_device_info(basic_device)
            
            self.assertEqual(enhanced_device.serial, "ABC123")
            self.assertEqual(enhanced_device.model, "SM-G973F")
            self.assertEqual(enhanced_device.brand, "samsung")
            self.assertEqual(enhanced_device.android_version, "11")
            self.assertEqual(enhanced_device.imei, "123456789012345")
            self.assertTrue(enhanced_device.usb_debugging)
            self.assertTrue(enhanced_device.root_status)
            self.assertEqual(enhanced_device.lock_type, LockType.PIN)
            self.assertEqual(enhanced_device.screen_timeout, 60)
            self.assertEqual(enhanced_device.build_number, "RP1A.200720.012")
            self.assertEqual(enhanced_device.security_patch_level, "2021-10-01")
            self.assertTrue(enhanced_device.bootloader_locked)
            self.assertTrue(enhanced_device.encryption_enabled)
            self.assertTrue(enhanced_device.developer_options_enabled)
    
    @patch('subprocess.run')
    def test_is_device_accessible_success(self, mock_run):
        """Test device accessibility check success"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="accessible",
            stderr=""
        )
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test",
            brand="Test",
            android_version="11"
        )
        
        result = self.handler.is_device_accessible(device)
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_is_device_accessible_failure(self, mock_run):
        """Test device accessibility check failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="device not found"
        )
        
        device = AndroidDevice(
            serial="ABC123",
            model="Test",
            brand="Test",
            android_version="11"
        )
        
        result = self.handler.is_device_accessible(device)
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_inject_input_text(self, mock_run):
        """Test text input injection"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="",
            stderr=""
        )
        
        result = self.handler.inject_input("ABC123", "text", "1234")
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        called_args = mock_run.call_args[0][0]
        self.assertIn("input", called_args)
        self.assertIn("text", called_args)
        self.assertIn("1234", called_args)
    
    @patch('subprocess.run')
    def test_inject_input_keyevent(self, mock_run):
        """Test keyevent input injection"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="",
            stderr=""
        )
        
        result = self.handler.inject_input("ABC123", "keyevent", "KEYCODE_ENTER")
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        called_args = mock_run.call_args[0][0]
        self.assertIn("keyevent", called_args)
        self.assertIn("KEYCODE_ENTER", called_args)
    
    @patch('subprocess.run')
    def test_inject_input_tap(self, mock_run):
        """Test tap input injection"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="",
            stderr=""
        )
        
        result = self.handler.inject_input("ABC123", "tap", "500, 800")
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        called_args = mock_run.call_args[0][0]
        self.assertIn("tap", called_args)
        self.assertIn("500", called_args)
        self.assertIn("800", called_args)
    
    @patch('subprocess.run')
    def test_inject_input_invalid_type(self, mock_run):
        """Test input injection with invalid type"""
        with self.assertRaises(ADBException) as context:
            self.handler.inject_input("ABC123", "invalid", "test")
        
        self.assertIn("Unsupported input type", str(context.exception))
    
    @patch('subprocess.run')
    def test_attempt_pin_unlock_success(self, mock_run):
        """Test successful PIN unlock attempt"""
        mock_responses = [
            # Wake up device
            Mock(returncode=0, stdout="", stderr=""),
            # Swipe up
            Mock(returncode=0, stdout="", stderr=""),
            # Input PIN
            Mock(returncode=0, stdout="", stderr=""),
            # Press enter
            Mock(returncode=0, stdout="", stderr=""),
            # Check unlock status
            Mock(returncode=0, stdout="StatusBar visible=true", stderr="")
        ]
        
        mock_run.side_effect = mock_responses
        
        success, message = self.handler.attempt_pin_unlock("ABC123", "1234")
        
        self.assertTrue(success)
        self.assertIn("unlocked successfully", message)
    
    @patch('subprocess.run')
    def test_attempt_pin_unlock_incorrect(self, mock_run):
        """Test incorrect PIN unlock attempt"""
        mock_responses = [
            # Wake up device
            Mock(returncode=0, stdout="", stderr=""),
            # Swipe up
            Mock(returncode=0, stdout="", stderr=""),
            # Input PIN
            Mock(returncode=0, stdout="", stderr=""),
            # Press enter
            Mock(returncode=0, stdout="", stderr=""),
            # Check unlock status - still locked
            Mock(returncode=0, stdout="Keyguard visible=true", stderr="")
        ]
        
        mock_run.side_effect = mock_responses
        
        success, message = self.handler.attempt_pin_unlock("ABC123", "0000")
        
        self.assertFalse(success)
        self.assertIn("Incorrect PIN", message)
    
    @patch('subprocess.run')
    def test_attempt_pin_unlock_lockout(self, mock_run):
        """Test PIN unlock attempt during lockout"""
        mock_responses = [
            # Wake up device
            Mock(returncode=0, stdout="", stderr=""),
            # Swipe up
            Mock(returncode=0, stdout="", stderr=""),
            # Input PIN
            Mock(returncode=0, stdout="", stderr=""),
            # Press enter
            Mock(returncode=0, stdout="", stderr=""),
            # Check unlock status - too many attempts
            Mock(returncode=0, stdout="Too many attempts. Try again later.", stderr="")
        ]
        
        mock_run.side_effect = mock_responses
        
        success, message = self.handler.attempt_pin_unlock("ABC123", "1234")
        
        self.assertFalse(success)
        self.assertIn("Too many attempts", message)
    
    @patch('subprocess.run')
    def test_pull_file_success(self, mock_run):
        """Test successful file pull"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="1 file pulled",
            stderr=""
        )
        
        result = self.handler.pull_file("ABC123", "/data/test.txt", "./test.txt")
        
        self.assertTrue(result)
        mock_run.assert_called_once()
        called_args = mock_run.call_args[0][0]
        self.assertIn("pull", called_args)
        self.assertIn("/data/test.txt", called_args)
        self.assertIn("./test.txt", called_args)
    
    @patch('subprocess.run')
    def test_pull_file_failure(self, mock_run):
        """Test file pull failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Permission denied"
        )
        
        result = self.handler.pull_file("ABC123", "/data/test.txt", "./test.txt")
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_pull_gesture_key_success(self, mock_run):
        """Test successful gesture key pull"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="1 file pulled",
            stderr=""
        )
        
        result = self.handler.pull_gesture_key("ABC123", "./gesture.key")
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_pull_gesture_key_failure(self, mock_run):
        """Test gesture key pull failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="No such file"
        )
        
        result = self.handler.pull_gesture_key("ABC123", "./gesture.key")
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_get_screen_state_unlocked(self, mock_run):
        """Test screen state detection - unlocked"""
        mock_responses = [
            Mock(returncode=0, stdout="Display Power: state=ON", stderr=""),
            Mock(returncode=0, stdout="StatusBar visible=true", stderr="")
        ]
        
        mock_run.side_effect = mock_responses
        
        state = self.handler.get_screen_state("ABC123")
        self.assertEqual(state, "unlocked")
    
    @patch('subprocess.run')
    def test_get_screen_state_locked(self, mock_run):
        """Test screen state detection - locked"""
        mock_responses = [
            Mock(returncode=0, stdout="Display Power: state=ON", stderr=""),
            Mock(returncode=0, stdout="Keyguard visible=true", stderr="")
        ]
        
        mock_run.side_effect = mock_responses
        
        state = self.handler.get_screen_state("ABC123")
        self.assertEqual(state, "locked")
    
    @patch('subprocess.run')
    def test_get_screen_state_off(self, mock_run):
        """Test screen state detection - off"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Display Power: state=OFF",
            stderr=""
        )
        
        state = self.handler.get_screen_state("ABC123")
        self.assertEqual(state, "off")
    
    @patch('subprocess.run')
    def test_detect_lockout_active(self, mock_run):
        """Test lockout detection - active lockout"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Device is locked for 45 seconds",
            stderr=""
        )
        
        is_locked, remaining_time = self.handler.detect_lockout("ABC123")
        
        self.assertTrue(is_locked)
        self.assertEqual(remaining_time, 45)
    
    @patch('subprocess.run')
    def test_detect_lockout_none(self, mock_run):
        """Test lockout detection - no lockout"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Device is active",
            stderr=""
        )
        
        is_locked, remaining_time = self.handler.detect_lockout("ABC123")
        
        self.assertFalse(is_locked)
        self.assertEqual(remaining_time, 0)
    
    def test_str_representation(self):
        """Test string representation"""
        str_repr = str(self.handler)
        self.assertIn("ADBHandler", str_repr)
        self.assertIn("connected_devices=0", str_repr)
    
    def test_repr_representation(self):
        """Test detailed representation"""
        repr_str = repr(self.handler)
        self.assertIn("ADBHandler", repr_str)
        self.assertIn("adb_path", repr_str)
        self.assertIn("timeout", repr_str)


class TestADBCommand(unittest.TestCase):
    """Test cases for ADB Command data class"""
    
    def test_adb_command_creation(self):
        """Test ADB command creation"""
        timestamp = datetime.now()
        
        cmd = ADBCommand(
            command="adb devices",
            returncode=0,
            stdout="List of devices attached",
            stderr="",
            execution_time=0.5,
            timestamp=timestamp,
            device_serial="ABC123"
        )
        
        self.assertEqual(cmd.command, "adb devices")
        self.assertEqual(cmd.returncode, 0)
        self.assertEqual(cmd.stdout, "List of devices attached")
        self.assertEqual(cmd.stderr, "")
        self.assertEqual(cmd.execution_time, 0.5)
        self.assertEqual(cmd.timestamp, timestamp)
        self.assertEqual(cmd.device_serial, "ABC123")


class TestADBException(unittest.TestCase):
    """Test cases for ADB Exception"""
    
    def test_adb_exception_creation(self):
        """Test ADB exception creation"""
        exc = ADBException(
            "Test error message",
            command="adb devices",
            device_serial="ABC123"
        )
        
        self.assertEqual(str(exc), "Test error message")
        self.assertEqual(exc.error_code, "ADB_ERROR")
        self.assertTrue(exc.evidence_impact)
        self.assertEqual(exc.command, "adb devices")
        self.assertEqual(exc.device_serial, "ABC123")
        self.assertIsInstance(exc.timestamp, datetime)


if __name__ == '__main__':
    unittest.main()