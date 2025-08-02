"""
Unit tests for FastbootHandler

This module contains comprehensive tests for the FastbootHandler class,
including device detection, connection, information gathering, and
forensic operations.
"""

import pytest
import subprocess
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from forensics_toolkit.services.fastboot_handler import (
    FastbootHandler, FastbootException, FastbootCommand, 
    DeviceState, PartitionInfo
)
from forensics_toolkit.models.device import AndroidDevice
from forensics_toolkit.interfaces import LockType


class TestFastbootHandler:
    """Test cases for FastbootHandler class"""
    
    @pytest.fixture
    def handler(self):
        """Create FastbootHandler instance for testing"""
        with patch.object(FastbootHandler, '_verify_fastboot_installation'):
            return FastbootHandler(fastboot_path="fastboot", timeout=30)
    
    @pytest.fixture
    def mock_device(self):
        """Create mock AndroidDevice for testing"""
        return AndroidDevice(
            serial="FB_TEST123",
            model="Test Device",
            brand="TestBrand",
            android_version="11"
        )
    
    @pytest.fixture
    def mock_fastboot_command(self):
        """Create mock FastbootCommand result"""
        return FastbootCommand(
            command="fastboot devices",
            returncode=0,
            stdout="FB_TEST123\tfastboot",
            stderr="",
            execution_time=1.0,
            timestamp=datetime.now()
        )

    def test_init_success(self):
        """Test successful FastbootHandler initialization"""
        with patch.object(FastbootHandler, '_verify_fastboot_installation'):
            handler = FastbootHandler(fastboot_path="fastboot", timeout=60)
            
            assert handler.fastboot_path == "fastboot"
            assert handler.timeout == 60
            assert handler.connected_devices == {}
            assert handler.device_states == {}
    
    def test_init_custom_path(self):
        """Test FastbootHandler initialization with custom path"""
        with patch.object(FastbootHandler, '_verify_fastboot_installation'):
            handler = FastbootHandler(fastboot_path="/custom/fastboot", timeout=120)
            
            assert handler.fastboot_path == "/custom/fastboot"
            assert handler.timeout == 120
    
    def test_verify_fastboot_installation_success(self):
        """Test successful fastboot installation verification"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="fastboot version", stderr="")
            
            handler = FastbootHandler()
            # Should not raise exception
    
    def test_verify_fastboot_installation_not_found(self):
        """Test fastboot installation verification when fastboot not found"""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            with pytest.raises(FastbootException) as exc_info:
                FastbootHandler()
            
            assert "Fastboot executable not found" in str(exc_info.value)
    
    def test_verify_fastboot_installation_failed(self):
        """Test fastboot installation verification when fastboot fails"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")
            
            with pytest.raises(FastbootException) as exc_info:
                FastbootHandler()
            
            assert "Fastboot not properly installed" in str(exc_info.value)
    
    def test_execute_fastboot_command_success(self, handler):
        """Test successful fastboot command execution"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="FB_TEST123\tfastboot\n",
                stderr=""
            )
            
            result = handler._execute_fastboot_command(["devices"])
            
            assert result.returncode == 0
            assert "FB_TEST123" in result.stdout
            assert result.command == "fastboot devices"
            mock_run.assert_called_once()
    
    def test_execute_fastboot_command_with_serial(self, handler):
        """Test fastboot command execution with device serial"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="product: test", stderr="")
            
            result = handler._execute_fastboot_command(["getvar", "product"], device_serial="FB_TEST123")
            
            assert result.device_serial == "FB_TEST123"
            # Verify -s serial was added to command
            call_args = mock_run.call_args[0][0]
            assert "-s" in call_args
            assert "FB_TEST123" in call_args
    
    def test_execute_fastboot_command_timeout(self, handler):
        """Test fastboot command timeout handling"""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("fastboot", 30)):
            with pytest.raises(FastbootException) as exc_info:
                handler._execute_fastboot_command(["devices"], timeout=30)
            
            assert "timed out after 30 seconds" in str(exc_info.value)
    
    def test_execute_fastboot_command_error(self, handler):
        """Test fastboot command execution error handling"""
        with patch('subprocess.run', side_effect=Exception("Command failed")):
            with pytest.raises(FastbootException) as exc_info:
                handler._execute_fastboot_command(["devices"])
            
            assert "Failed to execute fastboot command" in str(exc_info.value)
    
    def test_detect_devices_success(self, handler):
        """Test successful device detection"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot devices",
                returncode=0,
                stdout="FB_TEST123\tfastboot\nFB_TEST456\tfastboot",
                stderr="",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            devices = handler.detect_devices()
            
            assert len(devices) == 2
            assert devices[0].serial == "FB_TEST123"
            assert devices[1].serial == "FB_TEST456"
            assert all(not device.usb_debugging for device in devices)
            mock_exec.assert_called_once_with(["devices"])
    
    def test_detect_devices_empty(self, handler):
        """Test device detection with no devices"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot devices",
                returncode=0,
                stdout="",
                stderr="",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            devices = handler.detect_devices()
            
            assert len(devices) == 0
    
    def test_detect_devices_command_failed(self, handler):
        """Test device detection when fastboot command fails"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot devices",
                returncode=1,
                stdout="",
                stderr="error",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            with pytest.raises(FastbootException) as exc_info:
                handler.detect_devices()
            
            assert "Failed to detect fastboot devices" in str(exc_info.value)
    
    def test_connect_device_success(self, handler, mock_device):
        """Test successful device connection"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar product",
                returncode=0,
                stdout="",
                stderr="product: test_device",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            result = handler.connect_device(mock_device)
            
            assert result is True
            assert mock_device.serial in handler.connected_devices
            mock_exec.assert_called_once_with(["getvar", "product"], device_serial=mock_device.serial)
    
    def test_connect_device_failed(self, handler, mock_device):
        """Test failed device connection"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar product",
                returncode=1,
                stdout="",
                stderr="FAILED",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            with pytest.raises(FastbootException) as exc_info:
                handler.connect_device(mock_device)
            
            assert "Failed to connect to fastboot device" in str(exc_info.value)
    
    def test_get_device_variables(self, handler):
        """Test getting device variables"""
        mock_responses = {
            "product": "product: test_device",
            "brand": "brand: TestBrand", 
            "version": "version: 11",
            "unlocked": "unlocked: yes"
        }
        
        def mock_exec_side_effect(args, **kwargs):
            var_name = args[1] if len(args) > 1 else ""
            stderr_output = mock_responses.get(var_name, "")
            
            return FastbootCommand(
                command=f"fastboot getvar {var_name}",
                returncode=0,
                stdout="",
                stderr=stderr_output,
                execution_time=0.5,
                timestamp=datetime.now()
            )
        
        with patch.object(handler, '_execute_fastboot_command', side_effect=mock_exec_side_effect):
            variables = handler._get_device_variables("FB_TEST123")
            
            assert variables["product"] == "test_device"
            assert variables["brand"] == "TestBrand"
            assert variables["version"] == "11"
            assert variables["unlocked"] == "yes"
    
    def test_parse_device_state(self, handler):
        """Test parsing device state from variables"""
        variables = {
            'version-bootloader': '1.0.0',
            'product': 'test_device',
            'variant': 'user',
            'secure': 'yes',
            'unlocked': 'yes',
            'off-mode-charge': '1',
            'critical-unlocked': 'no',
            'slot-count': '2',
            'current-slot': 'a'
        }
        
        state = handler._parse_device_state(variables)
        
        assert state.bootloader_version == '1.0.0'
        assert state.product_name == 'test_device'
        assert state.variant == 'user'
        assert state.secure is True
        assert state.unlocked is True
        assert state.off_mode_charge is True
        assert state.critical_unlocked is False
        assert state.slot_count == 2
        assert state.current_slot == 'a'
    
    def test_get_device_info_success(self, handler, mock_device):
        """Test successful device info retrieval"""
        mock_variables = {
            'product': 'enhanced_device',
            'brand': 'EnhancedBrand',
            'version': '12',
            'version-bootloader': '2.0.0',
            'unlocked': 'no'
        }
        
        with patch.object(handler, '_get_device_variables', return_value=mock_variables):
            enhanced_device = handler.get_device_info(mock_device)
            
            assert enhanced_device.model == 'enhanced_device'
            assert enhanced_device.brand == 'EnhancedBrand'
            assert enhanced_device.android_version == '12'
            assert enhanced_device.build_number == '2.0.0'
            assert enhanced_device.bootloader_locked is True
            assert enhanced_device.usb_debugging is False
    
    def test_is_device_accessible_success(self, handler, mock_device):
        """Test device accessibility check success"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar product",
                returncode=0,
                stdout="",
                stderr="product: test",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            result = handler.is_device_accessible(mock_device)
            
            assert result is True
    
    def test_is_device_accessible_failed(self, handler, mock_device):
        """Test device accessibility check failure"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar product",
                returncode=1,
                stdout="",
                stderr="FAILED",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            result = handler.is_device_accessible(mock_device)
            
            assert result is False
    
    def test_get_partition_info(self, handler):
        """Test getting partition information"""
        getvar_output = """
        partition-size:system: 0x100000000
        partition-size:userdata: 0x200000000
        partition-type:system: ext4
        partition-type:userdata: f2fs
        """
        
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar all",
                returncode=0,
                stdout="",
                stderr=getvar_output,
                execution_time=2.0,
                timestamp=datetime.now()
            )
            
            partitions = handler.get_partition_info("FB_TEST123")
            
            assert len(partitions) == 2
            
            system_partition = next(p for p in partitions if p.name == "system")
            assert system_partition.size == 0x100000000
            assert system_partition.type == "ext4"
            
            userdata_partition = next(p for p in partitions if p.name == "userdata")
            assert userdata_partition.size == 0x200000000
            assert userdata_partition.type == "f2fs"
    
    def test_flash_recovery_success(self, handler):
        """Test successful recovery flashing"""
        recovery_path = "/path/to/recovery.img"
        
        with patch('os.path.exists', return_value=True):
            with patch.object(handler, '_execute_fastboot_command') as mock_exec:
                mock_exec.return_value = FastbootCommand(
                    command="fastboot flash recovery",
                    returncode=0,
                    stdout="OKAY",
                    stderr="",
                    execution_time=30.0,
                    timestamp=datetime.now()
                )
                
                result = handler.flash_recovery("FB_TEST123", recovery_path)
                
                assert result is True
                mock_exec.assert_called_once_with(
                    ["flash", "recovery", recovery_path],
                    device_serial="FB_TEST123",
                    timeout=120
                )
    
    def test_flash_recovery_file_not_found(self, handler):
        """Test recovery flashing with missing file"""
        recovery_path = "/nonexistent/recovery.img"
        
        with patch('os.path.exists', return_value=False):
            with pytest.raises(FastbootException) as exc_info:
                handler.flash_recovery("FB_TEST123", recovery_path)
            
            assert "Recovery image not found" in str(exc_info.value)
    
    def test_flash_recovery_failed(self, handler):
        """Test failed recovery flashing"""
        recovery_path = "/path/to/recovery.img"
        
        with patch('os.path.exists', return_value=True):
            with patch.object(handler, '_execute_fastboot_command') as mock_exec:
                mock_exec.return_value = FastbootCommand(
                    command="fastboot flash recovery",
                    returncode=1,
                    stdout="",
                    stderr="FAILED",
                    execution_time=5.0,
                    timestamp=datetime.now()
                )
                
                with pytest.raises(FastbootException) as exc_info:
                    handler.flash_recovery("FB_TEST123", recovery_path)
                
                assert "Failed to flash recovery" in str(exc_info.value)
    
    def test_boot_image_success(self, handler):
        """Test successful image booting"""
        boot_path = "/path/to/boot.img"
        
        with patch('os.path.exists', return_value=True):
            with patch.object(handler, '_execute_fastboot_command') as mock_exec:
                mock_exec.return_value = FastbootCommand(
                    command="fastboot boot",
                    returncode=0,
                    stdout="OKAY",
                    stderr="",
                    execution_time=10.0,
                    timestamp=datetime.now()
                )
                
                result = handler.boot_image("FB_TEST123", boot_path)
                
                assert result is True
                mock_exec.assert_called_once_with(
                    ["boot", boot_path],
                    device_serial="FB_TEST123",
                    timeout=60
                )
    
    def test_reboot_device_system(self, handler):
        """Test device reboot to system"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot reboot",
                returncode=0,
                stdout="OKAY",
                stderr="",
                execution_time=2.0,
                timestamp=datetime.now()
            )
            
            result = handler.reboot_device("FB_TEST123", "system")
            
            assert result is True
            mock_exec.assert_called_once_with(
                ["reboot"],
                device_serial="FB_TEST123",
                timeout=30
            )
    
    def test_reboot_device_bootloader(self, handler):
        """Test device reboot to bootloader"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot reboot bootloader",
                returncode=0,
                stdout="OKAY",
                stderr="",
                execution_time=2.0,
                timestamp=datetime.now()
            )
            
            result = handler.reboot_device("FB_TEST123", "bootloader")
            
            assert result is True
            mock_exec.assert_called_once_with(
                ["reboot", "bootloader"],
                device_serial="FB_TEST123",
                timeout=30
            )
    
    def test_reboot_device_invalid_target(self, handler):
        """Test device reboot with invalid target"""
        with pytest.raises(FastbootException) as exc_info:
            handler.reboot_device("FB_TEST123", "invalid")
        
        assert "Invalid reboot target" in str(exc_info.value)
    
    def test_unlock_bootloader_success(self, handler):
        """Test successful bootloader unlock"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot flashing unlock",
                returncode=0,
                stdout="OKAY",
                stderr="",
                execution_time=5.0,
                timestamp=datetime.now()
            )
            
            success, message = handler.unlock_bootloader("FB_TEST123")
            
            assert success is True
            assert "unlock successful" in message.lower()
    
    def test_unlock_bootloader_not_allowed(self, handler):
        """Test bootloader unlock when not allowed"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot flashing unlock",
                returncode=1,
                stdout="",
                stderr="FAILED (remote: 'Flashing Unlock is not allowed')",
                execution_time=2.0,
                timestamp=datetime.now()
            )
            
            success, message = handler.unlock_bootloader("FB_TEST123")
            
            assert success is False
            assert "not allowed" in message.lower()
    
    def test_unlock_bootloader_already_unlocked(self, handler):
        """Test bootloader unlock when already unlocked"""
        # Mock device state as already unlocked
        handler.device_states["FB_TEST123"] = DeviceState(
            bootloader_version="1.0",
            product_name="test",
            variant="user",
            secure=True,
            unlocked=True,
            off_mode_charge=False,
            critical_unlocked=False
        )
        
        success, message = handler.unlock_bootloader("FB_TEST123")
        
        assert success is True
        assert "already unlocked" in message.lower()
    
    def test_is_bootloader_unlocked_true(self, handler):
        """Test bootloader unlock status check - unlocked"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar unlocked",
                returncode=0,
                stdout="",
                stderr="unlocked: yes",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            result = handler.is_bootloader_unlocked("FB_TEST123")
            
            assert result is True
    
    def test_is_bootloader_unlocked_false(self, handler):
        """Test bootloader unlock status check - locked"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot getvar unlocked",
                returncode=0,
                stdout="",
                stderr="unlocked: no",
                execution_time=1.0,
                timestamp=datetime.now()
            )
            
            result = handler.is_bootloader_unlocked("FB_TEST123")
            
            assert result is False
    
    def test_erase_partition_success(self, handler):
        """Test successful partition erase"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot erase userdata",
                returncode=0,
                stdout="OKAY",
                stderr="",
                execution_time=10.0,
                timestamp=datetime.now()
            )
            
            result = handler.erase_partition("FB_TEST123", "userdata")
            
            assert result is True
            mock_exec.assert_called_once_with(
                ["erase", "userdata"],
                device_serial="FB_TEST123",
                timeout=60
            )
    
    def test_format_partition_success(self, handler):
        """Test successful partition format"""
        with patch.object(handler, '_execute_fastboot_command') as mock_exec:
            mock_exec.return_value = FastbootCommand(
                command="fastboot format userdata ext4",
                returncode=0,
                stdout="OKAY",
                stderr="",
                execution_time=30.0,
                timestamp=datetime.now()
            )
            
            result = handler.format_partition("FB_TEST123", "userdata", "ext4")
            
            assert result is True
            mock_exec.assert_called_once_with(
                ["format", "userdata", "ext4"],
                device_serial="FB_TEST123",
                timeout=120
            )
    
    def test_get_device_state(self, handler):
        """Test getting device state"""
        mock_state = DeviceState(
            bootloader_version="1.0",
            product_name="test",
            variant="user",
            secure=True,
            unlocked=False,
            off_mode_charge=False,
            critical_unlocked=False
        )
        
        handler.device_states["FB_TEST123"] = mock_state
        
        result = handler.get_device_state("FB_TEST123")
        
        assert result == mock_state
    
    def test_get_device_state_not_found(self, handler):
        """Test getting device state when not found"""
        result = handler.get_device_state("NONEXISTENT")
        
        assert result is None
    
    def test_str_representation(self, handler):
        """Test string representation of handler"""
        handler.connected_devices["FB_TEST123"] = Mock()
        
        result = str(handler)
        
        assert "FastbootHandler" in result
        assert "fastboot" in result
        assert "connected_devices=1" in result
    
    def test_repr_representation(self, handler):
        """Test detailed representation of handler"""
        handler.connected_devices["FB_TEST123"] = Mock()
        
        result = repr(handler)
        
        assert "FastbootHandler" in result
        assert "fastboot_path='fastboot'" in result
        assert "timeout=30" in result
        assert "FB_TEST123" in result


class TestFastbootException:
    """Test cases for FastbootException class"""
    
    def test_init_basic(self):
        """Test basic FastbootException initialization"""
        exc = FastbootException("Test error")
        
        assert str(exc) == "Test error"
        assert exc.error_code == "FASTBOOT_ERROR"
        assert exc.evidence_impact is True
        assert exc.command is None
        assert exc.device_serial is None
    
    def test_init_with_details(self):
        """Test FastbootException initialization with details"""
        exc = FastbootException(
            "Command failed",
            command="fastboot devices",
            device_serial="FB_TEST123"
        )
        
        assert str(exc) == "Command failed"
        assert exc.command == "fastboot devices"
        assert exc.device_serial == "FB_TEST123"


class TestFastbootCommand:
    """Test cases for FastbootCommand dataclass"""
    
    def test_init(self):
        """Test FastbootCommand initialization"""
        timestamp = datetime.now()
        cmd = FastbootCommand(
            command="fastboot devices",
            returncode=0,
            stdout="output",
            stderr="",
            execution_time=1.5,
            timestamp=timestamp,
            device_serial="FB_TEST123"
        )
        
        assert cmd.command == "fastboot devices"
        assert cmd.returncode == 0
        assert cmd.stdout == "output"
        assert cmd.stderr == ""
        assert cmd.execution_time == 1.5
        assert cmd.timestamp == timestamp
        assert cmd.device_serial == "FB_TEST123"


class TestDeviceState:
    """Test cases for DeviceState dataclass"""
    
    def test_init(self):
        """Test DeviceState initialization"""
        state = DeviceState(
            bootloader_version="1.0.0",
            product_name="test_device",
            variant="user",
            secure=True,
            unlocked=False,
            off_mode_charge=True,
            critical_unlocked=False,
            slot_count=2,
            current_slot="a",
            slot_successful="a",
            slot_unbootable="b"
        )
        
        assert state.bootloader_version == "1.0.0"
        assert state.product_name == "test_device"
        assert state.variant == "user"
        assert state.secure is True
        assert state.unlocked is False
        assert state.off_mode_charge is True
        assert state.critical_unlocked is False
        assert state.slot_count == 2
        assert state.current_slot == "a"
        assert state.slot_successful == "a"
        assert state.slot_unbootable == "b"


class TestPartitionInfo:
    """Test cases for PartitionInfo dataclass"""
    
    def test_init_basic(self):
        """Test basic PartitionInfo initialization"""
        partition = PartitionInfo(
            name="system",
            size=1073741824,
            type="ext4"
        )
        
        assert partition.name == "system"
        assert partition.size == 1073741824
        assert partition.type == "ext4"
        assert partition.is_logical is False
        assert partition.slot_suffix is None
    
    def test_init_with_optional_fields(self):
        """Test PartitionInfo initialization with optional fields"""
        partition = PartitionInfo(
            name="system",
            size=1073741824,
            type="ext4",
            is_logical=True,
            slot_suffix="_a"
        )
        
        assert partition.is_logical is True
        assert partition.slot_suffix == "_a"