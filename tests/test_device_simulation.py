"""
Device Simulation Tests for Integration Testing

This module provides comprehensive device simulation capabilities for testing
forensic workflows without requiring physical Android devices.
"""

import pytest
import time
import json
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from forensics_toolkit.models.device import AndroidDevice, LockoutPolicy
from forensics_toolkit.interfaces import LockType, AttackType, AttackResult
from forensics_toolkit.services.device_handlers.adb_handler import ADBHandler
from forensics_toolkit.services.device_handlers.edl_handler import EDLHandler
from forensics_toolkit.services.device_handlers.fastboot_handler import FastbootHandler


@dataclass
class DeviceSimulationConfig:
    """Configuration for device simulation"""
    serial: str
    model: str
    brand: str
    android_version: str
    lock_type: LockType
    correct_value: str
    usb_debugging: bool = True
    root_status: bool = False
    bootloader_locked: bool = True
    encryption_enabled: bool = True
    
    # Simulation parameters
    response_delay_ms: int = 100
    failure_probability: float = 0.0
    lockout_enabled: bool = True
    max_attempts_before_lockout: int = 5
    lockout_duration_seconds: int = 30
    
    # Advanced simulation features
    battery_level: int = 80
    storage_available_gb: float = 32.0
    network_connected: bool = True
    developer_options_enabled: bool = False


class AndroidDeviceSimulator:
    """Comprehensive Android device simulator"""
    
    def __init__(self, config: DeviceSimulationConfig):
        self.config = config
        self.current_attempts = 0
        self.locked_until: Optional[datetime] = None
        self.is_connected = True
        self.device_state = "idle"
        self.last_activity = datetime.now()
        self.session_data = {}
        
        # Simulate device files and data
        self.file_system = self._initialize_file_system()
        self.system_properties = self._initialize_system_properties()
        
    def _initialize_file_system(self) -> Dict[str, Any]:
        """Initialize simulated device file system"""
        file_system = {
            "/data/system/gesture.key": None,
            "/data/system/password.key": None,
            "/data/system/locksettings.db": None,
            "/system/build.prop": self._generate_build_prop(),
            "/proc/version": f"Linux version 4.14.0 (Android {self.config.android_version})",
            "/sys/class/power_supply/battery/capacity": str(self.config.battery_level),
        }
        
        # Add lock-specific files
        if self.config.lock_type == LockType.PATTERN:
            file_system["/data/system/gesture.key"] = self._generate_gesture_key()
        elif self.config.lock_type in [LockType.PIN, LockType.PASSWORD]:
            file_system["/data/system/password.key"] = self._generate_password_key()
            
        return file_system
    
    def _initialize_system_properties(self) -> Dict[str, str]:
        """Initialize simulated system properties"""
        return {
            "ro.build.version.release": self.config.android_version,
            "ro.product.model": self.config.model,
            "ro.product.brand": self.config.brand,
            "ro.product.manufacturer": self.config.brand,
            "ro.serialno": self.config.serial,
            "ro.debuggable": "1" if self.config.usb_debugging else "0",
            "ro.secure": "0" if self.config.root_status else "1",
            "ro.boot.verifiedbootstate": "orange" if not self.config.bootloader_locked else "green",
            "ro.crypto.state": "encrypted" if self.config.encryption_enabled else "unencrypted",
            "persist.sys.usb.config": "mtp,adb" if self.config.usb_debugging else "mtp",
        }
    
    def _generate_build_prop(self) -> str:
        """Generate simulated build.prop content"""
        return f"""
ro.build.version.release={self.config.android_version}
ro.build.version.sdk=31
ro.product.model={self.config.model}
ro.product.brand={self.config.brand}
ro.product.manufacturer={self.config.brand}
ro.serialno={self.config.serial}
ro.debuggable={'1' if self.config.usb_debugging else '0'}
ro.secure={'0' if self.config.root_status else '1'}
"""
    
    def _generate_gesture_key(self) -> bytes:
        """Generate simulated gesture.key file"""
        # Simulate SHA-1 hash of pattern
        import hashlib
        pattern_hash = hashlib.sha1(self.config.correct_value.encode()).digest()
        return pattern_hash
    
    def _generate_password_key(self) -> bytes:
        """Generate simulated password.key file"""
        # Simulate scrypt hash of password/PIN
        import hashlib
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          self.config.correct_value.encode(), 
                                          b'salt', 100000)
        return password_hash
    
    def simulate_adb_command(self, command: str) -> Dict[str, Any]:
        """Simulate ADB command execution"""
        self._simulate_delay()
        
        if not self.is_connected:
            return {"success": False, "error": "device_not_found"}
        
        if not self.config.usb_debugging:
            return {"success": False, "error": "usb_debugging_disabled"}
        
        # Parse and handle different ADB commands
        if command.startswith("shell getprop"):
            return self._handle_getprop_command(command)
        elif command.startswith("shell input"):
            return self._handle_input_command(command)
        elif command.startswith("pull"):
            return self._handle_pull_command(command)
        elif command.startswith("shell ls"):
            return self._handle_ls_command(command)
        elif command == "devices":
            return self._handle_devices_command()
        else:
            return {"success": True, "output": "command_executed"}
    
    def _handle_getprop_command(self, command: str) -> Dict[str, Any]:
        """Handle getprop commands"""
        parts = command.split()
        if len(parts) >= 3:
            prop_name = parts[2]
            if prop_name in self.system_properties:
                return {
                    "success": True,
                    "output": self.system_properties[prop_name]
                }
        
        return {"success": True, "output": ""}
    
    def _handle_input_command(self, command: str) -> Dict[str, Any]:
        """Handle input simulation commands"""
        if "input text" in command or "input keyevent" in command:
            return self._simulate_unlock_attempt(command)
        
        return {"success": True, "output": "input_executed"}
    
    def _handle_pull_command(self, command: str) -> Dict[str, Any]:
        """Handle file pull commands"""
        parts = command.split()
        if len(parts) >= 2:
            file_path = parts[1]
            if file_path in self.file_system:
                file_content = self.file_system[file_path]
                if file_content is not None:
                    return {
                        "success": True,
                        "output": "file_pulled",
                        "data": file_content
                    }
        
        return {"success": False, "error": "file_not_found"}
    
    def _handle_ls_command(self, command: str) -> Dict[str, Any]:
        """Handle ls commands"""
        parts = command.split()
        if len(parts) >= 3:
            directory = parts[2]
            files = [path for path in self.file_system.keys() 
                    if path.startswith(directory)]
            return {
                "success": True,
                "output": "\n".join(files)
            }
        
        return {"success": True, "output": ""}
    
    def _handle_devices_command(self) -> Dict[str, Any]:
        """Handle devices command"""
        if self.is_connected:
            return {
                "success": True,
                "output": f"{self.config.serial}\tdevice"
            }
        else:
            return {
                "success": True,
                "output": "List of devices attached\n"
            }
    
    def _simulate_unlock_attempt(self, input_command: str) -> Dict[str, Any]:
        """Simulate device unlock attempt"""
        self._simulate_delay()
        
        # Check if device is locked out
        if self.locked_until and datetime.now() < self.locked_until:
            remaining_seconds = (self.locked_until - datetime.now()).total_seconds()
            return {
                "success": False,
                "error": "device_locked",
                "lockout_remaining_seconds": int(remaining_seconds)
            }
        
        self.current_attempts += 1
        
        # Simulate random failures
        if self.config.failure_probability > 0:
            import random
            if random.random() < self.config.failure_probability:
                return {
                    "success": False,
                    "error": "communication_error",
                    "attempts": self.current_attempts
                }
        
        # Extract attempted value from input command
        attempted_value = self._extract_attempted_value(input_command)
        
        # Check if correct
        if attempted_value == self.config.correct_value:
            self.current_attempts = 0
            return {
                "success": True,
                "output": "unlock_successful",
                "attempts": self.current_attempts,
                "unlock_time": datetime.now().isoformat()
            }
        
        # Handle lockout
        if (self.config.lockout_enabled and 
            self.current_attempts >= self.config.max_attempts_before_lockout):
            self.locked_until = datetime.now() + timedelta(
                seconds=self.config.lockout_duration_seconds
            )
            return {
                "success": False,
                "error": "max_attempts_reached",
                "attempts": self.current_attempts,
                "locked_until": self.locked_until.isoformat()
            }
        
        return {
            "success": False,
            "error": "incorrect_value",
            "attempts": self.current_attempts
        }
    
    def _extract_attempted_value(self, input_command: str) -> str:
        """Extract attempted unlock value from input command"""
        # This is a simplified extraction - in reality, this would be more complex
        if "input text" in input_command:
            parts = input_command.split("input text")
            if len(parts) > 1:
                return parts[1].strip().strip('"\'')
        
        # For keyevent sequences (patterns), we'd need to decode the sequence
        return ""
    
    def _simulate_delay(self):
        """Simulate device response delay"""
        if self.config.response_delay_ms > 0:
            time.sleep(self.config.response_delay_ms / 1000.0)
    
    def simulate_fastboot_command(self, command: str) -> Dict[str, Any]:
        """Simulate Fastboot command execution"""
        self._simulate_delay()
        
        if not self.is_connected:
            return {"success": False, "error": "device_not_found"}
        
        if command == "devices":
            return {
                "success": True,
                "output": f"{self.config.serial}\tfastboot"
            }
        elif command == "getvar all":
            return self._handle_fastboot_getvar_all()
        elif command.startswith("oem unlock"):
            return self._handle_bootloader_unlock()
        else:
            return {"success": True, "output": "fastboot_command_executed"}
    
    def _handle_fastboot_getvar_all(self) -> Dict[str, Any]:
        """Handle fastboot getvar all command"""
        variables = {
            "version": "0.4",
            "version-bootloader": "1.0.0",
            "version-baseband": "1.0.0",
            "product": self.config.model.lower().replace(" ", "_"),
            "serialno": self.config.serial,
            "secure": "yes" if self.config.bootloader_locked else "no",
            "unlocked": "no" if self.config.bootloader_locked else "yes",
            "slot-count": "2",
            "current-slot": "a",
        }
        
        output = "\n".join([f"{k}: {v}" for k, v in variables.items()])
        return {"success": True, "output": output}
    
    def _handle_bootloader_unlock(self) -> Dict[str, Any]:
        """Handle bootloader unlock command"""
        if self.config.bootloader_locked:
            # Simulate unlock process
            self.config.bootloader_locked = False
            return {
                "success": True,
                "output": "OKAY [  2.000s]\nfinished. total time: 2.000s"
            }
        else:
            return {
                "success": True,
                "output": "Device already unlocked"
            }
    
    def simulate_edl_command(self, command: str) -> Dict[str, Any]:
        """Simulate EDL (Emergency Download Mode) command"""
        self._simulate_delay()
        
        if not self.is_connected:
            return {"success": False, "error": "device_not_found"}
        
        # EDL mode typically bypasses USB debugging requirements
        if command == "info":
            return self._handle_edl_info()
        elif command.startswith("dump"):
            return self._handle_edl_dump(command)
        else:
            return {"success": True, "output": "edl_command_executed"}
    
    def _handle_edl_info(self) -> Dict[str, Any]:
        """Handle EDL info command"""
        info = {
            "device_serial": self.config.serial,
            "model": self.config.model,
            "chipset": "Snapdragon 888",  # Simulated
            "emmc_size": "128GB",
            "ram_size": "8GB"
        }
        
        return {"success": True, "output": json.dumps(info)}
    
    def _handle_edl_dump(self, command: str) -> Dict[str, Any]:
        """Handle EDL dump command"""
        # Simulate NAND dump process
        return {
            "success": True,
            "output": "Dump completed",
            "dump_size_mb": 1024,  # Simulated dump size
            "dump_time_seconds": 300  # Simulated dump time
        }
    
    def disconnect(self):
        """Simulate device disconnection"""
        self.is_connected = False
        self.device_state = "disconnected"
    
    def reconnect(self):
        """Simulate device reconnection"""
        self.is_connected = True
        self.device_state = "idle"
        self.current_attempts = 0
        self.locked_until = None
    
    def set_battery_level(self, level: int):
        """Simulate battery level change"""
        self.config.battery_level = max(0, min(100, level))
        self.system_properties["sys.class.power_supply.battery.capacity"] = str(level)
    
    def enable_usb_debugging(self):
        """Simulate enabling USB debugging"""
        self.config.usb_debugging = True
        self.system_properties["persist.sys.usb.config"] = "mtp,adb"
    
    def disable_usb_debugging(self):
        """Simulate disabling USB debugging"""
        self.config.usb_debugging = False
        self.system_properties["persist.sys.usb.config"] = "mtp"
    
    def get_device_info(self) -> AndroidDevice:
        """Get AndroidDevice representation of simulated device"""
        return AndroidDevice(
            serial=self.config.serial,
            model=self.config.model,
            brand=self.config.brand,
            android_version=self.config.android_version,
            usb_debugging=self.config.usb_debugging,
            root_status=self.config.root_status,
            lock_type=self.config.lock_type,
            bootloader_locked=self.config.bootloader_locked,
            encryption_enabled=self.config.encryption_enabled,
            developer_options_enabled=self.config.developer_options_enabled,
            lockout_policy=LockoutPolicy(
                max_attempts=self.config.max_attempts_before_lockout,
                lockout_duration=self.config.lockout_duration_seconds,
                progressive_lockout=True
            )
        )


class TestDeviceSimulation:
    """Test device simulation functionality"""
    
    @pytest.fixture
    def pin_device_config(self):
        """Create PIN device configuration"""
        return DeviceSimulationConfig(
            serial="SIM_PIN_001",
            model="Galaxy S21",
            brand="Samsung",
            android_version="12.0",
            lock_type=LockType.PIN,
            correct_value="1234",
            usb_debugging=True
        )
    
    @pytest.fixture
    def pattern_device_config(self):
        """Create pattern device configuration"""
        return DeviceSimulationConfig(
            serial="SIM_PATTERN_001",
            model="Pixel 6",
            brand="Google",
            android_version="13.0",
            lock_type=LockType.PATTERN,
            correct_value="012345678",
            usb_debugging=True
        )
    
    @pytest.fixture
    def locked_device_config(self):
        """Create locked device configuration"""
        return DeviceSimulationConfig(
            serial="SIM_LOCKED_001",
            model="OnePlus 9",
            brand="OnePlus",
            android_version="11.0",
            lock_type=LockType.PASSWORD,
            correct_value="password123",
            usb_debugging=False,
            bootloader_locked=True
        )
    
    def test_pin_device_simulation(self, pin_device_config):
        """Test PIN device simulation"""
        simulator = AndroidDeviceSimulator(pin_device_config)
        
        # Test device detection
        devices_result = simulator.simulate_adb_command("devices")
        assert devices_result["success"] is True
        assert pin_device_config.serial in devices_result["output"]
        
        # Test property retrieval
        model_result = simulator.simulate_adb_command("shell getprop ro.product.model")
        assert model_result["success"] is True
        assert model_result["output"] == pin_device_config.model
        
        # Test incorrect PIN attempt
        wrong_pin_result = simulator.simulate_adb_command("shell input text 9999")
        assert wrong_pin_result["success"] is False
        assert wrong_pin_result["error"] == "incorrect_value"
        assert wrong_pin_result["attempts"] == 1
        
        # Test correct PIN attempt
        correct_pin_result = simulator.simulate_adb_command("shell input text 1234")
        assert correct_pin_result["success"] is True
        assert "unlock_successful" in correct_pin_result["output"]
    
    def test_pattern_device_simulation(self, pattern_device_config):
        """Test pattern device simulation"""
        simulator = AndroidDeviceSimulator(pattern_device_config)
        
        # Test gesture.key file pull
        pull_result = simulator.simulate_adb_command("pull /data/system/gesture.key")
        assert pull_result["success"] is True
        assert pull_result["data"] is not None
        
        # Test pattern unlock simulation
        pattern_result = simulator.simulate_adb_command("shell input text 012345678")
        assert pattern_result["success"] is True
    
    def test_lockout_simulation(self, pin_device_config):
        """Test device lockout simulation"""
        simulator = AndroidDeviceSimulator(pin_device_config)
        
        # Make maximum failed attempts
        for i in range(pin_device_config.max_attempts_before_lockout):
            result = simulator.simulate_adb_command("shell input text 9999")
            if i < pin_device_config.max_attempts_before_lockout - 1:
                assert result["error"] == "incorrect_value"
            else:
                assert result["error"] == "max_attempts_reached"
                assert "locked_until" in result
        
        # Test that device is locked
        locked_result = simulator.simulate_adb_command("shell input text 1234")
        assert locked_result["error"] == "device_locked"
        assert "lockout_remaining_seconds" in locked_result
    
    def test_device_disconnection_simulation(self, pin_device_config):
        """Test device disconnection simulation"""
        simulator = AndroidDeviceSimulator(pin_device_config)
        
        # Initially connected
        devices_result = simulator.simulate_adb_command("devices")
        assert pin_device_config.serial in devices_result["output"]
        
        # Disconnect device
        simulator.disconnect()
        
        # Should not be detected
        disconnected_result = simulator.simulate_adb_command("devices")
        assert disconnected_result["success"] is False
        assert disconnected_result["error"] == "device_not_found"
        
        # Reconnect device
        simulator.reconnect()
        
        # Should be detected again
        reconnected_result = simulator.simulate_adb_command("devices")
        assert reconnected_result["success"] is True
        assert pin_device_config.serial in reconnected_result["output"]
    
    def test_fastboot_simulation(self, pin_device_config):
        """Test Fastboot simulation"""
        simulator = AndroidDeviceSimulator(pin_device_config)
        
        # Test fastboot devices
        devices_result = simulator.simulate_fastboot_command("devices")
        assert devices_result["success"] is True
        assert pin_device_config.serial in devices_result["output"]
        
        # Test getvar all
        getvar_result = simulator.simulate_fastboot_command("getvar all")
        assert getvar_result["success"] is True
        assert "serialno" in getvar_result["output"]
        assert pin_device_config.serial in getvar_result["output"]
        
        # Test bootloader unlock
        unlock_result = simulator.simulate_fastboot_command("oem unlock")
        assert unlock_result["success"] is True
        assert not simulator.config.bootloader_locked
    
    def test_edl_simulation(self, locked_device_config):
        """Test EDL mode simulation"""
        simulator = AndroidDeviceSimulator(locked_device_config)
        
        # Test EDL info
        info_result = simulator.simulate_edl_command("info")
        assert info_result["success"] is True
        
        info_data = json.loads(info_result["output"])
        assert info_data["device_serial"] == locked_device_config.serial
        assert info_data["model"] == locked_device_config.model
        
        # Test EDL dump
        dump_result = simulator.simulate_edl_command("dump userdata")
        assert dump_result["success"] is True
        assert "dump_size_mb" in dump_result
        assert "dump_time_seconds" in dump_result
    
    def test_usb_debugging_toggle(self, pin_device_config):
        """Test USB debugging enable/disable simulation"""
        simulator = AndroidDeviceSimulator(pin_device_config)
        
        # Initially enabled
        assert simulator.config.usb_debugging is True
        
        # Disable USB debugging
        simulator.disable_usb_debugging()
        assert simulator.config.usb_debugging is False
        
        # ADB commands should fail
        adb_result = simulator.simulate_adb_command("shell getprop ro.product.model")
        assert adb_result["success"] is False
        assert adb_result["error"] == "usb_debugging_disabled"
        
        # Re-enable USB debugging
        simulator.enable_usb_debugging()
        assert simulator.config.usb_debugging is True
        
        # ADB commands should work again
        adb_result = simulator.simulate_adb_command("shell getprop ro.product.model")
        assert adb_result["success"] is True
    
    def test_battery_level_simulation(self, pin_device_config):
        """Test battery level simulation"""
        simulator = AndroidDeviceSimulator(pin_device_config)
        
        # Set battery level
        simulator.set_battery_level(50)
        assert simulator.config.battery_level == 50
        
        # Test boundary conditions
        simulator.set_battery_level(-10)
        assert simulator.config.battery_level == 0
        
        simulator.set_battery_level(150)
        assert simulator.config.battery_level == 100
    
    def test_failure_probability_simulation(self):
        """Test failure probability simulation"""
        config = DeviceSimulationConfig(
            serial="FAIL_TEST_001",
            model="Test Device",
            brand="Test",
            android_version="12.0",
            lock_type=LockType.PIN,
            correct_value="0000",
            failure_probability=0.5  # 50% failure rate
        )
        
        simulator = AndroidDeviceSimulator(config)
        
        # Run multiple attempts and check for failures
        results = []
        for _ in range(20):
            result = simulator.simulate_adb_command("shell input text 0000")
            results.append(result)
        
        # Should have some failures due to probability
        failures = [r for r in results if not r["success"] and r.get("error") == "communication_error"]
        # With 50% failure rate, we expect some failures (but this is probabilistic)
        # In a real test, you might want to use a fixed seed for reproducibility


if __name__ == "__main__":
    pytest.main([__file__, "-v"])