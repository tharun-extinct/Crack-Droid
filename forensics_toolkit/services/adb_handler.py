"""
ADB Handler for USB debugging enabled Android devices

This module provides comprehensive ADB communication capabilities for forensic
analysis of Android devices with USB debugging enabled.
"""

import subprocess
import re
import time
import json
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

from ..interfaces import IDeviceHandler, AndroidDevice, LockType, ForensicsException
from ..models.device import LockoutPolicy, DeviceValidationError


class ADBException(ForensicsException):
    """Exception raised for ADB-related errors"""
    
    def __init__(self, message: str, command: str = None, device_serial: str = None):
        super().__init__(message, "ADB_ERROR", evidence_impact=True)
        self.command = command
        self.device_serial = device_serial


@dataclass
class ADBCommand:
    """ADB command execution result"""
    command: str
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    timestamp: datetime
    device_serial: Optional[str] = None


class ADBHandler(IDeviceHandler):
    """
    ADB Handler for forensic operations on USB debugging enabled devices
    
    This handler provides comprehensive ADB communication capabilities including:
    - Device detection and connection
    - Lock type identification
    - Simulated input injection for brute force attacks
    - File system access for rooted devices
    - System property analysis
    """
    
    def __init__(self, adb_path: str = "adb", timeout: int = 30):
        """
        Initialize ADB handler
        
        Args:
            adb_path: Path to ADB executable
            timeout: Default command timeout in seconds
        """
        self.adb_path = adb_path
        self.timeout = timeout
        self.connected_devices: Dict[str, AndroidDevice] = {}
        self._verify_adb_installation()
    
    def _verify_adb_installation(self):
        """Verify ADB is installed and accessible"""
        try:
            result = self._execute_adb_command(["version"])
            if result.returncode != 0:
                raise ADBException("ADB not properly installed or accessible")
        except FileNotFoundError:
            raise ADBException(f"ADB executable not found at: {self.adb_path}")
    
    def _execute_adb_command(self, args: List[str], device_serial: str = None, 
                           timeout: int = None) -> ADBCommand:
        """
        Execute ADB command with proper error handling and logging
        
        Args:
            args: ADB command arguments
            device_serial: Target device serial (optional)
            timeout: Command timeout override
            
        Returns:
            ADBCommand: Command execution result
        """
        if timeout is None:
            timeout = self.timeout
        
        # Build command
        cmd = [self.adb_path]
        if device_serial:
            cmd.extend(["-s", device_serial])
        cmd.extend(args)
        
        start_time = time.time()
        timestamp = datetime.now()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            return ADBCommand(
                command=" ".join(cmd),
                returncode=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                execution_time=execution_time,
                timestamp=timestamp,
                device_serial=device_serial
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            raise ADBException(
                f"ADB command timed out after {timeout} seconds",
                command=" ".join(cmd),
                device_serial=device_serial
            )
        except Exception as e:
            raise ADBException(
                f"Failed to execute ADB command: {str(e)}",
                command=" ".join(cmd),
                device_serial=device_serial
            )
    
    def detect_devices(self) -> List[AndroidDevice]:
        """
        Detect connected Android devices via ADB
        
        Returns:
            List[AndroidDevice]: List of detected devices
        """
        try:
            result = self._execute_adb_command(["devices", "-l"])
            
            if result.returncode != 0:
                raise ADBException("Failed to detect devices", result.command)
            
            devices = []
            lines = result.stdout.split('\n')
            
            for line in lines[1:]:  # Skip header line
                line = line.strip()
                if not line or line.startswith('*'):
                    continue
                
                # Parse device line: serial\tdevice [properties]
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                
                serial = parts[0]
                status = parts[1]
                
                if status != "device":
                    continue  # Skip unauthorized, offline, etc.
                
                # Extract device properties if available
                properties = {}
                if len(parts) > 2:
                    prop_text = parts[2]
                    # Parse properties like "model:SM_G973F device:beyond1lte"
                    for prop in prop_text.split():
                        if ':' in prop:
                            key, value = prop.split(':', 1)
                            properties[key] = value
                
                # Create basic device info, will be enhanced by get_device_info
                device = AndroidDevice(
                    serial=serial,
                    model=properties.get('model', 'Unknown'),
                    brand=properties.get('brand', 'Unknown'),
                    android_version='Unknown',
                    usb_debugging=True  # Must be true if detected via ADB
                )
                
                devices.append(device)
            
            return devices
            
        except ADBException:
            raise
        except Exception as e:
            raise ADBException(f"Unexpected error during device detection: {str(e)}")
    
    def connect_device(self, device: AndroidDevice) -> bool:
        """
        Connect to a specific device and verify accessibility
        
        Args:
            device: Target Android device
            
        Returns:
            bool: True if connection successful
        """
        try:
            # Test connection with simple command
            result = self._execute_adb_command(
                ["shell", "echo", "test"], 
                device_serial=device.serial
            )
            
            if result.returncode == 0:
                self.connected_devices[device.serial] = device
                return True
            else:
                raise ADBException(
                    f"Failed to connect to device {device.serial}: {result.stderr}",
                    device_serial=device.serial
                )
                
        except ADBException:
            raise
        except Exception as e:
            raise ADBException(
                f"Unexpected error connecting to device {device.serial}: {str(e)}",
                device_serial=device.serial
            )
    
    def get_device_info(self, device: AndroidDevice) -> AndroidDevice:
        """
        Get comprehensive device information via ADB
        
        Args:
            device: Basic device info to enhance
            
        Returns:
            AndroidDevice: Enhanced device information
        """
        try:
            # Get system properties
            props = self._get_system_properties(device.serial)
            
            # Extract device information
            enhanced_device = AndroidDevice(
                serial=device.serial,
                model=props.get('ro.product.model', device.model),
                brand=props.get('ro.product.brand', device.brand),
                android_version=props.get('ro.build.version.release', 'Unknown'),
                imei=self._get_imei(device.serial),
                usb_debugging=True,
                root_status=self._check_root_status(device.serial),
                lock_type=self._identify_lock_type(device.serial),
                screen_timeout=self._get_screen_timeout(device.serial),
                lockout_policy=self._get_lockout_policy(device.serial),
                build_number=props.get('ro.build.display.id'),
                security_patch_level=props.get('ro.build.version.security_patch'),
                bootloader_locked=self._check_bootloader_status(device.serial),
                encryption_enabled=self._check_encryption_status(device.serial),
                developer_options_enabled=self._check_developer_options(device.serial)
            )
            
            return enhanced_device
            
        except Exception as e:
            raise ADBException(
                f"Failed to get device info for {device.serial}: {str(e)}",
                device_serial=device.serial
            )
    
    def _get_system_properties(self, device_serial: str) -> Dict[str, str]:
        """Get system properties from device"""
        result = self._execute_adb_command(
            ["shell", "getprop"], 
            device_serial=device_serial
        )
        
        if result.returncode != 0:
            raise ADBException(f"Failed to get system properties: {result.stderr}")
        
        properties = {}
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('[') and ']:' in line:
                # Parse format: [property.name]: [value]
                match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line)
                if match:
                    prop_name, prop_value = match.groups()
                    properties[prop_name] = prop_value
        
        return properties
    
    def _get_imei(self, device_serial: str) -> Optional[str]:
        """Get device IMEI if available"""
        try:
            # Try multiple methods to get IMEI
            methods = [
                ["shell", "service", "call", "iphonesubinfo", "1"],
                ["shell", "dumpsys", "iphonesubinfo"],
                ["shell", "getprop", "ro.ril.oem.imei"]
            ]
            
            for method in methods:
                result = self._execute_adb_command(method, device_serial=device_serial)
                if result.returncode == 0 and result.stdout:
                    # Extract IMEI from various output formats
                    imei_match = re.search(r'\b\d{15}\b', result.stdout)
                    if imei_match:
                        return imei_match.group()
            
            return None
            
        except Exception:
            return None  # IMEI is optional
    
    def _check_root_status(self, device_serial: str) -> bool:
        """Check if device is rooted"""
        try:
            # Check for su binary
            result = self._execute_adb_command(
                ["shell", "which", "su"], 
                device_serial=device_serial
            )
            
            if result.returncode == 0 and result.stdout:
                return True
            
            # Check for root access via id command
            result = self._execute_adb_command(
                ["shell", "su", "-c", "id"], 
                device_serial=device_serial,
                timeout=5
            )
            
            return result.returncode == 0 and "uid=0" in result.stdout
            
        except Exception:
            return False
    
    def _identify_lock_type(self, device_serial: str) -> Optional[LockType]:
        """Identify device lock screen type"""
        try:
            # Check lock settings
            result = self._execute_adb_command([
                "shell", "settings", "get", "secure", "lockscreen.password_type"
            ], device_serial=device_serial)
            
            if result.returncode == 0 and result.stdout:
                password_type = result.stdout.strip()
                
                # Android password type constants
                type_mapping = {
                    "0": LockType.NONE,
                    "1": LockType.PATTERN,
                    "2": LockType.PIN,
                    "3": LockType.PASSWORD,
                    "4": LockType.PIN,  # Numeric PIN
                    "5": LockType.PASSWORD,  # Alphanumeric password
                }
                
                return type_mapping.get(password_type, LockType.NONE)
            
            # Fallback: check for lock files
            lock_files = [
                "/data/system/gesture.key",
                "/data/system/password.key",
                "/data/system/gatekeeper.password.key"
            ]
            
            for lock_file in lock_files:
                result = self._execute_adb_command([
                    "shell", "ls", lock_file
                ], device_serial=device_serial)
                
                if result.returncode == 0:
                    if "gesture.key" in lock_file:
                        return LockType.PATTERN
                    elif "password.key" in lock_file:
                        return LockType.PASSWORD
            
            return LockType.NONE
            
        except Exception:
            return None
    
    def _get_screen_timeout(self, device_serial: str) -> int:
        """Get screen timeout setting"""
        try:
            result = self._execute_adb_command([
                "shell", "settings", "get", "system", "screen_off_timeout"
            ], device_serial=device_serial)
            
            if result.returncode == 0 and result.stdout.strip().isdigit():
                return int(result.stdout.strip()) // 1000  # Convert ms to seconds
            
            return 30  # Default timeout
            
        except Exception:
            return 30
    
    def _get_lockout_policy(self, device_serial: str) -> Optional[LockoutPolicy]:
        """Get device lockout policy"""
        try:
            # Get lockout settings
            max_attempts_result = self._execute_adb_command([
                "shell", "settings", "get", "secure", "lockscreen.maximumfailedpasswordsforfullwipe"
            ], device_serial=device_serial)
            
            lockout_duration_result = self._execute_adb_command([
                "shell", "settings", "get", "secure", "lockscreen.lockoutattemptdeadline"
            ], device_serial=device_serial)
            
            max_attempts = 5  # Default
            lockout_duration = 30  # Default
            
            if max_attempts_result.returncode == 0 and max_attempts_result.stdout.strip().isdigit():
                max_attempts = int(max_attempts_result.stdout.strip())
            
            if lockout_duration_result.returncode == 0 and lockout_duration_result.stdout.strip().isdigit():
                lockout_duration = int(lockout_duration_result.stdout.strip()) // 1000
            
            return LockoutPolicy(
                max_attempts=max_attempts,
                lockout_duration=lockout_duration,
                progressive_lockout=True,
                wipe_after_attempts=max_attempts * 2
            )
            
        except Exception:
            return None
    
    def _check_bootloader_status(self, device_serial: str) -> bool:
        """Check if bootloader is locked"""
        try:
            result = self._execute_adb_command([
                "shell", "getprop", "ro.boot.verifiedbootstate"
            ], device_serial=device_serial)
            
            if result.returncode == 0:
                boot_state = result.stdout.strip()
                return boot_state in ["green", "yellow"]  # Locked states
            
            return True  # Assume locked by default
            
        except Exception:
            return True
    
    def _check_encryption_status(self, device_serial: str) -> bool:
        """Check if device encryption is enabled"""
        try:
            result = self._execute_adb_command([
                "shell", "getprop", "ro.crypto.state"
            ], device_serial=device_serial)
            
            if result.returncode == 0:
                crypto_state = result.stdout.strip()
                return crypto_state == "encrypted"
            
            return True  # Assume encrypted by default
            
        except Exception:
            return True
    
    def _check_developer_options(self, device_serial: str) -> bool:
        """Check if developer options are enabled"""
        try:
            result = self._execute_adb_command([
                "shell", "settings", "get", "global", "development_settings_enabled"
            ], device_serial=device_serial)
            
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            
            return True  # Must be enabled if ADB works
            
        except Exception:
            return True
    
    def is_device_accessible(self, device: AndroidDevice) -> bool:
        """
        Check if device is accessible for forensic operations
        
        Args:
            device: Target device
            
        Returns:
            bool: True if device is accessible
        """
        try:
            result = self._execute_adb_command([
                "shell", "echo", "accessible"
            ], device_serial=device.serial)
            
            return result.returncode == 0 and "accessible" in result.stdout
            
        except Exception:
            return False
    
    # Forensic operation methods
    
    def inject_input(self, device_serial: str, input_type: str, value: str) -> bool:
        """
        Inject simulated input for brute force attacks
        
        Args:
            device_serial: Target device serial
            input_type: Type of input ('text', 'keyevent', 'tap')
            value: Input value
            
        Returns:
            bool: True if input injection successful
        """
        try:
            if input_type == "text":
                result = self._execute_adb_command([
                    "shell", "input", "text", value
                ], device_serial=device_serial)
            elif input_type == "keyevent":
                result = self._execute_adb_command([
                    "shell", "input", "keyevent", value
                ], device_serial=device_serial)
            elif input_type == "tap":
                x, y = value.split(',')
                result = self._execute_adb_command([
                    "shell", "input", "tap", x.strip(), y.strip()
                ], device_serial=device_serial)
            else:
                raise ADBException(f"Unsupported input type: {input_type}")
            
            return result.returncode == 0
            
        except Exception as e:
            raise ADBException(
                f"Failed to inject input: {str(e)}",
                device_serial=device_serial
            )
    
    def attempt_pin_unlock(self, device_serial: str, pin: str) -> Tuple[bool, str]:
        """
        Attempt to unlock device with PIN
        
        Args:
            device_serial: Target device serial
            pin: PIN to attempt
            
        Returns:
            Tuple[bool, str]: (success, status_message)
        """
        try:
            # Wake up device
            self._execute_adb_command([
                "shell", "input", "keyevent", "KEYCODE_WAKEUP"
            ], device_serial=device_serial)
            
            time.sleep(0.5)
            
            # Swipe up to show lock screen
            self._execute_adb_command([
                "shell", "input", "swipe", "500", "1000", "500", "500"
            ], device_serial=device_serial)
            
            time.sleep(0.5)
            
            # Input PIN
            success = self.inject_input(device_serial, "text", pin)
            if not success:
                return False, "Failed to inject PIN"
            
            time.sleep(0.2)
            
            # Press enter
            self._execute_adb_command([
                "shell", "input", "keyevent", "KEYCODE_ENTER"
            ], device_serial=device_serial)
            
            time.sleep(1)
            
            # Check if unlocked by testing access to secure content
            result = self._execute_adb_command([
                "shell", "dumpsys", "window", "windows"
            ], device_serial=device_serial)
            
            if result.returncode == 0:
                # Look for indicators that device is unlocked
                if "StatusBar" in result.stdout and "Keyguard" not in result.stdout:
                    return True, "Device unlocked successfully"
                elif "Too many attempts" in result.stdout or "try again" in result.stdout.lower():
                    return False, "Too many attempts - device locked out"
                else:
                    return False, "Incorrect PIN"
            
            return False, "Unable to determine unlock status"
            
        except Exception as e:
            return False, f"Error during PIN attempt: {str(e)}"
    
    def pull_file(self, device_serial: str, remote_path: str, local_path: str) -> bool:
        """
        Pull file from device (requires root for system files)
        
        Args:
            device_serial: Target device serial
            remote_path: Path on device
            local_path: Local destination path
            
        Returns:
            bool: True if file pulled successfully
        """
        try:
            result = self._execute_adb_command([
                "pull", remote_path, local_path
            ], device_serial=device_serial)
            
            return result.returncode == 0
            
        except Exception as e:
            raise ADBException(
                f"Failed to pull file {remote_path}: {str(e)}",
                device_serial=device_serial
            )
    
    def pull_gesture_key(self, device_serial: str, local_path: str) -> bool:
        """
        Pull gesture.key file for pattern analysis (requires root)
        
        Args:
            device_serial: Target device serial
            local_path: Local destination path
            
        Returns:
            bool: True if gesture.key pulled successfully
        """
        gesture_paths = [
            "/data/system/gesture.key",
            "/data/system/locksettings.db",
            "/data/system/gatekeeper.gesture.key"
        ]
        
        for gesture_path in gesture_paths:
            try:
                if self.pull_file(device_serial, gesture_path, local_path):
                    return True
            except ADBException:
                continue
        
        return False
    
    def pull_password_key(self, device_serial: str, local_path: str) -> bool:
        """
        Pull password.key file for hash analysis (requires root)
        
        Args:
            device_serial: Target device serial
            local_path: Local destination path
            
        Returns:
            bool: True if password.key pulled successfully
        """
        password_paths = [
            "/data/system/password.key",
            "/data/system/gatekeeper.password.key",
            "/data/system/locksettings.db"
        ]
        
        for password_path in password_paths:
            try:
                if self.pull_file(device_serial, password_path, local_path):
                    return True
            except ADBException:
                continue
        
        return False
    
    def get_screen_state(self, device_serial: str) -> str:
        """
        Get current screen state
        
        Args:
            device_serial: Target device serial
            
        Returns:
            str: Screen state ('on', 'off', 'locked', 'unlocked')
        """
        try:
            # Check display state
            result = self._execute_adb_command([
                "shell", "dumpsys", "display"
            ], device_serial=device_serial)
            
            if result.returncode == 0:
                if "Display Power: state=ON" in result.stdout:
                    # Check if locked
                    keyguard_result = self._execute_adb_command([
                        "shell", "dumpsys", "window", "windows"
                    ], device_serial=device_serial)
                    
                    if keyguard_result.returncode == 0:
                        if "Keyguard" in keyguard_result.stdout:
                            return "locked"
                        else:
                            return "unlocked"
                    
                    return "on"
                else:
                    return "off"
            
            return "unknown"
            
        except Exception:
            return "unknown"
    
    def detect_lockout(self, device_serial: str) -> Tuple[bool, int]:
        """
        Detect if device is in lockout state
        
        Args:
            device_serial: Target device serial
            
        Returns:
            Tuple[bool, int]: (is_locked_out, remaining_time_seconds)
        """
        try:
            result = self._execute_adb_command([
                "shell", "dumpsys", "deviceidle"
            ], device_serial=device_serial)
            
            if result.returncode == 0:
                # Look for lockout indicators
                if "locked" in result.stdout.lower() or "timeout" in result.stdout.lower():
                    # Try to extract remaining time
                    time_match = re.search(r'(\d+)\s*seconds?', result.stdout)
                    if time_match:
                        return True, int(time_match.group(1))
                    else:
                        return True, 30  # Default lockout time
            
            return False, 0
            
        except Exception:
            return False, 0
    
    def __str__(self) -> str:
        """String representation of ADB handler"""
        return f"ADBHandler(path={self.adb_path}, connected_devices={len(self.connected_devices)})"
    
    def __repr__(self) -> str:
        """Detailed representation of ADB handler"""
        return (f"ADBHandler(adb_path='{self.adb_path}', timeout={self.timeout}, "
                f"connected_devices={list(self.connected_devices.keys())})")