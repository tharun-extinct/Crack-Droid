"""
Fastboot Handler for bootloader communication

This module provides Fastboot communication capabilities for forensic
analysis of Android devices through bootloader access.
"""

import subprocess
import re
import time
import json
import os
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..interfaces import IDeviceHandler, LockType, ForensicsException
from ..models.device import AndroidDevice, LockoutPolicy, DeviceValidationError


class FastbootException(ForensicsException):
    """Exception raised for Fastboot-related errors"""
    
    def __init__(self, message: str, command: str = None, device_serial: str = None):
        super().__init__(message, "FASTBOOT_ERROR", evidence_impact=True)
        self.command = command
        self.device_serial = device_serial


@dataclass
class FastbootCommand:
    """Fastboot command execution result"""
    command: str
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    timestamp: datetime
    device_serial: Optional[str] = None


@dataclass
class DeviceState:
    """Device bootloader state information"""
    bootloader_version: str
    product_name: str
    variant: str
    secure: bool
    unlocked: bool
    off_mode_charge: bool
    critical_unlocked: bool
    slot_count: int = 0
    current_slot: Optional[str] = None
    slot_successful: Optional[str] = None
    slot_unbootable: Optional[str] = None


@dataclass
class PartitionInfo:
    """Partition information from bootloader"""
    name: str
    size: int
    type: str
    is_logical: bool = False
    slot_suffix: Optional[str] = None


class FastbootHandler(IDeviceHandler):
    """
    Fastboot Handler for forensic operations through bootloader access
    
    This handler provides bootloader communication capabilities including:
    - Device detection in fastboot mode
    - Bootloader state management
    - Recovery flashing capabilities
    - Partition information extraction
    - Device unlock status verification
    """
    
    def __init__(self, fastboot_path: str = "fastboot", timeout: int = 60):
        """
        Initialize Fastboot handler
        
        Args:
            fastboot_path: Path to fastboot executable
            timeout: Default command timeout in seconds
        """
        self.fastboot_path = fastboot_path
        self.timeout = timeout
        self.connected_devices: Dict[str, AndroidDevice] = {}
        self.device_states: Dict[str, DeviceState] = {}
        self._verify_fastboot_installation()
    
    def _verify_fastboot_installation(self):
        """Verify fastboot is installed and accessible"""
        try:
            result = self._execute_fastboot_command(["--version"])
            if result.returncode != 0:
                raise FastbootException("Fastboot not properly installed or accessible")
        except FileNotFoundError:
            raise FastbootException(f"Fastboot executable not found at: {self.fastboot_path}")
        except FastbootException as e:
            if "Failed to execute fastboot command" in str(e):
                raise FastbootException(f"Fastboot executable not found at: {self.fastboot_path}")
            raise
    
    def _execute_fastboot_command(self, args: List[str], device_serial: str = None,
                                timeout: int = None) -> FastbootCommand:
        """
        Execute fastboot command with proper error handling and logging
        
        Args:
            args: Fastboot command arguments
            device_serial: Target device serial (optional)
            timeout: Command timeout override
            
        Returns:
            FastbootCommand: Command execution result
        """
        if timeout is None:
            timeout = self.timeout
        
        # Build command
        cmd = [self.fastboot_path]
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
            
            return FastbootCommand(
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
            raise FastbootException(
                f"Fastboot command timed out after {timeout} seconds",
                command=" ".join(cmd),
                device_serial=device_serial
            )
        except Exception as e:
            raise FastbootException(
                f"Failed to execute fastboot command: {str(e)}",
                command=" ".join(cmd),
                device_serial=device_serial
            )
    
    def detect_devices(self) -> List[AndroidDevice]:
        """
        Detect connected Android devices in fastboot mode
        
        Returns:
            List[AndroidDevice]: List of detected devices in fastboot mode
        """
        try:
            result = self._execute_fastboot_command(["devices"])
            
            if result.returncode != 0:
                raise FastbootException("Failed to detect fastboot devices", result.command)
            
            devices = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse device line: serial\tfastboot
                parts = line.split('\t')
                if len(parts) >= 2 and parts[1].strip() == "fastboot":
                    serial = parts[0].strip()
                    
                    # Create basic device info, will be enhanced by get_device_info
                    device = AndroidDevice(
                        serial=serial,
                        model='Unknown (Fastboot Mode)',
                        brand='Unknown',
                        android_version='Unknown',
                        usb_debugging=False  # In fastboot mode, normal ADB is not available
                    )
                    
                    devices.append(device)
            
            return devices
            
        except FastbootException:
            raise
        except Exception as e:
            raise FastbootException(f"Unexpected error during fastboot device detection: {str(e)}")
    
    def connect_device(self, device: AndroidDevice) -> bool:
        """
        Connect to a specific device in fastboot mode and verify accessibility
        
        Args:
            device: Target Android device
            
        Returns:
            bool: True if connection successful
        """
        try:
            # Test connection with getvar command
            result = self._execute_fastboot_command(
                ["getvar", "product"],
                device_serial=device.serial
            )
            
            if result.returncode == 0 or "product:" in result.stderr:
                # Fastboot often returns info in stderr
                self.connected_devices[device.serial] = device
                return True
            else:
                raise FastbootException(
                    f"Failed to connect to fastboot device {device.serial}: {result.stderr}",
                    device_serial=device.serial
                )
                
        except FastbootException:
            raise
        except Exception as e:
            raise FastbootException(
                f"Unexpected error connecting to fastboot device {device.serial}: {str(e)}",
                device_serial=device.serial
            )
    
    def get_device_info(self, device: AndroidDevice) -> AndroidDevice:
        """
        Get comprehensive device information via fastboot
        
        Args:
            device: Basic device info to enhance
            
        Returns:
            AndroidDevice: Enhanced device information
        """
        try:
            # Get device variables
            device_vars = self._get_device_variables(device.serial)
            
            # Parse device state
            device_state = self._parse_device_state(device_vars)
            self.device_states[device.serial] = device_state
            
            # Extract device information
            enhanced_device = AndroidDevice(
                serial=device.serial,
                model=device_vars.get('product', device.model),
                brand=device_vars.get('brand', 'Unknown'),
                android_version=device_vars.get('version', 'Unknown'),
                imei=device_vars.get('imei'),
                usb_debugging=False,  # Not available in fastboot mode
                root_status=False,    # Cannot determine in fastboot mode
                lock_type=None,       # Cannot determine in fastboot mode
                screen_timeout=0,     # Not applicable in fastboot mode
                lockout_policy=None,  # Not applicable in fastboot mode
                build_number=device_vars.get('version-bootloader'),
                security_patch_level=None,  # Not available in fastboot mode
                bootloader_locked=not device_state.unlocked if device_state else True,
                encryption_enabled=None,  # Cannot determine in fastboot mode
                developer_options_enabled=None,  # Cannot determine in fastboot mode
                bootloader_version=device_state.bootloader_version if device_state else None,
                secure_boot=device_state.secure if device_state else None,
                slot_count=device_state.slot_count if device_state else 0,
                current_slot=device_state.current_slot if device_state else None
            )
            
            return enhanced_device
            
        except Exception as e:
            raise FastbootException(
                f"Failed to get device info for {device.serial}: {str(e)}",
                device_serial=device.serial
            )
    
    def _get_device_variables(self, device_serial: str) -> Dict[str, str]:
        """Get all device variables from fastboot"""
        variables = {}
        
        # Common fastboot variables to query
        var_names = [
            'product', 'brand', 'version', 'version-bootloader', 'version-baseband',
            'serialno', 'secure', 'unlocked', 'off-mode-charge', 'critical-unlocked',
            'variant', 'partition-type', 'partition-size', 'slot-count',
            'current-slot', 'slot-successful', 'slot-unbootable', 'imei'
        ]
        
        for var_name in var_names:
            try:
                result = self._execute_fastboot_command(
                    ["getvar", var_name],
                    device_serial=device_serial,
                    timeout=10
                )
                
                # Fastboot typically returns variable info in stderr
                output = result.stderr if result.stderr else result.stdout
                
                # Parse output format: "var_name: value"
                for line in output.split('\n'):
                    if f"{var_name}:" in line:
                        value = line.split(':', 1)[1].strip()
                        variables[var_name] = value
                        break
                        
            except FastbootException:
                # Continue if individual variable query fails
                continue
        
        return variables
    
    def _parse_device_state(self, variables: Dict[str, str]) -> DeviceState:
        """Parse device state from fastboot variables"""
        try:
            return DeviceState(
                bootloader_version=variables.get('version-bootloader', 'Unknown'),
                product_name=variables.get('product', 'Unknown'),
                variant=variables.get('variant', 'Unknown'),
                secure=variables.get('secure', 'yes').lower() == 'yes',
                unlocked=variables.get('unlocked', 'no').lower() == 'yes',
                off_mode_charge=variables.get('off-mode-charge', '0') == '1',
                critical_unlocked=variables.get('critical-unlocked', 'no').lower() == 'yes',
                slot_count=int(variables.get('slot-count', '0')),
                current_slot=variables.get('current-slot'),
                slot_successful=variables.get('slot-successful'),
                slot_unbootable=variables.get('slot-unbootable')
            )
        except (ValueError, KeyError) as e:
            raise FastbootException(f"Failed to parse device state: {str(e)}")
    
    def is_device_accessible(self, device: AndroidDevice) -> bool:
        """
        Check if device is accessible for forensic operations
        
        Args:
            device: Target device
            
        Returns:
            bool: True if device is accessible
        """
        try:
            result = self._execute_fastboot_command(
                ["getvar", "product"],
                device_serial=device.serial,
                timeout=10
            )
            
            # Device is accessible if we can query variables
            return result.returncode == 0 or "product:" in result.stderr
            
        except Exception:
            return False
    
    # Forensic operation methods
    
    def get_partition_info(self, device_serial: str) -> List[PartitionInfo]:
        """
        Get partition information from device
        
        Args:
            device_serial: Target device serial
            
        Returns:
            List[PartitionInfo]: List of device partitions
        """
        try:
            partitions = []
            
            # Try to get partition information
            result = self._execute_fastboot_command(
                ["getvar", "all"],
                device_serial=device_serial,
                timeout=30
            )
            
            # Parse partition information from output
            output = result.stderr if result.stderr else result.stdout
            
            for line in output.split('\n'):
                line = line.strip()
                
                # Look for partition-size entries
                if line.startswith('partition-size:'):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        partition_name = parts[1].strip()
                        size_hex = parts[2].strip()
                        
                        try:
                            size = int(size_hex, 16) if size_hex.startswith('0x') else int(size_hex)
                            
                            partition = PartitionInfo(
                                name=partition_name,
                                size=size,
                                type='unknown',
                                is_logical=False
                            )
                            partitions.append(partition)
                            
                        except ValueError:
                            continue
                
                # Look for partition-type entries
                elif line.startswith('partition-type:'):
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        partition_name = parts[1].strip()
                        partition_type = parts[2].strip()
                        
                        # Find existing partition and update type
                        for partition in partitions:
                            if partition.name == partition_name:
                                partition.type = partition_type
                                break
            
            return partitions
            
        except Exception as e:
            raise FastbootException(
                f"Failed to get partition info: {str(e)}",
                device_serial=device_serial
            )
    
    def flash_recovery(self, device_serial: str, recovery_image_path: str) -> bool:
        """
        Flash custom recovery image to device
        
        Args:
            device_serial: Target device serial
            recovery_image_path: Path to recovery image file
            
        Returns:
            bool: True if flashing successful
        """
        try:
            # Verify recovery image exists
            if not os.path.exists(recovery_image_path):
                raise FastbootException(f"Recovery image not found: {recovery_image_path}")
            
            # Flash recovery partition
            result = self._execute_fastboot_command([
                "flash", "recovery", recovery_image_path
            ], device_serial=device_serial, timeout=120)
            
            if result.returncode == 0:
                return True
            else:
                raise FastbootException(
                    f"Failed to flash recovery: {result.stderr}",
                    device_serial=device_serial
                )
                
        except Exception as e:
            raise FastbootException(
                f"Error flashing recovery: {str(e)}",
                device_serial=device_serial
            )
    
    def flash_partition(self, device_serial: str, partition_name: str, 
                       image_path: str) -> bool:
        """
        Flash image to specific partition
        
        Args:
            device_serial: Target device serial
            partition_name: Name of partition to flash
            image_path: Path to image file
            
        Returns:
            bool: True if flashing successful
        """
        try:
            # Verify image exists
            if not os.path.exists(image_path):
                raise FastbootException(f"Image file not found: {image_path}")
            
            # Flash partition
            result = self._execute_fastboot_command([
                "flash", partition_name, image_path
            ], device_serial=device_serial, timeout=180)
            
            if result.returncode == 0:
                return True
            else:
                raise FastbootException(
                    f"Failed to flash {partition_name}: {result.stderr}",
                    device_serial=device_serial
                )
                
        except Exception as e:
            raise FastbootException(
                f"Error flashing {partition_name}: {str(e)}",
                device_serial=device_serial
            )
    
    def boot_image(self, device_serial: str, boot_image_path: str) -> bool:
        """
        Boot device with custom image without flashing
        
        Args:
            device_serial: Target device serial
            boot_image_path: Path to boot image file
            
        Returns:
            bool: True if boot command successful
        """
        try:
            # Verify boot image exists
            if not os.path.exists(boot_image_path):
                raise FastbootException(f"Boot image not found: {boot_image_path}")
            
            # Boot with image
            result = self._execute_fastboot_command([
                "boot", boot_image_path
            ], device_serial=device_serial, timeout=60)
            
            if result.returncode == 0:
                return True
            else:
                raise FastbootException(
                    f"Failed to boot image: {result.stderr}",
                    device_serial=device_serial
                )
                
        except Exception as e:
            raise FastbootException(
                f"Error booting image: {str(e)}",
                device_serial=device_serial
            )
    
    def reboot_device(self, device_serial: str, target: str = "system") -> bool:
        """
        Reboot device to specified target
        
        Args:
            device_serial: Target device serial
            target: Reboot target ('system', 'bootloader', 'recovery', 'download')
            
        Returns:
            bool: True if reboot command successful
        """
        try:
            valid_targets = ['system', 'bootloader', 'recovery', 'download']
            if target not in valid_targets:
                raise FastbootException(f"Invalid reboot target: {target}")
            
            if target == "system":
                result = self._execute_fastboot_command([
                    "reboot"
                ], device_serial=device_serial, timeout=30)
            else:
                result = self._execute_fastboot_command([
                    "reboot", target
                ], device_serial=device_serial, timeout=30)
            
            return result.returncode == 0
            
        except Exception as e:
            raise FastbootException(
                f"Error rebooting device: {str(e)}",
                device_serial=device_serial
            )
    
    def unlock_bootloader(self, device_serial: str) -> Tuple[bool, str]:
        """
        Attempt to unlock device bootloader
        
        Args:
            device_serial: Target device serial
            
        Returns:
            Tuple[bool, str]: (success, status_message)
        """
        try:
            # Check current unlock status
            device_state = self.device_states.get(device_serial)
            if device_state and device_state.unlocked:
                return True, "Bootloader already unlocked"
            
            # Attempt unlock
            result = self._execute_fastboot_command([
                "flashing", "unlock"
            ], device_serial=device_serial, timeout=60)
            
            if result.returncode == 0:
                return True, "Bootloader unlock successful"
            elif "FAILED" in result.stderr:
                if "not allowed" in result.stderr.lower():
                    return False, "Bootloader unlock not allowed (OEM unlocking disabled)"
                elif "already unlocked" in result.stderr.lower():
                    return True, "Bootloader already unlocked"
                else:
                    return False, f"Unlock failed: {result.stderr}"
            else:
                return False, f"Unlock command failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Error during bootloader unlock: {str(e)}"
    
    def get_device_state(self, device_serial: str) -> Optional[DeviceState]:
        """
        Get current device state information
        
        Args:
            device_serial: Target device serial
            
        Returns:
            Optional[DeviceState]: Device state if available
        """
        return self.device_states.get(device_serial)
    
    def is_bootloader_unlocked(self, device_serial: str) -> bool:
        """
        Check if bootloader is unlocked
        
        Args:
            device_serial: Target device serial
            
        Returns:
            bool: True if bootloader is unlocked
        """
        try:
            result = self._execute_fastboot_command([
                "getvar", "unlocked"
            ], device_serial=device_serial, timeout=10)
            
            output = result.stderr if result.stderr else result.stdout
            return "unlocked: yes" in output.lower()
            
        except Exception:
            return False
    
    def erase_partition(self, device_serial: str, partition_name: str) -> bool:
        """
        Erase specified partition
        
        Args:
            device_serial: Target device serial
            partition_name: Name of partition to erase
            
        Returns:
            bool: True if erase successful
        """
        try:
            result = self._execute_fastboot_command([
                "erase", partition_name
            ], device_serial=device_serial, timeout=60)
            
            return result.returncode == 0
            
        except Exception as e:
            raise FastbootException(
                f"Error erasing {partition_name}: {str(e)}",
                device_serial=device_serial
            )
    
    def format_partition(self, device_serial: str, partition_name: str, 
                        fs_type: str = "ext4") -> bool:
        """
        Format specified partition with filesystem
        
        Args:
            device_serial: Target device serial
            partition_name: Name of partition to format
            fs_type: Filesystem type ('ext4', 'f2fs')
            
        Returns:
            bool: True if format successful
        """
        try:
            result = self._execute_fastboot_command([
                "format", partition_name, fs_type
            ], device_serial=device_serial, timeout=120)
            
            return result.returncode == 0
            
        except Exception as e:
            raise FastbootException(
                f"Error formatting {partition_name}: {str(e)}",
                device_serial=device_serial
            )
    
    def __str__(self) -> str:
        """String representation of Fastboot handler"""
        return f"FastbootHandler(path={self.fastboot_path}, connected_devices={len(self.connected_devices)})"
    
    def __repr__(self) -> str:
        """Detailed representation of Fastboot handler"""
        return (f"FastbootHandler(fastboot_path='{self.fastboot_path}', timeout={self.timeout}, "
                f"connected_devices={list(self.connected_devices.keys())})")