"""
EDL Handler for USB debugging disabled Android devices

This module provides Emergency Download Mode (EDL) communication capabilities
for forensic analysis of Android devices with USB debugging disabled.
"""

import subprocess
import time
import json
import struct
import os
import hashlib
from typing import List, Optional, Dict, Any, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..interfaces import IDeviceHandler, LockType, ForensicsException
from ..models.device import AndroidDevice, LockoutPolicy, DeviceValidationError


class EDLException(ForensicsException):
    """Exception raised for EDL-related errors"""
    
    def __init__(self, message: str, command: str = None, device_serial: str = None):
        super().__init__(message, "EDL_ERROR", evidence_impact=True)
        self.command = command
        self.device_serial = device_serial


@dataclass
class EDLCommand:
    """EDL command execution result"""
    command: str
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    timestamp: datetime
    device_serial: Optional[str] = None


@dataclass
class NANDPartition:
    """NAND partition information"""
    name: str
    start_sector: int
    size_sectors: int
    size_bytes: int
    partition_type: str
    file_system: Optional[str] = None
    mount_point: Optional[str] = None
    extracted_path: Optional[str] = None
    hash_sha256: Optional[str] = None


@dataclass
class FirehoseLoader:
    """Firehose loader configuration"""
    loader_path: str
    target_name: str
    protocol_version: str
    max_payload_size: int = 1048576  # 1MB default
    supported_commands: List[str] = None
    
    def __post_init__(self):
        if self.supported_commands is None:
            self.supported_commands = [
                "configure", "program", "read", "erase", "peek", "poke",
                "setbootablestoragedrive", "ufs", "emmc", "nop"
            ]


class EDLHandler(IDeviceHandler):
    """
    EDL Handler for forensic operations on USB debugging disabled devices
    
    This handler provides Emergency Download Mode capabilities including:
    - EDL mode detection and entry
    - Firehose loader communication
    - NAND dump extraction
    - Partition analysis and recovery
    - Integration with EDL.py tool
    """
    
    def __init__(self, edl_tool_path: str = "edl", timeout: int = 300):
        """
        Initialize EDL handler
        
        Args:
            edl_tool_path: Path to EDL.py tool executable
            timeout: Default command timeout in seconds (5 minutes for dumps)
        """
        self.edl_tool_path = edl_tool_path
        self.timeout = timeout
        self.connected_devices: Dict[str, AndroidDevice] = {}
        self.firehose_loaders: Dict[str, FirehoseLoader] = {}
        self.extracted_partitions: Dict[str, List[NANDPartition]] = {}
        self._verify_edl_installation()
        self._load_firehose_loaders()
    
    def _verify_edl_installation(self):
        """Verify EDL.py tool is installed and accessible"""
        try:
            result = self._execute_edl_command(["--help"])
            if result.returncode != 0:
                raise EDLException("EDL.py tool not properly installed or accessible")
        except FileNotFoundError:
            raise EDLException(f"EDL.py executable not found at: {self.edl_tool_path}")
        except EDLException as e:
            if "Failed to execute EDL command" in str(e):
                raise EDLException(f"EDL.py executable not found at: {self.edl_tool_path}")
            raise
    
    def _load_firehose_loaders(self):
        """Load available Firehose loaders configuration"""
        # Common Qualcomm Firehose loaders
        common_loaders = {
            "msm8998": FirehoseLoader(
                loader_path="loaders/prog_firehose_ddr.elf",
                target_name="msm8998",
                protocol_version="1.0"
            ),
            "sdm845": FirehoseLoader(
                loader_path="loaders/prog_firehose_lite.elf", 
                target_name="sdm845",
                protocol_version="1.0"
            ),
            "sm8150": FirehoseLoader(
                loader_path="loaders/prog_firehose_lite.elf",
                target_name="sm8150", 
                protocol_version="1.0"
            ),
            "generic": FirehoseLoader(
                loader_path="loaders/prog_firehose_lite.elf",
                target_name="generic",
                protocol_version="1.0"
            )
        }
        
        self.firehose_loaders.update(common_loaders)
    
    def _execute_edl_command(self, args: List[str], device_serial: str = None,
                           timeout: int = None) -> EDLCommand:
        """
        Execute EDL.py command with proper error handling and logging
        
        Args:
            args: EDL command arguments
            device_serial: Target device serial (optional)
            timeout: Command timeout override
            
        Returns:
            EDLCommand: Command execution result
        """
        if timeout is None:
            timeout = self.timeout
        
        # Build command
        cmd = [self.edl_tool_path]
        if device_serial:
            cmd.extend(["--serial", device_serial])
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
            
            return EDLCommand(
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
            raise EDLException(
                f"EDL command timed out after {timeout} seconds",
                command=" ".join(cmd),
                device_serial=device_serial
            )
        except Exception as e:
            raise EDLException(
                f"Failed to execute EDL command: {str(e)}",
                command=" ".join(cmd),
                device_serial=device_serial
            )
    
    def detect_devices(self) -> List[AndroidDevice]:
        """
        Detect devices in EDL mode
        
        Returns:
            List[AndroidDevice]: List of detected EDL devices
        """
        try:
            result = self._execute_edl_command(["--list"])
            
            if result.returncode != 0:
                raise EDLException("Failed to detect EDL devices", result.command)
            
            devices = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or "Found" not in line:
                    continue
                
                # Parse EDL device line format
                # Example: "Found device: Qualcomm HS-USB QDLoader 9008 (COM3)"
                if "Qualcomm" in line and "9008" in line:
                    # Extract device information
                    serial = self._extract_device_serial(line)
                    if not serial:
                        continue
                    
                    # Create basic device info for EDL mode
                    device = AndroidDevice(
                        serial=serial,
                        model="Unknown (EDL Mode)",
                        brand="Unknown",
                        android_version="Unknown",
                        usb_debugging=False  # EDL mode means USB debugging is disabled
                    )
                    
                    devices.append(device)
            
            return devices
            
        except EDLException:
            raise
        except Exception as e:
            raise EDLException(f"Unexpected error during EDL device detection: {str(e)}")
    
    def _extract_device_serial(self, device_line: str) -> Optional[str]:
        """Extract device serial from EDL device detection line"""
        # Try to extract COM port or USB path as serial identifier
        import re
        
        # Look for COM port (Windows)
        com_match = re.search(r'\(COM(\d+)\)', device_line)
        if com_match:
            return f"EDL_COM{com_match.group(1)}"
        
        # Look for USB path (Linux)
        usb_match = re.search(r'/dev/ttyUSB(\d+)', device_line)
        if usb_match:
            return f"EDL_USB{usb_match.group(1)}"
        
        # Fallback: use timestamp-based identifier
        return f"EDL_{int(time.time())}"
    
    def connect_device(self, device: AndroidDevice) -> bool:
        """
        Connect to EDL device and verify accessibility
        
        Args:
            device: Target Android device in EDL mode
            
        Returns:
            bool: True if connection successful
        """
        try:
            # Test EDL connection with info command
            result = self._execute_edl_command(
                ["--info"],
                device_serial=device.serial
            )
            
            if result.returncode == 0 and "Qualcomm" in result.stdout:
                self.connected_devices[device.serial] = device
                return True
            else:
                raise EDLException(
                    f"Failed to connect to EDL device {device.serial}: {result.stderr}",
                    device_serial=device.serial
                )
                
        except EDLException:
            raise
        except Exception as e:
            raise EDLException(
                f"Unexpected error connecting to EDL device {device.serial}: {str(e)}",
                device_serial=device.serial
            )
    
    def get_device_info(self, device: AndroidDevice) -> AndroidDevice:
        """
        Get device information via EDL mode
        
        Args:
            device: Basic device info to enhance
            
        Returns:
            AndroidDevice: Enhanced device information
        """
        try:
            # Get device information via EDL
            result = self._execute_edl_command(
                ["--info"],
                device_serial=device.serial
            )
            
            if result.returncode != 0:
                raise EDLException(f"Failed to get device info: {result.stderr}")
            
            # Parse device information from EDL output
            device_info = self._parse_edl_device_info(result.stdout)
            
            # Create enhanced device with EDL-specific information
            enhanced_device = AndroidDevice(
                serial=device.serial,
                model=device_info.get('model', device.model),
                brand=device_info.get('brand', device.brand),
                android_version=device_info.get('android_version', 'Unknown'),
                imei=device_info.get('imei'),
                usb_debugging=False,  # EDL mode means USB debugging is disabled
                root_status=False,    # Cannot determine in EDL mode
                lock_type=None,       # Cannot determine in EDL mode
                screen_timeout=0,     # Not applicable in EDL mode
                lockout_policy=None,  # Not applicable in EDL mode
                build_number=device_info.get('build_number'),
                security_patch_level=None,  # Not available in EDL mode
                bootloader_locked=True,     # Assume locked if in EDL mode
                encryption_enabled=None,    # Cannot determine in EDL mode
                developer_options_enabled=False  # Must be disabled if in EDL mode
            )
            
            return enhanced_device
            
        except Exception as e:
            raise EDLException(
                f"Failed to get device info for {device.serial}: {str(e)}",
                device_serial=device.serial
            )
    
    def _parse_edl_device_info(self, edl_output: str) -> Dict[str, str]:
        """Parse device information from EDL output"""
        info = {}
        
        # Parse EDL output for device information
        lines = edl_output.split('\n')
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                info[key] = value
        
        return info
    
    def is_device_accessible(self, device: AndroidDevice) -> bool:
        """
        Check if device is accessible for forensic operations
        
        Args:
            device: Target device
            
        Returns:
            bool: True if device is accessible
        """
        try:
            result = self._execute_edl_command(
                ["--info"],
                device_serial=device.serial,
                timeout=10
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def __str__(self) -> str:
        """String representation of EDL handler"""
        return f"EDLHandler(path={self.edl_tool_path}, connected_devices={len(self.connected_devices)})"
    
    def __repr__(self) -> str:
        """Detailed representation of EDL handler"""
        return (f"EDLHandler(edl_tool_path='{self.edl_tool_path}', timeout={self.timeout}, "
                f"connected_devices={list(self.connected_devices.keys())})")