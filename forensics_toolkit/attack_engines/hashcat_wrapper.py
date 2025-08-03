"""
Hashcat wrapper class with GPU configuration and performance monitoring
"""

import os
import subprocess
import tempfile
import json
import time
import threading
import psutil
import re
from typing import List, Dict, Any, Optional, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

from ..interfaces import ForensicsException


class HashcatException(ForensicsException):
    """Exception raised during Hashcat operations"""
    
    def __init__(self, message: str, error_code: str = "HASHCAT_ERROR"):
        super().__init__(message, error_code, evidence_impact=False)


class HashcatMode(Enum):
    """Hashcat hash modes"""
    MD5 = 0
    SHA1 = 100
    SHA256 = 1400
    SHA512 = 1700
    ANDROID_PIN = 5800
    ANDROID_PASSWORD = 5800
    ANDROID_PATTERN = 1400
    NTLM = 1000
    BCRYPT = 3200


class AttackMode(Enum):
    """Hashcat attack modes"""
    STRAIGHT = 0        # Dictionary attack
    COMBINATION = 1     # Combinator attack
    BRUTE_FORCE = 3     # Brute-force attack
    HYBRID_WL_MASK = 6  # Hybrid Wordlist + Mask
    HYBRID_MASK_WL = 7  # Hybrid Mask + Wordlist


@dataclass
class GPUInfo:
    """GPU information for Hashcat"""
    device_id: int
    name: str
    memory_total: int
    memory_free: int
    temperature: float = 0.0
    utilization: float = 0.0
    power_draw: float = 0.0
    
    @property
    def memory_used_percent(self) -> float:
        """Calculate memory usage percentage"""
        if self.memory_total == 0:
            return 0.0
        return ((self.memory_total - self.memory_free) / self.memory_total) * 100


@dataclass
class HashcatConfig:
    """Hashcat configuration settings"""
    # GPU settings
    gpu_enabled: bool = True
    gpu_devices: Optional[List[int]] = None
    gpu_temp_limit: int = 90
    gpu_power_limit: int = 100
    
    # Performance settings
    workload_profile: int = 3  # High performance
    kernel_accel: Optional[int] = None
    kernel_loops: Optional[int] = None
    optimized_kernel: bool = True
    
    # Attack settings
    attack_mode: AttackMode = AttackMode.STRAIGHT
    hash_mode: Optional[HashcatMode] = None
    increment_mode: bool = False
    increment_min: int = 1
    increment_max: int = 8
    
    # Output settings
    quiet_mode: bool = False
    status_timer: int = 10
    machine_readable: bool = True
    
    # Session settings
    session_name: Optional[str] = None
    restore_enabled: bool = True
    
    # Resource limits
    runtime_limit: Optional[int] = None
    memory_limit: Optional[int] = None


@dataclass
class HashcatProgress:
    """Hashcat progress information"""
    session: str
    status: str
    target: str
    progress: Tuple[int, int]  # (current, total)
    rejected: int
    restore_point: int
    recovered_hashes: Tuple[int, int]  # (recovered, total)
    recovered_salts: Tuple[int, int]   # (recovered, total)
    speed_hashes: List[int]  # Hashes per second per device
    speed_exec: List[int]    # Exec per second per device
    candidates: List[str]    # Current candidates being tested
    hardware_mon: List[Dict[str, Any]]  # Hardware monitoring data
    
    @property
    def progress_percent(self) -> float:
        """Calculate progress percentage"""
        if self.progress[1] == 0:
            return 0.0
        return (self.progress[0] / self.progress[1]) * 100
    
    @property
    def total_speed(self) -> int:
        """Calculate total speed across all devices"""
        return sum(self.speed_hashes)
    
    @property
    def estimated_time_remaining(self) -> Optional[timedelta]:
        """Estimate time remaining"""
        if self.total_speed == 0 or self.progress[1] == 0:
            return None
        
        remaining = self.progress[1] - self.progress[0]
        seconds = remaining / self.total_speed
        return timedelta(seconds=seconds)


@dataclass
class HashcatResult:
    """Hashcat cracking result"""
    hash_value: str
    plaintext: Optional[str] = None
    cracked: bool = False
    crack_time: Optional[timedelta] = None
    attempts: int = 0
    session_name: Optional[str] = None
    device_used: Optional[int] = None
    final_status: Optional[str] = None
    error_message: Optional[str] = None


class HashcatWrapper:
    """
    Comprehensive Hashcat wrapper with GPU configuration and performance monitoring
    """
    
    def __init__(self, hashcat_path: Optional[str] = None, logger: Optional[logging.Logger] = None):
        """
        Initialize Hashcat wrapper
        
        Args:
            hashcat_path: Path to Hashcat executable
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Find Hashcat executable
        self.hashcat_path = hashcat_path or self._find_hashcat()
        if not self.hashcat_path:
            raise HashcatException("Hashcat executable not found")
        
        # Verify Hashcat installation
        self._verify_hashcat()
        
        # GPU information
        self.gpu_devices: List[GPUInfo] = []
        self._detect_gpu_devices()
        
        # Configuration
        self.config = HashcatConfig()
        
        # Session management
        self._active_sessions: Dict[str, subprocess.Popen] = {}
        self._session_lock = threading.Lock()
        
        # Temporary files
        self._temp_files: List[str] = []
        
        self.logger.info(f"Hashcat wrapper initialized - Path: {self.hashcat_path}, "
                        f"GPUs: {len(self.gpu_devices)}")
    
    def _find_hashcat(self) -> Optional[str]:
        """Find Hashcat executable in system"""
        possible_paths = [
            'hashcat',
            '/usr/bin/hashcat',
            '/usr/local/bin/hashcat',
            '/opt/hashcat/hashcat',
            'C:\\hashcat\\hashcat.exe',
            'C:\\Program Files\\hashcat\\hashcat.exe',
            'C:\\Tools\\hashcat\\hashcat.exe'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.logger.info(f"Found Hashcat at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        # Try to find in PATH
        try:
            import shutil
            path = shutil.which('hashcat')
            if path:
                self.logger.info(f"Found Hashcat in PATH: {path}")
                return path
        except Exception:
            pass
        
        return None
    
    def _verify_hashcat(self):
        """Verify Hashcat installation and capabilities"""
        try:
            # Check version
            result = subprocess.run([self.hashcat_path, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                raise HashcatException("Hashcat version check failed")
            
            version_info = result.stdout.strip()
            self.logger.info(f"Hashcat version: {version_info}")
            
            # Check benchmark capability
            result = subprocess.run([self.hashcat_path, '-b', '--quiet'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.logger.info("Hashcat benchmark test passed")
            else:
                self.logger.warning("Hashcat benchmark test failed")
            
        except subprocess.TimeoutExpired:
            raise HashcatException("Hashcat verification timeout")
        except Exception as e:
            raise HashcatException(f"Hashcat verification failed: {e}")
    
    def _detect_gpu_devices(self):
        """Detect available GPU devices"""
        try:
            # Use Hashcat to list devices
            result = subprocess.run([self.hashcat_path, '-I'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode != 0:
                self.logger.warning("Failed to detect GPU devices")
                return
            
            # Parse device information
            devices = []
            current_device = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('Device #'):
                    if current_device:
                        devices.append(current_device)
                    
                    device_id = int(line.split('#')[1].split(':')[0])
                    current_device = GPUInfo(device_id=device_id, name="", 
                                           memory_total=0, memory_free=0)
                
                elif current_device and line.startswith('Name'):
                    current_device.name = line.split(':', 1)[1].strip()
                
                elif current_device and 'Global memory' in line:
                    # Parse memory info (e.g., "Global memory: 8192 MB")
                    memory_match = re.search(r'(\d+)\s*MB', line)
                    if memory_match:
                        current_device.memory_total = int(memory_match.group(1))
                        current_device.memory_free = current_device.memory_total  # Initial assumption
            
            if current_device:
                devices.append(current_device)
            
            self.gpu_devices = devices
            self.logger.info(f"Detected {len(devices)} GPU devices")
            
            for device in devices:
                self.logger.info(f"GPU #{device.device_id}: {device.name} "
                               f"({device.memory_total} MB)")
        
        except Exception as e:
            self.logger.warning(f"GPU detection failed: {e}")
    
    def get_gpu_info(self) -> List[GPUInfo]:
        """Get current GPU information"""
        return self.gpu_devices.copy()
    
    def update_gpu_monitoring(self):
        """Update GPU monitoring information"""
        try:
            # This would typically use nvidia-ml-py or similar
            # For now, we'll use a simplified approach
            for device in self.gpu_devices:
                # Update temperature, utilization, etc.
                # This is a placeholder - real implementation would use GPU APIs
                device.temperature = 65.0  # Mock temperature
                device.utilization = 80.0  # Mock utilization
                device.power_draw = 150.0  # Mock power draw
        
        except Exception as e:
            self.logger.debug(f"GPU monitoring update failed: {e}")
    
    def configure(self, config: HashcatConfig):
        """Update Hashcat configuration"""
        self.config = config
        self.logger.info("Hashcat configuration updated")
    
    def get_supported_hash_modes(self) -> Dict[int, str]:
        """Get supported hash modes"""
        try:
            result = subprocess.run([self.hashcat_path, '--help'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return {}
            
            # Parse hash modes from help output
            modes = {}
            in_hash_modes = False
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Hash modes:' in line:
                    in_hash_modes = True
                    continue
                
                if in_hash_modes and line.startswith('- ['):
                    # Parse format: "- [ 0 ] MD5"
                    match = re.match(r'-\s*\[\s*(\d+)\s*\]\s*(.+)', line)
                    if match:
                        mode_num = int(match.group(1))
                        mode_name = match.group(2).strip()
                        modes[mode_num] = mode_name
                
                elif in_hash_modes and not line:
                    break
            
            return modes
        
        except Exception as e:
            self.logger.warning(f"Failed to get hash modes: {e}")
            return {}
    
    def convert_hash_format(self, hash_value: str, source_format: str, 
                           target_format: str) -> str:
        """
        Convert hash between different formats
        
        Args:
            hash_value: Hash value to convert
            source_format: Source hash format
            target_format: Target hash format
            
        Returns:
            str: Converted hash value
        """
        # This is a simplified implementation
        # Real implementation would handle various hash format conversions
        
        if source_format == target_format:
            return hash_value
        
        # Handle common conversions
        if source_format == "hex" and target_format == "base64":
            import base64
            return base64.b64encode(bytes.fromhex(hash_value)).decode()
        
        elif source_format == "base64" and target_format == "hex":
            import base64
            return base64.b64decode(hash_value).hex()
        
        # Add more conversions as needed
        self.logger.warning(f"Hash format conversion not implemented: {source_format} -> {target_format}")
        return hash_value
    
    def optimize_attack_parameters(self, hash_mode: HashcatMode, 
                                 wordlist_size: int) -> Dict[str, Any]:
        """
        Optimize attack parameters based on hash mode and wordlist size
        
        Args:
            hash_mode: Hash mode being attacked
            wordlist_size: Size of wordlist
            
        Returns:
            Dict[str, Any]: Optimized parameters
        """
        params = {}
        
        # GPU-specific optimizations
        if self.gpu_devices and self.config.gpu_enabled:
            total_memory = sum(gpu.memory_total for gpu in self.gpu_devices)
            
            # Adjust workload profile based on available memory
            if total_memory > 8000:  # > 8GB
                params['workload_profile'] = 4  # Insane
            elif total_memory > 4000:  # > 4GB
                params['workload_profile'] = 3  # High
            else:
                params['workload_profile'] = 2  # Default
            
            # Optimize kernel parameters
            if hash_mode in [HashcatMode.MD5, HashcatMode.SHA1]:
                params['kernel_accel'] = 1024
                params['kernel_loops'] = 1024
            elif hash_mode in [HashcatMode.SHA256, HashcatMode.SHA512]:
                params['kernel_accel'] = 512
                params['kernel_loops'] = 512
            elif hash_mode == HashcatMode.BCRYPT:
                params['workload_profile'] = 3  # High for slow hash
                params['kernel_accel'] = 256
                params['kernel_loops'] = 256
            else:
                params['kernel_accel'] = 256
                params['kernel_loops'] = 256
        
        # Wordlist-specific optimizations
        if wordlist_size > 1000000:  # Large wordlist
            params['status_timer'] = 30
        else:
            params['status_timer'] = 10
        
        return params
    
    def create_session(self, session_name: str, hash_file: str, 
                      wordlist: str, **kwargs) -> str:
        """
        Create a new Hashcat session
        
        Args:
            session_name: Unique session name
            hash_file: Path to hash file
            wordlist: Path to wordlist file
            **kwargs: Additional Hashcat parameters
            
        Returns:
            str: Session ID
        """
        if not os.path.exists(hash_file):
            raise HashcatException(f"Hash file not found: {hash_file}")
        
        if not os.path.exists(wordlist):
            raise HashcatException(f"Wordlist not found: {wordlist}")
        
        # Build command
        cmd = self._build_command(hash_file, wordlist, session_name, **kwargs)
        
        with self._session_lock:
            if session_name in self._active_sessions:
                raise HashcatException(f"Session already exists: {session_name}")
            
            # Start process
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                self._active_sessions[session_name] = process
                self.logger.info(f"Created Hashcat session: {session_name}")
                
                return session_name
            
            except Exception as e:
                raise HashcatException(f"Failed to create session: {e}")
    
    def _build_command(self, hash_file: str, wordlist: str, 
                      session_name: str, **kwargs) -> List[str]:
        """Build Hashcat command line"""
        cmd = [self.hashcat_path]
        
        # Session name
        if session_name:
            cmd.extend(['--session', session_name])
        
        # Hash mode
        hash_mode = kwargs.get('hash_mode', self.config.hash_mode)
        if hash_mode:
            cmd.extend(['-m', str(hash_mode.value)])
        
        # Attack mode
        attack_mode = kwargs.get('attack_mode', self.config.attack_mode)
        cmd.extend(['-a', str(attack_mode.value)])
        
        # GPU configuration
        if self.config.gpu_enabled and self.gpu_devices:
            if self.config.gpu_devices:
                device_list = ','.join(map(str, self.config.gpu_devices))
                cmd.extend(['-d', device_list])
            
            if self.config.optimized_kernel:
                cmd.extend(['-O'])
        else:
            cmd.extend(['-D', '1'])  # CPU only
        
        # Workload profile
        workload = kwargs.get('workload_profile', self.config.workload_profile)
        cmd.extend(['-w', str(workload)])
        
        # Kernel parameters
        if self.config.kernel_accel:
            cmd.extend(['-n', str(self.config.kernel_accel)])
        
        if self.config.kernel_loops:
            cmd.extend(['-u', str(self.config.kernel_loops)])
        
        # Status updates
        if self.config.machine_readable:
            cmd.extend(['--machine-readable'])
        
        cmd.extend(['--status-timer', str(self.config.status_timer)])
        
        # Output options
        if self.config.quiet_mode:
            cmd.extend(['--quiet'])
        
        # Runtime limit
        if self.config.runtime_limit:
            cmd.extend(['--runtime', str(self.config.runtime_limit)])
        
        # Restore options
        if self.config.restore_enabled:
            cmd.extend(['--restore-disable'])  # We'll handle restore manually
        
        # Increment mode
        if self.config.increment_mode:
            cmd.extend(['--increment'])
            cmd.extend(['--increment-min', str(self.config.increment_min)])
            cmd.extend(['--increment-max', str(self.config.increment_max)])
        
        # Hash file
        cmd.append(hash_file)
        
        # Wordlist
        cmd.append(wordlist)
        
        return cmd
    
    def get_session_status(self, session_name: str) -> Optional[HashcatProgress]:
        """
        Get status of running session
        
        Args:
            session_name: Session name
            
        Returns:
            Optional[HashcatProgress]: Session progress or None if not found
        """
        with self._session_lock:
            if session_name not in self._active_sessions:
                return None
            
            process = self._active_sessions[session_name]
            
            # Check if process is still running
            if process.poll() is not None:
                # Process finished
                del self._active_sessions[session_name]
                return None
            
            # Get status from Hashcat
            try:
                # Send status request (this is simplified)
                # Real implementation would parse machine-readable output
                return HashcatProgress(
                    session=session_name,
                    status="Running",
                    target="",
                    progress=(0, 100),
                    rejected=0,
                    restore_point=0,
                    recovered_hashes=(0, 1),
                    recovered_salts=(0, 1),
                    speed_hashes=[1000000],
                    speed_exec=[1000],
                    candidates=["password123"],
                    hardware_mon=[]
                )
            
            except Exception as e:
                self.logger.warning(f"Failed to get session status: {e}")
                return None
    
    def stop_session(self, session_name: str) -> bool:
        """
        Stop running session
        
        Args:
            session_name: Session name
            
        Returns:
            bool: True if stopped successfully
        """
        with self._session_lock:
            if session_name not in self._active_sessions:
                return False
            
            process = self._active_sessions[session_name]
            
            try:
                # Send quit signal
                process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill
                    process.kill()
                    process.wait()
                
                del self._active_sessions[session_name]
                self.logger.info(f"Stopped Hashcat session: {session_name}")
                return True
            
            except Exception as e:
                self.logger.error(f"Failed to stop session {session_name}: {e}")
                return False
    
    def get_session_results(self, session_name: str, potfile_path: Optional[str] = None) -> List[HashcatResult]:
        """
        Get results from completed session
        
        Args:
            session_name: Session name
            potfile_path: Optional path to potfile
            
        Returns:
            List[HashcatResult]: Cracking results
        """
        results = []
        
        # Default potfile location
        if not potfile_path:
            potfile_path = os.path.expanduser("~/.hashcat/hashcat.potfile")
        
        try:
            if os.path.exists(potfile_path):
                with open(potfile_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if ':' in line:
                            hash_value, plaintext = line.split(':', 1)
                            results.append(HashcatResult(
                                hash_value=hash_value,
                                plaintext=plaintext,
                                cracked=True,
                                session_name=session_name
                            ))
        
        except Exception as e:
            self.logger.warning(f"Failed to read potfile: {e}")
        
        return results
    
    def benchmark(self, hash_mode: Optional[HashcatMode] = None) -> Dict[str, Any]:
        """
        Run Hashcat benchmark
        
        Args:
            hash_mode: Optional specific hash mode to benchmark
            
        Returns:
            Dict[str, Any]: Benchmark results
        """
        cmd = [self.hashcat_path, '-b']
        
        if hash_mode:
            cmd.extend(['-m', str(hash_mode.value)])
        
        if self.config.quiet_mode:
            cmd.extend(['--quiet'])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                raise HashcatException(f"Benchmark failed: {result.stderr}")
            
            # Parse benchmark output
            benchmark_data = {
                'timestamp': datetime.now().isoformat(),
                'gpu_devices': len(self.gpu_devices),
                'results': {}
            }
            
            # Simple parsing - real implementation would be more sophisticated
            for line in result.stdout.split('\n'):
                if 'H/s' in line:
                    # Extract hash rate information
                    parts = line.split()
                    if len(parts) >= 2:
                        hash_rate = parts[-1]
                        benchmark_data['results']['hash_rate'] = hash_rate
            
            return benchmark_data
        
        except subprocess.TimeoutExpired:
            raise HashcatException("Benchmark timeout")
        except Exception as e:
            raise HashcatException(f"Benchmark failed: {e}")
    
    def cleanup(self):
        """Clean up resources"""
        # Stop all active sessions
        with self._session_lock:
            for session_name in list(self._active_sessions.keys()):
                self.stop_session(session_name)
        
        # Clean up temporary files
        for temp_file in self._temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                self.logger.warning(f"Failed to clean up temp file {temp_file}: {e}")
        
        self._temp_files.clear()
        self.logger.info("Hashcat wrapper cleanup completed")
    
    def _create_temp_file(self, content: str, suffix: str = '.txt') -> str:
        """Create temporary file with content"""
        try:
            fd, path = tempfile.mkstemp(suffix=suffix, text=True)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self._temp_files.append(path)
            return path
        
        except Exception as e:
            raise HashcatException(f"Failed to create temp file: {e}")
    
    def __del__(self):
        """Destructor"""
        try:
            self.cleanup()
        except Exception:
            pass