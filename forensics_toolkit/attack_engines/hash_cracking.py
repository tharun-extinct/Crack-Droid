"""
Hash cracking module with Hashcat integration and John the Ripper fallback
"""

import os
import subprocess
import tempfile
import hashlib
import json
import time
import threading
from typing import List, Dict, Any, Optional, Callable, Iterator, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

from ..interfaces import IAttackEngine, AttackType, LockType, ForensicsException
from ..models.attack import AttackStrategy, AttackStatus, DelayStrategy
from ..models.device import AndroidDevice


class HashCrackingException(ForensicsException):
    """Exception raised during hash cracking operations"""
    
    def __init__(self, message: str, error_code: str = "HASH_CRACKING_ERROR"):
        super().__init__(message, error_code, evidence_impact=False)


class HashFormat(Enum):
    """Supported hash formats"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    ANDROID_PIN = "android_pin"
    ANDROID_PASSWORD = "android_password"
    ANDROID_PATTERN = "android_pattern"
    UNKNOWN = "unknown"


class CrackingEngine(Enum):
    """Available cracking engines"""
    HASHCAT = "hashcat"
    JOHN = "john"
    CUSTOM = "custom"


@dataclass
class HashTarget:
    """Hash target for cracking"""
    hash_value: str
    hash_format: HashFormat
    salt: Optional[str] = None
    iterations: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate hash target"""
        if not self.hash_value or not self.hash_value.strip():
            raise HashCrackingException("Hash value cannot be empty")
        
        # Auto-detect format if unknown
        if self.hash_format == HashFormat.UNKNOWN:
            self.hash_format = self._detect_hash_format()
    
    def _detect_hash_format(self) -> HashFormat:
        """Auto-detect hash format based on length and pattern"""
        hash_clean = self.hash_value.strip().lower()
        
        # Android-specific patterns (check first)
        if 'android' in self.metadata.get('source', '').lower():
            if len(hash_clean) == 40:
                return HashFormat.ANDROID_PIN
            elif len(hash_clean) == 64:
                return HashFormat.ANDROID_PASSWORD
        
        # Common hash length patterns
        if len(hash_clean) == 32 and all(c in '0123456789abcdef' for c in hash_clean):
            return HashFormat.MD5
        elif len(hash_clean) == 40 and all(c in '0123456789abcdef' for c in hash_clean):
            return HashFormat.SHA1
        elif len(hash_clean) == 64 and all(c in '0123456789abcdef' for c in hash_clean):
            return HashFormat.SHA256
        elif len(hash_clean) == 128 and all(c in '0123456789abcdef' for c in hash_clean):
            return HashFormat.SHA512
        
        return HashFormat.UNKNOWN


@dataclass
class CrackingProgress:
    """Progress tracking for hash cracking operations"""
    total_hashes: int
    cracked_hashes: int = 0
    current_hash: Optional[str] = None
    current_engine: Optional[CrackingEngine] = None
    start_time: datetime = field(default_factory=datetime.now)
    last_update: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    
    # Performance metrics
    hashes_per_second: float = 0.0
    gpu_utilization: float = 0.0
    temperature: float = 0.0
    
    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage"""
        if self.total_hashes == 0:
            return 0.0
        return (self.cracked_hashes / self.total_hashes) * 100
    
    @property
    def elapsed_time(self) -> timedelta:
        """Calculate elapsed time"""
        return datetime.now() - self.start_time
    
    def update_performance(self, hashes_per_second: float, gpu_util: float = 0.0, temp: float = 0.0):
        """Update performance metrics"""
        self.hashes_per_second = hashes_per_second
        self.gpu_utilization = gpu_util
        self.temperature = temp
        self.last_update = datetime.now()
        
        # Update ETA
        if hashes_per_second > 0:
            remaining_hashes = self.total_hashes - self.cracked_hashes
            remaining_seconds = remaining_hashes / hashes_per_second
            self.estimated_completion = datetime.now() + timedelta(seconds=remaining_seconds)


@dataclass
class CrackingResult:
    """Result of hash cracking operation"""
    hash_value: str
    plaintext: Optional[str] = None
    cracked: bool = False
    engine_used: Optional[CrackingEngine] = None
    crack_time: Optional[timedelta] = None
    attempts: int = 0
    error_message: Optional[str] = None


class HashCracking(IAttackEngine):
    """
    Hash cracking engine with Hashcat integration and John the Ripper fallback
    
    This engine provides GPU-accelerated hash cracking capabilities with support
    for multiple hash formats and automatic fallback between cracking engines.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize hash cracking engine
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Engine configuration
        self._hashcat_path = self._find_hashcat()
        self._john_path = self._find_john()
        self._gpu_available = self._check_gpu_availability()
        
        # Attack state
        self._current_strategy: Optional[AttackStrategy] = None
        self._progress: Optional[CrackingProgress] = None
        self._attack_status = AttackStatus.PENDING
        self._stop_event = threading.Event()
        
        # Callbacks
        self._progress_callback: Optional[Callable[[CrackingProgress], None]] = None
        self._result_callback: Optional[Callable[[CrackingResult], None]] = None
        
        # Temporary files management
        self._temp_files: List[str] = []
        
        self.logger.info(f"Hash cracking engine initialized - Hashcat: {bool(self._hashcat_path)}, "
                        f"John: {bool(self._john_path)}, GPU: {self._gpu_available}")
    
    def _find_hashcat(self) -> Optional[str]:
        """Find Hashcat executable"""
        possible_paths = [
            'hashcat',
            '/usr/bin/hashcat',
            '/usr/local/bin/hashcat',
            'C:\\hashcat\\hashcat.exe',
            'C:\\Program Files\\hashcat\\hashcat.exe'
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
        
        self.logger.warning("Hashcat not found in system PATH")
        return None
    
    def _find_john(self) -> Optional[str]:
        """Find John the Ripper executable"""
        possible_paths = [
            'john',
            '/usr/bin/john',
            '/usr/local/bin/john',
            'C:\\john\\john.exe'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.logger.info(f"Found John the Ripper at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        self.logger.warning("John the Ripper not found in system PATH")
        return None
    
    def _check_gpu_availability(self) -> bool:
        """Check if GPU acceleration is available"""
        if not self._hashcat_path:
            return False
        
        try:
            # Check for CUDA/OpenCL devices
            result = subprocess.run([self._hashcat_path, '-I'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and ('CUDA' in result.stdout or 'OpenCL' in result.stdout):
                self.logger.info("GPU acceleration available")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.debug(f"GPU check failed: {e}")
        
        return False
    
    def set_progress_callback(self, callback: Callable[[CrackingProgress], None]):
        """Set progress update callback"""
        self._progress_callback = callback
    
    def set_result_callback(self, callback: Callable[[CrackingResult], None]):
        """Set result callback"""
        self._result_callback = callback
    
    def validate_strategy(self, strategy: AttackStrategy) -> bool:
        """
        Validate if strategy is applicable for hash cracking
        
        Args:
            strategy: Attack strategy to validate
            
        Returns:
            bool: True if strategy is valid
        """
        try:
            # Check strategy type
            if strategy.strategy_type not in [AttackType.HASH_CRACKING, AttackType.HYBRID]:
                self.logger.debug(f"Invalid strategy type: {strategy.strategy_type}")
                return False
            
            # Check if we have at least one cracking engine
            if not self._hashcat_path and not self._john_path:
                self.logger.error("No hash cracking engines available")
                return False
            
            # Check device compatibility
            capabilities = strategy.target_device.get_forensic_capabilities()
            if not capabilities.get('hash_extraction', False):
                self.logger.debug("Hash extraction not available for device")
                return False
            
            # Validate GPU acceleration requirements
            if strategy.gpu_acceleration and not self._gpu_available:
                self.logger.warning("GPU acceleration requested but not available")
                # Don't fail validation, just log warning
            
            return True
            
        except Exception as e:
            self.logger.error(f"Strategy validation error: {e}")
            return False
    
    def estimate_duration(self, strategy: AttackStrategy) -> float:
        """
        Estimate hash cracking duration in seconds
        
        Args:
            strategy: Attack strategy
            
        Returns:
            float: Estimated duration in seconds
        """
        if not self.validate_strategy(strategy):
            return 0.0
        
        # Base cracking rate (hashes per second)
        if strategy.gpu_acceleration and self._gpu_available:
            base_rate = 1000000  # 1M hashes/sec for GPU
        else:
            base_rate = 10000    # 10K hashes/sec for CPU
        
        # Estimate total keyspace
        total_combinations = self._estimate_keyspace(strategy)
        
        # Account for wordlist size
        wordlist_size = self._estimate_wordlist_size(strategy.wordlists)
        
        # Calculate time for different attack modes
        if strategy.strategy_type == AttackType.HASH_CRACKING:
            # Pure hash cracking - depends on keyspace
            estimated_time = total_combinations / base_rate
        else:
            # Hybrid - wordlist + some brute force
            estimated_time = wordlist_size / base_rate
        
        return min(estimated_time, strategy.timeout_seconds)
    
    def _estimate_keyspace(self, strategy: AttackStrategy) -> int:
        """Estimate total keyspace for cracking"""
        device = strategy.target_device
        
        if device.lock_type == LockType.PIN:
            return 10000  # 4-digit PIN
        elif device.lock_type == LockType.PASSWORD:
            # Estimate based on common password patterns
            return 1000000  # Conservative estimate
        elif device.lock_type == LockType.PATTERN:
            return 389112   # 9-dot pattern combinations
        
        return 100000  # Default estimate
    
    def _estimate_wordlist_size(self, wordlists: List[str]) -> int:
        """Estimate total wordlist entries"""
        total_size = 0
        
        for wordlist in wordlists:
            try:
                if os.path.exists(wordlist):
                    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        total_size += sum(1 for _ in f)
                else:
                    # Estimate based on common wordlist sizes
                    total_size += 10000
            except Exception:
                total_size += 10000  # Default estimate
        
        return max(total_size, 1000)  # Minimum estimate   
 
    def execute_attack(self, strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Execute hash cracking attack strategy
        
        Args:
            strategy: Attack strategy to execute
            
        Returns:
            Dict[str, Any]: Attack results
        """
        if not self.validate_strategy(strategy):
            raise HashCrackingException("Invalid attack strategy")
        
        self.logger.info(f"Starting hash cracking attack on {strategy.target_device.serial}")
        
        try:
            # Initialize attack state
            self._initialize_attack(strategy)
            
            # Extract hashes from device
            hash_targets = self._extract_hashes(strategy)
            
            if not hash_targets:
                raise HashCrackingException("No hashes extracted from device")
            
            # Execute cracking operation
            results = self._crack_hashes(hash_targets, strategy)
            
            return self._compile_results(results, strategy)
            
        except Exception as e:
            self.logger.error(f"Hash cracking attack failed: {e}")
            self._attack_status = AttackStatus.FAILED
            raise HashCrackingException(f"Attack execution failed: {e}")
        
        finally:
            self._cleanup_attack()
    
    def _initialize_attack(self, strategy: AttackStrategy):
        """Initialize attack state and progress tracking"""
        self._current_strategy = strategy
        self._attack_status = AttackStatus.RUNNING
        self._stop_event.clear()
        
        self.logger.info("Hash cracking attack initialized")
    
    def _extract_hashes(self, strategy: AttackStrategy) -> List[HashTarget]:
        """
        Extract hashes from target device
        
        Args:
            strategy: Attack strategy
            
        Returns:
            List[HashTarget]: Extracted hash targets
        """
        device = strategy.target_device
        hash_targets = []
        
        try:
            # This is a simplified implementation
            # In practice, would use device handlers to extract actual hashes
            
            if device.lock_type == LockType.PIN:
                # Mock PIN hash extraction
                hash_targets.append(HashTarget(
                    hash_value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # "password" SHA256
                    hash_format=HashFormat.ANDROID_PIN,
                    metadata={'source': 'android_pin', 'device': device.serial}
                ))
            
            elif device.lock_type == LockType.PASSWORD:
                # Mock password hash extraction
                hash_targets.append(HashTarget(
                    hash_value="ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",  # "secret123" SHA256
                    hash_format=HashFormat.ANDROID_PASSWORD,
                    salt="randomsalt",
                    metadata={'source': 'android_password', 'device': device.serial}
                ))
            
            elif device.lock_type == LockType.PATTERN:
                # Mock pattern hash extraction
                hash_targets.append(HashTarget(
                    hash_value="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f",  # Pattern hash
                    hash_format=HashFormat.ANDROID_PATTERN,
                    metadata={'source': 'android_pattern', 'device': device.serial}
                ))
            
            self.logger.info(f"Extracted {len(hash_targets)} hashes from device")
            return hash_targets
            
        except Exception as e:
            self.logger.error(f"Hash extraction failed: {e}")
            raise HashCrackingException(f"Failed to extract hashes: {e}")
    
    def _crack_hashes(self, hash_targets: List[HashTarget], strategy: AttackStrategy) -> List[CrackingResult]:
        """
        Crack extracted hashes using available engines
        
        Args:
            hash_targets: List of hash targets to crack
            strategy: Attack strategy
            
        Returns:
            List[CrackingResult]: Cracking results
        """
        # Initialize progress tracking
        self._progress = CrackingProgress(total_hashes=len(hash_targets))
        
        results = []
        
        for i, hash_target in enumerate(hash_targets):
            if self._stop_event.is_set():
                break
            
            self._progress.current_hash = hash_target.hash_value
            self._update_progress()
            
            # Try cracking with preferred engine
            result = self._crack_single_hash(hash_target, strategy)
            results.append(result)
            
            if result.cracked:
                self._progress.cracked_hashes += 1
                self.logger.info(f"Successfully cracked hash: {hash_target.hash_value[:16]}...")
            else:
                self.logger.warning(f"Failed to crack hash: {hash_target.hash_value[:16]}...")
            
            self._update_progress()
            
            # Callback for individual result
            if self._result_callback:
                self._result_callback(result)
        
        return results
    
    def _crack_single_hash(self, hash_target: HashTarget, strategy: AttackStrategy) -> CrackingResult:
        """
        Crack a single hash using available engines
        
        Args:
            hash_target: Hash target to crack
            strategy: Attack strategy
            
        Returns:
            CrackingResult: Cracking result
        """
        start_time = datetime.now()
        
        # Determine engine preference
        engines_to_try = self._get_engine_preference(strategy)
        
        for engine in engines_to_try:
            if self._stop_event.is_set():
                break
            
            try:
                self._progress.current_engine = engine
                self._update_progress()
                
                result = self._crack_with_engine(hash_target, strategy, engine)
                
                if result.cracked:
                    result.engine_used = engine
                    result.crack_time = datetime.now() - start_time
                    return result
                
            except Exception as e:
                self.logger.warning(f"Engine {engine.value} failed: {e}")
                continue
        
        # No engine succeeded
        return CrackingResult(
            hash_value=hash_target.hash_value,
            cracked=False,
            crack_time=datetime.now() - start_time,
            error_message="All cracking engines failed"
        )
    
    def _get_engine_preference(self, strategy: AttackStrategy) -> List[CrackingEngine]:
        """Get preferred engine order based on strategy"""
        engines = []
        
        # Prefer GPU-accelerated Hashcat if available and requested
        if strategy.gpu_acceleration and self._hashcat_path and self._gpu_available:
            engines.append(CrackingEngine.HASHCAT)
        
        # Add Hashcat (CPU mode) if available
        if self._hashcat_path and CrackingEngine.HASHCAT not in engines:
            engines.append(CrackingEngine.HASHCAT)
        
        # Add John the Ripper as fallback
        if self._john_path:
            engines.append(CrackingEngine.JOHN)
        
        return engines
    
    def _crack_with_engine(self, hash_target: HashTarget, strategy: AttackStrategy, 
                          engine: CrackingEngine) -> CrackingResult:
        """
        Crack hash with specific engine
        
        Args:
            hash_target: Hash target to crack
            strategy: Attack strategy
            engine: Cracking engine to use
            
        Returns:
            CrackingResult: Cracking result
        """
        if engine == CrackingEngine.HASHCAT:
            return self._crack_with_hashcat(hash_target, strategy)
        elif engine == CrackingEngine.JOHN:
            return self._crack_with_john(hash_target, strategy)
        else:
            raise HashCrackingException(f"Unsupported engine: {engine}")
    
    def _crack_with_hashcat(self, hash_target: HashTarget, strategy: AttackStrategy) -> CrackingResult:
        """
        Crack hash using Hashcat
        
        Args:
            hash_target: Hash target to crack
            strategy: Attack strategy
            
        Returns:
            CrackingResult: Cracking result
        """
        if not self._hashcat_path:
            raise HashCrackingException("Hashcat not available")
        
        try:
            # Create temporary files
            hash_file = self._create_temp_file(hash_target.hash_value + '\n')
            output_file = self._create_temp_file('')
            
            # Build Hashcat command
            cmd = self._build_hashcat_command(hash_target, strategy, hash_file, output_file)
            
            self.logger.debug(f"Running Hashcat command: {' '.join(cmd)}")
            
            # Execute Hashcat
            start_time = datetime.now()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Monitor progress
            plaintext = self._monitor_hashcat_progress(process, output_file, strategy.timeout_seconds)
            
            crack_time = datetime.now() - start_time
            
            return CrackingResult(
                hash_value=hash_target.hash_value,
                plaintext=plaintext,
                cracked=plaintext is not None,
                crack_time=crack_time,
                attempts=1  # Simplified
            )
            
        except Exception as e:
            self.logger.error(f"Hashcat execution failed: {e}")
            return CrackingResult(
                hash_value=hash_target.hash_value,
                cracked=False,
                error_message=str(e)
            )
    
    def _build_hashcat_command(self, hash_target: HashTarget, strategy: AttackStrategy, 
                              hash_file: str, output_file: str) -> List[str]:
        """Build Hashcat command line"""
        cmd = [self._hashcat_path]
        
        # Hash mode based on format
        hash_mode = self._get_hashcat_mode(hash_target.hash_format)
        cmd.extend(['-m', str(hash_mode)])
        
        # Attack mode
        cmd.extend(['-a', '0'])  # Dictionary attack
        
        # GPU acceleration
        if strategy.gpu_acceleration and self._gpu_available:
            cmd.extend(['-O'])  # Optimized kernels
        else:
            cmd.extend(['-D', '1'])  # CPU only
        
        # Output format
        cmd.extend(['--outfile', output_file])
        cmd.extend(['--outfile-format', '2'])  # Plain text
        
        # Disable potfile
        cmd.extend(['--potfile-disable'])
        
        # Quiet mode
        cmd.extend(['--quiet'])
        
        # Hash file
        cmd.append(hash_file)
        
        # Wordlists
        if strategy.wordlists:
            cmd.extend(strategy.wordlists)
        else:
            # Use built-in wordlist or generate simple one
            simple_wordlist = self._create_simple_wordlist()
            cmd.append(simple_wordlist)
        
        return cmd
    
    def _get_hashcat_mode(self, hash_format: HashFormat) -> int:
        """Get Hashcat hash mode number"""
        mode_map = {
            HashFormat.MD5: 0,
            HashFormat.SHA1: 100,
            HashFormat.SHA256: 1400,
            HashFormat.SHA512: 1700,
            HashFormat.ANDROID_PIN: 5800,      # Android PIN
            HashFormat.ANDROID_PASSWORD: 5800, # Android Password
            HashFormat.ANDROID_PATTERN: 1400   # Treat as SHA256
        }
        
        return mode_map.get(hash_format, 1400)  # Default to SHA256
    
    def _monitor_hashcat_progress(self, process: subprocess.Popen, output_file: str, 
                                 timeout: int) -> Optional[str]:
        """Monitor Hashcat progress and return result"""
        start_time = time.time()
        
        while process.poll() is None:
            if self._stop_event.is_set():
                process.terminate()
                return None
            
            if time.time() - start_time > timeout:
                process.terminate()
                return None
            
            # Check for results
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        content = f.read().strip()
                        if content:
                            return content
                except Exception:
                    pass
            
            time.sleep(1)
        
        # Process finished, check final result
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    content = f.read().strip()
                    return content if content else None
            except Exception:
                pass
        
        return None
    
    def _crack_with_john(self, hash_target: HashTarget, strategy: AttackStrategy) -> CrackingResult:
        """
        Crack hash using John the Ripper
        
        Args:
            hash_target: Hash target to crack
            strategy: Attack strategy
            
        Returns:
            CrackingResult: Cracking result
        """
        if not self._john_path:
            raise HashCrackingException("John the Ripper not available")
        
        try:
            # Create temporary hash file
            hash_file = self._create_temp_file(hash_target.hash_value + '\n')
            
            # Build John command
            cmd = [self._john_path, '--format=raw-sha256', hash_file]
            
            # Add wordlist if available
            if strategy.wordlists:
                cmd.extend(['--wordlist=' + strategy.wordlists[0]])
            
            self.logger.debug(f"Running John command: {' '.join(cmd)}")
            
            # Execute John
            start_time = datetime.now()
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=min(strategy.timeout_seconds, 300))
            
            crack_time = datetime.now() - start_time
            
            # Check if cracked
            if result.returncode == 0:
                # Try to get the result
                show_cmd = [self._john_path, '--show', hash_file]
                show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=10)
                
                if show_result.returncode == 0 and show_result.stdout.strip():
                    # Parse John output format: hash:plaintext
                    lines = show_result.stdout.strip().split('\n')
                    for line in lines:
                        if ':' in line:
                            plaintext = line.split(':', 1)[1]
                            return CrackingResult(
                                hash_value=hash_target.hash_value,
                                plaintext=plaintext,
                                cracked=True,
                                crack_time=crack_time,
                                attempts=1
                            )
            
            return CrackingResult(
                hash_value=hash_target.hash_value,
                cracked=False,
                crack_time=crack_time,
                error_message="John the Ripper failed to crack hash"
            )
            
        except subprocess.TimeoutExpired:
            return CrackingResult(
                hash_value=hash_target.hash_value,
                cracked=False,
                error_message="John the Ripper timeout"
            )
        except Exception as e:
            self.logger.error(f"John execution failed: {e}")
            return CrackingResult(
                hash_value=hash_target.hash_value,
                cracked=False,
                error_message=str(e)
            )
    
    def _create_temp_file(self, content: str) -> str:
        """Create temporary file with content"""
        fd, path = tempfile.mkstemp(text=True)
        self._temp_files.append(path)
        
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(content)
            return path
        except Exception:
            os.close(fd)
            raise
    
    def _create_simple_wordlist(self) -> str:
        """Create simple wordlist for testing"""
        common_passwords = [
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "1234567890", "qwerty", "abc123",
            "Password1", "password1", "123456789", "welcome123",
            "admin123", "root", "toor", "pass", "test", "guest"
        ]
        
        # Add common PINs
        for i in range(10000):
            common_passwords.append(f"{i:04d}")
        
        content = '\n'.join(common_passwords) + '\n'
        return self._create_temp_file(content)
    
    def _update_progress(self):
        """Update progress and call callback"""
        if self._progress and self._progress_callback:
            self._progress_callback(self._progress)
    
    def _compile_results(self, results: List[CrackingResult], strategy: AttackStrategy) -> Dict[str, Any]:
        """Compile final attack results"""
        successful_cracks = [r for r in results if r.cracked]
        
        end_time = datetime.now()
        start_time = self._progress.start_time if self._progress else end_time
        duration = (end_time - start_time).total_seconds()
        
        compiled_results = {
            'success': len(successful_cracks) > 0,
            'total_hashes': len(results),
            'cracked_hashes': len(successful_cracks),
            'duration_seconds': duration,
            'status': AttackStatus.COMPLETED.value if len(successful_cracks) > 0 else AttackStatus.FAILED.value,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'results': []
        }
        
        # Add individual results
        for result in results:
            compiled_results['results'].append({
                'hash': result.hash_value,
                'plaintext': result.plaintext,
                'cracked': result.cracked,
                'engine': result.engine_used.value if result.engine_used else None,
                'crack_time_seconds': result.crack_time.total_seconds() if result.crack_time else None,
                'error': result.error_message
            })
        
        # Performance metrics
        if self._progress:
            compiled_results.update({
                'hashes_per_second': self._progress.hashes_per_second,
                'gpu_utilization': self._progress.gpu_utilization,
                'temperature': self._progress.temperature
            })
        
        self.logger.info(f"Hash cracking completed: {compiled_results}")
        return compiled_results
    
    def _cleanup_attack(self):
        """Clean up attack resources"""
        self._stop_event.set()
        
        # Clean up temporary files
        for temp_file in self._temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                self.logger.warning(f"Failed to clean up temp file {temp_file}: {e}")
        
        self._temp_files.clear()
        self._current_strategy = None
        self._progress = None
    
    def stop_attack(self):
        """Stop the current attack"""
        self._stop_event.set()
        self._attack_status = AttackStatus.ABORTED
        self.logger.info("Hash cracking attack stopped")
    
    def get_attack_status(self) -> AttackStatus:
        """Get current attack status"""
        return self._attack_status
    
    def get_progress(self) -> Optional[CrackingProgress]:
        """Get current attack progress"""
        return self._progress
    
    def get_supported_formats(self) -> List[HashFormat]:
        """Get list of supported hash formats"""
        return list(HashFormat)
    
    def detect_hash_format(self, hash_value: str) -> HashFormat:
        """
        Detect hash format from hash value
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            HashFormat: Detected format
        """
        temp_target = HashTarget(hash_value, HashFormat.UNKNOWN)
        return temp_target.hash_format
    
    def convert_hash_format(self, hash_value: str, from_format: HashFormat, 
                           to_format: HashFormat) -> str:
        """
        Convert hash between formats (if possible)
        
        Args:
            hash_value: Original hash value
            from_format: Source format
            to_format: Target format
            
        Returns:
            str: Converted hash value
            
        Raises:
            HashCrackingException: If conversion not possible
        """
        # This is a simplified implementation
        # In practice, would implement actual format conversions
        
        if from_format == to_format:
            return hash_value
        
        # Some basic conversions
        if from_format == HashFormat.UNKNOWN:
            # Try to detect and convert
            detected = self.detect_hash_format(hash_value)
            if detected != HashFormat.UNKNOWN:
                return self.convert_hash_format(hash_value, detected, to_format)
        
        # For now, just return original hash
        self.logger.warning(f"Hash format conversion not implemented: {from_format} -> {to_format}")
        return hash_value
    
    def configure_gpu_acceleration(self, enable: bool = True, device_ids: List[int] = None) -> bool:
        """
        Configure GPU acceleration settings
        
        Args:
            enable: Enable/disable GPU acceleration
            device_ids: Specific GPU device IDs to use
            
        Returns:
            bool: True if configuration successful
        """
        if enable and not self._gpu_available:
            self.logger.warning("GPU acceleration requested but not available")
            return False
        
        # This would configure GPU settings in practice
        self.logger.info(f"GPU acceleration configured: enabled={enable}, devices={device_ids}")
        return True
    
    def benchmark_performance(self, hash_format: HashFormat = HashFormat.SHA256, 
                            duration: int = 10) -> Dict[str, float]:
        """
        Benchmark cracking performance
        
        Args:
            hash_format: Hash format to benchmark
            duration: Benchmark duration in seconds
            
        Returns:
            Dict[str, float]: Performance metrics
        """
        if not self._hashcat_path:
            return {'error': 'Hashcat not available for benchmarking'}
        
        try:
            hash_mode = self._get_hashcat_mode(hash_format)
            cmd = [self._hashcat_path, '-b', '-m', str(hash_mode), '--runtime', str(duration)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
            
            if result.returncode == 0:
                # Parse benchmark output
                # This is simplified - would parse actual Hashcat benchmark output
                return {
                    'hashes_per_second': 1000000.0,  # Mock value
                    'gpu_utilization': 95.0,
                    'temperature': 65.0
                }
            else:
                return {'error': 'Benchmark failed'}
                
        except Exception as e:
            return {'error': str(e)}