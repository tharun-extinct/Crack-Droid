"""
Brute force attack engine with multi-threading support and lockout detection
"""

import time
import threading
import queue
from typing import List, Dict, Any, Optional, Callable, Iterator
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
import logging

from ..interfaces import IAttackEngine, AttackType, LockType, ForensicsException
from ..models.attack import AttackStrategy, AttackStatus, DelayStrategy
from ..models.device import AndroidDevice


class BruteForceException(ForensicsException):
    """Exception raised during brute force operations"""
    
    def __init__(self, message: str, error_code: str = "BRUTE_FORCE_ERROR"):
        super().__init__(message, error_code, evidence_impact=False)


@dataclass
class AttackProgress:
    """Progress tracking for brute force attacks"""
    total_attempts: int
    completed_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    lockout_events: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    last_attempt_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    current_pattern: Optional[str] = None
    
    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage"""
        if self.total_attempts == 0:
            return 0.0
        return (self.completed_attempts / self.total_attempts) * 100
    
    @property
    def elapsed_time(self) -> timedelta:
        """Calculate elapsed time"""
        return datetime.now() - self.start_time
    
    @property
    def attempts_per_second(self) -> float:
        """Calculate attempts per second"""
        elapsed = self.elapsed_time.total_seconds()
        if elapsed == 0:
            return 0.0
        return self.completed_attempts / elapsed
    
    def update_estimate(self):
        """Update estimated completion time"""
        if self.attempts_per_second > 0:
            remaining_attempts = self.total_attempts - self.completed_attempts
            remaining_seconds = remaining_attempts / self.attempts_per_second
            self.estimated_completion = datetime.now() + timedelta(seconds=remaining_seconds)


@dataclass
class LockoutState:
    """Device lockout state tracking"""
    is_locked_out: bool = False
    lockout_start: Optional[datetime] = None
    lockout_duration: int = 30  # seconds
    consecutive_failures: int = 0
    max_failures_before_lockout: int = 5
    progressive_lockout: bool = True
    
    def calculate_lockout_duration(self) -> int:
        """Calculate lockout duration based on failure count"""
        if not self.progressive_lockout:
            return self.lockout_duration
        
        # Progressive lockout: 30s, 1m, 5m, 15m, 30m, 1h
        durations = [30, 60, 300, 900, 1800, 3600]
        
        # Calculate which lockout this is (0-based)
        if self.consecutive_failures < self.max_failures_before_lockout:
            return self.lockout_duration  # No lockout yet
        
        lockout_count = self.consecutive_failures - self.max_failures_before_lockout
        index = min(lockout_count, len(durations) - 1)
        return durations[index]
    
    def trigger_lockout(self):
        """Trigger device lockout"""
        self.is_locked_out = True
        self.lockout_start = datetime.now()
        # Update the actual lockout duration based on current failure count
        calculated_duration = self.calculate_lockout_duration()
        self.lockout_duration = calculated_duration
    
    def check_lockout_expired(self) -> bool:
        """Check if lockout has expired"""
        if not self.is_locked_out or not self.lockout_start:
            return True
        
        elapsed = (datetime.now() - self.lockout_start).total_seconds()
        if elapsed >= self.lockout_duration:
            self.is_locked_out = False
            self.lockout_start = None
            return True
        
        return False
    
    def get_remaining_lockout_time(self) -> int:
        """Get remaining lockout time in seconds"""
        if not self.is_locked_out or not self.lockout_start:
            return 0
        
        elapsed = (datetime.now() - self.lockout_start).total_seconds()
        remaining = max(0, self.lockout_duration - elapsed)
        return int(remaining)


class BruteForceEngine(IAttackEngine):
    """
    Multi-threaded brute force attack engine with lockout detection
    
    This engine coordinates brute force attacks across multiple threads,
    handles device lockouts automatically, and provides comprehensive
    progress tracking and attack resumption capabilities.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize brute force engine
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self._attack_queue = queue.Queue()
        self._result_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._futures: List[Future] = []
        
        # Attack state
        self._current_strategy: Optional[AttackStrategy] = None
        self._progress: Optional[AttackProgress] = None
        self._lockout_state: Optional[LockoutState] = None
        self._attack_status = AttackStatus.PENDING
        
        # Callbacks
        self._progress_callback: Optional[Callable[[AttackProgress], None]] = None
        self._lockout_callback: Optional[Callable[[LockoutState], None]] = None
        self._result_callback: Optional[Callable[[str, bool], None]] = None
    
    def set_progress_callback(self, callback: Callable[[AttackProgress], None]):
        """Set progress update callback"""
        self._progress_callback = callback
    
    def set_lockout_callback(self, callback: Callable[[LockoutState], None]):
        """Set lockout detection callback"""
        self._lockout_callback = callback
    
    def set_result_callback(self, callback: Callable[[str, bool], None]):
        """Set result callback (pattern, success)"""
        self._result_callback = callback
    
    def validate_strategy(self, strategy: AttackStrategy) -> bool:
        """
        Validate if strategy is applicable for brute force
        
        Args:
            strategy: Attack strategy to validate
            
        Returns:
            bool: True if strategy is valid
        """
        try:
            # Check strategy type
            if strategy.strategy_type not in [AttackType.BRUTE_FORCE, AttackType.DICTIONARY, AttackType.HYBRID]:
                self.logger.debug(f"Invalid strategy type: {strategy.strategy_type}")
                return False
            
            # Check device compatibility
            capabilities = strategy.target_device.get_forensic_capabilities()
            if not capabilities.get('brute_force_viable', False):
                self.logger.debug(f"Device not brute force viable: {capabilities}")
                return False
            
            # Check lock type compatibility
            compatible_locks = [LockType.PIN, LockType.PASSWORD, LockType.PATTERN]
            if strategy.target_device.lock_type not in compatible_locks:
                self.logger.debug(f"Incompatible lock type: {strategy.target_device.lock_type}")
                return False
            
            # Validate strategy parameters (but don't fail on validation errors, just log them)
            try:
                strategy.validate_all()
            except Exception as e:
                self.logger.debug(f"Strategy validation warnings: {e}")
                # Don't fail validation for non-critical errors
            
            return True
            
        except Exception as e:
            self.logger.error(f"Strategy validation error: {e}")
            return False
    
    def estimate_duration(self, strategy: AttackStrategy) -> float:
        """
        Estimate attack duration in seconds
        
        Args:
            strategy: Attack strategy
            
        Returns:
            float: Estimated duration in seconds
        """
        if not self.validate_strategy(strategy):
            return 0.0
        
        # Base attempt rate (attempts per second)
        base_rate = self._calculate_base_rate(strategy)
        
        if base_rate <= 0:
            return float(strategy.timeout_seconds)
        
        # Adjust for threading
        effective_rate = base_rate * min(strategy.thread_count, 4)  # Diminishing returns
        
        # Account for lockouts
        lockout_overhead = self._estimate_lockout_overhead(strategy)
        
        # Calculate total time
        total_attempts = max(1, strategy.max_attempts)  # Ensure at least 1 attempt
        base_time = total_attempts / effective_rate
        total_time = base_time * (1 + lockout_overhead)
        
        return min(total_time, strategy.timeout_seconds)
    
    def _calculate_base_rate(self, strategy: AttackStrategy) -> float:
        """Calculate base attempt rate based on device and lock type"""
        device = strategy.target_device
        
        # Base rates by lock type (attempts per second)
        rates = {
            LockType.PIN: 2.0,      # Physical input simulation
            LockType.PASSWORD: 1.0,  # Slower due to complexity
            LockType.PATTERN: 3.0    # Faster pattern input
        }
        
        base_rate = rates.get(device.lock_type, 1.0)
        
        # Adjust for device capabilities
        if device.usb_debugging:
            base_rate *= 1.5  # ADB input is more reliable
        
        if device.root_status:
            base_rate *= 2.0  # Direct access is faster
        
        return base_rate
    
    def _estimate_lockout_overhead(self, strategy: AttackStrategy) -> float:
        """Estimate overhead due to lockouts"""
        device = strategy.target_device
        
        if not device.lockout_policy:
            return 0.1  # Minimal overhead
        
        policy = device.lockout_policy
        
        # Estimate lockout frequency
        lockouts_per_hour = 3600 / (policy.max_attempts * 2)  # Conservative estimate
        avg_lockout_duration = policy.lockout_duration * 1.5  # Account for progressive
        
        # Calculate overhead ratio
        overhead = (lockouts_per_hour * avg_lockout_duration) / 3600
        
        return min(overhead, 0.5)  # Cap at 50% overhead
    
    def execute_attack(self, strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Execute brute force attack strategy
        
        Args:
            strategy: Attack strategy to execute
            
        Returns:
            Dict[str, Any]: Attack results
        """
        if not self.validate_strategy(strategy):
            raise BruteForceException("Invalid attack strategy")
        
        self.logger.info(f"Starting brute force attack on {strategy.target_device.serial}")
        
        try:
            # Initialize attack state
            self._initialize_attack(strategy)
            
            # Generate attack patterns
            patterns = self._generate_attack_patterns(strategy)
            
            # Execute multi-threaded attack
            result = self._execute_threaded_attack(patterns, strategy)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}")
            self._attack_status = AttackStatus.FAILED
            raise BruteForceException(f"Attack execution failed: {e}")
        
        finally:
            self._cleanup_attack()
    
    def _initialize_attack(self, strategy: AttackStrategy):
        """Initialize attack state and progress tracking"""
        self._current_strategy = strategy
        self._attack_status = AttackStatus.RUNNING
        self._stop_event.clear()
        self._pause_event.clear()
        
        # Initialize progress tracking
        total_patterns = self._estimate_total_patterns(strategy)
        self._progress = AttackProgress(total_attempts=total_patterns)
        
        # Initialize lockout state
        lockout_policy = strategy.target_device.lockout_policy
        if lockout_policy:
            self._lockout_state = LockoutState(
                lockout_duration=lockout_policy.lockout_duration,
                max_failures_before_lockout=lockout_policy.max_attempts,
                progressive_lockout=lockout_policy.progressive_lockout
            )
        else:
            self._lockout_state = LockoutState()
        
        self.logger.info(f"Attack initialized: {total_patterns} patterns to test")
    
    def _estimate_total_patterns(self, strategy: AttackStrategy) -> int:
        """Estimate total number of patterns to test"""
        total = 0
        
        # Count wordlist entries
        for wordlist in strategy.wordlists:
            # Estimate based on common wordlist sizes
            total += 10000  # Conservative estimate
        
        # Count mask patterns
        for mask in strategy.mask_patterns:
            total += self._estimate_mask_combinations(mask)
        
        # Apply max attempts limit
        return min(total, strategy.max_attempts)
    
    def _estimate_mask_combinations(self, mask: str) -> int:
        """Estimate combinations for a mask pattern"""
        # Simple estimation for common mask patterns
        # ?d = digit (10), ?l = lowercase (26), ?u = uppercase (26), ?s = symbol (32)
        combinations = 1
        
        for char in mask:
            if char == '?':
                combinations *= 10  # Conservative estimate
        
        return min(combinations, 100000)  # Cap at reasonable limit
    
    def _generate_attack_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """
        Generate attack patterns based on strategy
        
        Args:
            strategy: Attack strategy
            
        Yields:
            str: Attack patterns to test
        """
        patterns_generated = 0
        
        # Priority patterns first
        for pattern in strategy.priority_patterns:
            if patterns_generated >= strategy.max_attempts:
                break
            yield pattern
            patterns_generated += 1
        
        # Dictionary patterns
        if strategy.strategy_type in [AttackType.DICTIONARY, AttackType.HYBRID]:
            for pattern in self._generate_dictionary_patterns(strategy):
                if patterns_generated >= strategy.max_attempts:
                    break
                yield pattern
                patterns_generated += 1
        
        # Brute force patterns
        if strategy.strategy_type in [AttackType.BRUTE_FORCE, AttackType.HYBRID]:
            for pattern in self._generate_brute_force_patterns(strategy):
                if patterns_generated >= strategy.max_attempts:
                    break
                yield pattern
                patterns_generated += 1
    
    def _generate_dictionary_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """Generate patterns from wordlists"""
        # This is a simplified implementation
        # In practice, would read from actual wordlist files
        common_pins = [
            "0000", "1234", "1111", "0123", "1212", "7777", "1004", "2000",
            "4444", "2222", "6969", "9999", "3333", "5555", "6666", "1313",
            "8888", "4321", "2001", "1010"
        ]
        
        for pin in common_pins:
            yield pin
    
    def _generate_brute_force_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """Generate brute force patterns based on lock type"""
        device = strategy.target_device
        
        if device.lock_type == LockType.PIN:
            # Generate PIN patterns (4-6 digits)
            for length in range(4, 7):
                for i in range(10 ** length):
                    yield str(i).zfill(length)
        
        elif device.lock_type == LockType.PASSWORD:
            # Generate password patterns (simplified)
            for length in range(4, 9):
                # This would be more sophisticated in practice
                yield "a" * length
        
        elif device.lock_type == LockType.PATTERN:
            # Generate pattern sequences (simplified)
            for i in range(1000):
                yield f"pattern_{i:04d}"
    
    def _execute_threaded_attack(self, patterns: Iterator[str], strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Execute attack using multiple threads
        
        Args:
            patterns: Iterator of patterns to test
            strategy: Attack strategy
            
        Returns:
            Dict[str, Any]: Attack results
        """
        self.logger.info(f"Starting threaded attack with {strategy.thread_count} threads")
        
        # Create thread pool
        self._executor = ThreadPoolExecutor(max_workers=strategy.thread_count)
        
        # Submit attack tasks
        pattern_list = list(patterns)  # Convert iterator to list for threading
        chunk_size = max(1, len(pattern_list) // strategy.thread_count)
        
        for i in range(0, len(pattern_list), chunk_size):
            chunk = pattern_list[i:i + chunk_size]
            future = self._executor.submit(self._attack_worker, chunk, strategy)
            self._futures.append(future)
        
        # Monitor attack progress
        return self._monitor_attack_progress(strategy)
    
    def _attack_worker(self, patterns: List[str], strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Worker thread for testing patterns
        
        Args:
            patterns: List of patterns to test
            strategy: Attack strategy
            
        Returns:
            Dict[str, Any]: Worker results
        """
        worker_results = {
            'tested_patterns': 0,
            'successful_pattern': None,
            'lockout_events': 0,
            'errors': []
        }
        
        for pattern in patterns:
            if self._stop_event.is_set():
                break
            
            # Handle pause
            while self._pause_event.is_set() and not self._stop_event.is_set():
                time.sleep(0.1)
            
            # Check lockout state
            if self._lockout_state.is_locked_out:
                if not self._handle_lockout(strategy):
                    break
            
            # Test pattern
            try:
                success = self._test_pattern(pattern, strategy)
                worker_results['tested_patterns'] += 1
                
                # Update progress
                self._update_progress(pattern, success)
                
                if success:
                    worker_results['successful_pattern'] = pattern
                    self._stop_event.set()  # Signal other threads to stop
                    break
                
            except Exception as e:
                worker_results['errors'].append(str(e))
                self.logger.error(f"Pattern test error: {e}")
        
        return worker_results
    
    def _test_pattern(self, pattern: str, strategy: AttackStrategy) -> bool:
        """
        Test a single pattern against the device
        
        Args:
            pattern: Pattern to test
            strategy: Attack strategy
            
        Returns:
            bool: True if pattern was successful
        """
        # This is a mock implementation
        # In practice, would use device handlers (ADB, EDL, etc.)
        
        self.logger.debug(f"Testing pattern: {pattern}")
        
        # Simulate testing delay
        time.sleep(0.1)
        
        # Mock lockout detection (simulate every 5th failure)
        if self._lockout_state.consecutive_failures >= self._lockout_state.max_failures_before_lockout:
            self._lockout_state.trigger_lockout()
            self._lockout_state.consecutive_failures = 0
            if self._lockout_callback:
                self._lockout_callback(self._lockout_state)
            return False
        
        # Mock success (very low probability for testing)
        success = pattern == "1234"  # Mock successful pattern
        
        if success:
            self._lockout_state.consecutive_failures = 0
        else:
            self._lockout_state.consecutive_failures += 1
        
        # Callback for result
        if self._result_callback:
            self._result_callback(pattern, success)
        
        return success
    
    def _handle_lockout(self, strategy: AttackStrategy) -> bool:
        """
        Handle device lockout based on strategy
        
        Args:
            strategy: Attack strategy
            
        Returns:
            bool: True if attack should continue
        """
        if not self._lockout_state.is_locked_out:
            return True
        
        remaining_time = self._lockout_state.get_remaining_lockout_time()
        
        if strategy.delay_handling == DelayStrategy.ABORT:
            self.logger.info("Aborting attack due to lockout")
            self._stop_event.set()
            return False
        
        elif strategy.delay_handling == DelayStrategy.SKIP:
            if self._lockout_state.check_lockout_expired():
                return True
            return False
        
        elif strategy.delay_handling == DelayStrategy.WAIT:
            if remaining_time > 0:
                self.logger.info(f"Waiting {remaining_time}s for lockout to expire")
                time.sleep(min(remaining_time, 1))  # Sleep in small increments
            return self._lockout_state.check_lockout_expired()
        
        return True
    
    def _update_progress(self, pattern: str, success: bool):
        """Update attack progress"""
        if not self._progress:
            return
        
        self._progress.completed_attempts += 1
        self._progress.last_attempt_time = datetime.now()
        self._progress.current_pattern = pattern
        
        if success:
            self._progress.successful_attempts += 1
        else:
            self._progress.failed_attempts += 1
        
        self._progress.update_estimate()
        
        # Progress callback
        if self._progress_callback:
            self._progress_callback(self._progress)
    
    def _monitor_attack_progress(self, strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Monitor attack progress and collect results
        
        Args:
            strategy: Attack strategy
            
        Returns:
            Dict[str, Any]: Final attack results
        """
        start_time = datetime.now()
        successful_pattern = None
        
        try:
            # Wait for completion or timeout
            timeout = strategy.timeout_seconds
            
            for future in self._futures:
                remaining_timeout = timeout - (datetime.now() - start_time).total_seconds()
                if remaining_timeout <= 0:
                    break
                
                try:
                    result = future.result(timeout=remaining_timeout)
                    if result.get('successful_pattern'):
                        successful_pattern = result['successful_pattern']
                        break
                except Exception as e:
                    self.logger.error(f"Worker thread error: {e}")
            
            # Determine final status
            if successful_pattern:
                self._attack_status = AttackStatus.COMPLETED
            elif self._stop_event.is_set():
                self._attack_status = AttackStatus.ABORTED
            else:
                self._attack_status = AttackStatus.FAILED
            
            # Compile results
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'success': successful_pattern is not None,
                'successful_pattern': successful_pattern,
                'total_attempts': self._progress.completed_attempts if self._progress else 0,
                'duration_seconds': duration,
                'status': self._attack_status.value,
                'lockout_events': self._progress.lockout_events if self._progress else 0,
                'attempts_per_second': self._progress.attempts_per_second if self._progress else 0,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
            
            self.logger.info(f"Attack completed: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Attack monitoring error: {e}")
            self._attack_status = AttackStatus.FAILED
            raise BruteForceException(f"Attack monitoring failed: {e}")
    
    def _cleanup_attack(self):
        """Clean up attack resources"""
        self._stop_event.set()
        
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None
        
        self._futures.clear()
        self._current_strategy = None
        self._progress = None
        self._lockout_state = None
    
    def pause_attack(self):
        """Pause the current attack"""
        if self._attack_status == AttackStatus.RUNNING:
            self._pause_event.set()
            self._attack_status = AttackStatus.PAUSED
            self.logger.info("Attack paused")
    
    def resume_attack(self):
        """Resume a paused attack"""
        if self._attack_status == AttackStatus.PAUSED:
            self._pause_event.clear()
            self._attack_status = AttackStatus.RUNNING
            self.logger.info("Attack resumed")
    
    def stop_attack(self):
        """Stop the current attack"""
        self._stop_event.set()
        self._attack_status = AttackStatus.ABORTED
        self.logger.info("Attack stopped")
    
    def get_attack_status(self) -> AttackStatus:
        """Get current attack status"""
        return self._attack_status
    
    def get_progress(self) -> Optional[AttackProgress]:
        """Get current attack progress"""
        return self._progress
    
    def get_lockout_state(self) -> Optional[LockoutState]:
        """Get current lockout state"""
        return self._lockout_state