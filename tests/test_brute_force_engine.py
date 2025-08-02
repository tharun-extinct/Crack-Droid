"""
Unit tests for brute force attack engine
"""

import unittest
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from forensics_toolkit.attack_engines.brute_force import (
    BruteForceEngine, AttackProgress, LockoutState, BruteForceException
)
from forensics_toolkit.models.attack import AttackStrategy, DelayStrategy, AttackStatus
from forensics_toolkit.models.device import AndroidDevice, LockoutPolicy
from forensics_toolkit.interfaces import AttackType, LockType


class TestAttackProgress(unittest.TestCase):
    """Test AttackProgress class"""
    
    def test_progress_initialization(self):
        """Test progress initialization"""
        progress = AttackProgress(total_attempts=1000)
        
        self.assertEqual(progress.total_attempts, 1000)
        self.assertEqual(progress.completed_attempts, 0)
        self.assertEqual(progress.successful_attempts, 0)
        self.assertEqual(progress.failed_attempts, 0)
        self.assertEqual(progress.lockout_events, 0)
        self.assertIsInstance(progress.start_time, datetime)
        self.assertIsNone(progress.last_attempt_time)
        self.assertIsNone(progress.estimated_completion)
        self.assertIsNone(progress.current_pattern)
    
    def test_progress_percentage(self):
        """Test progress percentage calculation"""
        progress = AttackProgress(total_attempts=100)
        
        # Initial progress
        self.assertEqual(progress.progress_percentage, 0.0)
        
        # Partial progress
        progress.completed_attempts = 25
        self.assertEqual(progress.progress_percentage, 25.0)
        
        # Complete progress
        progress.completed_attempts = 100
        self.assertEqual(progress.progress_percentage, 100.0)
        
        # Zero total attempts
        progress.total_attempts = 0
        self.assertEqual(progress.progress_percentage, 0.0)
    
    def test_elapsed_time(self):
        """Test elapsed time calculation"""
        progress = AttackProgress(total_attempts=100)
        
        # Small delay to ensure elapsed time > 0
        time.sleep(0.01)
        
        elapsed = progress.elapsed_time
        self.assertIsInstance(elapsed, timedelta)
        self.assertGreater(elapsed.total_seconds(), 0)
    
    def test_attempts_per_second(self):
        """Test attempts per second calculation"""
        progress = AttackProgress(total_attempts=100)
        
        # Initial rate (should be 0)
        self.assertEqual(progress.attempts_per_second, 0.0)
        
        # Mock elapsed time and completed attempts
        progress.start_time = datetime.now() - timedelta(seconds=10)
        progress.completed_attempts = 50
        
        rate = progress.attempts_per_second
        self.assertGreater(rate, 0)
        self.assertAlmostEqual(rate, 5.0, places=1)  # 50 attempts / 10 seconds
    
    def test_update_estimate(self):
        """Test estimated completion time update"""
        progress = AttackProgress(total_attempts=100)
        progress.start_time = datetime.now() - timedelta(seconds=10)
        progress.completed_attempts = 25
        
        progress.update_estimate()
        
        self.assertIsNotNone(progress.estimated_completion)
        self.assertIsInstance(progress.estimated_completion, datetime)


class TestLockoutState(unittest.TestCase):
    """Test LockoutState class"""
    
    def test_lockout_initialization(self):
        """Test lockout state initialization"""
        lockout = LockoutState()
        
        self.assertFalse(lockout.is_locked_out)
        self.assertIsNone(lockout.lockout_start)
        self.assertEqual(lockout.lockout_duration, 30)
        self.assertEqual(lockout.consecutive_failures, 0)
        self.assertEqual(lockout.max_failures_before_lockout, 5)
        self.assertTrue(lockout.progressive_lockout)
    
    def test_calculate_lockout_duration(self):
        """Test lockout duration calculation"""
        lockout = LockoutState(progressive_lockout=True, max_failures_before_lockout=5)
        
        # Test progressive lockout durations
        lockout.consecutive_failures = 5  # First lockout (index 0)
        self.assertEqual(lockout.calculate_lockout_duration(), 30)
        
        lockout.consecutive_failures = 6  # Second lockout (index 1)
        self.assertEqual(lockout.calculate_lockout_duration(), 60)
        
        lockout.consecutive_failures = 7  # Third lockout (index 2)
        self.assertEqual(lockout.calculate_lockout_duration(), 300)
        
        # Test non-progressive lockout
        lockout.progressive_lockout = False
        lockout.lockout_duration = 60
        self.assertEqual(lockout.calculate_lockout_duration(), 60)
    
    def test_trigger_lockout(self):
        """Test lockout triggering"""
        lockout = LockoutState()
        
        self.assertFalse(lockout.is_locked_out)
        
        lockout.trigger_lockout()
        
        self.assertTrue(lockout.is_locked_out)
        self.assertIsNotNone(lockout.lockout_start)
        self.assertIsInstance(lockout.lockout_start, datetime)
    
    def test_check_lockout_expired(self):
        """Test lockout expiration check"""
        lockout = LockoutState(lockout_duration=1, progressive_lockout=False)  # 1 second lockout
        
        # No lockout active
        self.assertTrue(lockout.check_lockout_expired())
        
        # Trigger lockout
        lockout.trigger_lockout()
        self.assertFalse(lockout.check_lockout_expired())
        
        # Wait for expiration
        time.sleep(1.1)
        self.assertTrue(lockout.check_lockout_expired())
        self.assertFalse(lockout.is_locked_out)
    
    def test_get_remaining_lockout_time(self):
        """Test remaining lockout time calculation"""
        lockout = LockoutState(lockout_duration=5, progressive_lockout=False)
        
        # No lockout
        self.assertEqual(lockout.get_remaining_lockout_time(), 0)
        
        # Active lockout
        lockout.trigger_lockout()
        remaining = lockout.get_remaining_lockout_time()
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 5)


class TestBruteForceEngine(unittest.TestCase):
    """Test BruteForceEngine class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = BruteForceEngine()
        
        # Create test device
        self.device = AndroidDevice(
            serial="test_device_001",
            model="Test Model",
            brand="Test Brand",
            android_version="11.0",
            usb_debugging=True,
            lock_type=LockType.PIN,
            lockout_policy=LockoutPolicy(
                max_attempts=5,
                lockout_duration=30,
                progressive_lockout=True
            )
        )
        
        # Create test strategy
        self.strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.device,
            max_attempts=100,
            thread_count=2,
            timeout_seconds=60
        )
    
    def test_engine_initialization(self):
        """Test engine initialization"""
        engine = BruteForceEngine()
        
        self.assertIsNotNone(engine.logger)
        self.assertEqual(engine.get_attack_status(), AttackStatus.PENDING)
        self.assertIsNone(engine.get_progress())
        self.assertIsNone(engine.get_lockout_state())
    
    def test_validate_strategy_valid(self):
        """Test strategy validation with valid strategy"""
        self.assertTrue(self.engine.validate_strategy(self.strategy))
    
    def test_validate_strategy_invalid_type(self):
        """Test strategy validation with invalid type"""
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,  # Not supported by brute force
            target_device=self.device,
            max_attempts=100
        )
        
        self.assertFalse(self.engine.validate_strategy(invalid_strategy))
    
    def test_validate_strategy_incompatible_device(self):
        """Test strategy validation with incompatible device"""
        incompatible_device = AndroidDevice(
            serial="test_device_002",
            model="Test Model",
            brand="Test Brand",
            android_version="11.0",
            lock_type=LockType.FINGERPRINT  # Not brute force viable
        )
        
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=incompatible_device,
            max_attempts=100
        )
        
        self.assertFalse(self.engine.validate_strategy(invalid_strategy))
    
    def test_estimate_duration(self):
        """Test duration estimation"""
        duration = self.engine.estimate_duration(self.strategy)
        
        self.assertIsInstance(duration, float)
        self.assertGreater(duration, 0)
        self.assertLessEqual(duration, self.strategy.timeout_seconds)
    
    def test_estimate_duration_invalid_strategy(self):
        """Test duration estimation with invalid strategy"""
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.device,
            max_attempts=100
        )
        
        duration = self.engine.estimate_duration(invalid_strategy)
        self.assertEqual(duration, 0.0)
    
    def test_calculate_base_rate(self):
        """Test base rate calculation"""
        # Test PIN rate
        pin_device = AndroidDevice(
            serial="test", model="test", brand="test", android_version="11.0",
            lock_type=LockType.PIN, usb_debugging=True
        )
        pin_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=pin_device,
            max_attempts=100
        )
        
        rate = self.engine._calculate_base_rate(pin_strategy)
        self.assertGreater(rate, 0)
        
        # Test with root access (should be higher)
        pin_device.root_status = True
        root_rate = self.engine._calculate_base_rate(pin_strategy)
        self.assertGreater(root_rate, rate)
    
    def test_estimate_lockout_overhead(self):
        """Test lockout overhead estimation"""
        overhead = self.engine._estimate_lockout_overhead(self.strategy)
        
        self.assertIsInstance(overhead, float)
        self.assertGreaterEqual(overhead, 0)
        self.assertLessEqual(overhead, 0.5)  # Capped at 50%
    
    def test_estimate_total_patterns(self):
        """Test total patterns estimation"""
        # Add some wordlists and masks
        self.strategy.wordlists = ["wordlist1.txt", "wordlist2.txt"]
        self.strategy.mask_patterns = ["?d?d?d?d", "?d?d?d?d?d"]
        
        total = self.engine._estimate_total_patterns(self.strategy)
        
        self.assertIsInstance(total, int)
        self.assertGreater(total, 0)
        self.assertLessEqual(total, self.strategy.max_attempts)
    
    def test_estimate_mask_combinations(self):
        """Test mask combinations estimation"""
        # Test simple mask
        combinations = self.engine._estimate_mask_combinations("?d?d?d?d")
        self.assertGreater(combinations, 0)
        
        # Test complex mask
        complex_combinations = self.engine._estimate_mask_combinations("?d?d?d?d?d?d")
        self.assertGreater(complex_combinations, combinations)
    
    def test_generate_dictionary_patterns(self):
        """Test dictionary pattern generation"""
        patterns = list(self.engine._generate_dictionary_patterns(self.strategy))
        
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Check that patterns are strings
        for pattern in patterns:
            self.assertIsInstance(pattern, str)
    
    def test_generate_brute_force_patterns(self):
        """Test brute force pattern generation"""
        patterns = list(self.engine._generate_brute_force_patterns(self.strategy))
        
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Check that patterns are strings
        for pattern in patterns[:10]:  # Check first 10
            self.assertIsInstance(pattern, str)
    
    def test_callbacks(self):
        """Test callback functionality"""
        progress_callback = Mock()
        lockout_callback = Mock()
        result_callback = Mock()
        
        self.engine.set_progress_callback(progress_callback)
        self.engine.set_lockout_callback(lockout_callback)
        self.engine.set_result_callback(result_callback)
        
        # Verify callbacks are set
        self.assertEqual(self.engine._progress_callback, progress_callback)
        self.assertEqual(self.engine._lockout_callback, lockout_callback)
        self.assertEqual(self.engine._result_callback, result_callback)
    
    def test_pause_resume_stop(self):
        """Test attack control methods"""
        # Initial state
        self.assertEqual(self.engine.get_attack_status(), AttackStatus.PENDING)
        
        # Test pause (should not change from PENDING)
        self.engine.pause_attack()
        self.assertEqual(self.engine.get_attack_status(), AttackStatus.PENDING)
        
        # Simulate running state
        self.engine._attack_status = AttackStatus.RUNNING
        
        # Test pause
        self.engine.pause_attack()
        self.assertEqual(self.engine.get_attack_status(), AttackStatus.PAUSED)
        
        # Test resume
        self.engine.resume_attack()
        self.assertEqual(self.engine.get_attack_status(), AttackStatus.RUNNING)
        
        # Test stop
        self.engine.stop_attack()
        self.assertEqual(self.engine.get_attack_status(), AttackStatus.ABORTED)
    
    @patch('forensics_toolkit.attack_engines.brute_force.BruteForceEngine._test_pattern')
    def test_execute_attack_success(self, mock_test_pattern):
        """Test successful attack execution"""
        # Mock successful pattern test
        mock_test_pattern.side_effect = lambda pattern, strategy: pattern == "1234"
        
        # Use a small strategy for quick testing
        small_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.device,
            max_attempts=10,
            thread_count=1,
            timeout_seconds=5
        )
        
        result = self.engine.execute_attack(small_strategy)
        
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        self.assertIn('total_attempts', result)
        self.assertIn('duration_seconds', result)
        self.assertIn('status', result)
    
    def test_execute_attack_invalid_strategy(self):
        """Test attack execution with invalid strategy"""
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.device,
            max_attempts=100
        )
        
        with self.assertRaises(BruteForceException):
            self.engine.execute_attack(invalid_strategy)
    
    @patch('forensics_toolkit.attack_engines.brute_force.BruteForceEngine._test_pattern')
    def test_lockout_handling_wait(self, mock_test_pattern):
        """Test lockout handling with WAIT strategy"""
        # Mock pattern testing to trigger lockout
        call_count = 0
        def mock_test_side_effect(pattern, strategy):
            nonlocal call_count
            call_count += 1
            # Trigger lockout after 5 attempts
            if call_count >= 5:
                self.engine._lockout_state.trigger_lockout()
            return False
        
        mock_test_pattern.side_effect = mock_test_side_effect
        
        # Test with WAIT delay strategy
        wait_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.device,
            max_attempts=10,
            thread_count=1,
            timeout_seconds=5,
            delay_handling=DelayStrategy.WAIT
        )
        
        # This should handle lockout by waiting
        result = self.engine.execute_attack(wait_strategy)
        self.assertIsInstance(result, dict)
    
    def test_handle_lockout_abort(self):
        """Test lockout handling with ABORT strategy"""
        self.engine._initialize_attack(self.strategy)
        self.engine._lockout_state.trigger_lockout()
        
        # Test ABORT strategy
        abort_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.device,
            max_attempts=100,
            delay_handling=DelayStrategy.ABORT
        )
        
        result = self.engine._handle_lockout(abort_strategy)
        self.assertFalse(result)
        self.assertTrue(self.engine._stop_event.is_set())
    
    def test_handle_lockout_skip(self):
        """Test lockout handling with SKIP strategy"""
        self.engine._initialize_attack(self.strategy)
        self.engine._lockout_state.trigger_lockout()
        
        # Test SKIP strategy
        skip_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.device,
            max_attempts=100,
            delay_handling=DelayStrategy.SKIP
        )
        
        result = self.engine._handle_lockout(skip_strategy)
        self.assertFalse(result)  # Should skip while locked out
    
    def test_update_progress(self):
        """Test progress update"""
        self.engine._progress = AttackProgress(total_attempts=100)
        
        # Mock callback
        progress_callback = Mock()
        self.engine.set_progress_callback(progress_callback)
        
        # Update progress
        self.engine._update_progress("test_pattern", False)
        
        # Verify progress was updated
        self.assertEqual(self.engine._progress.completed_attempts, 1)
        self.assertEqual(self.engine._progress.failed_attempts, 1)
        self.assertEqual(self.engine._progress.current_pattern, "test_pattern")
        self.assertIsNotNone(self.engine._progress.last_attempt_time)
        
        # Verify callback was called
        progress_callback.assert_called_once_with(self.engine._progress)
    
    def test_cleanup_attack(self):
        """Test attack cleanup"""
        # Initialize some state
        self.engine._current_strategy = self.strategy
        self.engine._progress = AttackProgress(total_attempts=100)
        self.engine._lockout_state = LockoutState()
        
        # Cleanup
        self.engine._cleanup_attack()
        
        # Verify cleanup
        self.assertTrue(self.engine._stop_event.is_set())
        self.assertIsNone(self.engine._current_strategy)
        self.assertIsNone(self.engine._progress)
        self.assertIsNone(self.engine._lockout_state)


if __name__ == '__main__':
    unittest.main()