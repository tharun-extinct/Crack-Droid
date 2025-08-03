"""
Unit tests for hash cracking module
"""

import unittest
import tempfile
import os
import subprocess
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime, timedelta

from forensics_toolkit.attack_engines.hash_cracking import (
    HashCracking, HashTarget, CrackingProgress, CrackingResult, 
    HashFormat, CrackingEngine, HashCrackingException
)
from forensics_toolkit.interfaces import AttackType, LockType
from forensics_toolkit.models.attack import AttackStrategy
from forensics_toolkit.models.device import AndroidDevice


class TestHashTarget(unittest.TestCase):
    """Test HashTarget class"""
    
    def test_hash_target_creation(self):
        """Test basic hash target creation"""
        target = HashTarget(
            hash_value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            hash_format=HashFormat.SHA256
        )
        
        self.assertEqual(target.hash_format, HashFormat.SHA256)
        self.assertIsNone(target.salt)
        self.assertIsNone(target.iterations)
    
    def test_hash_format_detection_md5(self):
        """Test MD5 hash format detection"""
        target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",  # 32 chars
            hash_format=HashFormat.UNKNOWN
        )
        
        self.assertEqual(target.hash_format, HashFormat.MD5)
    
    def test_hash_format_detection_sha1(self):
        """Test SHA1 hash format detection"""
        target = HashTarget(
            hash_value="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # 40 chars
            hash_format=HashFormat.UNKNOWN
        )
        
        self.assertEqual(target.hash_format, HashFormat.SHA1)
    
    def test_hash_format_detection_sha256(self):
        """Test SHA256 hash format detection"""
        target = HashTarget(
            hash_value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # 64 chars
            hash_format=HashFormat.UNKNOWN
        )
        
        self.assertEqual(target.hash_format, HashFormat.SHA256)
    
    def test_hash_format_detection_android(self):
        """Test Android hash format detection"""
        target = HashTarget(
            hash_value="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # 40 chars
            hash_format=HashFormat.UNKNOWN,
            metadata={'source': 'android_pin'}
        )
        
        self.assertEqual(target.hash_format, HashFormat.ANDROID_PIN)
    
    def test_empty_hash_validation(self):
        """Test validation of empty hash"""
        with self.assertRaises(HashCrackingException):
            HashTarget(hash_value="", hash_format=HashFormat.SHA256)
    
    def test_whitespace_hash_validation(self):
        """Test validation of whitespace-only hash"""
        with self.assertRaises(HashCrackingException):
            HashTarget(hash_value="   ", hash_format=HashFormat.SHA256)


class TestCrackingProgress(unittest.TestCase):
    """Test CrackingProgress class"""
    
    def test_progress_creation(self):
        """Test basic progress creation"""
        progress = CrackingProgress(total_hashes=10)
        
        self.assertEqual(progress.total_hashes, 10)
        self.assertEqual(progress.cracked_hashes, 0)
        self.assertEqual(progress.progress_percentage, 0.0)
    
    def test_progress_percentage_calculation(self):
        """Test progress percentage calculation"""
        progress = CrackingProgress(total_hashes=10)
        progress.cracked_hashes = 3
        
        self.assertEqual(progress.progress_percentage, 30.0)
    
    def test_progress_percentage_zero_total(self):
        """Test progress percentage with zero total"""
        progress = CrackingProgress(total_hashes=0)
        
        self.assertEqual(progress.progress_percentage, 0.0)
    
    def test_elapsed_time_calculation(self):
        """Test elapsed time calculation"""
        progress = CrackingProgress(total_hashes=10)
        
        # Elapsed time should be very small for new progress
        elapsed = progress.elapsed_time
        self.assertIsInstance(elapsed, timedelta)
        self.assertLess(elapsed.total_seconds(), 1.0)
    
    def test_performance_update(self):
        """Test performance metrics update"""
        progress = CrackingProgress(total_hashes=10)
        progress.update_performance(1000.0, 85.0, 65.0)
        
        self.assertEqual(progress.hashes_per_second, 1000.0)
        self.assertEqual(progress.gpu_utilization, 85.0)
        self.assertEqual(progress.temperature, 65.0)
        self.assertIsNotNone(progress.last_update)


class TestCrackingResult(unittest.TestCase):
    """Test CrackingResult class"""
    
    def test_successful_result(self):
        """Test successful cracking result"""
        result = CrackingResult(
            hash_value="test_hash",
            plaintext="password123",
            cracked=True,
            engine_used=CrackingEngine.HASHCAT
        )
        
        self.assertTrue(result.cracked)
        self.assertEqual(result.plaintext, "password123")
        self.assertEqual(result.engine_used, CrackingEngine.HASHCAT)
    
    def test_failed_result(self):
        """Test failed cracking result"""
        result = CrackingResult(
            hash_value="test_hash",
            cracked=False,
            error_message="Timeout"
        )
        
        self.assertFalse(result.cracked)
        self.assertIsNone(result.plaintext)
        self.assertEqual(result.error_message, "Timeout")


class TestHashCracking(unittest.TestCase):
    """Test HashCracking engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.device = AndroidDevice(
            serial="test_device",
            model="Test Model",
            brand="Test Brand",
            android_version="10",
            usb_debugging=True,
            root_status=True,
            lock_type=LockType.PIN
        )
        
        self.strategy = AttackStrategy(
            strategy_type=AttackType.HASH_CRACKING,
            target_device=self.device,
            wordlists=[],
            mask_patterns=[],
            max_attempts=1000,
            gpu_acceleration=False
        )
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_initialization_with_hashcat(self, mock_run):
        """Test initialization when Hashcat is available"""
        # Mock successful Hashcat version check
        mock_run.return_value = Mock(returncode=0, stdout="hashcat v6.2.5")
        
        engine = HashCracking()
        
        self.assertIsNotNone(engine._hashcat_path)
        mock_run.assert_called()
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_initialization_without_tools(self, mock_run):
        """Test initialization when no tools are available"""
        # Mock failed tool checks
        mock_run.side_effect = FileNotFoundError()
        
        engine = HashCracking()
        
        self.assertIsNone(engine._hashcat_path)
        self.assertIsNone(engine._john_path)
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_gpu_availability_check(self, mock_run):
        """Test GPU availability detection"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_find_john', return_value='/usr/bin/john'):
            
            # Mock GPU check specifically
            mock_run.return_value = Mock(returncode=0, stdout="CUDA API (CUDA 11.0)")
            
            engine = HashCracking()
            
            self.assertTrue(engine._gpu_available)
    
    def test_strategy_validation_valid(self):
        """Test validation of valid strategy"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            engine = HashCracking()
            
            self.assertTrue(engine.validate_strategy(self.strategy))
    
    def test_strategy_validation_invalid_type(self):
        """Test validation of invalid strategy type"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            engine = HashCracking()
            
            invalid_strategy = AttackStrategy(
                strategy_type=AttackType.PATTERN_ANALYSIS,  # Invalid for hash cracking
                target_device=self.device,
                wordlists=[],
                mask_patterns=[],
                max_attempts=1000
            )
            
            self.assertFalse(engine.validate_strategy(invalid_strategy))
    
    def test_strategy_validation_no_tools(self):
        """Test validation when no cracking tools available"""
        with patch.object(HashCracking, '_find_hashcat', return_value=None), \
             patch.object(HashCracking, '_find_john', return_value=None):
            engine = HashCracking()
            
            self.assertFalse(engine.validate_strategy(self.strategy))
    
    def test_duration_estimation_gpu(self):
        """Test duration estimation with GPU acceleration"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=True):
            engine = HashCracking()
            
            gpu_strategy = AttackStrategy(
                strategy_type=AttackType.HASH_CRACKING,
                target_device=self.device,
                wordlists=[],
                mask_patterns=[],
                max_attempts=1000,
                gpu_acceleration=True
            )
            
            duration = engine.estimate_duration(gpu_strategy)
            self.assertGreater(duration, 0)
            self.assertLess(duration, 60)  # Should be fast with GPU
    
    def test_duration_estimation_cpu(self):
        """Test duration estimation with CPU only"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            engine = HashCracking()
            
            duration = engine.estimate_duration(self.strategy)
            self.assertGreater(duration, 0)
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_hash_format_detection(self, mock_run):
        """Test hash format detection"""
        mock_run.return_value = Mock(returncode=0, stdout="hashcat v6.2.5")
        
        engine = HashCracking()
        
        # Test MD5
        md5_format = engine.detect_hash_format("5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(md5_format, HashFormat.MD5)
        
        # Test SHA256
        sha256_format = engine.detect_hash_format("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
        self.assertEqual(sha256_format, HashFormat.SHA256)
    
    def test_hashcat_mode_mapping(self):
        """Test Hashcat mode number mapping"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            engine = HashCracking()
            
            self.assertEqual(engine._get_hashcat_mode(HashFormat.MD5), 0)
            self.assertEqual(engine._get_hashcat_mode(HashFormat.SHA1), 100)
            self.assertEqual(engine._get_hashcat_mode(HashFormat.SHA256), 1400)
            self.assertEqual(engine._get_hashcat_mode(HashFormat.ANDROID_PIN), 5800)
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.tempfile.mkstemp')
    def test_temp_file_creation(self, mock_mkstemp):
        """Test temporary file creation"""
        mock_fd = 3
        mock_path = '/tmp/test_file'
        mock_mkstemp.return_value = (mock_fd, mock_path)
        
        with patch('os.fdopen') as mock_fdopen, \
             patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            
            mock_file = Mock()
            mock_fdopen.return_value.__enter__.return_value = mock_file
            
            engine = HashCracking()
            result_path = engine._create_temp_file("test content")
            
            self.assertEqual(result_path, mock_path)
            self.assertIn(mock_path, engine._temp_files)
            mock_file.write.assert_called_once_with("test content")
    
    def test_simple_wordlist_creation(self):
        """Test simple wordlist creation"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_create_temp_file') as mock_create_temp:
            
            mock_create_temp.return_value = '/tmp/wordlist'
            
            engine = HashCracking()
            wordlist_path = engine._create_simple_wordlist()
            
            self.assertEqual(wordlist_path, '/tmp/wordlist')
            mock_create_temp.assert_called_once()
            
            # Check that the content includes common passwords and PINs
            call_args = mock_create_temp.call_args[0][0]
            self.assertIn('password', call_args)
            self.assertIn('123456', call_args)
            self.assertIn('0000', call_args)  # PIN
            self.assertIn('9999', call_args)  # PIN
    
    def test_engine_preference_gpu(self):
        """Test engine preference with GPU acceleration"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_find_john', return_value='/usr/bin/john'), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=True):
            
            engine = HashCracking()
            
            gpu_strategy = AttackStrategy(
                strategy_type=AttackType.HASH_CRACKING,
                target_device=self.device,
                wordlists=[],
                mask_patterns=[],
                max_attempts=1000,
                gpu_acceleration=True
            )
            
            engines = engine._get_engine_preference(gpu_strategy)
            
            # Should prefer Hashcat first (GPU), then John
            self.assertEqual(engines[0], CrackingEngine.HASHCAT)
            self.assertIn(CrackingEngine.JOHN, engines)
    
    def test_engine_preference_cpu_only(self):
        """Test engine preference without GPU"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_find_john', return_value='/usr/bin/john'), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=False):
            
            engine = HashCracking()
            
            engines = engine._get_engine_preference(self.strategy)
            
            # Should have Hashcat (CPU) and John
            self.assertIn(CrackingEngine.HASHCAT, engines)
            self.assertIn(CrackingEngine.JOHN, engines)
    
    def test_hashcat_execution_success(self):
        """Test successful Hashcat execution"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_find_john', return_value=None), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=False), \
             patch.object(HashCracking, '_create_temp_file') as mock_create_temp, \
             patch.object(HashCracking, '_create_simple_wordlist', return_value='/tmp/wordlist'), \
             patch.object(HashCracking, '_monitor_hashcat_progress', return_value='cracked_password') as mock_monitor, \
             patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.Popen') as mock_popen:
            
            # Mock file creation
            mock_create_temp.side_effect = ['/tmp/hash', '/tmp/output']
            
            # Mock process
            mock_process = Mock()
            mock_popen.return_value = mock_process
            
            engine = HashCracking()
            
            hash_target = HashTarget(
                hash_value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                hash_format=HashFormat.SHA256
            )
            
            result = engine._crack_with_hashcat(hash_target, self.strategy)
            
            self.assertTrue(result.cracked)
            self.assertEqual(result.plaintext, 'cracked_password')
            mock_monitor.assert_called_once()
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_john_execution_success(self, mock_run):
        """Test successful John the Ripper execution"""
        with patch.object(HashCracking, '_find_john', return_value='/usr/bin/john'), \
             patch.object(HashCracking, '_find_hashcat', return_value=None), \
             patch.object(HashCracking, '_create_temp_file') as mock_create_temp:
            
            mock_create_temp.return_value = '/tmp/hash'
            
            # Mock successful John execution
            mock_run.side_effect = [
                Mock(returncode=0, stdout="", stderr=""),  # Main john run
                Mock(returncode=0, stdout="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:cracked_password\n", stderr="")  # Show results
            ]
            
            engine = HashCracking()
            
            hash_target = HashTarget(
                hash_value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                hash_format=HashFormat.SHA256
            )
            
            result = engine._crack_with_john(hash_target, self.strategy)
            
            self.assertTrue(result.cracked)
            self.assertEqual(result.plaintext, 'cracked_password')
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_john_execution_timeout(self, mock_run):
        """Test John the Ripper timeout"""
        with patch.object(HashCracking, '_find_john', return_value='/usr/bin/john'), \
             patch.object(HashCracking, '_create_temp_file') as mock_create_temp:
            
            mock_create_temp.return_value = '/tmp/hash'
            
            # Mock timeout
            mock_run.side_effect = subprocess.TimeoutExpired('john', 300)
            
            engine = HashCracking()
            
            hash_target = HashTarget(
                hash_value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                hash_format=HashFormat.SHA256
            )
            
            result = engine._crack_with_john(hash_target, self.strategy)
            
            self.assertFalse(result.cracked)
            self.assertIn("timeout", result.error_message.lower())
    
    def test_callbacks(self):
        """Test progress and result callbacks"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            engine = HashCracking()
            
            progress_callback = Mock()
            result_callback = Mock()
            
            engine.set_progress_callback(progress_callback)
            engine.set_result_callback(result_callback)
            
            # Test progress callback
            progress = CrackingProgress(total_hashes=1)
            engine._progress = progress
            engine._update_progress()
            
            progress_callback.assert_called_once_with(progress)
            
            # Test result callback
            result = CrackingResult(hash_value="test", cracked=True)
            if engine._result_callback:
                engine._result_callback(result)
            
            result_callback.assert_called_once_with(result)
    
    def test_cleanup(self):
        """Test resource cleanup"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch('os.path.exists', return_value=True), \
             patch('os.unlink') as mock_unlink:
            
            engine = HashCracking()
            
            # Add some temp files
            engine._temp_files = ['/tmp/file1', '/tmp/file2']
            
            engine._cleanup_attack()
            
            # Check that temp files were cleaned up
            self.assertEqual(len(engine._temp_files), 0)
            self.assertEqual(mock_unlink.call_count, 2)
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.subprocess.run')
    def test_benchmark_performance(self, mock_run):
        """Test performance benchmarking"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_find_john', return_value=None), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=False):
            
            # Mock successful benchmark
            mock_run.return_value = Mock(returncode=0, stdout="Benchmark output")
            
            engine = HashCracking()
            
            result = engine.benchmark_performance(HashFormat.SHA256, 5)
            
            self.assertIn('hashes_per_second', result)
            # Should be called at least once for the benchmark
            self.assertGreater(mock_run.call_count, 0)
    
    def test_supported_formats(self):
        """Test getting supported hash formats"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'):
            engine = HashCracking()
            
            formats = engine.get_supported_formats()
            
            self.assertIn(HashFormat.MD5, formats)
            self.assertIn(HashFormat.SHA256, formats)
            self.assertIn(HashFormat.ANDROID_PIN, formats)
    
    def test_gpu_configuration(self):
        """Test GPU acceleration configuration"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=True):
            
            engine = HashCracking()
            
            # Test enabling GPU
            result = engine.configure_gpu_acceleration(True, [0, 1])
            self.assertTrue(result)
            
            # Test disabling GPU
            result = engine.configure_gpu_acceleration(False)
            self.assertTrue(result)
    
    def test_gpu_configuration_unavailable(self):
        """Test GPU configuration when GPU unavailable"""
        with patch.object(HashCracking, '_find_hashcat', return_value='/usr/bin/hashcat'), \
             patch.object(HashCracking, '_check_gpu_availability', return_value=False):
            
            engine = HashCracking()
            
            # Should fail when GPU requested but not available
            result = engine.configure_gpu_acceleration(True)
            self.assertFalse(result)


def mock_open(read_data=''):
    """Helper function to create mock open context manager"""
    from unittest.mock import MagicMock
    mock_file = MagicMock()
    mock_file.read.return_value = read_data
    mock_file.__enter__.return_value = mock_file
    mock_file.__exit__.return_value = None
    return lambda *args, **kwargs: mock_file


if __name__ == '__main__':
    unittest.main()