"""
Integration tests for Hashcat wrapper and hash cracking functionality
"""

import os
import tempfile
import unittest
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from forensics_toolkit.attack_engines.hashcat_wrapper import (
    HashcatWrapper, HashcatConfig, HashcatMode, AttackMode, 
    GPUInfo, HashcatProgress, HashcatResult, HashcatException
)
from forensics_toolkit.attack_engines.hash_cracking import HashCracking, HashTarget, HashFormat, CrackingResult
from forensics_toolkit.models.attack import AttackStrategy, AttackType
from forensics_toolkit.models.device import AndroidDevice, LockType


class TestHashcatWrapper(unittest.TestCase):
    """Test Hashcat wrapper functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_logger = Mock()
        
        # Mock Hashcat executable
        self.mock_hashcat_path = "/usr/bin/hashcat"
        
    @patch('subprocess.run')
    @patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper._find_hashcat')
    def test_hashcat_wrapper_initialization(self, mock_find_hashcat, mock_subprocess):
        """Test Hashcat wrapper initialization"""
        # Mock successful Hashcat detection
        mock_find_hashcat.return_value = self.mock_hashcat_path
        
        # Mock version check
        mock_subprocess.return_value = Mock(returncode=0, stdout="hashcat v6.2.5")
        
        # Initialize wrapper
        wrapper = HashcatWrapper(logger=self.mock_logger)
        
        self.assertEqual(wrapper.hashcat_path, self.mock_hashcat_path)
        self.assertIsInstance(wrapper.config, HashcatConfig)
        
    @patch('subprocess.run')
    def test_gpu_detection(self, mock_subprocess):
        """Test GPU device detection"""
        # Mock GPU detection output
        gpu_output = """
Device #1: NVIDIA GeForce RTX 3080
  Type: GPU
  Vendor: NVIDIA Corporation
  Name: NVIDIA GeForce RTX 3080
  Version: OpenCL 1.2 CUDA 11.4
  Global memory: 10240 MB
  
Device #2: NVIDIA GeForce RTX 3090
  Type: GPU
  Vendor: NVIDIA Corporation
  Name: NVIDIA GeForce RTX 3090
  Version: OpenCL 1.2 CUDA 11.4
  Global memory: 24576 MB
"""
        
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout="hashcat v6.2.5"),  # Version check
            Mock(returncode=0, stdout=""),  # Benchmark check
            Mock(returncode=0, stdout=gpu_output)  # GPU detection
        ]
        
        with patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper._find_hashcat') as mock_find:
            mock_find.return_value = self.mock_hashcat_path
            wrapper = HashcatWrapper(logger=self.mock_logger)
            
            gpu_info = wrapper.get_gpu_info()
            self.assertEqual(len(gpu_info), 2)
            self.assertEqual(gpu_info[0].name, "NVIDIA GeForce RTX 3080")
            self.assertEqual(gpu_info[0].memory_total, 10240)
            self.assertEqual(gpu_info[1].name, "NVIDIA GeForce RTX 3090")
            self.assertEqual(gpu_info[1].memory_total, 24576)
    
    def test_hashcat_config_creation(self):
        """Test Hashcat configuration creation"""
        config = HashcatConfig()
        
        # Test default values
        self.assertTrue(config.gpu_enabled)
        self.assertEqual(config.workload_profile, 3)
        self.assertEqual(config.attack_mode, AttackMode.STRAIGHT)
        self.assertTrue(config.optimized_kernel)
        
        # Test custom configuration
        config.gpu_enabled = False
        config.workload_profile = 2
        config.attack_mode = AttackMode.BRUTE_FORCE
        
        self.assertFalse(config.gpu_enabled)
        self.assertEqual(config.workload_profile, 2)
        self.assertEqual(config.attack_mode, AttackMode.BRUTE_FORCE)
    
    @patch('subprocess.run')
    def test_hash_format_conversion(self, mock_subprocess):
        """Test hash format conversion"""
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout="hashcat v6.2.5"),
            Mock(returncode=0, stdout=""),
            Mock(returncode=0, stdout="")
        ]
        
        with patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper._find_hashcat') as mock_find:
            mock_find.return_value = self.mock_hashcat_path
            wrapper = HashcatWrapper(logger=self.mock_logger)
            
            # Test hex to base64 conversion
            hex_hash = "5d41402abc4b2a76b9719d911017c592"
            base64_result = wrapper.convert_hash_format(hex_hash, "hex", "base64")
            self.assertIsInstance(base64_result, str)
            
            # Test same format (no conversion)
            same_result = wrapper.convert_hash_format(hex_hash, "hex", "hex")
            self.assertEqual(same_result, hex_hash)
    
    @patch('subprocess.run')
    def test_attack_parameter_optimization(self, mock_subprocess):
        """Test attack parameter optimization"""
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout="hashcat v6.2.5"),
            Mock(returncode=0, stdout=""),
            Mock(returncode=0, stdout="")
        ]
        
        with patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper._find_hashcat') as mock_find:
            mock_find.return_value = self.mock_hashcat_path
            wrapper = HashcatWrapper(logger=self.mock_logger)
            
            # Mock GPU devices
            wrapper.gpu_devices = [
                GPUInfo(device_id=0, name="RTX 3080", memory_total=10240, memory_free=8192),
                GPUInfo(device_id=1, name="RTX 3090", memory_total=24576, memory_free=20480)
            ]
            
            # Test optimization for fast hash
            params = wrapper.optimize_attack_parameters(HashcatMode.MD5, 100000)
            self.assertEqual(params['workload_profile'], 4)  # Insane for fast hash
            self.assertEqual(params['kernel_accel'], 1024)
            
            # Test optimization for slow hash
            params = wrapper.optimize_attack_parameters(HashcatMode.BCRYPT, 10000)
            self.assertEqual(params['workload_profile'], 3)  # High for slow hash
            self.assertEqual(params['kernel_accel'], 256)
    
    @patch('subprocess.Popen')
    @patch('subprocess.run')
    def test_session_management(self, mock_subprocess, mock_popen):
        """Test Hashcat session creation and management"""
        # Mock initialization
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout="hashcat v6.2.5"),
            Mock(returncode=0, stdout=""),
            Mock(returncode=0, stdout="")
        ]
        
        # Mock session process
        mock_process = Mock()
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process
        
        with patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper._find_hashcat') as mock_find:
            mock_find.return_value = self.mock_hashcat_path
            wrapper = HashcatWrapper(logger=self.mock_logger)
            
            # Create temporary files
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as hash_file:
                hash_file.write("5d41402abc4b2a76b9719d911017c592\n")
                hash_file_path = hash_file.name
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as wordlist_file:
                wordlist_file.write("password\nhello\nworld\n")
                wordlist_path = wordlist_file.name
            
            try:
                # Create session
                session_id = wrapper.create_session(
                    session_name="test_session",
                    hash_file=hash_file_path,
                    wordlist=wordlist_path,
                    hash_mode=HashcatMode.MD5
                )
                
                self.assertEqual(session_id, "test_session")
                
                # Get session status
                status = wrapper.get_session_status("test_session")
                self.assertIsInstance(status, HashcatProgress)
                
                # Stop session
                success = wrapper.stop_session("test_session")
                self.assertTrue(success)
                
            finally:
                # Clean up
                os.unlink(hash_file_path)
                os.unlink(wordlist_path)
    
    @patch('subprocess.run')
    def test_benchmark_functionality(self, mock_subprocess):
        """Test Hashcat benchmark functionality"""
        # Mock benchmark output
        benchmark_output = """
Benchmark relevant options:
* --optimized-kernel-enable

Hashmode: 0 - MD5

Speed.#1.........:  1000.0 MH/s (50.00ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1
Speed.#2.........:  1200.0 MH/s (45.00ms) @ Accel:1024 Loops:1024 Thr:64 Vec:1
Speed.#*.........:  2200.0 MH/s
"""
        
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout="hashcat v6.2.5"),  # Version
            Mock(returncode=0, stdout=""),  # Benchmark check
            Mock(returncode=0, stdout=""),  # GPU detection
            Mock(returncode=0, stdout=benchmark_output)  # Actual benchmark
        ]
        
        with patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper._find_hashcat') as mock_find:
            mock_find.return_value = self.mock_hashcat_path
            wrapper = HashcatWrapper(logger=self.mock_logger)
            
            # Run benchmark
            result = wrapper.benchmark(HashcatMode.MD5)
            
            self.assertIn('timestamp', result)
            self.assertIn('results', result)
            self.assertIsInstance(result['gpu_devices'], int)


class TestHashCrackingIntegration(unittest.TestCase):
    """Test hash cracking integration with Hashcat wrapper"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_logger = Mock()
        
        # Create test device
        self.test_device = AndroidDevice(
            serial="test_device_001",
            model="Pixel 6",
            brand="Google",
            android_version="12",
            usb_debugging=True,
            root_status=False,
            lock_type=LockType.PIN
        )
        
        # Create test strategy
        self.test_strategy = AttackStrategy(
            strategy_type=AttackType.HASH_CRACKING,
            target_device=self.test_device,
            wordlists=[],
            gpu_acceleration=True,
            timeout_seconds=300
        )
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.HashcatWrapper')
    def test_hash_cracking_initialization(self, mock_hashcat_wrapper):
        """Test hash cracking engine initialization with Hashcat wrapper"""
        # Mock successful wrapper initialization
        mock_wrapper_instance = Mock()
        mock_wrapper_instance.get_gpu_info.return_value = [
            GPUInfo(device_id=0, name="RTX 3080", memory_total=10240, memory_free=8192)
        ]
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        # Initialize hash cracking engine
        engine = HashCracking(logger=self.mock_logger)
        
        self.assertTrue(engine._hashcat_available)
        self.assertTrue(engine._gpu_available)
        self.assertIsNotNone(engine._hashcat_wrapper)
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.HashcatWrapper')
    def test_hashcat_config_creation(self, mock_hashcat_wrapper):
        """Test Hashcat configuration creation for different hash types"""
        mock_wrapper_instance = Mock()
        mock_wrapper_instance.get_gpu_info.return_value = [
            GPUInfo(device_id=0, name="RTX 3080", memory_total=10240, memory_free=8192)
        ]
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        engine = HashCracking(logger=self.mock_logger)
        
        # Test MD5 hash configuration
        md5_target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_format=HashFormat.MD5
        )
        
        config = engine._create_hashcat_config(md5_target, self.test_strategy)
        self.assertTrue(config.gpu_enabled)
        self.assertEqual(config.workload_profile, 4)  # Insane for fast hash
        self.assertEqual(config.hash_mode, HashcatMode.MD5)
        
        # Test SHA256 hash configuration
        sha256_target = HashTarget(
            hash_value="ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
            hash_format=HashFormat.SHA256
        )
        
        config = engine._create_hashcat_config(sha256_target, self.test_strategy)
        self.assertEqual(config.workload_profile, 3)  # High for medium hash
        self.assertEqual(config.hash_mode, HashcatMode.SHA256)
    
    @patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper')
    def test_hash_format_conversion(self, mock_hashcat_wrapper):
        """Test hash format conversion for Hashcat input"""
        mock_wrapper_instance = Mock()
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        engine = HashCracking(logger=self.mock_logger)
        
        # Test simple hash
        simple_target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_format=HashFormat.MD5
        )
        
        formatted = engine._format_hash_for_hashcat(simple_target)
        self.assertEqual(formatted, "5d41402abc4b2a76b9719d911017c592\n")
        
        # Test hash with salt
        salted_target = HashTarget(
            hash_value="ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
            hash_format=HashFormat.SHA256,
            salt="randomsalt"
        )
        
        formatted = engine._format_hash_for_hashcat(salted_target)
        self.assertEqual(formatted, "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:randomsalt\n")
        
        # Test hash with salt and iterations
        pbkdf2_target = HashTarget(
            hash_value="ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
            hash_format=HashFormat.SHA256,
            salt="randomsalt",
            iterations=10000
        )
        
        formatted = engine._format_hash_for_hashcat(pbkdf2_target)
        self.assertEqual(formatted, "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:randomsalt:10000\n")
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.HashcatWrapper')
    def test_performance_monitoring(self, mock_hashcat_wrapper):
        """Test performance monitoring during hash cracking"""
        mock_wrapper_instance = Mock()
        mock_wrapper_instance.get_gpu_info.return_value = [
            GPUInfo(device_id=0, name="RTX 3080", memory_total=10240, memory_free=8192, 
                   temperature=65.0, utilization=85.0)
        ]
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        engine = HashCracking(logger=self.mock_logger)
        
        # Test performance data collection
        performance_data = engine.get_performance_data()
        self.assertIsInstance(performance_data, dict)
        
        # Test GPU utilization calculation
        avg_util = engine._get_average_gpu_utilization()
        self.assertEqual(avg_util, 85.0)
        
        # Test GPU temperature calculation
        avg_temp = engine._get_average_gpu_temperature()
        self.assertEqual(avg_temp, 65.0)
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.HashcatWrapper')
    def test_benchmark_integration(self, mock_hashcat_wrapper):
        """Test GPU benchmark integration"""
        mock_wrapper_instance = Mock()
        mock_wrapper_instance.get_gpu_info.return_value = [
            GPUInfo(device_id=0, name="RTX 3080", memory_total=10240, memory_free=8192)
        ]
        
        # Mock benchmark results
        mock_benchmark_result = {
            'timestamp': datetime.now().isoformat(),
            'gpu_devices': 1,
            'results': {'hash_rate': '1000.0 MH/s'}
        }
        mock_wrapper_instance.benchmark.return_value = mock_benchmark_result
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        engine = HashCracking(logger=self.mock_logger)
        
        # Run benchmark
        result = engine.benchmark_gpu_performance()
        
        self.assertIn('timestamp', result)
        self.assertIn('gpu_devices', result)
        self.assertIn('benchmarks', result)
        self.assertEqual(result['gpu_devices'], 1)
    
    @patch('forensics_toolkit.attack_engines.hashcat_wrapper.HashcatWrapper')
    def test_wordlist_selection(self, mock_hashcat_wrapper):
        """Test wordlist selection and creation"""
        mock_wrapper_instance = Mock()
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        engine = HashCracking(logger=self.mock_logger)
        
        # Test with existing wordlist
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_wordlist:
            temp_wordlist.write("password\nhello\nworld\n")
            temp_wordlist_path = temp_wordlist.name
        
        try:
            strategy_with_wordlist = AttackStrategy(
                strategy_type=AttackType.HASH_CRACKING,
                target_device=self.test_device,
                wordlists=[temp_wordlist_path],
                gpu_acceleration=True,
                timeout_seconds=300
            )
            
            selected_wordlist = engine._select_wordlist(strategy_with_wordlist)
            self.assertEqual(selected_wordlist, temp_wordlist_path)
            
        finally:
            os.unlink(temp_wordlist_path)
        
        # Test with no wordlist (should create simple one)
        selected_wordlist = engine._select_wordlist(self.test_strategy)
        self.assertTrue(os.path.exists(selected_wordlist))
        
        # Verify simple wordlist content
        with open(selected_wordlist, 'r') as f:
            content = f.read()
            self.assertIn("password", content)
            self.assertIn("123456", content)
            self.assertIn("0000", content)  # PIN
    
    def test_hash_target_creation(self):
        """Test hash target creation and validation"""
        # Test valid hash target
        target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_format=HashFormat.MD5
        )
        
        self.assertEqual(target.hash_value, "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(target.hash_format, HashFormat.MD5)
        
        # Test hash target with auto-detection
        target_auto = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_format=HashFormat.UNKNOWN
        )
        
        self.assertEqual(target_auto.hash_format, HashFormat.MD5)  # Should auto-detect
        
        # Test Android-specific hash detection
        android_target = HashTarget(
            hash_value="ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
            hash_format=HashFormat.UNKNOWN,
            metadata={'source': 'android_pin'}
        )
        
        self.assertEqual(android_target.hash_format, HashFormat.ANDROID_PIN)
        
        # Test invalid hash target
        with self.assertRaises(Exception):
            HashTarget(hash_value="", hash_format=HashFormat.MD5)


class TestHashcatIntegrationEndToEnd(unittest.TestCase):
    """End-to-end integration tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_logger = Mock()
    
    @patch('forensics_toolkit.attack_engines.hash_cracking.HashcatWrapper')
    def test_complete_hash_cracking_workflow(self, mock_hashcat_wrapper):
        """Test complete hash cracking workflow"""
        # Mock Hashcat wrapper
        mock_wrapper_instance = Mock()
        mock_wrapper_instance.get_gpu_info.return_value = [
            GPUInfo(device_id=0, name="RTX 3080", memory_total=10240, memory_free=8192)
        ]
        
        # Mock successful cracking
        mock_hashcat_result = HashcatResult(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            plaintext="hello",
            cracked=True,
            session_name="test_session"
        )
        mock_wrapper_instance.get_session_results.return_value = [mock_hashcat_result]
        mock_wrapper_instance.create_session.return_value = "test_session"
        mock_wrapper_instance.get_session_status.return_value = None  # Session finished
        mock_wrapper_instance.configure = Mock()
        mock_wrapper_instance.optimize_attack_parameters.return_value = {'workload_profile': 3}
        
        mock_hashcat_wrapper.return_value = mock_wrapper_instance
        
        # Create test components
        device = AndroidDevice(
            serial="test_device",
            model="Pixel 6",
            brand="Google",
            android_version="12",
            usb_debugging=True,
            root_status=True,  # Enable root for hash extraction
            lock_type=LockType.PIN
        )
        
        strategy = AttackStrategy(
            strategy_type=AttackType.HASH_CRACKING,
            target_device=device,
            wordlists=[],
            gpu_acceleration=True,
            timeout_seconds=300
        )
        
        # Initialize engine
        engine = HashCracking(logger=self.mock_logger)
        
        # Test the Hashcat wrapper integration directly
        hash_target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_format=HashFormat.MD5
        )
        
        # Test _crack_with_hashcat method directly
        result = engine._crack_with_hashcat(hash_target, strategy)
        
        # Verify the result
        self.assertIsInstance(result, CrackingResult)
        self.assertEqual(result.hash_value, "5d41402abc4b2a76b9719d911017c592")
        
        # Verify Hashcat wrapper was called
        mock_wrapper_instance.configure.assert_called_once()
        mock_wrapper_instance.create_session.assert_called_once()


if __name__ == '__main__':
    unittest.main()