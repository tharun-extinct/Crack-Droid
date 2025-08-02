"""
Unit tests for dictionary attack module
"""

import unittest
import tempfile
import os
import hashlib
from datetime import datetime
from unittest.mock import Mock, patch, mock_open

from forensics_toolkit.attack_engines.dictionary_attack import (
    DictionaryAttack, WordlistInfo, DictionaryStats, DictionaryAttackException
)
from forensics_toolkit.models.attack import AttackStrategy
from forensics_toolkit.models.device import AndroidDevice
from forensics_toolkit.interfaces import AttackType, LockType


class TestWordlistInfo(unittest.TestCase):
    """Test WordlistInfo class"""
    
    def test_wordlist_info_initialization(self):
        """Test wordlist info initialization"""
        info = WordlistInfo(path="/nonexistent/path", name="test_wordlist")
        
        self.assertEqual(info.path, "/nonexistent/path")
        self.assertEqual(info.name, "test_wordlist")
        self.assertEqual(info.size, 0)
        self.assertEqual(info.entry_count, 0)
        self.assertIsNone(info.hash_md5)
        self.assertIsNone(info.last_modified)
        self.assertEqual(info.priority, 0)
    
    @patch('os.path.exists')
    @patch('os.stat')
    @patch('builtins.open', new_callable=mock_open, read_data="line1\nline2\nline3\n")
    @patch('hashlib.md5')
    def test_wordlist_info_with_file(self, mock_md5, mock_file, mock_stat, mock_exists):
        """Test wordlist info with existing file"""
        mock_exists.return_value = True
        mock_stat.return_value.st_size = 100
        mock_stat.return_value.st_mtime = 1640995200  # 2022-01-01
        mock_md5.return_value.hexdigest.return_value = "test_hash"
        
        info = WordlistInfo(path="/test/wordlist.txt", name="test")
        
        self.assertEqual(info.size, 100)
        self.assertEqual(info.entry_count, 3)
        self.assertIsNotNone(info.hash_md5)
        self.assertIsNotNone(info.last_modified)


class TestDictionaryStats(unittest.TestCase):
    """Test DictionaryStats class"""
    
    def test_stats_initialization(self):
        """Test stats initialization"""
        stats = DictionaryStats()
        
        self.assertEqual(stats.total_wordlists, 0)
        self.assertEqual(stats.processed_wordlists, 0)
        self.assertEqual(stats.total_patterns, 0)
        self.assertEqual(stats.tested_patterns, 0)
        self.assertEqual(stats.successful_patterns, 0)
        self.assertEqual(stats.duplicate_patterns, 0)
        self.assertEqual(stats.invalid_patterns, 0)
        self.assertIsInstance(stats.start_time, datetime)
        self.assertIsNone(stats.current_wordlist)
        self.assertIsNone(stats.current_pattern)
    
    def test_progress_percentage(self):
        """Test progress percentage calculation"""
        stats = DictionaryStats(total_patterns=100)
        
        # Initial progress
        self.assertEqual(stats.progress_percentage, 0.0)
        
        # Partial progress
        stats.tested_patterns = 25
        self.assertEqual(stats.progress_percentage, 25.0)
        
        # Complete progress
        stats.tested_patterns = 100
        self.assertEqual(stats.progress_percentage, 100.0)
        
        # Zero total patterns
        stats.total_patterns = 0
        self.assertEqual(stats.progress_percentage, 0.0)
    
    def test_patterns_per_second(self):
        """Test patterns per second calculation"""
        stats = DictionaryStats()
        
        # Initial rate (should be 0)
        self.assertEqual(stats.patterns_per_second, 0.0)
        
        # Mock elapsed time and tested patterns
        import time
        time.sleep(0.01)  # Small delay
        stats.tested_patterns = 10
        
        rate = stats.patterns_per_second
        self.assertGreater(rate, 0)


class TestDictionaryAttack(unittest.TestCase):
    """Test DictionaryAttack class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.attack = DictionaryAttack()
        
        # Create test device
        self.device = AndroidDevice(
            serial="test_device_001",
            model="Test Model",
            brand="Test Brand",
            android_version="11.0",
            usb_debugging=True,
            lock_type=LockType.PIN
        )
        
        # Create test strategy
        self.strategy = AttackStrategy(
            strategy_type=AttackType.DICTIONARY,
            target_device=self.device,
            max_attempts=100,
            timeout_seconds=60
        )
    
    def test_attack_initialization(self):
        """Test attack initialization"""
        attack = DictionaryAttack()
        
        self.assertIsNotNone(attack.logger)
        self.assertEqual(len(attack._wordlists), 0)
        self.assertEqual(len(attack._pattern_cache), 0)
        self.assertIsNone(attack._stats)
        self.assertFalse(attack._stop_event.is_set())
        
        # Check built-in patterns are loaded
        self.assertGreater(len(attack._common_pins), 0)
        self.assertGreater(len(attack._common_patterns), 0)
        self.assertGreater(len(attack._common_passwords), 0)
    
    def test_load_common_pins(self):
        """Test common PIN loading"""
        pins = self.attack._load_common_pins()
        
        self.assertIsInstance(pins, list)
        self.assertGreater(len(pins), 0)
        
        # Check for expected common PINs
        self.assertIn("1234", pins)
        self.assertIn("0000", pins)
        self.assertIn("1111", pins)
        
        # All should be strings
        for pin in pins:
            self.assertIsInstance(pin, str)
    
    def test_load_common_patterns(self):
        """Test common pattern loading"""
        patterns = self.attack._load_common_patterns()
        
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Check for expected patterns
        self.assertIn("123", patterns)
        self.assertIn("147", patterns)
        
        # All should be strings
        for pattern in patterns:
            self.assertIsInstance(pattern, str)
    
    def test_load_common_passwords(self):
        """Test common password loading"""
        passwords = self.attack._load_common_passwords()
        
        self.assertIsInstance(passwords, list)
        self.assertGreater(len(passwords), 0)
        
        # Check for expected passwords
        self.assertIn("password", passwords)
        self.assertIn("123456", passwords)
        
        # All should be strings
        for password in passwords:
            self.assertIsInstance(password, str)
    
    def test_add_wordlist_nonexistent(self):
        """Test adding non-existent wordlist"""
        result = self.attack.add_wordlist("/nonexistent/wordlist.txt")
        self.assertFalse(result)
        self.assertEqual(len(self.attack._wordlists), 0)
    
    def test_add_wordlist_success(self):
        """Test adding wordlist successfully"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test1\ntest2\ntest3\n")
            temp_path = f.name
        
        try:
            result = self.attack.add_wordlist(temp_path, "test_wordlist", priority=5)
            
            self.assertTrue(result)
            self.assertEqual(len(self.attack._wordlists), 1)
            self.assertIn(temp_path, self.attack._wordlists)
            
            wordlist_info = self.attack._wordlists[temp_path]
            self.assertEqual(wordlist_info.name, "test_wordlist")
            self.assertEqual(wordlist_info.priority, 5)
            self.assertEqual(wordlist_info.entry_count, 3)
            
        finally:
            os.unlink(temp_path)
    
    def test_remove_wordlist(self):
        """Test removing wordlist"""
        # Add a wordlist first
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test1\ntest2\n")
            temp_path = f.name
        
        try:
            self.attack.add_wordlist(temp_path)
            self.assertEqual(len(self.attack._wordlists), 1)
            
            # Remove it
            result = self.attack.remove_wordlist(temp_path)
            self.assertTrue(result)
            self.assertEqual(len(self.attack._wordlists), 0)
            
            # Try to remove non-existent
            result = self.attack.remove_wordlist("/nonexistent/path")
            self.assertFalse(result)
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_get_wordlist_info(self):
        """Test getting wordlist information"""
        # Initially empty
        info_list = self.attack.get_wordlist_info()
        self.assertEqual(len(info_list), 0)
        
        # Add wordlists
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test1\ntest2\n")
            temp_path = f.name
        
        try:
            self.attack.add_wordlist(temp_path, "test")
            info_list = self.attack.get_wordlist_info()
            
            self.assertEqual(len(info_list), 1)
            self.assertIsInstance(info_list[0], WordlistInfo)
            self.assertEqual(info_list[0].name, "test")
            
        finally:
            os.unlink(temp_path)
    
    def test_validate_strategy_valid(self):
        """Test strategy validation with valid strategy"""
        self.assertTrue(self.attack.validate_strategy(self.strategy))
    
    def test_validate_strategy_invalid_type(self):
        """Test strategy validation with invalid type"""
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,  # Not supported
            target_device=self.device,
            max_attempts=100
        )
        
        self.assertFalse(self.attack.validate_strategy(invalid_strategy))
    
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
            strategy_type=AttackType.DICTIONARY,
            target_device=incompatible_device,
            max_attempts=100
        )
        
        self.assertFalse(self.attack.validate_strategy(invalid_strategy))
    
    def test_estimate_duration(self):
        """Test duration estimation"""
        duration = self.attack.estimate_duration(self.strategy)
        
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
        
        duration = self.attack.estimate_duration(invalid_strategy)
        self.assertEqual(duration, 0.0)
    
    def test_estimate_total_patterns(self):
        """Test total patterns estimation"""
        total = self.attack._estimate_total_patterns(self.strategy)
        
        self.assertIsInstance(total, int)
        self.assertGreater(total, 0)
        self.assertLessEqual(total, self.strategy.max_attempts)
    
    def test_estimate_mask_combinations(self):
        """Test mask combinations estimation"""
        # Test simple mask
        combinations = self.attack._estimate_mask_combinations("?d?d?d?d")
        self.assertGreater(combinations, 0)
        
        # Test complex mask
        complex_combinations = self.attack._estimate_mask_combinations("?d?d?d?d?d?d")
        self.assertGreater(complex_combinations, combinations)
        
        # Test literal pattern
        literal_combinations = self.attack._estimate_mask_combinations("1234")
        self.assertEqual(literal_combinations, 1)
    
    def test_calculate_base_rate(self):
        """Test base rate calculation"""
        rate = self.attack._calculate_base_rate(self.strategy)
        
        self.assertIsInstance(rate, float)
        self.assertGreater(rate, 0)
        
        # Test with different lock types
        password_device = AndroidDevice(
            serial="test", model="test", brand="test", android_version="11.0",
            lock_type=LockType.PASSWORD, usb_debugging=True
        )
        password_strategy = AttackStrategy(
            strategy_type=AttackType.DICTIONARY,
            target_device=password_device,
            max_attempts=100
        )
        
        password_rate = self.attack._calculate_base_rate(password_strategy)
        self.assertGreater(password_rate, 0)
    
    def test_prioritize_patterns(self):
        """Test pattern prioritization"""
        patterns = ["9999", "1234", "0000", "abcd", "2023", "1111"]
        prioritized = self.attack._prioritize_patterns(patterns, self.device)
        
        self.assertEqual(len(prioritized), len(patterns))
        self.assertIsInstance(prioritized, list)
        
        # Common patterns should be prioritized
        self.assertIn("1234", prioritized[:3])  # Should be in top 3
    
    def test_is_sequential(self):
        """Test sequential pattern detection"""
        self.assertTrue(self.attack._is_sequential("123"))
        self.assertTrue(self.attack._is_sequential("321"))
        self.assertTrue(self.attack._is_sequential("abcd"))
        self.assertTrue(self.attack._is_sequential("dcba"))
        
        self.assertFalse(self.attack._is_sequential("135"))
        self.assertFalse(self.attack._is_sequential("12"))  # Too short
        self.assertFalse(self.attack._is_sequential("1324"))
    
    def test_is_repeated(self):
        """Test repeated pattern detection"""
        self.assertTrue(self.attack._is_repeated("1111"))
        self.assertTrue(self.attack._is_repeated("aaaa"))
        self.assertTrue(self.attack._is_repeated("00"))
        
        self.assertFalse(self.attack._is_repeated("1234"))
        self.assertFalse(self.attack._is_repeated("1"))  # Too short
        self.assertFalse(self.attack._is_repeated("1122"))
    
    def test_is_date_like(self):
        """Test date-like pattern detection"""
        self.assertTrue(self.attack._is_date_like("2023"))
        self.assertTrue(self.attack._is_date_like("1990"))
        self.assertTrue(self.attack._is_date_like("2000"))
        
        self.assertFalse(self.attack._is_date_like("123"))  # Wrong length
        self.assertFalse(self.attack._is_date_like("12345"))  # Wrong length
        self.assertFalse(self.attack._is_date_like("1800"))  # Too old
        self.assertFalse(self.attack._is_date_like("2050"))  # Too future
        self.assertFalse(self.attack._is_date_like("abcd"))  # Not numeric
    
    def test_generate_builtin_patterns(self):
        """Test built-in pattern generation"""
        patterns = list(self.attack._generate_builtin_patterns(self.strategy))
        
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Should contain common PINs for PIN lock type
        self.assertIn("1234", patterns)
        self.assertIn("0000", patterns)
    
    def test_read_wordlist(self):
        """Test wordlist reading"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("pattern1\npattern2\n# comment\npattern3\n\n")
            temp_path = f.name
        
        try:
            patterns = list(self.attack._read_wordlist(temp_path))
            
            self.assertEqual(len(patterns), 3)  # Comments and empty lines excluded
            self.assertIn("pattern1", patterns)
            self.assertIn("pattern2", patterns)
            self.assertIn("pattern3", patterns)
            self.assertNotIn("# comment", patterns)
            
        finally:
            os.unlink(temp_path)
    
    def test_expand_mask(self):
        """Test mask expansion"""
        patterns = list(self.attack._expand_mask("?d?d"))
        
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Should generate digit combinations
        for pattern in patterns[:10]:  # Check first 10
            self.assertIsInstance(pattern, str)
    
    @patch('forensics_toolkit.attack_engines.dictionary_attack.DictionaryAttack._test_pattern')
    def test_execute_attack_success(self, mock_test_pattern):
        """Test successful attack execution"""
        # Mock successful pattern test
        mock_test_pattern.side_effect = lambda pattern, strategy: pattern == "1234"
        
        result = self.attack.execute_attack(self.strategy)
        
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        self.assertIn('successful_pattern', result)
        self.assertIn('total_attempts', result)
        self.assertIn('duration_seconds', result)
        self.assertIn('attack_type', result)
        self.assertEqual(result['attack_type'], 'dictionary')
    
    def test_execute_attack_invalid_strategy(self):
        """Test attack execution with invalid strategy"""
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.device,
            max_attempts=100
        )
        
        with self.assertRaises(DictionaryAttackException):
            self.attack.execute_attack(invalid_strategy)
    
    def test_stop_attack(self):
        """Test attack stopping"""
        self.assertFalse(self.attack._stop_event.is_set())
        
        self.attack.stop_attack()
        
        self.assertTrue(self.attack._stop_event.is_set())
    
    def test_get_attack_stats(self):
        """Test getting attack statistics"""
        # Initially None
        self.assertIsNone(self.attack.get_attack_stats())
        
        # After initialization
        self.attack._initialize_attack(self.strategy)
        stats = self.attack.get_attack_stats()
        
        self.assertIsNotNone(stats)
        self.assertIsInstance(stats, DictionaryStats)
    
    def test_create_custom_wordlist(self):
        """Test custom wordlist creation"""
        patterns = ["custom1", "custom2", "custom3"]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            result = self.attack.create_custom_wordlist(patterns, temp_path, "custom_test")
            
            self.assertTrue(result)
            self.assertTrue(os.path.exists(temp_path))
            self.assertIn(temp_path, self.attack._wordlists)
            
            # Verify file contents
            with open(temp_path, 'r') as f:
                content = f.read()
                for pattern in patterns:
                    self.assertIn(pattern, content)
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_merge_wordlists(self):
        """Test wordlist merging"""
        # Create test wordlists
        wordlist1_content = "pattern1\npattern2\npattern3\n"
        wordlist2_content = "pattern2\npattern4\npattern5\n"  # pattern2 is duplicate
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f1:
            f1.write(wordlist1_content)
            temp_path1 = f1.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f2:
            f2.write(wordlist2_content)
            temp_path2 = f2.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f3:
            output_path = f3.name
        
        try:
            # Test merge with duplicate removal
            result = self.attack.merge_wordlists([temp_path1, temp_path2], output_path, remove_duplicates=True)
            
            self.assertTrue(result)
            self.assertTrue(os.path.exists(output_path))
            
            # Verify merged content
            with open(output_path, 'r') as f:
                content = f.read()
                self.assertIn("pattern1", content)
                self.assertIn("pattern2", content)
                self.assertIn("pattern3", content)
                self.assertIn("pattern4", content)
                self.assertIn("pattern5", content)
            
        finally:
            for path in [temp_path1, temp_path2, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def test_advanced_mask_expansion(self):
        """Test advanced mask expansion with multiple character types"""
        # Test digit mask
        patterns = list(self.attack._expand_mask("?d?d"))
        self.assertGreater(len(patterns), 0)
        self.assertTrue(all(p.isdigit() and len(p) == 2 for p in patterns[:10]))
        
        # Test mixed mask
        patterns = list(self.attack._expand_mask("test?d"))
        self.assertGreater(len(patterns), 0)
        self.assertTrue(all(p.startswith("test") and p[4].isdigit() for p in patterns[:10]))
        
        # Test literal pattern (no masks)
        patterns = list(self.attack._expand_mask("literal"))
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0], "literal")
    
    def test_advanced_prioritization(self):
        """Test advanced heuristic prioritization"""
        patterns = ["9999", "1234", "0000", "password", "2023", "qwerty", "admin123"]
        
        # Create device with specific characteristics
        device = AndroidDevice(
            serial="test", model="Galaxy S23", brand="Samsung", android_version="13.0",
            lock_type=LockType.PASSWORD, usb_debugging=True
        )
        
        prioritized = self.attack._prioritize_patterns(patterns, device)
        
        self.assertEqual(len(prioritized), len(patterns))
        
        # Ultra-common patterns should be at the top
        top_patterns = prioritized[:3]
        self.assertIn("1234", top_patterns)
        self.assertIn("0000", top_patterns)
        self.assertIn("password", top_patterns)
    
    def test_brand_specific_patterns(self):
        """Test brand-specific pattern recognition"""
        samsung_patterns = self.attack._get_brand_specific_patterns("samsung")
        self.assertIsInstance(samsung_patterns, list)
        self.assertIn("2580", samsung_patterns)  # Common Samsung pattern
        
        # Test unknown brand
        unknown_patterns = self.attack._get_brand_specific_patterns("unknownbrand")
        self.assertEqual(unknown_patterns, [])
    
    def test_pattern_scoring_methods(self):
        """Test individual pattern scoring methods"""
        # Test PIN scoring
        pin_score = self.attack._score_pin_pattern("1234")
        self.assertGreater(pin_score, 0)
        
        non_pin_score = self.attack._score_pin_pattern("abcd")
        self.assertEqual(non_pin_score, 0)
        
        # Test password scoring
        password_score = self.attack._score_password_pattern("password")
        self.assertGreater(password_score, 0)
        
        # Test gesture scoring
        gesture_score = self.attack._score_gesture_pattern("123")
        self.assertGreater(gesture_score, 0)
    
    def test_pattern_detection_methods(self):
        """Test pattern detection helper methods"""
        # Test keyboard pattern detection
        self.assertTrue(self.attack._is_keyboard_pattern("qwerty"))
        self.assertFalse(self.attack._is_keyboard_pattern("random"))
        
        # Test phone keypad pattern detection
        self.assertTrue(self.attack._is_phone_keypad_pattern("2580"))
        self.assertFalse(self.attack._is_phone_keypad_pattern("1111"))
        
        # Test complexity calculation
        simple_complexity = self.attack._calculate_pattern_complexity("1234")
        complex_complexity = self.attack._calculate_pattern_complexity("Tr0ub4dor&3")
        self.assertGreater(complex_complexity, simple_complexity)
    
    def test_hybrid_pattern_generation(self):
        """Test hybrid pattern generation"""
        # Create hybrid strategy
        hybrid_strategy = AttackStrategy(
            strategy_type=AttackType.HYBRID,
            target_device=self.device,
            mask_patterns=["?d?d", "?l?l"],
            max_attempts=1000
        )
        
        patterns = list(self.attack._generate_hybrid_patterns(hybrid_strategy))
        
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Should contain transformed patterns
        pattern_strings = [str(p) for p in patterns]
        # Check for some expected transformations
        has_transformations = any("123" in p for p in pattern_strings)
        self.assertTrue(has_transformations)
    
    def test_year_extraction(self):
        """Test year extraction from model names"""
        year = self.attack._extract_year_from_model("Galaxy S23 2023")
        self.assertEqual(year, 2023)
        
        year = self.attack._extract_year_from_model("iPhone 14")
        self.assertIsNone(year)
        
        year = self.attack._extract_year_from_model("Pixel 7 Pro 2022")
        self.assertEqual(year, 2022)


if __name__ == '__main__':
    unittest.main()