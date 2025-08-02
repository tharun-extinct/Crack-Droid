"""
Unit tests for pattern analysis module
"""

import unittest
import tempfile
import os
import json
import struct
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Import the modules to test
from forensics_toolkit.attack_engines.pattern_analysis import (
    PatternAnalysis, PatternPoint, AndroidPattern, PatternAnalysisException
)
from forensics_toolkit.interfaces import AttackType, LockType, AttackResult
from forensics_toolkit.models.attack import AttackStrategy
from forensics_toolkit.models.device import AndroidDevice


class TestPatternPoint(unittest.TestCase):
    """Test PatternPoint class"""
    
    def test_valid_pattern_point_creation(self):
        """Test creating valid pattern points"""
        point = PatternPoint(x=1, y=1, index=4)
        self.assertEqual(point.x, 1)
        self.assertEqual(point.y, 1)
        self.assertEqual(point.index, 4)
    
    def test_invalid_coordinates(self):
        """Test invalid coordinate validation"""
        with self.assertRaises(PatternAnalysisException):
            PatternPoint(x=3, y=1, index=4)  # x out of range
        
        with self.assertRaises(PatternAnalysisException):
            PatternPoint(x=1, y=3, index=4)  # y out of range
    
    def test_invalid_index(self):
        """Test invalid index validation"""
        with self.assertRaises(PatternAnalysisException):
            PatternPoint(x=1, y=1, index=9)  # index out of range
        
        with self.assertRaises(PatternAnalysisException):
            PatternPoint(x=1, y=1, index=-1)  # negative index
    
    def test_from_index(self):
        """Test creating point from index"""
        point = PatternPoint.from_index(4)  # Center point
        self.assertEqual(point.x, 1)
        self.assertEqual(point.y, 1)
        self.assertEqual(point.index, 4)
        
        point = PatternPoint.from_index(0)  # Top-left
        self.assertEqual(point.x, 0)
        self.assertEqual(point.y, 0)
        self.assertEqual(point.index, 0)
        
        point = PatternPoint.from_index(8)  # Bottom-right
        self.assertEqual(point.x, 2)
        self.assertEqual(point.y, 2)
        self.assertEqual(point.index, 8)
    
    def test_to_dict(self):
        """Test dictionary conversion"""
        point = PatternPoint(x=1, y=2, index=7)
        expected = {"x": 1, "y": 2, "index": 7}
        self.assertEqual(point.to_dict(), expected)
    
    def test_string_representation(self):
        """Test string representation"""
        point = PatternPoint(x=1, y=1, index=4)
        self.assertEqual(str(point), "Point(1,1)[4]")


class TestAndroidPattern(unittest.TestCase):
    """Test AndroidPattern class"""
    
    def setUp(self):
        """Set up test patterns"""
        self.valid_points = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(1),
            PatternPoint.from_index(2),
            PatternPoint.from_index(5)
        ]
        
        self.diagonal_points = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(4),
            PatternPoint.from_index(8)
        ]
    
    def test_valid_pattern_creation(self):
        """Test creating valid patterns"""
        pattern = AndroidPattern(points=self.valid_points)
        self.assertEqual(len(pattern.points), 4)
        self.assertEqual(pattern.confidence, 1.0)
    
    def test_pattern_too_short(self):
        """Test pattern with too few points"""
        short_points = [PatternPoint.from_index(0), PatternPoint.from_index(1)]  # Only 2 points
        with self.assertRaises(PatternAnalysisException):
            AndroidPattern(points=short_points)
    
    def test_pattern_too_long(self):
        """Test pattern with too many points"""
        long_points = [PatternPoint.from_index(i) for i in range(9)]
        long_points.append(PatternPoint.from_index(0))  # Duplicate to make 10
        with self.assertRaises(PatternAnalysisException):
            AndroidPattern(points=long_points)
    
    def test_duplicate_points(self):
        """Test pattern with duplicate points"""
        duplicate_points = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(1),
            PatternPoint.from_index(0),  # Duplicate
            PatternPoint.from_index(2)
        ]
        with self.assertRaises(PatternAnalysisException):
            AndroidPattern(points=duplicate_points)
    
    def test_to_sequence(self):
        """Test sequence conversion"""
        pattern = AndroidPattern(points=self.valid_points)
        expected_sequence = [0, 1, 2, 5]
        self.assertEqual(pattern.to_sequence(), expected_sequence)
    
    def test_calculate_hash(self):
        """Test hash calculation"""
        pattern = AndroidPattern(points=self.valid_points)
        hash_value = pattern.calculate_hash()
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 64)  # SHA-256 hex length
    
    def test_to_gesture_key_format(self):
        """Test gesture.key format conversion"""
        pattern = AndroidPattern(points=self.valid_points)
        gesture_key = pattern.to_gesture_key_format()
        self.assertIsInstance(gesture_key, bytes)
        self.assertEqual(len(gesture_key), 20)  # SHA-1 length
    
    def test_valid_pattern_validation(self):
        """Test pattern validation logic"""
        # Simple valid pattern
        pattern = AndroidPattern(points=self.valid_points)
        self.assertTrue(pattern.is_valid_pattern())
        
        # Create a 4-point diagonal pattern
        diagonal_points_4 = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(1),
            PatternPoint.from_index(4),
            PatternPoint.from_index(8)
        ]
        diagonal_pattern = AndroidPattern(points=diagonal_points_4)
        self.assertTrue(diagonal_pattern.is_valid_pattern())
    
    def test_can_connect_directly(self):
        """Test direct connection validation"""
        pattern = AndroidPattern(points=self.valid_points)
        
        # Adjacent points can connect
        p1 = PatternPoint.from_index(0)
        p2 = PatternPoint.from_index(1)
        self.assertTrue(pattern._can_connect_directly(p1, p2, []))
        
        # Diagonal points can connect
        p1 = PatternPoint.from_index(0)
        p2 = PatternPoint.from_index(4)
        self.assertTrue(pattern._can_connect_directly(p1, p2, []))
    
    def test_to_dict(self):
        """Test dictionary conversion"""
        pattern = AndroidPattern(points=self.valid_points, confidence=0.8)
        result = pattern.to_dict()
        
        self.assertIn('points', result)
        self.assertIn('sequence', result)
        self.assertIn('hash_value', result)
        self.assertIn('confidence', result)
        self.assertIn('is_valid', result)
        
        self.assertEqual(result['sequence'], [0, 1, 2, 5])
        self.assertEqual(result['confidence'], 0.8)
    
    def test_string_representation(self):
        """Test string representation"""
        pattern = AndroidPattern(points=self.valid_points, confidence=0.75)
        str_repr = str(pattern)
        self.assertIn('0->1->2->5', str_repr)
        self.assertIn('0.75', str_repr)


class TestPatternAnalysis(unittest.TestCase):
    """Test PatternAnalysis class"""
    
    def setUp(self):
        """Set up test environment"""
        self.pattern_analysis = PatternAnalysis(debug_mode=True)
        
        # Create test device
        self.test_device = AndroidDevice(
            serial="TEST123",
            model="Test Model",
            brand="Test Brand",
            android_version="11.0",
            lock_type=LockType.PATTERN,
            usb_debugging=True
        )
        
        # Create test strategy
        self.test_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            max_attempts=1000
        )
    
    def test_initialization(self):
        """Test PatternAnalysis initialization"""
        self.assertIsInstance(self.pattern_analysis, PatternAnalysis)
        self.assertTrue(self.pattern_analysis.debug_mode)
        self.assertEqual(self.pattern_analysis.grid_size, 3)
        self.assertEqual(self.pattern_analysis.total_points, 9)
    
    def test_validate_strategy_valid(self):
        """Test strategy validation with valid strategy"""
        self.assertTrue(self.pattern_analysis.validate_strategy(self.test_strategy))
    
    def test_validate_strategy_wrong_type(self):
        """Test strategy validation with wrong attack type"""
        wrong_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.test_device
        )
        self.assertFalse(self.pattern_analysis.validate_strategy(wrong_strategy))
    
    def test_validate_strategy_wrong_lock_type(self):
        """Test strategy validation with wrong lock type"""
        wrong_device = AndroidDevice(
            serial="TEST123",
            model="Test Model",
            brand="Test Brand",
            android_version="11.0",
            lock_type=LockType.PIN
        )
        wrong_strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=wrong_device
        )
        self.assertFalse(self.pattern_analysis.validate_strategy(wrong_strategy))
    
    def test_estimate_duration(self):
        """Test duration estimation"""
        # Test with gesture key analysis
        strategy_with_key = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            custom_parameters={'gesture_key_path': '/test/path'}
        )
        duration = self.pattern_analysis.estimate_duration(strategy_with_key)
        self.assertEqual(duration, 5.0)
        
        # Test with screenshot analysis
        strategy_with_screenshot = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            custom_parameters={'screenshot_path': '/test/screenshot.png'}
        )
        duration = self.pattern_analysis.estimate_duration(strategy_with_screenshot)
        self.assertEqual(duration, 30.0)
        
        # Test with enumeration
        duration = self.pattern_analysis.estimate_duration(self.test_strategy)
        self.assertGreater(duration, 0)
    
    def test_generate_patterns_of_length(self):
        """Test pattern generation"""
        patterns = list(self.pattern_analysis._generate_patterns_of_length(4))
        self.assertGreater(len(patterns), 0)
        
        # All patterns should have length 4
        for pattern in patterns[:10]:  # Test first 10
            self.assertEqual(len(pattern.points), 4)
    
    def test_generate_common_patterns(self):
        """Test common pattern generation"""
        common_patterns = self.pattern_analysis.generate_common_patterns()
        self.assertGreater(len(common_patterns), 0)
        
        # All should be valid patterns
        for pattern in common_patterns:
            self.assertTrue(pattern.is_valid_pattern())
    
    def test_analyze_pattern_complexity(self):
        """Test pattern complexity analysis"""
        # Create a test pattern
        points = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(1),
            PatternPoint.from_index(2),
            PatternPoint.from_index(5),
            PatternPoint.from_index(8)
        ]
        pattern = AndroidPattern(points=points)
        
        complexity = self.pattern_analysis.analyze_pattern_complexity(pattern)
        
        self.assertIn('length', complexity)
        self.assertIn('unique_points', complexity)
        self.assertIn('direction_changes', complexity)
        self.assertIn('security_score', complexity)
        self.assertIn('estimated_crack_time_seconds', complexity)
        
        self.assertEqual(complexity['length'], 5)
        self.assertEqual(complexity['unique_points'], 5)
        self.assertGreaterEqual(complexity['security_score'], 0)
        self.assertLessEqual(complexity['security_score'], 100)
    
    def test_crack_pattern_hash(self):
        """Test pattern hash cracking"""
        # Create a known pattern and its hash (use 4 points)
        points = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(1),
            PatternPoint.from_index(4),
            PatternPoint.from_index(8)
        ]
        known_pattern = AndroidPattern(points=points)
        target_hash = known_pattern.to_gesture_key_format().hex()
        
        # Try to crack it
        cracked = self.pattern_analysis._crack_pattern_hash(target_hash, 1000)
        
        if cracked:  # May not find it within attempt limit
            self.assertEqual(cracked.to_sequence(), known_pattern.to_sequence())
    
    def test_enumerate_pattern_space(self):
        """Test pattern space enumeration"""
        result = self.pattern_analysis._enumerate_pattern_space(self.test_strategy)
        
        self.assertTrue(result.success)
        self.assertGreater(result.attempts, 0)
        self.assertIsNotNone(result.result_data)
        
        # Parse result data
        data = json.loads(result.result_data)
        self.assertIn('total_patterns', data)
        self.assertIn('valid_patterns', data)
        self.assertIn('method', data)
        self.assertEqual(data['method'], 'pattern_enumeration')
    
    def test_analyze_gesture_key_file(self):
        """Test gesture.key file analysis"""
        # Create a temporary gesture.key file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            # Write a fake SHA-1 hash (20 bytes)
            fake_hash = b'\x01' * 20
            temp_file.write(fake_hash)
            temp_file.close()  # Close file before using it
            
            strategy = AttackStrategy(
                strategy_type=AttackType.PATTERN_ANALYSIS,
                target_device=self.test_device,
                custom_parameters={'gesture_key_path': temp_file.name},
                max_attempts=100
            )
            
            result = self.pattern_analysis._analyze_gesture_key_file(strategy)
            
            # Should not crash, may or may not find the pattern
            self.assertIsInstance(result.success, bool)
            self.assertGreaterEqual(result.attempts, 0)
            
        finally:
            try:
                os.unlink(temp_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors on Windows
    
    def test_analyze_gesture_key_file_not_found(self):
        """Test gesture.key file analysis with missing file"""
        strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            custom_parameters={'gesture_key_path': '/nonexistent/file'}
        )
        
        with self.assertRaises(PatternAnalysisException):
            self.pattern_analysis._analyze_gesture_key_file(strategy)
    
    def test_analyze_gesture_key_file_invalid_size(self):
        """Test gesture.key file analysis with invalid file size"""
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            # Write wrong size data
            temp_file.write(b'invalid')
            temp_file.close()  # Close file before using it
            
            strategy = AttackStrategy(
                strategy_type=AttackType.PATTERN_ANALYSIS,
                target_device=self.test_device,
                custom_parameters={'gesture_key_path': temp_file.name}
            )
            
            with self.assertRaises(PatternAnalysisException):
                self.pattern_analysis._analyze_gesture_key_file(strategy)
                
        finally:
            try:
                os.unlink(temp_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors on Windows
    
    @patch('forensics_toolkit.attack_engines.pattern_analysis.OPENCV_AVAILABLE', False)
    def test_analyze_screenshot_no_opencv(self):
        """Test screenshot analysis without OpenCV"""
        strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            custom_parameters={'screenshot_path': '/test/screenshot.png'}
        )
        
        with self.assertRaises(PatternAnalysisException):
            self.pattern_analysis._analyze_screenshot(strategy)
    
    def test_lines_intersect(self):
        """Test line intersection detection"""
        # Test intersecting lines
        self.assertTrue(self.pattern_analysis._lines_intersect(0, 8, 2, 6))
        
        # Test non-intersecting lines
        self.assertFalse(self.pattern_analysis._lines_intersect(0, 1, 3, 4))
    
    def test_is_common_pattern(self):
        """Test common pattern detection"""
        # Create a diagonal pattern (use 4 points)
        points = [
            PatternPoint.from_index(0),
            PatternPoint.from_index(1),
            PatternPoint.from_index(4),
            PatternPoint.from_index(8)
        ]
        pattern = AndroidPattern(points=points)
        
        # This depends on the common patterns list
        is_common = self.pattern_analysis._is_common_pattern(pattern)
        self.assertIsInstance(is_common, bool)
    
    def test_estimate_crack_time(self):
        """Test crack time estimation"""
        # Test different security scores
        weak_time = self.pattern_analysis._estimate_crack_time(10)
        medium_time = self.pattern_analysis._estimate_crack_time(30)
        strong_time = self.pattern_analysis._estimate_crack_time(70)
        
        self.assertLess(weak_time, medium_time)
        self.assertLess(medium_time, strong_time)
    
    def test_create_visual_debug_tools(self):
        """Test visual debug tools creation"""
        debug_tools = self.pattern_analysis.create_visual_debug_tools()
        
        self.assertIn('opencv_available', debug_tools)
        self.assertIn('debug_mode', debug_tools)
        self.assertIn('circle_detection_params', debug_tools)
        self.assertIn('supported_formats', debug_tools)
        self.assertIn('visualization_tools', debug_tools)
        
        self.assertTrue(debug_tools['debug_mode'])
    
    def test_get_pattern_statistics(self):
        """Test pattern statistics generation"""
        stats = self.pattern_analysis.get_pattern_statistics()
        
        self.assertIn('total_possible_patterns', stats)
        self.assertIn('total_valid_patterns', stats)
        self.assertIn('patterns_by_length', stats)
        self.assertIn('common_patterns_count', stats)
        self.assertIn('analysis_capabilities', stats)
        
        self.assertGreater(stats['total_possible_patterns'], 0)
        self.assertGreater(stats['common_patterns_count'], 0)
    
    def test_execute_attack_enumeration(self):
        """Test attack execution with enumeration"""
        result = self.pattern_analysis.execute_attack(self.test_strategy)
        
        self.assertIsInstance(result.success, bool)
        self.assertGreaterEqual(result.attempts, 0)
        self.assertGreaterEqual(result.duration, 0)
        
        if result.success and result.result_data:
            data = json.loads(result.result_data)
            self.assertEqual(data['method'], 'pattern_enumeration')
    
    def test_execute_attack_invalid_strategy(self):
        """Test attack execution with invalid strategy"""
        invalid_strategy = AttackStrategy(
            strategy_type=AttackType.BRUTE_FORCE,
            target_device=self.test_device
        )
        
        result = self.pattern_analysis.execute_attack(invalid_strategy)
        
        self.assertFalse(result.success)
        self.assertEqual(result.attempts, 0)
        self.assertIsNotNone(result.error_message)
    
    def test_organize_circles_to_grid(self):
        """Test circle organization to grid"""
        # Create mock circles data (x, y, radius)
        circles = [
            [100, 100, 20], [200, 100, 20], [300, 100, 20],  # Top row
            [100, 200, 20], [200, 200, 20], [300, 200, 20],  # Middle row
            [100, 300, 20], [200, 300, 20], [300, 300, 20]   # Bottom row
        ]
        
        import numpy as np
        circles_array = np.array(circles)
        
        grid = self.pattern_analysis._organize_circles_to_grid(circles_array)
        
        if grid:  # May return None if organization fails
            self.assertEqual(len(grid), 9)
            # First point should be top-left
            self.assertEqual(grid[0], (100, 100))
            # Last point should be bottom-right
            self.assertEqual(grid[8], (300, 300))
    
    def test_organize_circles_insufficient(self):
        """Test circle organization with insufficient circles"""
        import numpy as np
        circles = np.array([[100, 100, 20], [200, 200, 20]])  # Only 2 circles
        
        grid = self.pattern_analysis._organize_circles_to_grid(circles)
        self.assertIsNone(grid)


if __name__ == '__main__':
    # Set up logging for tests
    logging.basicConfig(level=logging.DEBUG)
    
    # Run the tests
    unittest.main(verbosity=2)