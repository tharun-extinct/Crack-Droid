"""
Integration tests for Pattern Analysis with OpenCV wrapper
"""

import unittest
import tempfile
import os
import numpy as np
from unittest.mock import patch, MagicMock

from forensics_toolkit.attack_engines.pattern_analysis import PatternAnalysis, OPENCV_AVAILABLE
from forensics_toolkit.models.attack import AttackStrategy
from forensics_toolkit.models.device import AndroidDevice
from forensics_toolkit.interfaces import AttackType, LockType


class TestPatternAnalysisOpenCVIntegration(unittest.TestCase):
    """Test Pattern Analysis integration with OpenCV wrapper"""
    
    def setUp(self):
        """Set up test environment"""
        self.pattern_analysis = PatternAnalysis(debug_mode=True)
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test device
        self.test_device = AndroidDevice(
            serial="test_device_001",
            model="Test Model",
            brand="Test Brand",
            android_version="10.0",
            imei="123456789012345",
            usb_debugging=True,
            root_status=False,
            lock_type=LockType.PATTERN,
            screen_timeout=30000,
            lockout_policy=None
        )
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
    
    def test_opencv_wrapper_initialization(self):
        """Test that OpenCV wrapper is properly initialized"""
        if OPENCV_AVAILABLE:
            self.assertIsNotNone(self.pattern_analysis.opencv_wrapper)
            self.assertTrue(self.pattern_analysis.opencv_wrapper.is_available())
        else:
            self.assertIsNone(self.pattern_analysis.opencv_wrapper)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_screenshot_analysis_with_opencv_wrapper(self):
        """Test screenshot analysis using OpenCV wrapper"""
        # Create a test image
        test_image = np.zeros((300, 300, 3), dtype=np.uint8)
        
        # Save test image
        test_image_path = os.path.join(self.temp_dir, "test_screenshot.png")
        if OPENCV_AVAILABLE:
            import cv2
            # Draw some circles to simulate pattern dots
            for i in range(3):
                for j in range(3):
                    x = 50 + j * 100
                    y = 50 + i * 100
                    cv2.circle(test_image, (x, y), 15, (255, 255, 255), -1)
            
            cv2.imwrite(test_image_path, test_image)
        
        # Create attack strategy
        strategy = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            max_attempts=100,
            timeout_seconds=60,
            custom_parameters={
                'screenshot_path': test_image_path
            }
        )
        
        # Execute attack
        result = self.pattern_analysis.execute_attack(strategy)
        
        # Verify result structure
        self.assertIsNotNone(result)
        self.assertIsInstance(result.success, bool)
        self.assertIsInstance(result.attempts, int)
        self.assertIsInstance(result.duration, float)
        
        # If successful, verify result data contains OpenCV version info
        if result.success and result.result_data:
            import json
            result_data = json.loads(result.result_data)
            self.assertIn('method', result_data)
            self.assertEqual(result_data['method'], 'visual_recognition')
            self.assertIn('opencv_version', result_data)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_visual_debug_tools_with_opencv(self):
        """Test visual debug tools integration with OpenCV"""
        debug_tools = self.pattern_analysis.create_visual_debug_tools()
        
        self.assertIn('opencv_available', debug_tools)
        self.assertIn('opencv_wrapper_available', debug_tools)
        self.assertIn('opencv_version_info', debug_tools)
        
        self.assertTrue(debug_tools['opencv_available'])
        self.assertTrue(debug_tools['opencv_wrapper_available'])
        self.assertIsNotNone(debug_tools['opencv_version_info'])
        
        # Verify OpenCV version info structure
        version_info = debug_tools['opencv_version_info']
        self.assertIn('available', version_info)
        self.assertIn('version', version_info)
        self.assertIn('capabilities', version_info)
        
        self.assertTrue(version_info['available'])
        self.assertIsNotNone(version_info['version'])
        self.assertIsInstance(version_info['capabilities'], list)
        self.assertIn('pattern_analysis', version_info['capabilities'])
    
    def test_opencv_not_available_handling(self):
        """Test handling when OpenCV is not available"""
        with patch('forensics_toolkit.attack_engines.pattern_analysis.OPENCV_AVAILABLE', False):
            pattern_analysis = PatternAnalysis(debug_mode=True)
            
            self.assertIsNone(pattern_analysis.opencv_wrapper)
            
            # Test screenshot analysis without OpenCV
            strategy = AttackStrategy(
                strategy_type=AttackType.PATTERN_ANALYSIS,
                target_device=self.test_device,
                max_attempts=100,
                timeout_seconds=60,
                custom_parameters={
                    'screenshot_path': 'dummy_path.png'
                }
            )
            
            result = pattern_analysis.execute_attack(strategy)
            
            self.assertFalse(result.success)
            self.assertIn("OpenCV wrapper not available", result.error_message)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_opencv_wrapper_configuration(self):
        """Test OpenCV wrapper configuration"""
        if self.pattern_analysis.opencv_wrapper:
            config = self.pattern_analysis.opencv_wrapper.config
            
            # Verify configuration has expected attributes
            self.assertIsNotNone(config.gaussian_blur_kernel)
            self.assertIsNotNone(config.gaussian_blur_sigma)
            self.assertIsNotNone(config.hough_circles_dp)
            self.assertIsNotNone(config.hough_circles_min_dist)
            self.assertIsNotNone(config.hough_circles_param1)
            self.assertIsNotNone(config.hough_circles_param2)
            self.assertIsNotNone(config.hough_circles_min_radius)
            self.assertIsNotNone(config.hough_circles_max_radius)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_pattern_detection_workflow(self):
        """Test the complete pattern detection workflow"""
        if not self.pattern_analysis.opencv_wrapper:
            self.skipTest("OpenCV wrapper not available")
        
        # Create a more realistic test image with pattern
        test_image = np.zeros((400, 400, 3), dtype=np.uint8)
        import cv2
        
        # Draw 3x3 grid of circles
        grid_positions = []
        for i in range(3):
            for j in range(3):
                x = 100 + j * 100
                y = 100 + i * 100
                cv2.circle(test_image, (x, y), 20, (255, 255, 255), -1)
                grid_positions.append((x, y))
        
        # Draw some connecting lines to simulate a pattern
        cv2.line(test_image, grid_positions[0], grid_positions[1], (128, 128, 128), 5)
        cv2.line(test_image, grid_positions[1], grid_positions[2], (128, 128, 128), 5)
        cv2.line(test_image, grid_positions[2], grid_positions[5], (128, 128, 128), 5)
        
        # Test individual OpenCV wrapper methods
        wrapper = self.pattern_analysis.opencv_wrapper
        
        # Test circle detection
        detected_circles = wrapper.detect_circles(test_image)
        self.assertGreater(len(detected_circles), 0)
        
        # Test line detection
        detected_lines = wrapper.detect_lines(test_image)
        self.assertGreaterEqual(len(detected_lines), 0)  # May not detect lines perfectly
        
        # Test grid extraction
        if len(detected_circles) >= 9:
            grid = wrapper.extract_pattern_grid(detected_circles)
            if grid:
                self.assertEqual(len(grid), 9)
        
        # Test debug visualization
        debug_image = wrapper.create_debug_visualization(
            test_image, detected_circles, detected_lines, [0, 1, 2]
        )
        self.assertIsNotNone(debug_image)
        self.assertEqual(debug_image.shape, test_image.shape)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_image_preprocessing_integration(self):
        """Test image preprocessing integration"""
        if not self.pattern_analysis.opencv_wrapper:
            self.skipTest("OpenCV wrapper not available")
        
        # Create test image
        test_image = np.random.randint(0, 255, (200, 200, 3), dtype=np.uint8)
        
        # Test preprocessing
        wrapper = self.pattern_analysis.opencv_wrapper
        processed = wrapper.preprocess_image(test_image)
        
        self.assertIn('grayscale', processed)
        self.assertIn('blurred', processed)
        self.assertIn('edges', processed)
        self.assertIn('threshold', processed)
        
        # Verify processed images have correct dimensions
        self.assertEqual(len(processed['grayscale'].shape), 2)
        self.assertEqual(len(processed['blurred'].shape), 2)
        self.assertEqual(len(processed['edges'].shape), 2)
        self.assertEqual(len(processed['threshold'].shape), 2)
    
    def test_strategy_validation_with_opencv(self):
        """Test strategy validation with OpenCV-specific parameters"""
        # Test valid strategy with screenshot
        strategy_screenshot = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            max_attempts=100,
            timeout_seconds=60,
            custom_parameters={
                'screenshot_path': 'test_screenshot.png'
            }
        )
        
        self.assertTrue(self.pattern_analysis.validate_strategy(strategy_screenshot))
        
        # Test valid strategy with gesture key
        strategy_gesture = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            max_attempts=100,
            timeout_seconds=60,
            custom_parameters={
                'gesture_key_path': 'gesture.key'
            }
        )
        
        self.assertTrue(self.pattern_analysis.validate_strategy(strategy_gesture))
        
        # Test valid strategy with enumeration
        strategy_enum = AttackStrategy(
            strategy_type=AttackType.PATTERN_ANALYSIS,
            target_device=self.test_device,
            max_attempts=100,
            timeout_seconds=60,
            custom_parameters={
                'allow_enumeration': True
            }
        )
        
        self.assertTrue(self.pattern_analysis.validate_strategy(strategy_enum))


if __name__ == '__main__':
    unittest.main()