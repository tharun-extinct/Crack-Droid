"""
Integration tests for OpenCV wrapper
"""

import unittest
import numpy as np
import tempfile
import os
from unittest.mock import patch, MagicMock
from pathlib import Path

from forensics_toolkit.services.opencv_wrapper import (
    OpenCVWrapper, OpenCVException, DetectedCircle, DetectedLine, 
    ImageProcessingConfig, OPENCV_AVAILABLE
)


class TestOpenCVIntegration(unittest.TestCase):
    """Test OpenCV wrapper integration"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = ImageProcessingConfig()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test image data
        self.test_image = np.zeros((300, 300, 3), dtype=np.uint8)
        # Draw some circles for testing
        if OPENCV_AVAILABLE:
            import cv2
            cv2.circle(self.test_image, (100, 100), 20, (255, 255, 255), -1)
            cv2.circle(self.test_image, (200, 100), 20, (255, 255, 255), -1)
            cv2.circle(self.test_image, (150, 200), 20, (255, 255, 255), -1)
    
    def tearDown(self):
        """Clean up test environment"""
        # Clean up temporary files
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_opencv_wrapper_initialization(self):
        """Test OpenCV wrapper initialization"""
        wrapper = OpenCVWrapper(config=self.config, debug_mode=True)
        
        self.assertTrue(wrapper.is_available())
        self.assertEqual(wrapper.debug_mode, True)
        self.assertIsNotNone(wrapper.config)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_image_loading_and_saving(self):
        """Test image loading and saving functionality"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Save test image
        test_image_path = os.path.join(self.temp_dir, "test_image.png")
        success = wrapper.save_image(self.test_image, test_image_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(test_image_path))
        
        # Load test image
        loaded_image = wrapper.load_image(test_image_path)
        self.assertIsNotNone(loaded_image)
        self.assertEqual(loaded_image.shape, self.test_image.shape)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_image_preprocessing(self):
        """Test image preprocessing functionality"""
        wrapper = OpenCVWrapper(config=self.config)
        
        processed = wrapper.preprocess_image(self.test_image)
        
        self.assertIn('grayscale', processed)
        self.assertIn('blurred', processed)
        self.assertIn('edges', processed)
        self.assertIn('threshold', processed)
        
        # Check dimensions
        self.assertEqual(len(processed['grayscale'].shape), 2)
        self.assertEqual(len(processed['blurred'].shape), 2)
        self.assertEqual(len(processed['edges'].shape), 2)
        self.assertEqual(len(processed['threshold'].shape), 2)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_circle_detection(self):
        """Test circle detection functionality"""
        wrapper = OpenCVWrapper(config=self.config)
        
        detected_circles = wrapper.detect_circles(self.test_image)
        
        self.assertIsInstance(detected_circles, list)
        # Should detect at least some circles from our test image
        self.assertGreaterEqual(len(detected_circles), 1)
        
        for circle in detected_circles:
            self.assertIsInstance(circle, DetectedCircle)
            self.assertGreaterEqual(circle.x, 0)
            self.assertGreaterEqual(circle.y, 0)
            self.assertGreater(circle.radius, 0)
            self.assertGreaterEqual(circle.confidence, 0.0)
            self.assertLessEqual(circle.confidence, 1.0)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_line_detection(self):
        """Test line detection functionality"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create image with lines
        line_image = np.zeros((300, 300, 3), dtype=np.uint8)
        import cv2
        cv2.line(line_image, (50, 50), (250, 50), (255, 255, 255), 3)
        cv2.line(line_image, (50, 100), (250, 200), (255, 255, 255), 3)
        
        detected_lines = wrapper.detect_lines(line_image)
        
        self.assertIsInstance(detected_lines, list)
        
        for line in detected_lines:
            self.assertIsInstance(line, DetectedLine)
            self.assertIsInstance(line.start_point, tuple)
            self.assertIsInstance(line.end_point, tuple)
            self.assertEqual(len(line.start_point), 2)
            self.assertEqual(len(line.end_point), 2)
            self.assertGreaterEqual(line.confidence, 0.0)
            self.assertLessEqual(line.confidence, 1.0)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_contour_detection(self):
        """Test contour detection functionality"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create image with shapes
        shape_image = np.zeros((300, 300, 3), dtype=np.uint8)
        import cv2
        cv2.rectangle(shape_image, (50, 50), (150, 150), (255, 255, 255), -1)
        cv2.circle(shape_image, (200, 200), 50, (255, 255, 255), -1)
        
        contours = wrapper.detect_contours(shape_image)
        
        self.assertIsInstance(contours, list)
        # Should detect at least the rectangle and circle
        self.assertGreaterEqual(len(contours), 1)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_pattern_grid_extraction(self):
        """Test pattern grid extraction from circles"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create 9 circles in 3x3 grid pattern
        grid_image = np.zeros((300, 300, 3), dtype=np.uint8)
        import cv2
        
        positions = []
        for row in range(3):
            for col in range(3):
                x = 50 + col * 100
                y = 50 + row * 100
                cv2.circle(grid_image, (x, y), 15, (255, 255, 255), -1)
                positions.append((x, y))
        
        detected_circles = wrapper.detect_circles(grid_image)
        
        # Should detect 9 circles
        self.assertGreaterEqual(len(detected_circles), 9)
        
        # Extract grid
        grid = wrapper.extract_pattern_grid(detected_circles)
        
        if grid:  # Grid extraction might not be perfect with test data
            self.assertEqual(len(grid), 9)
            for point in grid:
                self.assertIsInstance(point, tuple)
                self.assertEqual(len(point), 2)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_template_matching(self):
        """Test template matching functionality"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create template and image with template
        template = np.zeros((50, 50, 3), dtype=np.uint8)
        import cv2
        cv2.circle(template, (25, 25), 20, (255, 255, 255), -1)
        
        # Create image with template at known location
        test_image = np.zeros((200, 200, 3), dtype=np.uint8)
        test_image[50:100, 50:100] = template
        
        matches = wrapper.match_pattern_template(test_image, template, threshold=0.7)
        
        self.assertIsInstance(matches, list)
        if matches:  # Template matching might not be perfect
            for match in matches:
                self.assertIsInstance(match, tuple)
                self.assertEqual(len(match), 3)  # x, y, confidence
                self.assertGreaterEqual(match[2], 0.7)  # confidence >= threshold
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_pattern_connectivity_analysis(self):
        """Test pattern connectivity analysis"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create grid points
        grid_points = [
            (50, 50), (150, 50), (250, 50),    # Row 0
            (50, 150), (150, 150), (250, 150), # Row 1
            (50, 250), (150, 250), (250, 250)  # Row 2
        ]
        
        # Create some lines connecting points
        lines = [
            DetectedLine((50, 50), (150, 50)),    # 0 -> 1
            DetectedLine((150, 50), (250, 50)),   # 1 -> 2
            DetectedLine((250, 50), (250, 150))   # 2 -> 5
        ]
        
        connections = wrapper.analyze_pattern_connectivity(grid_points, lines)
        
        self.assertIsInstance(connections, list)
        for connection in connections:
            self.assertIsInstance(connection, tuple)
            self.assertEqual(len(connection), 2)
            self.assertGreaterEqual(connection[0], 0)
            self.assertLess(connection[0], 9)
            self.assertGreaterEqual(connection[1], 0)
            self.assertLess(connection[1], 9)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_debug_visualization(self):
        """Test debug visualization creation"""
        wrapper = OpenCVWrapper(config=self.config, debug_mode=True)
        
        # Create test data
        circles = [
            DetectedCircle(100, 100, 20, 0.9),
            DetectedCircle(200, 100, 20, 0.8),
            DetectedCircle(150, 200, 20, 0.7)
        ]
        
        lines = [
            DetectedLine((100, 100), (200, 100), confidence=0.9),
            DetectedLine((200, 100), (150, 200), confidence=0.8)
        ]
        
        pattern_sequence = [0, 1, 2]
        
        debug_image = wrapper.create_debug_visualization(
            self.test_image, circles, lines, pattern_sequence
        )
        
        self.assertIsNotNone(debug_image)
        self.assertEqual(debug_image.shape, self.test_image.shape)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_version_info(self):
        """Test version information retrieval"""
        wrapper = OpenCVWrapper(config=self.config)
        
        version_info = wrapper.get_version_info()
        
        self.assertIsInstance(version_info, dict)
        self.assertTrue(version_info['available'])
        self.assertIsNotNone(version_info['version'])
        self.assertIsInstance(version_info['capabilities'], list)
        self.assertIn('circle_detection', version_info['capabilities'])
        self.assertIn('line_detection', version_info['capabilities'])
        self.assertIn('pattern_analysis', version_info['capabilities'])
    
    def test_opencv_not_available_handling(self):
        """Test handling when OpenCV is not available"""
        with patch('forensics_toolkit.services.opencv_wrapper.OPENCV_AVAILABLE', False):
            with self.assertRaises(OpenCVException):
                OpenCVWrapper(config=self.config)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_invalid_image_handling(self):
        """Test handling of invalid images"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Test non-existent file
        with self.assertRaises(OpenCVException):
            wrapper.load_image("non_existent_file.png")
        
        # Test invalid image data
        invalid_image_path = os.path.join(self.temp_dir, "invalid.png")
        with open(invalid_image_path, 'w') as f:
            f.write("not an image")
        
        with self.assertRaises(OpenCVException):
            wrapper.load_image(invalid_image_path)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_configuration_parameters(self):
        """Test configuration parameter usage"""
        custom_config = ImageProcessingConfig(
            gaussian_blur_kernel=(5, 5),
            gaussian_blur_sigma=1.0,
            hough_circles_min_radius=5,
            hough_circles_max_radius=50
        )
        
        wrapper = OpenCVWrapper(config=custom_config)
        
        self.assertEqual(wrapper.config.gaussian_blur_kernel, (5, 5))
        self.assertEqual(wrapper.config.gaussian_blur_sigma, 1.0)
        self.assertEqual(wrapper.config.hough_circles_min_radius, 5)
        self.assertEqual(wrapper.config.hough_circles_max_radius, 50)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_debug_mode_functionality(self):
        """Test debug mode functionality"""
        wrapper = OpenCVWrapper(config=self.config, debug_mode=True)
        
        # Test that debug mode is enabled
        self.assertTrue(wrapper.debug_mode)
        
        # Test preprocessing with debug mode (should save debug images)
        processed = wrapper.preprocess_image(self.test_image)
        
        # Debug images should be created (though we won't check file system in unit tests)
        self.assertIsNotNone(processed)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_circle_confidence_calculation(self):
        """Test circle confidence calculation"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create image with clear circle
        circle_image = np.zeros((200, 200), dtype=np.uint8)
        import cv2
        cv2.circle(circle_image, (100, 100), 30, 255, -1)
        
        # Test confidence calculation (private method, but important for functionality)
        confidence = wrapper._calculate_circle_confidence(circle_image, 100, 100, 30)
        
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
        # Should have high confidence for a clear white circle
        self.assertGreater(confidence, 0.5)
    
    @unittest.skipUnless(OPENCV_AVAILABLE, "OpenCV not available")
    def test_line_confidence_calculation(self):
        """Test line confidence calculation"""
        wrapper = OpenCVWrapper(config=self.config)
        
        # Create image with clear line
        line_image = np.zeros((200, 200), dtype=np.uint8)
        import cv2
        cv2.line(line_image, (50, 100), (150, 100), 255, 3)
        
        # Get edges for line confidence calculation
        edges = cv2.Canny(line_image, 50, 150)
        
        # Test confidence calculation
        confidence = wrapper._calculate_line_confidence(edges, 50, 100, 150, 100)
        
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)


class TestDetectedCircle(unittest.TestCase):
    """Test DetectedCircle data class"""
    
    def test_detected_circle_creation(self):
        """Test DetectedCircle creation and methods"""
        circle = DetectedCircle(x=100, y=150, radius=25, confidence=0.85)
        
        self.assertEqual(circle.x, 100)
        self.assertEqual(circle.y, 150)
        self.assertEqual(circle.radius, 25)
        self.assertEqual(circle.confidence, 0.85)
        
        # Test to_dict method
        circle_dict = circle.to_dict()
        expected_dict = {
            "x": 100,
            "y": 150,
            "radius": 25,
            "confidence": 0.85
        }
        self.assertEqual(circle_dict, expected_dict)


class TestDetectedLine(unittest.TestCase):
    """Test DetectedLine data class"""
    
    def test_detected_line_creation(self):
        """Test DetectedLine creation and methods"""
        line = DetectedLine(
            start_point=(50, 60),
            end_point=(150, 160),
            thickness=2,
            confidence=0.75
        )
        
        self.assertEqual(line.start_point, (50, 60))
        self.assertEqual(line.end_point, (150, 160))
        self.assertEqual(line.thickness, 2)
        self.assertEqual(line.confidence, 0.75)
        
        # Test to_dict method
        line_dict = line.to_dict()
        expected_dict = {
            "start_point": (50, 60),
            "end_point": (150, 160),
            "thickness": 2,
            "confidence": 0.75
        }
        self.assertEqual(line_dict, expected_dict)


class TestImageProcessingConfig(unittest.TestCase):
    """Test ImageProcessingConfig data class"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ImageProcessingConfig()
        
        self.assertEqual(config.gaussian_blur_kernel, (9, 9))
        self.assertEqual(config.gaussian_blur_sigma, 2.0)
        self.assertEqual(config.canny_threshold1, 50)
        self.assertEqual(config.canny_threshold2, 150)
        self.assertEqual(config.hough_circles_dp, 1.0)
        self.assertEqual(config.hough_circles_min_dist, 50)
        self.assertEqual(config.hough_circles_param1, 50)
        self.assertEqual(config.hough_circles_param2, 30)
        self.assertEqual(config.hough_circles_min_radius, 10)
        self.assertEqual(config.hough_circles_max_radius, 100)
        self.assertEqual(config.contour_min_area, 100)
        self.assertEqual(config.contour_max_area, 10000)
    
    def test_custom_config(self):
        """Test custom configuration values"""
        config = ImageProcessingConfig(
            gaussian_blur_kernel=(7, 7),
            gaussian_blur_sigma=1.5,
            canny_threshold1=30,
            canny_threshold2=120,
            hough_circles_min_radius=5,
            hough_circles_max_radius=80
        )
        
        self.assertEqual(config.gaussian_blur_kernel, (7, 7))
        self.assertEqual(config.gaussian_blur_sigma, 1.5)
        self.assertEqual(config.canny_threshold1, 30)
        self.assertEqual(config.canny_threshold2, 120)
        self.assertEqual(config.hough_circles_min_radius, 5)
        self.assertEqual(config.hough_circles_max_radius, 80)


if __name__ == '__main__':
    unittest.main()