"""
OpenCV wrapper for pattern analysis and image processing
"""

import os
import numpy as np
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import logging
import json

from ..interfaces import ForensicsException

# OpenCV is optional - graceful degradation if not available
try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    cv2 = None
    OPENCV_AVAILABLE = False


class OpenCVException(ForensicsException):
    """Exception raised during OpenCV operations"""
    
    def __init__(self, message: str, error_code: str = "OPENCV_ERROR"):
        super().__init__(message, error_code, evidence_impact=False)


@dataclass
class ImageProcessingConfig:
    """Configuration for image processing operations"""
    gaussian_blur_kernel: Tuple[int, int] = (9, 9)
    gaussian_blur_sigma: float = 2.0
    canny_threshold1: int = 50
    canny_threshold2: int = 150
    hough_circles_dp: float = 1.0
    hough_circles_min_dist: int = 50
    hough_circles_param1: int = 50
    hough_circles_param2: int = 30
    hough_circles_min_radius: int = 10
    hough_circles_max_radius: int = 100
    contour_min_area: int = 100
    contour_max_area: int = 10000


@dataclass
class DetectedCircle:
    """Represents a detected circle in an image"""
    x: int
    y: int
    radius: int
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "x": self.x,
            "y": self.y,
            "radius": self.radius,
            "confidence": self.confidence
        }


@dataclass
class DetectedLine:
    """Represents a detected line in an image"""
    start_point: Tuple[int, int]
    end_point: Tuple[int, int]
    thickness: int = 1
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_point": self.start_point,
            "end_point": self.end_point,
            "thickness": self.thickness,
            "confidence": self.confidence
        }


class OpenCVWrapper:
    """
    OpenCV wrapper for pattern analysis and image processing
    
    This class provides a comprehensive interface to OpenCV functionality
    specifically tailored for Android pattern analysis and forensic image processing.
    """
    
    def __init__(self, config: Optional[ImageProcessingConfig] = None, debug_mode: bool = False):
        """
        Initialize OpenCV wrapper
        
        Args:
            config: Image processing configuration
            debug_mode: Enable debug output and image saving
        """
        self.config = config or ImageProcessingConfig()
        self.debug_mode = debug_mode
        self.logger = logging.getLogger(__name__)
        
        if not OPENCV_AVAILABLE:
            self.logger.warning("OpenCV not available - image processing disabled")
            raise OpenCVException("OpenCV not available. Install opencv-python package.")
        
        self.logger.info(f"OpenCV wrapper initialized (Debug: {debug_mode})")
    
    def is_available(self) -> bool:
        """
        Check if OpenCV is available
        
        Returns:
            bool: True if OpenCV is available
        """
        return OPENCV_AVAILABLE
    
    def load_image(self, image_path: str) -> np.ndarray:
        """
        Load image from file
        
        Args:
            image_path: Path to image file
            
        Returns:
            np.ndarray: Loaded image
            
        Raises:
            OpenCVException: If image cannot be loaded
        """
        if not os.path.exists(image_path):
            raise OpenCVException(f"Image file not found: {image_path}")
        
        image = cv2.imread(image_path)
        if image is None:
            raise OpenCVException(f"Could not load image: {image_path}")
        
        self.logger.debug(f"Loaded image: {image_path} ({image.shape})")
        return image
    
    def save_image(self, image: np.ndarray, output_path: str) -> bool:
        """
        Save image to file
        
        Args:
            image: Image to save
            output_path: Output file path
            
        Returns:
            bool: True if successful
        """
        try:
            success = cv2.imwrite(output_path, image)
            if success:
                self.logger.debug(f"Saved image: {output_path}")
            return success
        except Exception as e:
            self.logger.error(f"Failed to save image: {str(e)}")
            return False
    
    def preprocess_image(self, image: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Preprocess image for pattern analysis
        
        Args:
            image: Input image
            
        Returns:
            Dict[str, np.ndarray]: Dictionary of processed images
        """
        processed = {}
        
        # Convert to grayscale
        if len(image.shape) == 3:
            processed['grayscale'] = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            processed['grayscale'] = image.copy()
        
        # Apply Gaussian blur
        processed['blurred'] = cv2.GaussianBlur(
            processed['grayscale'],
            self.config.gaussian_blur_kernel,
            self.config.gaussian_blur_sigma
        )
        
        # Edge detection
        processed['edges'] = cv2.Canny(
            processed['blurred'],
            self.config.canny_threshold1,
            self.config.canny_threshold2
        )
        
        # Adaptive threshold
        processed['threshold'] = cv2.adaptiveThreshold(
            processed['grayscale'],
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            11,
            2
        )
        
        if self.debug_mode:
            self._save_debug_images(processed, "preprocessing")
        
        return processed
    
    def detect_circles(self, image: np.ndarray) -> List[DetectedCircle]:
        """
        Detect circles in image using Hough Circle Transform
        
        Args:
            image: Input image (grayscale)
            
        Returns:
            List[DetectedCircle]: List of detected circles
        """
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray = image
        
        # Apply Gaussian blur
        blurred = cv2.GaussianBlur(gray, self.config.gaussian_blur_kernel, self.config.gaussian_blur_sigma)
        
        # Detect circles
        circles = cv2.HoughCircles(
            blurred,
            cv2.HOUGH_GRADIENT,
            dp=self.config.hough_circles_dp,
            minDist=self.config.hough_circles_min_dist,
            param1=self.config.hough_circles_param1,
            param2=self.config.hough_circles_param2,
            minRadius=self.config.hough_circles_min_radius,
            maxRadius=self.config.hough_circles_max_radius
        )
        
        detected_circles = []
        if circles is not None:
            circles = np.round(circles[0, :]).astype("int")
            for (x, y, r) in circles:
                # Calculate confidence based on circle quality
                confidence = self._calculate_circle_confidence(gray, x, y, r)
                detected_circles.append(DetectedCircle(x=x, y=y, radius=r, confidence=confidence))
        
        self.logger.debug(f"Detected {len(detected_circles)} circles")
        
        if self.debug_mode and detected_circles:
            self._save_circles_debug_image(image, detected_circles)
        
        return detected_circles
    
    def detect_lines(self, image: np.ndarray) -> List[DetectedLine]:
        """
        Detect lines in image using Hough Line Transform
        
        Args:
            image: Input image
            
        Returns:
            List[DetectedLine]: List of detected lines
        """
        # Preprocess image
        processed = self.preprocess_image(image)
        edges = processed['edges']
        
        # Detect lines using probabilistic Hough transform
        lines = cv2.HoughLinesP(
            edges,
            rho=1,
            theta=np.pi/180,
            threshold=50,
            minLineLength=30,
            maxLineGap=10
        )
        
        detected_lines = []
        if lines is not None:
            for line in lines:
                x1, y1, x2, y2 = line[0]
                confidence = self._calculate_line_confidence(edges, x1, y1, x2, y2)
                detected_lines.append(DetectedLine(
                    start_point=(x1, y1),
                    end_point=(x2, y2),
                    confidence=confidence
                ))
        
        self.logger.debug(f"Detected {len(detected_lines)} lines")
        
        if self.debug_mode and detected_lines:
            self._save_lines_debug_image(image, detected_lines)
        
        return detected_lines
    
    def detect_contours(self, image: np.ndarray) -> List[np.ndarray]:
        """
        Detect contours in image
        
        Args:
            image: Input image
            
        Returns:
            List[np.ndarray]: List of detected contours
        """
        # Preprocess image
        processed = self.preprocess_image(image)
        threshold = processed['threshold']
        
        # Find contours
        contours, _ = cv2.findContours(threshold, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        # Filter contours by area
        filtered_contours = []
        for contour in contours:
            area = cv2.contourArea(contour)
            # Use more lenient area filtering for better detection
            if area >= self.config.contour_min_area:
                filtered_contours.append(contour)
        
        self.logger.debug(f"Detected {len(filtered_contours)} contours")
        
        if self.debug_mode and filtered_contours:
            self._save_contours_debug_image(image, filtered_contours)
        
        return filtered_contours
    
    def extract_pattern_grid(self, circles: List[DetectedCircle]) -> Optional[List[Tuple[int, int]]]:
        """
        Extract 3x3 pattern grid from detected circles
        
        Args:
            circles: List of detected circles
            
        Returns:
            List[Tuple[int, int]]: 3x3 grid coordinates or None
        """
        if len(circles) < 9:
            self.logger.warning(f"Not enough circles for 3x3 grid: {len(circles)}")
            return None
        
        # Sort circles by confidence and take top 9
        sorted_circles = sorted(circles, key=lambda c: c.confidence, reverse=True)[:9]
        
        # Convert to coordinate list
        coords = [(c.x, c.y) for c in sorted_circles]
        
        # Organize into 3x3 grid
        grid = self._organize_points_to_grid(coords)
        
        if grid and len(grid) == 9:
            self.logger.debug("Successfully extracted 3x3 pattern grid")
            return grid
        
        return None
    
    def match_pattern_template(self, image: np.ndarray, template: np.ndarray, threshold: float = 0.8) -> List[Tuple[int, int, float]]:
        """
        Match pattern template in image
        
        Args:
            image: Input image
            template: Template to match
            threshold: Matching threshold (0-1)
            
        Returns:
            List[Tuple[int, int, float]]: List of (x, y, confidence) matches
        """
        # Convert to grayscale if needed
        if len(image.shape) == 3:
            gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray_image = image
        
        if len(template.shape) == 3:
            gray_template = cv2.cvtColor(template, cv2.COLOR_BGR2GRAY)
        else:
            gray_template = template
        
        # Perform template matching
        result = cv2.matchTemplate(gray_image, gray_template, cv2.TM_CCOEFF_NORMED)
        
        # Find matches above threshold
        locations = np.where(result >= threshold)
        matches = []
        
        for pt in zip(*locations[::-1]):
            confidence = result[pt[1], pt[0]]
            matches.append((pt[0], pt[1], confidence))
        
        self.logger.debug(f"Found {len(matches)} template matches")
        return matches
    
    def analyze_pattern_connectivity(self, grid_points: List[Tuple[int, int]], lines: List[DetectedLine]) -> List[Tuple[int, int]]:
        """
        Analyze pattern connectivity from grid points and detected lines
        
        Args:
            grid_points: 3x3 grid of pattern points
            lines: Detected lines in the image
            
        Returns:
            List[Tuple[int, int]]: Pattern connections as (from_index, to_index) pairs
        """
        if len(grid_points) != 9:
            return []
        
        connections = []
        
        # For each detected line, find which grid points it connects
        for line in lines:
            start_point = line.start_point
            end_point = line.end_point
            
            # Find closest grid points to line endpoints
            start_idx = self._find_closest_grid_point(start_point, grid_points)
            end_idx = self._find_closest_grid_point(end_point, grid_points)
            
            if start_idx != end_idx and start_idx is not None and end_idx is not None:
                connections.append((start_idx, end_idx))
        
        self.logger.debug(f"Analyzed pattern connectivity: {len(connections)} connections")
        return connections
    
    def create_debug_visualization(self, image: np.ndarray, circles: List[DetectedCircle], 
                                 lines: List[DetectedLine], pattern_sequence: List[int]) -> np.ndarray:
        """
        Create debug visualization with detected elements
        
        Args:
            image: Original image
            circles: Detected circles
            lines: Detected lines
            pattern_sequence: Pattern sequence
            
        Returns:
            np.ndarray: Debug visualization image
        """
        debug_image = image.copy()
        
        # Draw circles
        for i, circle in enumerate(circles):
            color = (0, 255, 0) if i < 9 else (0, 255, 255)  # Green for grid, yellow for extras
            cv2.circle(debug_image, (circle.x, circle.y), circle.radius, color, 2)
            cv2.putText(debug_image, str(i), (circle.x - 10, circle.y + 5), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        # Draw lines
        for line in lines:
            cv2.line(debug_image, line.start_point, line.end_point, (255, 0, 0), 2)
        
        # Draw pattern sequence
        if len(pattern_sequence) > 1 and len(circles) >= 9:
            for i in range(len(pattern_sequence) - 1):
                if pattern_sequence[i] < len(circles) and pattern_sequence[i + 1] < len(circles):
                    start_circle = circles[pattern_sequence[i]]
                    end_circle = circles[pattern_sequence[i + 1]]
                    cv2.line(debug_image, (start_circle.x, start_circle.y), 
                            (end_circle.x, end_circle.y), (0, 0, 255), 3)
        
        return debug_image
    
    def _calculate_circle_confidence(self, image: np.ndarray, x: int, y: int, radius: int) -> float:
        """Calculate confidence score for detected circle"""
        try:
            # Create a mask for the circle
            mask = np.zeros(image.shape, dtype=np.uint8)
            cv2.circle(mask, (x, y), radius, 255, -1)
            
            # Calculate mean intensity within circle
            mean_intensity = cv2.mean(image, mask=mask)[0]
            
            # Normalize to 0-1 range (higher intensity = higher confidence)
            confidence = min(1.0, mean_intensity / 255.0)
            return confidence
        except:
            return 0.5  # Default confidence
    
    def _calculate_line_confidence(self, edges: np.ndarray, x1: int, y1: int, x2: int, y2: int) -> float:
        """Calculate confidence score for detected line"""
        try:
            # Sample points along the line
            num_samples = 10
            line_points = []
            
            for i in range(num_samples):
                t = i / (num_samples - 1)
                x = int(x1 + t * (x2 - x1))
                y = int(y1 + t * (y2 - y1))
                if 0 <= x < edges.shape[1] and 0 <= y < edges.shape[0]:
                    line_points.append(edges[y, x])
            
            # Calculate confidence based on edge strength along line
            if line_points:
                confidence = np.mean(line_points) / 255.0
                return min(1.0, confidence)
            
            return 0.5
        except:
            return 0.5  # Default confidence
    
    def _organize_points_to_grid(self, points: List[Tuple[int, int]]) -> Optional[List[Tuple[int, int]]]:
        """Organize points into 3x3 grid"""
        if len(points) < 9:
            return None
        
        # Sort points by y-coordinate first, then x-coordinate
        sorted_points = sorted(points, key=lambda p: (p[1], p[0]))
        
        # Group into rows
        rows = []
        for i in range(0, 9, 3):
            row = sorted(sorted_points[i:i+3], key=lambda p: p[0])
            rows.extend(row)
        
        return rows
    
    def _find_closest_grid_point(self, point: Tuple[int, int], grid_points: List[Tuple[int, int]]) -> Optional[int]:
        """Find closest grid point to given point"""
        if not grid_points:
            return None
        
        min_distance = float('inf')
        closest_idx = None
        
        for i, grid_point in enumerate(grid_points):
            distance = np.sqrt((point[0] - grid_point[0])**2 + (point[1] - grid_point[1])**2)
            if distance < min_distance:
                min_distance = distance
                closest_idx = i
        
        # Only return if distance is reasonable (within 50 pixels)
        return closest_idx if min_distance < 50 else None
    
    def _build_pattern_sequence(self, connections: List[Tuple[int, int]]) -> List[int]:
        """Build pattern sequence from connections"""
        if not connections:
            return []
        
        # Simple approach: try to build a path through connections
        # This is a simplified implementation - real forensic tools would use more sophisticated algorithms
        
        # Start with the first connection
        sequence = [connections[0][0], connections[0][1]]
        used_connections = {0}
        
        # Try to extend the sequence
        while len(used_connections) < len(connections):
            extended = False
            last_point = sequence[-1]
            
            for i, (start, end) in enumerate(connections):
                if i in used_connections:
                    continue
                
                if start == last_point:
                    sequence.append(end)
                    used_connections.add(i)
                    extended = True
                    break
                elif end == last_point:
                    sequence.append(start)
                    used_connections.add(i)
                    extended = True
                    break
            
            if not extended:
                break
        
        return sequence
    
    def _save_debug_images(self, processed_images: Dict[str, np.ndarray], prefix: str):
        """Save debug images"""
        if not self.debug_mode:
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        for name, image in processed_images.items():
            filename = f"{prefix}_{name}_{timestamp}.png"
            self.save_image(image, filename)
    
    def _save_circles_debug_image(self, image: np.ndarray, circles: List[DetectedCircle]):
        """Save debug image with detected circles"""
        debug_image = image.copy()
        
        for i, circle in enumerate(circles):
            cv2.circle(debug_image, (circle.x, circle.y), circle.radius, (0, 255, 0), 2)
            cv2.putText(debug_image, f"{i}({circle.confidence:.2f})", 
                       (circle.x - 20, circle.y - circle.radius - 10),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"circles_debug_{timestamp}.png"
        self.save_image(debug_image, filename)
        self.logger.debug(f"Saved circles debug image: {filename}")
    
    def _save_lines_debug_image(self, image: np.ndarray, lines: List[DetectedLine]):
        """Save debug image with detected lines"""
        debug_image = image.copy()
        
        for line in lines:
            cv2.line(debug_image, line.start_point, line.end_point, (255, 0, 0), 2)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"lines_debug_{timestamp}.png"
        self.save_image(debug_image, filename)
        self.logger.debug(f"Saved lines debug image: {filename}")
    
    def _save_contours_debug_image(self, image: np.ndarray, contours: List[np.ndarray]):
        """Save debug image with detected contours"""
        debug_image = image.copy()
        cv2.drawContours(debug_image, contours, -1, (0, 255, 255), 2)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"contours_debug_{timestamp}.png"
        self.save_image(debug_image, filename)
        self.logger.debug(f"Saved contours debug image: {filename}")
    
    def get_version_info(self) -> Dict[str, Any]:
        """
        Get OpenCV version and capability information
        
        Returns:
            Dict[str, Any]: Version and capability info
        """
        if not OPENCV_AVAILABLE:
            return {
                'available': False,
                'version': None,
                'capabilities': []
            }
        
        return {
            'available': True,
            'version': cv2.__version__,
            'capabilities': [
                'circle_detection',
                'line_detection',
                'contour_detection',
                'template_matching',
                'image_preprocessing',
                'pattern_analysis'
            ],
            'build_info': cv2.getBuildInformation() if hasattr(cv2, 'getBuildInformation') else 'Not available'
        }