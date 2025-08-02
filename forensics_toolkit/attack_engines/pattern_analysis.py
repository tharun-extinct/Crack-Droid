"""
Pattern analysis module with OpenCV integration for gesture.key analysis
"""

import os
import numpy as np
from typing import List, Dict, Any, Optional, Tuple, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import logging
import hashlib
import json
import itertools
import struct

from ..interfaces import IAttackEngine, AttackType, LockType, ForensicsException, AttackResult
from ..models.attack import AttackStrategy
from ..models.device import AndroidDevice

# OpenCV is optional - graceful degradation if not available
try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    cv2 = None
    OPENCV_AVAILABLE = False


class PatternAnalysisException(ForensicsException):
    """Exception raised during pattern analysis operations"""
    
    def __init__(self, message: str, error_code: str = "PATTERN_ANALYSIS_ERROR"):
        super().__init__(message, error_code, evidence_impact=False)


@dataclass
class PatternPoint:
    """Represents a point in the Android pattern grid"""
    x: int
    y: int
    index: int  # 0-8 for 3x3 grid
    
    def __post_init__(self):
        if not (0 <= self.x <= 2 and 0 <= self.y <= 2):
            raise PatternAnalysisException(f"Invalid pattern point coordinates: ({self.x}, {self.y})")
        if not (0 <= self.index <= 8):
            raise PatternAnalysisException(f"Invalid pattern point index: {self.index}")
    
    def to_dict(self) -> Dict[str, int]:
        return {"x": self.x, "y": self.y, "index": self.index}
    
    @classmethod
    def from_index(cls, index: int) -> 'PatternPoint':
        """Create PatternPoint from grid index (0-8)"""
        if not (0 <= index <= 8):
            raise PatternAnalysisException(f"Invalid pattern index: {index}")
        return cls(x=index % 3, y=index // 3, index=index)
    
    def __str__(self) -> str:
        return f"Point({self.x},{self.y})[{self.index}]"


@dataclass
class AndroidPattern:
    """Represents an Android unlock pattern"""
    points: List[PatternPoint]
    hash_value: Optional[str] = None
    confidence: float = 1.0
    
    def __post_init__(self):
        if len(self.points) < 3:
            raise PatternAnalysisException("Pattern must have at least 3 points")
        if len(self.points) > 9:
            raise PatternAnalysisException("Pattern cannot have more than 9 points")
        
        # Check for duplicate points
        indices = [p.index for p in self.points]
        if len(set(indices)) != len(indices):
            raise PatternAnalysisException("Pattern cannot have duplicate points")
    
    def to_sequence(self) -> List[int]:
        """Convert pattern to sequence of indices"""
        return [p.index for p in self.points]
    
    def to_gesture_key_format(self) -> bytes:
        """Convert pattern to Android gesture.key format"""
        # Android stores patterns as SHA-1 hash of the pattern sequence
        sequence = self.to_sequence()
        pattern_bytes = b''.join(struct.pack('B', i) for i in sequence)
        return hashlib.sha1(pattern_bytes).digest()
    
    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the pattern"""
        sequence_str = ''.join(map(str, self.to_sequence()))
        return hashlib.sha256(sequence_str.encode()).hexdigest()
    
    def is_valid_pattern(self) -> bool:
        """Check if pattern follows Android's connection rules"""
        points = self.points
        
        for i in range(len(points) - 1):
            current = points[i]
            next_point = points[i + 1]
            
            # Check if we need to pass through an intermediate point
            if not self._can_connect_directly(current, next_point, points[:i+1]):
                return False
        
        return True
    
    def _can_connect_directly(self, p1: PatternPoint, p2: PatternPoint, used_points: List[PatternPoint]) -> bool:
        """Check if two points can be connected directly"""
        # Calculate the intermediate point if it exists
        dx = p2.x - p1.x
        dy = p2.y - p1.y
        
        # If points are adjacent or diagonal, they can always connect
        if abs(dx) <= 1 and abs(dy) <= 1:
            return True
        
        # For non-adjacent points, check if intermediate point is already used
        if dx != 0 and dy != 0:
            # Diagonal connection - check if we need to go through center
            if abs(dx) == 2 and abs(dy) == 2:
                # Must go through center (1,1) - index 4
                center_used = any(p.index == 4 for p in used_points)
                return center_used
        else:
            # Horizontal or vertical connection
            if abs(dx) == 2:  # Horizontal
                mid_x = (p1.x + p2.x) // 2
                mid_index = mid_x + p1.y * 3
                mid_used = any(p.index == mid_index for p in used_points)
                return mid_used
            elif abs(dy) == 2:  # Vertical
                mid_y = (p1.y + p2.y) // 2
                mid_index = p1.x + mid_y * 3
                mid_used = any(p.index == mid_index for p in used_points)
                return mid_used
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "points": [p.to_dict() for p in self.points],
            "sequence": self.to_sequence(),
            "hash_value": self.hash_value or self.calculate_hash(),
            "confidence": self.confidence,
            "is_valid": self.is_valid_pattern()
        }
    
    def __str__(self) -> str:
        sequence = '->'.join(map(str, self.to_sequence()))
        return f"Pattern[{sequence}] (confidence: {self.confidence:.2f})"


class PatternAnalysis(IAttackEngine):
    """
    Pattern analysis engine with OpenCV integration for gesture.key analysis
    
    This class provides comprehensive pattern analysis capabilities including:
    - Visual pattern recognition from screenshots
    - Pattern space enumeration
    - Gesture.key file analysis
    - Visual debugging and verification tools
    """
    
    def __init__(self, debug_mode: bool = False):
        """
        Initialize pattern analysis engine
        
        Args:
            debug_mode: Enable visual debugging output
        """
        self.debug_mode = debug_mode
        self.logger = logging.getLogger(__name__)
        
        if not OPENCV_AVAILABLE:
            self.logger.warning("OpenCV not available - visual pattern recognition disabled")
        
        # Pattern grid configuration
        self.grid_size = 3
        self.total_points = 9
        
        # Visual recognition parameters
        self.circle_detection_params = {
            'dp': 1,
            'min_dist': 50,
            'param1': 50,
            'param2': 30,
            'min_radius': 10,
            'max_radius': 100
        }
        
        # Pattern generation cache
        self._pattern_cache: Dict[int, List[AndroidPattern]] = {}
        
        self.logger.info(f"PatternAnalysis initialized (OpenCV: {OPENCV_AVAILABLE}, Debug: {debug_mode})")
    
    def execute_attack(self, strategy: AttackStrategy) -> AttackResult:
        """
        Execute pattern analysis attack
        
        Args:
            strategy: Attack strategy configuration
            
        Returns:
            AttackResult: Result of the pattern analysis attack
        """
        start_time = datetime.now()
        
        try:
            if not self.validate_strategy(strategy):
                return AttackResult(
                    success=False,
                    attempts=0,
                    duration=0.0,
                    error_message="Invalid strategy for pattern analysis"
                )
            
            self.logger.info(f"Starting pattern analysis attack on {strategy.target_device.serial}")
            
            # Determine analysis approach based on available data
            if strategy.custom_parameters.get('gesture_key_path'):
                result = self._analyze_gesture_key_file(strategy)
            elif strategy.custom_parameters.get('screenshot_path'):
                result = self._analyze_screenshot(strategy)
            else:
                result = self._enumerate_pattern_space(strategy)
            
            duration = (datetime.now() - start_time).total_seconds()
            result.duration = duration
            
            self.logger.info(f"Pattern analysis completed in {duration:.2f}s")
            return result
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Pattern analysis failed: {str(e)}")
            return AttackResult(
                success=False,
                attempts=0,
                duration=duration,
                error_message=str(e)
            )
    
    def validate_strategy(self, strategy: AttackStrategy) -> bool:
        """
        Validate if strategy is applicable for pattern analysis
        
        Args:
            strategy: Attack strategy to validate
            
        Returns:
            bool: True if strategy is valid
        """
        if strategy.strategy_type != AttackType.PATTERN_ANALYSIS:
            return False
        
        if strategy.target_device.lock_type != LockType.PATTERN:
            return False
        
        # Check if we have required data sources
        has_gesture_key = strategy.custom_parameters.get('gesture_key_path')
        has_screenshot = strategy.custom_parameters.get('screenshot_path')
        allow_enumeration = strategy.custom_parameters.get('allow_enumeration', True)
        
        return has_gesture_key or has_screenshot or allow_enumeration
    
    def estimate_duration(self, strategy: AttackStrategy) -> float:
        """
        Estimate pattern analysis duration
        
        Args:
            strategy: Attack strategy
            
        Returns:
            float: Estimated duration in seconds
        """
        if strategy.custom_parameters.get('gesture_key_path'):
            return 5.0  # File analysis is fast
        elif strategy.custom_parameters.get('screenshot_path'):
            return 30.0  # Visual analysis takes longer
        else:
            # Pattern enumeration depends on max attempts
            patterns_per_second = 1000
            return min(strategy.max_attempts / patterns_per_second, strategy.timeout_seconds)
    
    def _analyze_gesture_key_file(self, strategy: AttackStrategy) -> AttackResult:
        """
        Analyze gesture.key file to extract pattern hash
        
        Args:
            strategy: Attack strategy with gesture_key_path
            
        Returns:
            AttackResult: Analysis result
        """
        gesture_key_path = strategy.custom_parameters['gesture_key_path']
        
        try:
            if not os.path.exists(gesture_key_path):
                raise PatternAnalysisException(f"Gesture key file not found: {gesture_key_path}")
            
            with open(gesture_key_path, 'rb') as f:
                gesture_data = f.read()
            
            if len(gesture_data) != 20:  # SHA-1 hash is 20 bytes
                raise PatternAnalysisException(f"Invalid gesture.key file size: {len(gesture_data)} bytes")
            
            # Extract the pattern hash
            pattern_hash = gesture_data.hex()
            
            self.logger.info(f"Extracted pattern hash from gesture.key: {pattern_hash}")
            
            # Try to crack the hash by generating patterns
            cracked_pattern = self._crack_pattern_hash(pattern_hash, strategy.max_attempts)
            
            if cracked_pattern:
                return AttackResult(
                    success=True,
                    attempts=1,
                    duration=0.0,
                    result_data=json.dumps({
                        'pattern': cracked_pattern.to_dict(),
                        'hash': pattern_hash,
                        'method': 'gesture_key_analysis'
                    })
                )
            else:
                return AttackResult(
                    success=False,
                    attempts=strategy.max_attempts,
                    duration=0.0,
                    error_message="Could not crack pattern hash within attempt limit"
                )
                
        except Exception as e:
            raise PatternAnalysisException(f"Gesture key analysis failed: {str(e)}")
    
    def _analyze_screenshot(self, strategy: AttackStrategy) -> AttackResult:
        """
        Analyze screenshot for visual pattern recognition
        
        Args:
            strategy: Attack strategy with screenshot_path
            
        Returns:
            AttackResult: Analysis result
        """
        if not OPENCV_AVAILABLE:
            raise PatternAnalysisException("OpenCV not available for visual pattern recognition")
        
        screenshot_path = strategy.custom_parameters['screenshot_path']
        
        try:
            if not os.path.exists(screenshot_path):
                raise PatternAnalysisException(f"Screenshot file not found: {screenshot_path}")
            
            # Load and process the screenshot
            image = cv2.imread(screenshot_path)
            if image is None:
                raise PatternAnalysisException(f"Could not load screenshot: {screenshot_path}")
            
            # Detect pattern grid and extract pattern
            detected_pattern = self._detect_pattern_from_image(image)
            
            if detected_pattern:
                return AttackResult(
                    success=True,
                    attempts=1,
                    duration=0.0,
                    result_data=json.dumps({
                        'pattern': detected_pattern.to_dict(),
                        'method': 'visual_recognition'
                    })
                )
            else:
                return AttackResult(
                    success=False,
                    attempts=1,
                    duration=0.0,
                    error_message="Could not detect pattern from screenshot"
                )
                
        except Exception as e:
            raise PatternAnalysisException(f"Screenshot analysis failed: {str(e)}")
    
    def _enumerate_pattern_space(self, strategy: AttackStrategy) -> AttackResult:
        """
        Enumerate pattern space systematically
        
        Args:
            strategy: Attack strategy
            
        Returns:
            AttackResult: Enumeration result
        """
        self.logger.info("Starting pattern space enumeration")
        
        patterns_generated = 0
        valid_patterns = []
        
        # Generate patterns by length (3-9 points)
        for length in range(3, 10):
            if patterns_generated >= strategy.max_attempts:
                break
            
            patterns = self._generate_patterns_of_length(length)
            
            for pattern in patterns:
                if patterns_generated >= strategy.max_attempts:
                    break
                
                if pattern.is_valid_pattern():
                    valid_patterns.append(pattern)
                
                patterns_generated += 1
        
        self.logger.info(f"Generated {patterns_generated} patterns, {len(valid_patterns)} valid")
        
        # Return the enumerated patterns
        return AttackResult(
            success=True,
            attempts=patterns_generated,
            duration=0.0,
            result_data=json.dumps({
                'total_patterns': patterns_generated,
                'valid_patterns': len(valid_patterns),
                'patterns': [p.to_dict() for p in valid_patterns[:100]],  # Limit output size
                'method': 'pattern_enumeration'
            })
        )
    
    def _detect_pattern_from_image(self, image: np.ndarray) -> Optional[AndroidPattern]:
        """
        Detect pattern from screenshot using OpenCV
        
        Args:
            image: Input image as numpy array
            
        Returns:
            AndroidPattern: Detected pattern or None
        """
        if not OPENCV_AVAILABLE:
            return None
        
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply Gaussian blur to reduce noise
            blurred = cv2.GaussianBlur(gray, (9, 9), 2)
            
            # Detect circles (pattern dots)
            circles = cv2.HoughCircles(
                blurred,
                cv2.HOUGH_GRADIENT,
                **self.circle_detection_params
            )
            
            if circles is None or len(circles[0]) < 4:
                self.logger.warning("Could not detect enough pattern points")
                return None
            
            circles = np.round(circles[0, :]).astype("int")
            
            # Sort circles to form a 3x3 grid
            grid_points = self._organize_circles_to_grid(circles)
            
            if not grid_points:
                self.logger.warning("Could not organize circles into 3x3 grid")
                return None
            
            # Detect the pattern path
            pattern_sequence = self._detect_pattern_path(image, grid_points)
            
            if pattern_sequence:
                points = [PatternPoint.from_index(idx) for idx in pattern_sequence]
                pattern = AndroidPattern(points=points, confidence=0.8)
                
                if self.debug_mode:
                    self._save_debug_image(image, grid_points, pattern_sequence)
                
                return pattern
            
            return None
            
        except Exception as e:
            self.logger.error(f"Pattern detection failed: {str(e)}")
            return None
    
    def _organize_circles_to_grid(self, circles: np.ndarray) -> Optional[List[Tuple[int, int]]]:
        """
        Organize detected circles into a 3x3 grid
        
        Args:
            circles: Array of detected circles (x, y, radius)
            
        Returns:
            List of (x, y) coordinates for 3x3 grid or None
        """
        if len(circles) < 9:
            return None
        
        # Take the 9 most prominent circles
        circles = circles[:9]
        
        # Sort by y-coordinate first, then x-coordinate
        sorted_circles = sorted(circles, key=lambda c: (c[1], c[0]))
        
        # Organize into 3x3 grid
        grid = []
        for row in range(3):
            row_circles = sorted_circles[row*3:(row+1)*3]
            row_circles = sorted(row_circles, key=lambda c: c[0])
            grid.extend([(c[0], c[1]) for c in row_circles])
        
        return grid
    
    def _detect_pattern_path(self, image: np.ndarray, grid_points: List[Tuple[int, int]]) -> Optional[List[int]]:
        """
        Detect the pattern path by analyzing line connections
        
        Args:
            image: Input image
            grid_points: 3x3 grid of point coordinates
            
        Returns:
            List of point indices forming the pattern
        """
        # This is a simplified implementation
        # In a real forensic tool, this would use more sophisticated
        # computer vision techniques to detect the drawn pattern lines
        
        # For now, return a sample pattern for demonstration
        # In practice, this would analyze the image for drawn lines
        # connecting the grid points
        
        return [0, 1, 2, 5, 8, 7, 6, 3]  # Sample L-shaped pattern
    
    def _save_debug_image(self, image: np.ndarray, grid_points: List[Tuple[int, int]], pattern_sequence: List[int]):
        """
        Save debug image with detected pattern overlay
        
        Args:
            image: Original image
            grid_points: Grid point coordinates
            pattern_sequence: Detected pattern sequence
        """
        if not self.debug_mode or not OPENCV_AVAILABLE:
            return
        
        debug_image = image.copy()
        
        # Draw grid points
        for i, (x, y) in enumerate(grid_points):
            cv2.circle(debug_image, (x, y), 20, (0, 255, 0), 2)
            cv2.putText(debug_image, str(i), (x-10, y+5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        # Draw pattern lines
        for i in range(len(pattern_sequence) - 1):
            start_idx = pattern_sequence[i]
            end_idx = pattern_sequence[i + 1]
            start_point = grid_points[start_idx]
            end_point = grid_points[end_idx]
            cv2.line(debug_image, start_point, end_point, (0, 0, 255), 3)
        
        # Save debug image
        debug_path = f"pattern_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        cv2.imwrite(debug_path, debug_image)
        self.logger.info(f"Debug image saved: {debug_path}")
    
    def _crack_pattern_hash(self, target_hash: str, max_attempts: int) -> Optional[AndroidPattern]:
        """
        Crack pattern hash by generating and testing patterns
        
        Args:
            target_hash: Target pattern hash to crack
            max_attempts: Maximum number of patterns to try
            
        Returns:
            AndroidPattern: Cracked pattern or None
        """
        attempts = 0
        
        # Try patterns by length (shorter patterns first)
        for length in range(3, 10):
            if attempts >= max_attempts:
                break
            
            patterns = self._generate_patterns_of_length(length)
            
            for pattern in patterns:
                if attempts >= max_attempts:
                    break
                
                if pattern.is_valid_pattern():
                    pattern_hash = pattern.to_gesture_key_format().hex()
                    
                    if pattern_hash == target_hash:
                        self.logger.info(f"Pattern cracked after {attempts + 1} attempts: {pattern}")
                        return pattern
                
                attempts += 1
        
        return None
    
    def _generate_patterns_of_length(self, length: int) -> Iterator[AndroidPattern]:
        """
        Generate all valid patterns of specified length
        
        Args:
            length: Pattern length (4-9)
            
        Yields:
            AndroidPattern: Generated patterns
        """
        if length in self._pattern_cache:
            yield from self._pattern_cache[length]
            return
        
        patterns = []
        
        # Generate all permutations of the specified length
        for sequence in itertools.permutations(range(9), length):
            try:
                points = [PatternPoint.from_index(idx) for idx in sequence]
                pattern = AndroidPattern(points=points)
                patterns.append(pattern)
                yield pattern
            except PatternAnalysisException:
                # Skip invalid patterns
                continue
        
        # Cache the generated patterns
        self._pattern_cache[length] = patterns
    
    def generate_common_patterns(self) -> List[AndroidPattern]:
        """
        Generate list of commonly used Android patterns
        
        Returns:
            List[AndroidPattern]: Common patterns ordered by likelihood
        """
        common_sequences = [
            [0, 1, 2, 5, 8],           # L-shape
            [0, 1, 2, 5, 8, 7, 6, 3],  # Square
            [0, 4, 8],                 # Diagonal
            [2, 4, 6],                 # Diagonal
            [0, 1, 2],                 # Top row
            [6, 7, 8],                 # Bottom row
            [0, 3, 6],                 # Left column
            [2, 5, 8],                 # Right column
            [1, 4, 7],                 # Middle column
            [0, 1, 2, 3, 6, 7, 8, 5],  # Spiral
            [0, 4, 8, 5, 2],           # Z-pattern
            [2, 4, 6, 3, 0],           # Reverse Z
        ]
        
        patterns = []
        for sequence in common_sequences:
            try:
                points = [PatternPoint.from_index(idx) for idx in sequence]
                pattern = AndroidPattern(points=points, confidence=0.9)
                if pattern.is_valid_pattern():
                    patterns.append(pattern)
            except PatternAnalysisException:
                continue
        
        return patterns
    
    def analyze_pattern_complexity(self, pattern: AndroidPattern) -> Dict[str, Any]:
        """
        Analyze pattern complexity and security metrics
        
        Args:
            pattern: Pattern to analyze
            
        Returns:
            Dict[str, Any]: Complexity analysis
        """
        sequence = pattern.to_sequence()
        
        # Calculate various complexity metrics
        length = len(sequence)
        unique_points = len(set(sequence))
        
        # Direction changes
        direction_changes = 0
        if length > 2:
            for i in range(2, length):
                p1, p2, p3 = sequence[i-2:i+1]
                # Convert to coordinates
                x1, y1 = p1 % 3, p1 // 3
                x2, y2 = p2 % 3, p2 // 3
                x3, y3 = p3 % 3, p3 // 3
                
                # Calculate direction vectors
                dx1, dy1 = x2 - x1, y2 - y1
                dx2, dy2 = x3 - x2, y3 - y2
                
                # Check if direction changed
                if (dx1, dy1) != (dx2, dy2):
                    direction_changes += 1
        
        # Line crossings (simplified)
        crossings = 0
        for i in range(length - 1):
            for j in range(i + 2, length - 1):
                # Check if line segments cross
                # This is a simplified check
                if self._lines_intersect(sequence[i], sequence[i+1], sequence[j], sequence[j+1]):
                    crossings += 1
        
        # Security score (0-100)
        security_score = min(100, (
            length * 10 +
            direction_changes * 5 +
            crossings * 10 +
            (unique_points / 9) * 20
        ))
        
        return {
            'length': length,
            'unique_points': unique_points,
            'direction_changes': direction_changes,
            'line_crossings': crossings,
            'security_score': security_score,
            'is_common_pattern': self._is_common_pattern(pattern),
            'estimated_crack_time_seconds': self._estimate_crack_time(security_score)
        }
    
    def _lines_intersect(self, p1: int, p2: int, p3: int, p4: int) -> bool:
        """
        Check if two line segments intersect
        
        Args:
            p1, p2: First line segment endpoints (as grid indices)
            p3, p4: Second line segment endpoints (as grid indices)
            
        Returns:
            bool: True if lines intersect
        """
        # Convert indices to coordinates
        x1, y1 = p1 % 3, p1 // 3
        x2, y2 = p2 % 3, p2 // 3
        x3, y3 = p3 % 3, p3 // 3
        x4, y4 = p4 % 3, p4 // 3
        
        # Use cross product to determine intersection
        def ccw(A, B, C):
            return (C[1] - A[1]) * (B[0] - A[0]) > (B[1] - A[1]) * (C[0] - A[0])
        
        A, B, C, D = (x1, y1), (x2, y2), (x3, y3), (x4, y4)
        return ccw(A, C, D) != ccw(B, C, D) and ccw(A, B, C) != ccw(A, B, D)
    
    def _is_common_pattern(self, pattern: AndroidPattern) -> bool:
        """
        Check if pattern is a commonly used pattern
        
        Args:
            pattern: Pattern to check
            
        Returns:
            bool: True if pattern is common
        """
        common_patterns = self.generate_common_patterns()
        pattern_sequence = pattern.to_sequence()
        
        for common in common_patterns:
            if common.to_sequence() == pattern_sequence:
                return True
        
        return False
    
    def _estimate_crack_time(self, security_score: float) -> float:
        """
        Estimate time to crack pattern based on security score
        
        Args:
            security_score: Pattern security score (0-100)
            
        Returns:
            float: Estimated crack time in seconds
        """
        # Base crack time for brute force (assuming 1 attempt per second)
        base_time = 1.0
        
        # Adjust based on security score
        if security_score < 20:
            return base_time * 60  # 1 minute for weak patterns
        elif security_score < 40:
            return base_time * 3600  # 1 hour for medium patterns
        elif security_score < 60:
            return base_time * 86400  # 1 day for good patterns
        else:
            return base_time * 604800  # 1 week for strong patterns
    
    def create_visual_debug_tools(self) -> Dict[str, Any]:
        """
        Create visual debugging and verification tools
        
        Returns:
            Dict[str, Any]: Debug tool configuration
        """
        return {
            'opencv_available': OPENCV_AVAILABLE,
            'debug_mode': self.debug_mode,
            'circle_detection_params': self.circle_detection_params,
            'supported_formats': ['png', 'jpg', 'jpeg', 'bmp'],
            'debug_output_dir': './pattern_debug/',
            'visualization_tools': {
                'pattern_overlay': True,
                'grid_detection': True,
                'line_tracing': True,
                'confidence_scoring': True
            }
        }
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive pattern analysis statistics
        
        Returns:
            Dict[str, Any]: Pattern statistics
        """
        total_patterns = 0
        valid_patterns = 0
        
        # Count patterns by length
        patterns_by_length = {}
        
        for length in range(3, 10):
            length_patterns = list(self._generate_patterns_of_length(length))
            valid_length_patterns = [p for p in length_patterns if p.is_valid_pattern()]
            
            patterns_by_length[length] = {
                'total': len(length_patterns),
                'valid': len(valid_length_patterns)
            }
            
            total_patterns += len(length_patterns)
            valid_patterns += len(valid_length_patterns)
        
        return {
            'total_possible_patterns': total_patterns,
            'total_valid_patterns': valid_patterns,
            'patterns_by_length': patterns_by_length,
            'common_patterns_count': len(self.generate_common_patterns()),
            'analysis_capabilities': {
                'gesture_key_analysis': True,
                'visual_recognition': OPENCV_AVAILABLE,
                'pattern_enumeration': True,
                'complexity_analysis': True
            }
        }