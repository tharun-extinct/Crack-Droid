"""
Dictionary attack module with wordlist management and hybrid strategies
"""

import os
import hashlib
import threading
from typing import List, Dict, Any, Optional, Iterator, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import logging

from ..interfaces import IAttackEngine, AttackType, LockType, ForensicsException
from ..models.attack import AttackStrategy, AttackStatus
from ..models.device import AndroidDevice


class DictionaryAttackException(ForensicsException):
    """Exception raised during dictionary attack operations"""
    
    def __init__(self, message: str, error_code: str = "DICTIONARY_ATTACK_ERROR"):
        super().__init__(message, error_code, evidence_impact=False)


@dataclass
class WordlistInfo:
    """Information about a wordlist file"""
    path: str
    name: str
    size: int = 0
    entry_count: int = 0
    hash_md5: Optional[str] = None
    last_modified: Optional[datetime] = None
    priority: int = 0  # Higher priority = processed first
    
    def __post_init__(self):
        """Initialize wordlist information"""
        if os.path.exists(self.path):
            stat = os.stat(self.path)
            self.size = stat.st_size
            self.last_modified = datetime.fromtimestamp(stat.st_mtime)
            self._calculate_hash()
            self._count_entries()
    
    def _calculate_hash(self):
        """Calculate MD5 hash of wordlist file"""
        try:
            with open(self.path, 'rb') as f:
                self.hash_md5 = hashlib.md5(f.read()).hexdigest()
        except Exception:
            self.hash_md5 = None
    
    def _count_entries(self):
        """Count entries in wordlist file"""
        try:
            with open(self.path, 'r', encoding='utf-8', errors='ignore') as f:
                self.entry_count = sum(1 for line in f if line.strip())
        except Exception:
            self.entry_count = 0


@dataclass
class DictionaryStats:
    """Statistics for dictionary attack progress"""
    total_wordlists: int = 0
    processed_wordlists: int = 0
    total_patterns: int = 0
    tested_patterns: int = 0
    successful_patterns: int = 0
    duplicate_patterns: int = 0
    invalid_patterns: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    current_wordlist: Optional[str] = None
    current_pattern: Optional[str] = None
    
    @property
    def progress_percentage(self) -> float:
        """Calculate overall progress percentage"""
        if self.total_patterns == 0:
            return 0.0
        return (self.tested_patterns / self.total_patterns) * 100
    
    @property
    def patterns_per_second(self) -> float:
        """Calculate patterns tested per second"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if elapsed == 0:
            return 0.0
        return self.tested_patterns / elapsed


class DictionaryAttack(IAttackEngine):
    """
    Dictionary attack engine with wordlist management and hybrid strategies
    
    This engine manages wordlists, implements common PIN/pattern databases,
    and supports hybrid attack strategies combining dictionary and mask attacks.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize dictionary attack engine
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self._wordlists: Dict[str, WordlistInfo] = {}
        self._pattern_cache: Set[str] = set()
        self._stats: Optional[DictionaryStats] = None
        self._stop_event = threading.Event()
        
        # Built-in pattern databases
        self._common_pins = self._load_common_pins()
        self._common_patterns = self._load_common_patterns()
        self._common_passwords = self._load_common_passwords()
    
    def _load_common_pins(self) -> List[str]:
        """Load common PIN patterns"""
        return [
            # Most common PINs
            "1234", "0000", "1111", "1212", "7777", "1004", "2000", "4444",
            "2222", "6969", "9999", "3333", "5555", "6666", "1313", "8888",
            "4321", "2001", "1010", "1122", "1001", "2580", "0123", "1230",
            
            # Date-based patterns
            "2023", "2024", "2025", "1990", "1991", "1992", "1993", "1994",
            "1995", "1996", "1997", "1998", "1999", "2000", "2001", "2002",
            
            # Sequential patterns
            "0123", "1234", "2345", "3456", "4567", "5678", "6789", "9876",
            "8765", "7654", "6543", "5432", "4321", "3210", "2109", "1098",
            
            # Repeated digits
            "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777",
            "8888", "9999", "1010", "2020", "3030", "4040", "5050", "6060",
            
            # Phone keypad patterns
            "2580", "1470", "3690", "1590", "7410", "8520", "9630", "4560",
            "1357", "2468", "1379", "3571", "7531", "9513", "1593", "7539"
        ]
    
    def _load_common_patterns(self) -> List[str]:
        """Load common Android lock patterns"""
        # Android pattern grid:
        # 1 2 3
        # 4 5 6
        # 7 8 9
        return [
            # Simple patterns
            "123", "147", "159", "357", "789", "741", "963", "951",
            "135", "246", "468", "258", "456", "654", "321", "987",
            
            # L-shapes
            "1236", "1478", "3698", "7894", "1456", "2569", "3478", "1596",
            
            # Common shapes
            "12369", "14789", "15963", "25874", "35791", "45612", "65432",
            "74185", "85296", "95174", "12587", "36987", "14725", "96321",
            
            # Complex patterns
            "123654", "147852", "159753", "357159", "789456", "741963",
            "135792", "246813", "468135", "258741", "456789", "654321",
            
            # Zigzag patterns
            "142536", "362514", "741852", "963258", "159357", "357951",
            "123789", "321987", "147963", "369741", "159753", "357159"
        ]
    
    def _load_common_passwords(self) -> List[str]:
        """Load common password patterns"""
        return [
            # Simple passwords
            "password", "123456", "password123", "admin", "user", "guest",
            "root", "test", "demo", "sample", "default", "login", "pass",
            
            # Common words
            "android", "phone", "mobile", "device", "unlock", "secret",
            "private", "secure", "access", "entry", "open", "key", "code",
            
            # Variations with numbers
            "password1", "password12", "password123", "admin123", "user123",
            "test123", "demo123", "android123", "phone123", "mobile123",
            
            # Common substitutions
            "p@ssword", "p@ssw0rd", "passw0rd", "@ndroid", "m0bile", "s3cret",
            "pr1vate", "s3cure", "@ccess", "3ntry", "0pen", "k3y", "c0de",
            
            # Keyboard patterns
            "qwerty", "qwertyui", "asdfgh", "zxcvbn", "123qwe", "qwe123",
            "abc123", "123abc", "asd123", "123asd", "zxc123", "123zxc"
        ]
    
    def add_wordlist(self, path: str, name: Optional[str] = None, priority: int = 0) -> bool:
        """
        Add a wordlist file to the attack engine
        
        Args:
            path: Path to wordlist file
            name: Optional name for the wordlist
            priority: Priority level (higher = processed first)
            
        Returns:
            bool: True if wordlist was added successfully
        """
        try:
            if not os.path.exists(path):
                self.logger.error(f"Wordlist file not found: {path}")
                return False
            
            if not name:
                name = Path(path).stem
            
            wordlist_info = WordlistInfo(
                path=path,
                name=name,
                priority=priority
            )
            
            self._wordlists[path] = wordlist_info
            self.logger.info(f"Added wordlist: {name} ({wordlist_info.entry_count} entries)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add wordlist {path}: {e}")
            return False
    
    def remove_wordlist(self, path: str) -> bool:
        """
        Remove a wordlist from the attack engine
        
        Args:
            path: Path to wordlist file
            
        Returns:
            bool: True if wordlist was removed
        """
        if path in self._wordlists:
            del self._wordlists[path]
            self.logger.info(f"Removed wordlist: {path}")
            return True
        return False
    
    def get_wordlist_info(self) -> List[WordlistInfo]:
        """
        Get information about all loaded wordlists
        
        Returns:
            List[WordlistInfo]: List of wordlist information
        """
        return list(self._wordlists.values())
    
    def validate_strategy(self, strategy: AttackStrategy) -> bool:
        """
        Validate if strategy is applicable for dictionary attack
        
        Args:
            strategy: Attack strategy to validate
            
        Returns:
            bool: True if strategy is valid
        """
        try:
            # Check strategy type
            if strategy.strategy_type not in [AttackType.DICTIONARY, AttackType.HYBRID]:
                return False
            
            # Check device compatibility
            capabilities = strategy.target_device.get_forensic_capabilities()
            if not capabilities.get('brute_force_viable', False):
                return False
            
            # Check if wordlists are available (built-in patterns are always available)
            if not strategy.wordlists and not self._wordlists:
                self.logger.debug("No external wordlists available, using built-in patterns only")
            
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
        
        # Count total patterns
        total_patterns = self._estimate_total_patterns(strategy)
        
        # Base rate (patterns per second)
        base_rate = self._calculate_base_rate(strategy)
        
        if base_rate <= 0:
            return float(strategy.timeout_seconds)
        
        # Calculate estimated time
        estimated_time = total_patterns / base_rate
        
        return min(estimated_time, strategy.timeout_seconds)
    
    def _estimate_total_patterns(self, strategy: AttackStrategy) -> int:
        """Estimate total number of patterns to test"""
        total = 0
        
        # Count built-in patterns
        device = strategy.target_device
        if device.lock_type == LockType.PIN:
            total += len(self._common_pins)
        elif device.lock_type == LockType.PATTERN:
            total += len(self._common_patterns)
        elif device.lock_type == LockType.PASSWORD:
            total += len(self._common_passwords)
        
        # Count wordlist entries
        for wordlist_path in strategy.wordlists:
            if wordlist_path in self._wordlists:
                total += self._wordlists[wordlist_path].entry_count
            else:
                # Estimate for unknown wordlists
                total += 10000
        
        # Count mask patterns (simplified)
        for mask in strategy.mask_patterns:
            total += self._estimate_mask_combinations(mask)
        
        return min(total, strategy.max_attempts)
    
    def _estimate_mask_combinations(self, mask: str) -> int:
        """Estimate combinations for a mask pattern"""
        combinations = 1
        i = 0
        
        while i < len(mask):
            if i < len(mask) - 1 and mask[i] == '?':
                # Mask character
                char_type = mask[i + 1]
                if char_type == 'd':  # digit
                    combinations *= 10
                elif char_type == 'l':  # lowercase
                    combinations *= 26
                elif char_type == 'u':  # uppercase
                    combinations *= 26
                elif char_type == 's':  # symbol
                    combinations *= 32
                else:
                    combinations *= 10  # default
                i += 2
            else:
                # Literal character
                i += 1
        
        return min(combinations, 100000)  # Cap at reasonable limit
    
    def _calculate_base_rate(self, strategy: AttackStrategy) -> float:
        """Calculate base pattern testing rate"""
        device = strategy.target_device
        
        # Base rates by lock type (patterns per second)
        rates = {
            LockType.PIN: 3.0,      # Dictionary PINs are faster
            LockType.PASSWORD: 1.5,  # Password testing
            LockType.PATTERN: 4.0    # Pattern testing
        }
        
        base_rate = rates.get(device.lock_type, 2.0)
        
        # Adjust for device capabilities
        if device.usb_debugging:
            base_rate *= 1.5
        
        if device.root_status:
            base_rate *= 2.0
        
        return base_rate
    
    def execute_attack(self, strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Execute dictionary attack strategy
        
        Args:
            strategy: Attack strategy to execute
            
        Returns:
            Dict[str, Any]: Attack results
        """
        if not self.validate_strategy(strategy):
            raise DictionaryAttackException("Invalid dictionary attack strategy")
        
        self.logger.info(f"Starting dictionary attack on {strategy.target_device.serial}")
        
        try:
            # Initialize attack
            self._initialize_attack(strategy)
            
            # Generate patterns
            patterns = self._generate_attack_patterns(strategy)
            
            # Execute attack
            result = self._execute_dictionary_attack(patterns, strategy)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Dictionary attack failed: {e}")
            raise DictionaryAttackException(f"Dictionary attack failed: {e}")
        
        finally:
            self._cleanup_attack()
    
    def _initialize_attack(self, strategy: AttackStrategy):
        """Initialize attack state"""
        self._stop_event.clear()
        self._pattern_cache.clear()
        
        # Initialize statistics
        total_patterns = self._estimate_total_patterns(strategy)
        self._stats = DictionaryStats(
            total_wordlists=len(strategy.wordlists) + 1,  # +1 for built-in patterns
            total_patterns=total_patterns
        )
        
        self.logger.info(f"Dictionary attack initialized: {total_patterns} patterns to test")
    
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
            if patterns_generated >= strategy.max_attempts or self._stop_event.is_set():
                break
            if pattern not in self._pattern_cache:
                self._pattern_cache.add(pattern)
                yield pattern
                patterns_generated += 1
        
        # Built-in common patterns
        for pattern in self._generate_builtin_patterns(strategy):
            if patterns_generated >= strategy.max_attempts or self._stop_event.is_set():
                break
            if pattern not in self._pattern_cache:
                self._pattern_cache.add(pattern)
                yield pattern
                patterns_generated += 1
        
        # Wordlist patterns
        for pattern in self._generate_wordlist_patterns(strategy):
            if patterns_generated >= strategy.max_attempts or self._stop_event.is_set():
                break
            if pattern not in self._pattern_cache:
                self._pattern_cache.add(pattern)
                yield pattern
                patterns_generated += 1
        
        # Hybrid mask patterns (if hybrid strategy)
        if strategy.strategy_type == AttackType.HYBRID:
            # Generate mask patterns
            for pattern in self._generate_mask_patterns(strategy):
                if patterns_generated >= strategy.max_attempts or self._stop_event.is_set():
                    break
                if pattern not in self._pattern_cache:
                    self._pattern_cache.add(pattern)
                    yield pattern
                    patterns_generated += 1
            
            # Generate hybrid wordlist + mask combinations
            for pattern in self._generate_hybrid_patterns(strategy):
                if patterns_generated >= strategy.max_attempts or self._stop_event.is_set():
                    break
                if pattern not in self._pattern_cache:
                    self._pattern_cache.add(pattern)
                    yield pattern
                    patterns_generated += 1
    
    def _generate_builtin_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """Generate built-in common patterns"""
        device = strategy.target_device
        
        if device.lock_type == LockType.PIN:
            patterns = self._common_pins
        elif device.lock_type == LockType.PATTERN:
            patterns = self._common_patterns
        elif device.lock_type == LockType.PASSWORD:
            patterns = self._common_passwords
        else:
            patterns = []
        
        # Apply heuristic prioritization
        prioritized_patterns = self._prioritize_patterns(patterns, device)
        
        for pattern in prioritized_patterns:
            yield pattern
    
    def _prioritize_patterns(self, patterns: List[str], device: AndroidDevice) -> List[str]:
        """
        Apply advanced heuristic prioritization to patterns
        
        Uses multiple heuristics to prioritize patterns based on:
        - Statistical frequency of patterns
        - Device-specific characteristics
        - Pattern complexity and structure
        - Lock type compatibility
        
        Args:
            patterns: List of patterns to prioritize
            device: Target device
            
        Returns:
            List[str]: Prioritized patterns
        """
        def priority_score(pattern: str) -> int:
            score = 0
            
            # Base score for pattern length (shorter patterns are generally faster to test)
            length_score = max(0, 20 - len(pattern)) * 5
            score += length_score
            
            # Ultra-high priority for most common patterns
            ultra_common = {
                "1234": 1000, "0000": 950, "1111": 900, "password": 850,
                "123456": 800, "1212": 750, "2580": 700  # 2580 is phone keypad pattern
            }
            if pattern in ultra_common:
                score += ultra_common[pattern]
            
            # High priority for very common patterns
            very_common = {
                "7777": 600, "1004": 580, "2000": 560, "4444": 540,
                "2222": 520, "6969": 500, "9999": 480, "3333": 460,
                "5555": 440, "6666": 420, "1313": 400, "8888": 380
            }
            if pattern in very_common:
                score += very_common[pattern]
            
            # Device-specific heuristics
            if device.brand and device.model:
                # Brand-specific common patterns
                brand_patterns = self._get_brand_specific_patterns(device.brand.lower())
                if pattern in brand_patterns:
                    score += 300
                
                # Model year heuristics (if model contains year)
                model_year = self._extract_year_from_model(device.model)
                if model_year and pattern == str(model_year):
                    score += 250
            
            # Lock type specific scoring
            if device.lock_type == LockType.PIN:
                score += self._score_pin_pattern(pattern)
            elif device.lock_type == LockType.PATTERN:
                score += self._score_gesture_pattern(pattern)
            elif device.lock_type == LockType.PASSWORD:
                score += self._score_password_pattern(pattern)
            
            # Pattern structure heuristics
            if self._is_sequential(pattern):
                score += 150  # Sequential patterns are common
            
            if self._is_repeated(pattern):
                score += 120  # Repeated patterns are common
            
            if self._is_date_like(pattern):
                score += 100  # Date patterns are common
            
            if self._is_keyboard_pattern(pattern):
                score += 80   # Keyboard patterns are moderately common
            
            if self._is_phone_keypad_pattern(pattern):
                score += 90   # Phone keypad patterns are common
            
            # Penalize very complex patterns (less likely to be user-chosen)
            complexity_penalty = self._calculate_pattern_complexity(pattern)
            score -= complexity_penalty
            
            return score
        
        return sorted(patterns, key=priority_score, reverse=True)
    
    def _get_brand_specific_patterns(self, brand: str) -> List[str]:
        """Get common patterns specific to device brands"""
        brand_patterns = {
            'samsung': ['0000', '1234', '2580', '1111'],
            'xiaomi': ['1234', '0000', '1111', '6666'],
            'huawei': ['1234', '0000', '8888', '6666'],
            'oppo': ['1234', '0000', '1111', '8888'],
            'vivo': ['1234', '0000', '1111', '6666'],
            'oneplus': ['1234', '0000', '1111', '7777'],
            'google': ['1234', '0000', '1111', '4321'],
            'lg': ['1234', '0000', '1111', '2580'],
            'htc': ['1234', '0000', '1111', '1212'],
            'sony': ['1234', '0000', '1111', '7777']
        }
        return brand_patterns.get(brand, [])
    
    def _extract_year_from_model(self, model: str) -> Optional[int]:
        """Extract year from device model name"""
        import re
        # Look for 4-digit years in model name
        year_match = re.search(r'20\d{2}', model)
        if year_match:
            year = int(year_match.group())
            if 2010 <= year <= 2030:  # Reasonable range
                return year
        return None
    
    def _score_pin_pattern(self, pattern: str) -> int:
        """Score PIN patterns based on common PIN characteristics"""
        if not pattern.isdigit():
            return 0
        
        score = 0
        
        # Length-based scoring (4-6 digits are most common)
        if len(pattern) == 4:
            score += 50
        elif len(pattern) == 6:
            score += 30
        elif len(pattern) == 5:
            score += 20
        
        # Specific PIN patterns
        if pattern.startswith('19') or pattern.startswith('20'):  # Birth years
            score += 40
        
        if pattern in ['1234', '4321', '0123', '3210']:  # Sequential
            score += 60
        
        if len(set(pattern)) == 1:  # All same digits
            score += 45
        
        return score
    
    def _score_gesture_pattern(self, pattern: str) -> int:
        """Score gesture patterns based on common gesture characteristics"""
        score = 0
        
        # Length-based scoring (3-9 points are typical)
        if 3 <= len(pattern) <= 9:
            score += 30
        
        # Simple patterns (straight lines, L-shapes)
        if pattern in ['123', '147', '159', '357', '789']:
            score += 50
        
        # Common shapes
        if pattern in ['1236', '1478', '3698', '7894']:
            score += 40
        
        return score
    
    def _score_password_pattern(self, pattern: str) -> int:
        """Score password patterns based on common password characteristics"""
        score = 0
        
        # Length-based scoring
        if 6 <= len(pattern) <= 12:
            score += 30
        
        # Common passwords
        common_passwords = [
            'password', '123456', 'password123', 'admin', 'user',
            'android', 'phone', 'mobile', 'unlock'
        ]
        if pattern.lower() in common_passwords:
            score += 60
        
        # Simple transformations
        if any(pattern.lower().startswith(base) for base in ['password', 'admin', 'user']):
            score += 40
        
        return score
    
    def _is_keyboard_pattern(self, pattern: str) -> bool:
        """Check if pattern follows keyboard layout"""
        keyboard_patterns = [
            'qwerty', 'qwertyui', 'asdfgh', 'zxcvbn',
            'qwe', 'asd', 'zxc', '123qwe', 'qwe123'
        ]
        return pattern.lower() in keyboard_patterns
    
    def _is_phone_keypad_pattern(self, pattern: str) -> bool:
        """Check if pattern follows phone keypad layout"""
        # Phone keypad:
        # 1 2 3
        # 4 5 6
        # 7 8 9
        #   0
        keypad_patterns = [
            '2580', '1470', '3690', '1590', '7410', '8520', '9630',
            '1357', '2468', '1379', '3571', '7531', '9513'
        ]
        return pattern in keypad_patterns
    
    def _calculate_pattern_complexity(self, pattern: str) -> int:
        """Calculate pattern complexity penalty"""
        complexity = 0
        
        # Character type diversity penalty (very mixed patterns are less common)
        has_digit = any(c.isdigit() for c in pattern)
        has_lower = any(c.islower() for c in pattern)
        has_upper = any(c.isupper() for c in pattern)
        has_symbol = any(not c.isalnum() for c in pattern)
        
        char_types = sum([has_digit, has_lower, has_upper, has_symbol])
        if char_types > 2:
            complexity += char_types * 20
        
        # Length penalty for very long patterns
        if len(pattern) > 12:
            complexity += (len(pattern) - 12) * 10
        
        # Randomness penalty (patterns with high entropy are less likely)
        if len(set(pattern)) == len(pattern) and len(pattern) > 6:
            complexity += 30
        
        return complexity
    
    def _is_sequential(self, pattern: str) -> bool:
        """Check if pattern is sequential"""
        if len(pattern) < 3:
            return False
        
        # Check ascending sequence
        ascending = all(ord(pattern[i]) == ord(pattern[i-1]) + 1 for i in range(1, len(pattern)))
        
        # Check descending sequence
        descending = all(ord(pattern[i]) == ord(pattern[i-1]) - 1 for i in range(1, len(pattern)))
        
        return ascending or descending
    
    def _is_repeated(self, pattern: str) -> bool:
        """Check if pattern has repeated characters"""
        if len(pattern) < 2:
            return False
        
        # Check if all characters are the same
        return len(set(pattern)) == 1
    
    def _is_date_like(self, pattern: str) -> bool:
        """Check if pattern looks like a date"""
        if len(pattern) != 4:
            return False
        
        try:
            year = int(pattern)
            return 1900 <= year <= 2030
        except ValueError:
            return False
    
    def _generate_wordlist_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """Generate patterns from wordlists"""
        # Sort wordlists by priority
        wordlist_paths = sorted(strategy.wordlists, 
                               key=lambda p: self._wordlists.get(p, WordlistInfo("", "", priority=0)).priority,
                               reverse=True)
        
        for wordlist_path in wordlist_paths:
            if self._stop_event.is_set():
                break
            
            if self._stats:
                self._stats.current_wordlist = wordlist_path
            
            try:
                for pattern in self._read_wordlist(wordlist_path):
                    if self._stop_event.is_set():
                        break
                    yield pattern
                
                if self._stats:
                    self._stats.processed_wordlists += 1
                    
            except Exception as e:
                self.logger.error(f"Error reading wordlist {wordlist_path}: {e}")
                if self._stats:
                    self._stats.invalid_patterns += 1
    
    def _read_wordlist(self, path: str) -> Iterator[str]:
        """Read patterns from wordlist file"""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pattern = line.strip()
                    if pattern and not pattern.startswith('#'):  # Skip comments
                        yield pattern
        except Exception as e:
            self.logger.error(f"Failed to read wordlist {path}: {e}")
    
    def _generate_mask_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """Generate patterns from mask patterns (simplified implementation)"""
        for mask in strategy.mask_patterns:
            if self._stop_event.is_set():
                break
            
            # This is a simplified implementation
            # In practice, would generate all combinations based on mask
            for pattern in self._expand_mask(mask):
                if self._stop_event.is_set():
                    break
                yield pattern
    
    def _expand_mask(self, mask: str) -> Iterator[str]:
        """
        Expand mask pattern to generate all possible combinations
        
        Supports mask characters:
        - ?d = digit (0-9)
        - ?l = lowercase letter (a-z)
        - ?u = uppercase letter (A-Z)
        - ?s = symbol (!@#$%^&*()_+-=[]{}|;:,.<>?)
        - ?a = any printable ASCII character
        
        Args:
            mask: Mask pattern string
            
        Yields:
            str: Generated patterns based on mask
        """
        import itertools
        import string
        
        # Character sets for different mask types
        char_sets = {
            'd': string.digits,                    # 0-9
            'l': string.ascii_lowercase,           # a-z
            'u': string.ascii_uppercase,           # A-Z
            's': '!@#$%^&*()_+-=[]{}|;:,.<>?',    # Common symbols
            'a': string.printable.strip()          # All printable ASCII
        }
        
        # Parse mask pattern
        positions = []
        literal_chars = []
        i = 0
        
        while i < len(mask):
            if i < len(mask) - 1 and mask[i] == '?':
                # Mask character
                mask_type = mask[i + 1]
                if mask_type in char_sets:
                    positions.append(len(literal_chars))
                    literal_chars.append(None)  # Placeholder for mask position
                    positions.append(char_sets[mask_type])
                else:
                    # Unknown mask type, treat as literal
                    literal_chars.append(mask[i:i+2])
                i += 2
            else:
                # Literal character
                literal_chars.append(mask[i])
                i += 1
        
        # If no mask characters found, return the literal string
        if not any(char is None for char in literal_chars):
            yield mask
            return
        
        # Generate combinations for mask positions
        mask_positions = [i for i, char in enumerate(literal_chars) if char is None]
        mask_char_sets = [positions[i+1] for i in range(0, len(positions), 2)]
        
        # Limit combinations to prevent excessive generation
        max_combinations = 10000
        combination_count = 1
        for char_set in mask_char_sets:
            combination_count *= len(char_set)
        
        if combination_count > max_combinations:
            # Sample combinations instead of generating all
            import random
            for _ in range(max_combinations):
                pattern_chars = literal_chars.copy()
                for pos, char_set in zip(mask_positions, mask_char_sets):
                    pattern_chars[pos] = random.choice(char_set)
                yield ''.join(pattern_chars)
        else:
            # Generate all combinations
            for combination in itertools.product(*mask_char_sets):
                pattern_chars = literal_chars.copy()
                for pos, char in zip(mask_positions, combination):
                    pattern_chars[pos] = char
                yield ''.join(pattern_chars)
    
    def _generate_hybrid_patterns(self, strategy: AttackStrategy) -> Iterator[str]:
        """
        Generate hybrid patterns combining wordlist entries with mask patterns
        
        This method implements advanced hybrid attacks by:
        1. Taking base words from wordlists
        2. Applying common transformations (numbers, symbols)
        3. Combining with mask patterns
        
        Args:
            strategy: Attack strategy
            
        Yields:
            str: Hybrid patterns
        """
        # Get base words from built-in patterns and wordlists
        base_words = set()
        
        # Add built-in patterns as base words
        device = strategy.target_device
        if device.lock_type == LockType.PASSWORD:
            base_words.update(self._common_passwords[:20])  # Top 20 passwords
        elif device.lock_type == LockType.PIN:
            base_words.update(self._common_pins[:10])  # Top 10 PINs
        
        # Add words from wordlists (limited to prevent explosion)
        for wordlist_path in strategy.wordlists[:3]:  # Limit to first 3 wordlists
            if self._stop_event.is_set():
                break
            
            word_count = 0
            try:
                for word in self._read_wordlist(wordlist_path):
                    if word_count >= 50:  # Limit words per wordlist
                        break
                    base_words.add(word)
                    word_count += 1
            except Exception as e:
                self.logger.error(f"Error reading wordlist for hybrid attack: {e}")
        
        # Common transformations to apply to base words
        transformations = [
            lambda w: w + "123",      # Add common numbers
            lambda w: w + "1",
            lambda w: w + "12",
            lambda w: w + "2023",
            lambda w: w + "2024",
            lambda w: "123" + w,      # Prepend numbers
            lambda w: "1" + w,
            lambda w: w + "!",        # Add symbols
            lambda w: w + "@",
            lambda w: w + "#",
            lambda w: w.upper(),      # Case transformations
            lambda w: w.lower(),
            lambda w: w.capitalize(),
            lambda w: w[::-1],        # Reverse
            lambda w: w + w[:2],      # Repeat first 2 chars
        ]
        
        # Apply transformations to base words
        for base_word in base_words:
            if self._stop_event.is_set():
                break
            
            # Original word
            yield base_word
            
            # Apply transformations
            for transform in transformations:
                if self._stop_event.is_set():
                    break
                
                try:
                    transformed = transform(base_word)
                    if transformed != base_word and len(transformed) <= 20:  # Reasonable length limit
                        yield transformed
                except Exception:
                    continue  # Skip failed transformations
        
        # Combine base words with mask patterns
        for base_word in list(base_words)[:10]:  # Limit base words for mask combination
            if self._stop_event.is_set():
                break
            
            for mask in strategy.mask_patterns[:5]:  # Limit masks
                if self._stop_event.is_set():
                    break
                
                # Create hybrid masks by combining word with mask
                hybrid_masks = [
                    base_word + mask,      # word + mask
                    mask + base_word,      # mask + word
                    base_word + "?" + mask, # word + separator + mask
                ]
                
                for hybrid_mask in hybrid_masks:
                    if self._stop_event.is_set():
                        break
                    
                    # Generate patterns from hybrid mask (limited)
                    pattern_count = 0
                    for pattern in self._expand_mask(hybrid_mask):
                        if pattern_count >= 10 or self._stop_event.is_set():  # Limit patterns per hybrid mask
                            break
                        yield pattern
                        pattern_count += 1
    
    def _execute_dictionary_attack(self, patterns: Iterator[str], strategy: AttackStrategy) -> Dict[str, Any]:
        """
        Execute the dictionary attack
        
        Args:
            patterns: Iterator of patterns to test
            strategy: Attack strategy
            
        Returns:
            Dict[str, Any]: Attack results
        """
        start_time = datetime.now()
        successful_pattern = None
        
        try:
            for pattern in patterns:
                if self._stop_event.is_set():
                    break
                
                # Update statistics
                if self._stats:
                    self._stats.current_pattern = pattern
                    self._stats.tested_patterns += 1
                
                # Test pattern
                success = self._test_pattern(pattern, strategy)
                
                if success:
                    successful_pattern = pattern
                    if self._stats:
                        self._stats.successful_patterns += 1
                    break
                
                # Check timeout
                elapsed = (datetime.now() - start_time).total_seconds()
                if elapsed >= strategy.timeout_seconds:
                    self.logger.info("Dictionary attack timed out")
                    break
            
            # Compile results
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'success': successful_pattern is not None,
                'successful_pattern': successful_pattern,
                'total_attempts': self._stats.tested_patterns if self._stats else 0,
                'duration_seconds': duration,
                'patterns_per_second': self._stats.patterns_per_second if self._stats else 0,
                'wordlists_processed': self._stats.processed_wordlists if self._stats else 0,
                'duplicate_patterns': self._stats.duplicate_patterns if self._stats else 0,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'attack_type': 'dictionary'
            }
            
            self.logger.info(f"Dictionary attack completed: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Dictionary attack execution error: {e}")
            raise DictionaryAttackException(f"Dictionary attack execution failed: {e}")
    
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
        
        self.logger.debug(f"Testing dictionary pattern: {pattern}")
        
        # Simulate testing delay
        import time
        time.sleep(0.05)  # Faster than brute force
        
        # Mock success (very low probability for testing)
        success = pattern in ["1234", "password", "123456"]
        
        return success
    
    def _cleanup_attack(self):
        """Clean up attack resources"""
        self._stop_event.set()
        self._pattern_cache.clear()
        self._stats = None
    
    def stop_attack(self):
        """Stop the current attack"""
        self._stop_event.set()
        self.logger.info("Dictionary attack stopped")
    
    def get_attack_stats(self) -> Optional[DictionaryStats]:
        """Get current attack statistics"""
        return self._stats
    
    def create_custom_wordlist(self, patterns: List[str], output_path: str, name: str) -> bool:
        """
        Create a custom wordlist file
        
        Args:
            patterns: List of patterns to include
            output_path: Path for output wordlist file
            name: Name for the wordlist
            
        Returns:
            bool: True if wordlist was created successfully
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"# Custom wordlist: {name}\n")
                f.write(f"# Created: {datetime.now().isoformat()}\n")
                f.write(f"# Entries: {len(patterns)}\n\n")
                
                for pattern in patterns:
                    f.write(f"{pattern}\n")
            
            # Add to wordlists
            self.add_wordlist(output_path, name, priority=10)  # High priority for custom lists
            
            self.logger.info(f"Created custom wordlist: {name} ({len(patterns)} entries)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create custom wordlist: {e}")
            return False
    
    def merge_wordlists(self, input_paths: List[str], output_path: str, 
                       remove_duplicates: bool = True) -> bool:
        """
        Merge multiple wordlists into one
        
        Args:
            input_paths: List of input wordlist paths
            output_path: Path for merged wordlist
            remove_duplicates: Whether to remove duplicate entries
            
        Returns:
            bool: True if merge was successful
        """
        try:
            patterns = set() if remove_duplicates else []
            
            for path in input_paths:
                try:
                    for pattern in self._read_wordlist(path):
                        if remove_duplicates:
                            patterns.add(pattern)
                        else:
                            patterns.append(pattern)
                except Exception as e:
                    self.logger.error(f"Error reading {path} for merge: {e}")
            
            # Write merged wordlist
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"# Merged wordlist\n")
                f.write(f"# Created: {datetime.now().isoformat()}\n")
                f.write(f"# Source files: {', '.join(input_paths)}\n")
                f.write(f"# Entries: {len(patterns)}\n\n")
                
                if remove_duplicates:
                    for pattern in sorted(patterns):
                        f.write(f"{pattern}\n")
                else:
                    for pattern in patterns:
                        f.write(f"{pattern}\n")
            
            self.logger.info(f"Merged {len(input_paths)} wordlists into {output_path} ({len(patterns)} entries)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to merge wordlists: {e}")
            return False