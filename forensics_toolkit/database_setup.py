"""
Wordlist and pattern database setup module for ForenCrack Droid
Handles loading, indexing, and managing wordlists and Android pattern databases
"""

import os
import json
import sqlite3
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class WordlistMetadata:
    """Metadata for wordlist files"""
    name: str
    path: str
    size: int
    hash_sha256: str
    created_date: datetime
    last_modified: datetime
    description: str = ""
    category: str = "general"
    indexed: bool = False


@dataclass
class PatternMetadata:
    """Metadata for Android pattern databases"""
    name: str
    pattern_count: int
    hash_sha256: str
    created_date: datetime
    description: str = ""
    pattern_type: str = "gesture"  # gesture, pin, password


class DatabaseSetupManager:
    """Manages wordlist and pattern database setup and indexing"""
    
    def __init__(self, base_path: str = "./wordlists"):
        self.base_path = Path(base_path)
        self.db_path = self.base_path / "forensics_db.sqlite"
        self.logger = logging.getLogger(__name__)
        
        # Create directories
        self.base_path.mkdir(parents=True, exist_ok=True)
        (self.base_path / "wordlists").mkdir(exist_ok=True)
        (self.base_path / "patterns").mkdir(exist_ok=True)
        (self.base_path / "custom").mkdir(exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for wordlist and pattern indexing"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create wordlists table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wordlists (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        path TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        hash_sha256 TEXT NOT NULL,
                        created_date TEXT NOT NULL,
                        last_modified TEXT NOT NULL,
                        description TEXT,
                        category TEXT DEFAULT 'general',
                        indexed BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Create patterns table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        pattern_count INTEGER NOT NULL,
                        hash_sha256 TEXT NOT NULL,
                        created_date TEXT NOT NULL,
                        description TEXT,
                        pattern_type TEXT DEFAULT 'gesture'
                    )
                ''')
                
                # Create wordlist_index table for fast lookups
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS wordlist_index (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        wordlist_id INTEGER,
                        word TEXT NOT NULL,
                        length INTEGER NOT NULL,
                        FOREIGN KEY (wordlist_id) REFERENCES wordlists (id)
                    )
                ''')
                
                # Create pattern_index table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS pattern_index (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_id INTEGER,
                        pattern TEXT NOT NULL,
                        complexity INTEGER DEFAULT 1,
                        FOREIGN KEY (pattern_id) REFERENCES patterns (id)
                    )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_word_length ON wordlist_index(length)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_word_text ON wordlist_index(word)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_pattern_complexity ON pattern_index(complexity)')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
    
    def load_wordlist(self, file_path: str, name: str = None, 
                     description: str = "", category: str = "general") -> bool:
        """Load and index a wordlist file"""
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.error(f"Wordlist file not found: {file_path}")
                return False
            
            # Use filename as name if not provided
            if not name:
                name = path.stem
            
            # Calculate metadata
            file_size = path.stat().st_size
            file_hash = self._calculate_file_hash(path)
            created_date = datetime.fromtimestamp(path.stat().st_ctime)
            modified_date = datetime.fromtimestamp(path.stat().st_mtime)
            
            # Store metadata in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if wordlist already exists
                cursor.execute('SELECT id FROM wordlists WHERE name = ?', (name,))
                existing = cursor.fetchone()
                
                if existing:
                    self.logger.warning(f"Wordlist '{name}' already exists, updating...")
                    cursor.execute('''
                        UPDATE wordlists SET path=?, size=?, hash_sha256=?, 
                        last_modified=?, description=?, category=?, indexed=FALSE
                        WHERE name=?
                    ''', (str(path), file_size, file_hash, modified_date.isoformat(),
                          description, category, name))
                    wordlist_id = existing[0]
                else:
                    cursor.execute('''
                        INSERT INTO wordlists (name, path, size, hash_sha256, 
                        created_date, last_modified, description, category)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (name, str(path), file_size, file_hash, 
                          created_date.isoformat(), modified_date.isoformat(),
                          description, category))
                    wordlist_id = cursor.lastrowid
                
                conn.commit()
            
            # Index the wordlist
            return self._index_wordlist(wordlist_id, path)
            
        except Exception as e:
            self.logger.error(f"Failed to load wordlist {file_path}: {e}")
            return False
    
    def _index_wordlist(self, wordlist_id: int, file_path: Path) -> bool:
        """Index words from a wordlist file for fast lookups"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear existing index for this wordlist
                cursor.execute('DELETE FROM wordlist_index WHERE wordlist_id = ?', (wordlist_id,))
                
                # Read and index words
                words_indexed = 0
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    batch = []
                    for line in f:
                        word = line.strip()
                        if word and len(word) <= 100:  # Reasonable length limit
                            batch.append((wordlist_id, word, len(word)))
                            words_indexed += 1
                            
                            # Insert in batches for performance
                            if len(batch) >= 1000:
                                cursor.executemany('''
                                    INSERT INTO wordlist_index (wordlist_id, word, length)
                                    VALUES (?, ?, ?)
                                ''', batch)
                                batch = []
                    
                    # Insert remaining words
                    if batch:
                        cursor.executemany('''
                            INSERT INTO wordlist_index (wordlist_id, word, length)
                            VALUES (?, ?, ?)
                        ''', batch)
                
                # Mark as indexed
                cursor.execute('UPDATE wordlists SET indexed = TRUE WHERE id = ?', (wordlist_id,))
                conn.commit()
                
                self.logger.info(f"Indexed {words_indexed} words from wordlist ID {wordlist_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to index wordlist {wordlist_id}: {e}")
            return False    
    
    def create_android_pattern_database(self) -> bool:
        """Create common Android pattern database"""
        try:
            patterns = self._generate_common_android_patterns()
            pattern_data = {
                'name': 'common_android_patterns',
                'description': 'Common Android unlock patterns',
                'patterns': patterns,
                'pattern_type': 'gesture'
            }
            
            return self._store_pattern_database(pattern_data)
            
        except Exception as e:
            self.logger.error(f"Failed to create Android pattern database: {e}")
            return False
    
    def _generate_common_android_patterns(self) -> List[Dict]:
        """Generate common Android unlock patterns"""
        patterns = []
        
        # Common simple patterns (L-shapes, lines, etc.)
        common_patterns = [
            # Simple lines
            [0, 1, 2],  # Top row
            [3, 4, 5],  # Middle row
            [6, 7, 8],  # Bottom row
            [0, 3, 6],  # Left column
            [1, 4, 7],  # Middle column
            [2, 5, 8],  # Right column
            [0, 4, 8],  # Diagonal
            [2, 4, 6],  # Reverse diagonal
            
            # L-shapes
            [0, 1, 4, 7],  # L from top-left
            [2, 1, 4, 7],  # Reverse L from top-right
            [6, 7, 4, 1],  # L from bottom-left
            [8, 7, 4, 1],  # Reverse L from bottom-right
            
            # Common sequences
            [0, 1, 2, 5, 8],  # Top to bottom-right
            [0, 3, 6, 7, 8],  # Left to bottom-right
            [2, 5, 8, 7, 6],  # Right to bottom-left
            [6, 3, 0, 1, 2],  # Bottom-left to top-right
            
            # Z patterns
            [0, 1, 2, 4, 6, 7, 8],  # Z pattern
            [2, 1, 0, 4, 8, 7, 6],  # Reverse Z
            
            # Common user patterns (based on research)
            [0, 1, 2, 5, 4],  # Common user pattern
            [0, 4, 8, 5, 2],  # X pattern variant
            [1, 4, 7, 5, 3],  # Cross pattern
            [0, 3, 4, 5, 2],  # Square pattern
        ]
        
        # Convert to pattern format with complexity scoring
        for i, pattern in enumerate(common_patterns):
            patterns.append({
                'id': i,
                'sequence': pattern,
                'complexity': self._calculate_pattern_complexity(pattern),
                'description': f"Common pattern {i+1}"
            })
        
        return patterns
    
    def _calculate_pattern_complexity(self, pattern: List[int]) -> int:
        """Calculate complexity score for a pattern (1-10)"""
        complexity = 1
        
        # Length factor
        complexity += min(len(pattern) - 3, 5)  # 3-8 points max
        
        # Direction changes
        if len(pattern) > 2:
            direction_changes = 0
            for i in range(2, len(pattern)):
                prev_dir = (pattern[i-1] - pattern[i-2])
                curr_dir = (pattern[i] - pattern[i-1])
                if prev_dir != curr_dir:
                    direction_changes += 1
            complexity += min(direction_changes, 3)
        
        # Crossing lines (more complex)
        if self._has_crossing_lines(pattern):
            complexity += 2
        
        return min(complexity, 10)
    
    def _has_crossing_lines(self, pattern: List[int]) -> bool:
        """Check if pattern has crossing lines (simplified check)"""
        # This is a simplified implementation
        # In practice, you'd need more sophisticated geometry
        if len(pattern) < 4:
            return False
        
        # Check for common crossing patterns
        crossing_patterns = [
            [0, 8, 2, 6],  # X pattern
            [1, 7, 3, 5],  # Cross pattern
        ]
        
        for crossing in crossing_patterns:
            if all(point in pattern for point in crossing):
                return True
        
        return False
    
    def _store_pattern_database(self, pattern_data: Dict) -> bool:
        """Store pattern database in SQLite"""
        try:
            # Calculate hash of pattern data
            pattern_json = json.dumps(pattern_data, sort_keys=True)
            pattern_hash = hashlib.sha256(pattern_json.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Store pattern metadata
                cursor.execute('''
                    INSERT OR REPLACE INTO patterns 
                    (name, pattern_count, hash_sha256, created_date, description, pattern_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    pattern_data['name'],
                    len(pattern_data['patterns']),
                    pattern_hash,
                    datetime.now().isoformat(),
                    pattern_data['description'],
                    pattern_data['pattern_type']
                ))
                
                pattern_id = cursor.lastrowid
                
                # Clear existing patterns for this database
                cursor.execute('DELETE FROM pattern_index WHERE pattern_id = ?', (pattern_id,))
                
                # Store individual patterns
                pattern_batch = []
                for pattern in pattern_data['patterns']:
                    pattern_str = json.dumps(pattern['sequence'])
                    pattern_batch.append((
                        pattern_id,
                        pattern_str,
                        pattern['complexity']
                    ))
                
                cursor.executemany('''
                    INSERT INTO pattern_index (pattern_id, pattern, complexity)
                    VALUES (?, ?, ?)
                ''', pattern_batch)
                
                conn.commit()
                
            self.logger.info(f"Stored {len(pattern_data['patterns'])} patterns in database")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store pattern database: {e}")
            return False
    
    def import_custom_wordlist(self, file_path: str, name: str = None, 
                              category: str = "custom") -> bool:
        """Import a custom wordlist file"""
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                self.logger.error(f"Custom wordlist file not found: {file_path}")
                return False
            
            # Copy to custom directory
            if not name:
                name = source_path.stem
            
            dest_path = self.base_path / "custom" / f"{name}.txt"
            
            # Copy file
            import shutil
            shutil.copy2(source_path, dest_path)
            
            # Load and index
            return self.load_wordlist(str(dest_path), name, 
                                    f"Custom wordlist: {name}", category)
            
        except Exception as e:
            self.logger.error(f"Failed to import custom wordlist: {e}")
            return False
    
    def verify_database_integrity(self) -> Dict[str, bool]:
        """Verify integrity of wordlist and pattern databases"""
        integrity_results = {
            'database_accessible': False,
            'wordlists_valid': False,
            'patterns_valid': False,
            'indexes_valid': False
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check database accessibility
                cursor.execute('SELECT COUNT(*) FROM sqlite_master')
                integrity_results['database_accessible'] = True
                
                # Verify wordlists
                cursor.execute('SELECT id, name, path, hash_sha256 FROM wordlists')
                wordlists = cursor.fetchall()
                
                wordlist_valid = True
                for wl_id, name, path, stored_hash in wordlists:
                    if Path(path).exists():
                        current_hash = self._calculate_file_hash(Path(path))
                        if current_hash != stored_hash:
                            self.logger.warning(f"Hash mismatch for wordlist '{name}'")
                            wordlist_valid = False
                    else:
                        self.logger.warning(f"Wordlist file missing: {path}")
                        wordlist_valid = False
                
                integrity_results['wordlists_valid'] = wordlist_valid
                
                # Verify patterns
                cursor.execute('SELECT COUNT(*) FROM patterns')
                pattern_count = cursor.fetchone()[0]
                integrity_results['patterns_valid'] = pattern_count > 0
                
                # Verify indexes
                cursor.execute('SELECT COUNT(*) FROM wordlist_index')
                index_count = cursor.fetchone()[0]
                integrity_results['indexes_valid'] = index_count > 0
                
        except Exception as e:
            self.logger.error(f"Database integrity check failed: {e}")
        
        return integrity_results
    
    def get_wordlist_stats(self) -> Dict:
        """Get statistics about loaded wordlists"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get wordlist counts by category
                cursor.execute('''
                    SELECT category, COUNT(*), SUM(size) 
                    FROM wordlists 
                    GROUP BY category
                ''')
                categories = cursor.fetchall()
                
                # Get total word count
                cursor.execute('SELECT COUNT(*) FROM wordlist_index')
                total_words = cursor.fetchone()[0]
                
                # Get pattern count
                cursor.execute('SELECT COUNT(*) FROM pattern_index')
                total_patterns = cursor.fetchone()[0]
                
                return {
                    'categories': {cat: {'count': count, 'size': size} 
                                 for cat, count, size in categories},
                    'total_words': total_words,
                    'total_patterns': total_patterns
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get wordlist stats: {e}")
            return {}
    
    def search_words_by_length(self, min_length: int, max_length: int, 
                              limit: int = 1000) -> List[str]:
        """Search words by length range"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT DISTINCT word FROM wordlist_index 
                    WHERE length BETWEEN ? AND ? 
                    LIMIT ?
                ''', (min_length, max_length, limit))
                
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Failed to search words by length: {e}")
            return []
    
    def get_patterns_by_complexity(self, min_complexity: int = 1, 
                                  max_complexity: int = 10) -> List[List[int]]:
        """Get patterns by complexity range"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT pattern FROM pattern_index 
                    WHERE complexity BETWEEN ? AND ?
                    ORDER BY complexity
                ''', (min_complexity, max_complexity))
                
                patterns = []
                for row in cursor.fetchall():
                    pattern_data = json.loads(row[0])
                    patterns.append(pattern_data)
                
                return patterns
                
        except Exception as e:
            self.logger.error(f"Failed to get patterns by complexity: {e}")
            return []


def setup_default_databases(base_path: str = "./wordlists") -> bool:
    """Setup default wordlists and pattern databases"""
    try:
        db_manager = DatabaseSetupManager(base_path)
        
        # Create default Android pattern database
        if not db_manager.create_android_pattern_database():
            logging.error("Failed to create Android pattern database")
            return False
        
        # Create default wordlists directory structure
        wordlists_dir = Path(base_path) / "wordlists"
        wordlists_dir.mkdir(exist_ok=True)
        
        # Create sample PIN wordlist
        pin_wordlist = wordlists_dir / "common_pins.txt"
        if not pin_wordlist.exists():
            common_pins = [
                "0000", "1234", "1111", "0000", "1212", "7777", "1004", "2000",
                "4444", "2222", "6969", "9999", "3333", "5555", "6666", "1313",
                "8888", "4321", "2001", "1010", "2580", "1122", "1001", "2468",
                "0123", "1357", "9876", "5432", "0987", "6543", "3210", "7890"
            ]
            
            with open(pin_wordlist, 'w') as f:
                for pin in common_pins:
                    f.write(f"{pin}\n")
        
        # Load the PIN wordlist
        if not db_manager.load_wordlist(str(pin_wordlist), "common_pins", 
                                       "Common Android PINs", "pins"):
            logging.error("Failed to load common PINs wordlist")
            return False
        
        logging.info("Default databases setup completed successfully")
        return True
        
    except Exception as e:
        logging.error(f"Failed to setup default databases: {e}")
        return False


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Setup default databases
    success = setup_default_databases()
    if success:
        print("Database setup completed successfully")
    else:
        print("Database setup failed")