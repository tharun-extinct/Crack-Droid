"""
Unit tests for database setup functionality
"""

import unittest
import tempfile
import shutil
import sqlite3
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from forensics_toolkit.database_setup import (
    DatabaseSetupManager, 
    WordlistMetadata, 
    PatternMetadata,
    setup_default_databases
)


class TestDatabaseSetupManager(unittest.TestCase):
    """Test cases for DatabaseSetupManager"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.db_manager = DatabaseSetupManager(self.test_dir)
        
        # Create test wordlist file
        self.test_wordlist = Path(self.test_dir) / "test_wordlist.txt"
        with open(self.test_wordlist, 'w') as f:
            f.write("password\n123456\nqwerty\nadmin\ntest\n")
    
    def tearDown(self):
        """Clean up test environment"""
        # Close any open database connections
        if hasattr(self, 'db_manager'):
            del self.db_manager
        
        # Force garbage collection to close connections
        import gc
        gc.collect()
        
        # Try to remove directory, retry if locked
        import time
        for i in range(3):
            try:
                shutil.rmtree(self.test_dir)
                break
            except PermissionError:
                if i < 2:
                    time.sleep(0.1)
                    continue
                else:
                    # If still locked, just pass - temp dir will be cleaned up eventually
                    pass
    
    def test_database_initialization(self):
        """Test database initialization"""
        # Check if database file exists
        self.assertTrue(self.db_manager.db_path.exists())
        
        # Check if tables are created
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Check wordlists table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wordlists'")
            self.assertIsNotNone(cursor.fetchone())
            
            # Check patterns table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='patterns'")
            self.assertIsNotNone(cursor.fetchone())
            
            # Check index tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wordlist_index'")
            self.assertIsNotNone(cursor.fetchone())
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pattern_index'")
            self.assertIsNotNone(cursor.fetchone())
    
    def test_load_wordlist(self):
        """Test wordlist loading and indexing"""
        # Load test wordlist
        result = self.db_manager.load_wordlist(
            str(self.test_wordlist), 
            "test_wordlist", 
            "Test wordlist", 
            "test"
        )
        self.assertTrue(result)
        
        # Verify wordlist metadata in database
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM wordlists WHERE name = ?", ("test_wordlist",))
            wordlist_data = cursor.fetchone()
            self.assertIsNotNone(wordlist_data)
            self.assertEqual(wordlist_data[1], "test_wordlist")  # name
            self.assertEqual(wordlist_data[7], "Test wordlist")  # description
            self.assertEqual(wordlist_data[8], "test")  # category
            self.assertTrue(wordlist_data[9])  # indexed
        
        # Verify words are indexed
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM wordlist_index WHERE wordlist_id = ?", (wordlist_data[0],))
            word_count = cursor.fetchone()[0]
            self.assertEqual(word_count, 5)  # 5 words in test file
    
    def test_create_android_pattern_database(self):
        """Test Android pattern database creation"""
        result = self.db_manager.create_android_pattern_database()
        self.assertTrue(result)
        
        # Verify patterns are stored
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM patterns WHERE name = ?", ("common_android_patterns",))
            pattern_data = cursor.fetchone()
            self.assertIsNotNone(pattern_data)
            self.assertGreater(pattern_data[2], 0)  # pattern_count > 0
            
            # Verify pattern index
            cursor.execute("SELECT COUNT(*) FROM pattern_index WHERE pattern_id = ?", (pattern_data[0],))
            pattern_count = cursor.fetchone()[0]
            self.assertGreater(pattern_count, 0)
    
    def test_import_custom_wordlist(self):
        """Test custom wordlist import"""
        # Create a custom wordlist file outside the database directory
        custom_file = Path(self.test_dir) / "custom_wordlist.txt"
        with open(custom_file, 'w') as f:
            f.write("custom1\ncustom2\ncustom3\n")
        
        result = self.db_manager.import_custom_wordlist(str(custom_file), "my_custom")
        self.assertTrue(result)
        
        # Verify file was copied to custom directory
        custom_dest = self.db_manager.base_path / "custom" / "my_custom.txt"
        self.assertTrue(custom_dest.exists())
        
        # Verify it was loaded into database
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM wordlists WHERE name = ?", ("my_custom",))
            wordlist_data = cursor.fetchone()
            self.assertIsNotNone(wordlist_data)
            self.assertEqual(wordlist_data[8], "custom")  # category
    
    def test_verify_database_integrity(self):
        """Test database integrity verification"""
        # Load a wordlist first
        self.db_manager.load_wordlist(str(self.test_wordlist), "test_wordlist")
        self.db_manager.create_android_pattern_database()
        
        # Verify integrity
        integrity = self.db_manager.verify_database_integrity()
        
        self.assertTrue(integrity['database_accessible'])
        self.assertTrue(integrity['wordlists_valid'])
        self.assertTrue(integrity['patterns_valid'])
        self.assertTrue(integrity['indexes_valid'])
    
    def test_get_wordlist_stats(self):
        """Test wordlist statistics"""
        # Load test data
        self.db_manager.load_wordlist(str(self.test_wordlist), "test_wordlist", category="test")
        self.db_manager.create_android_pattern_database()
        
        stats = self.db_manager.get_wordlist_stats()
        
        self.assertIn('categories', stats)
        self.assertIn('total_words', stats)
        self.assertIn('total_patterns', stats)
        self.assertGreater(stats['total_words'], 0)
        self.assertGreater(stats['total_patterns'], 0)
    
    def test_search_words_by_length(self):
        """Test word search by length"""
        self.db_manager.load_wordlist(str(self.test_wordlist), "test_wordlist")
        
        # Search for words of length 4-6
        words = self.db_manager.search_words_by_length(4, 6)
        self.assertGreater(len(words), 0)
        
        # Verify all returned words are within length range
        for word in words:
            self.assertGreaterEqual(len(word), 4)
            self.assertLessEqual(len(word), 6)
    
    def test_get_patterns_by_complexity(self):
        """Test pattern search by complexity"""
        self.db_manager.create_android_pattern_database()
        
        # Get patterns with complexity 1-5
        patterns = self.db_manager.get_patterns_by_complexity(1, 5)
        self.assertGreater(len(patterns), 0)
        
        # Verify patterns are lists of integers
        for pattern in patterns:
            self.assertIsInstance(pattern, list)
            for point in pattern:
                self.assertIsInstance(point, int)
                self.assertGreaterEqual(point, 0)
                self.assertLessEqual(point, 8)  # Android pattern grid is 0-8
    
    def test_calculate_pattern_complexity(self):
        """Test pattern complexity calculation"""
        # Simple 3-point pattern
        simple_pattern = [0, 1, 2]
        complexity = self.db_manager._calculate_pattern_complexity(simple_pattern)
        self.assertGreaterEqual(complexity, 1)
        self.assertLessEqual(complexity, 10)
        
        # Complex pattern with direction changes
        complex_pattern = [0, 4, 8, 2, 6]
        complex_complexity = self.db_manager._calculate_pattern_complexity(complex_pattern)
        self.assertGreater(complex_complexity, complexity)
    
    def test_file_hash_calculation(self):
        """Test file hash calculation"""
        hash_value = self.db_manager._calculate_file_hash(self.test_wordlist)
        self.assertEqual(len(hash_value), 64)  # SHA-256 hash length
        self.assertTrue(all(c in '0123456789abcdef' for c in hash_value))
    
    @patch('forensics_toolkit.database_setup.logging')
    def test_error_handling(self, mock_logging):
        """Test error handling in various scenarios"""
        # Test loading non-existent wordlist
        result = self.db_manager.load_wordlist("/non/existent/file.txt", "test")
        self.assertFalse(result)
        
        # Test importing non-existent custom wordlist
        result = self.db_manager.import_custom_wordlist("/non/existent/custom.txt", "test")
        self.assertFalse(result)


class TestSetupDefaultDatabases(unittest.TestCase):
    """Test cases for setup_default_databases function"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        # Force garbage collection to close connections
        import gc
        gc.collect()
        
        # Try to remove directory, retry if locked
        import time
        for i in range(3):
            try:
                shutil.rmtree(self.test_dir)
                break
            except PermissionError:
                if i < 2:
                    time.sleep(0.1)
                    continue
                else:
                    # If still locked, just pass - temp dir will be cleaned up eventually
                    pass
    
    def test_setup_default_databases(self):
        """Test default database setup"""
        result = setup_default_databases(self.test_dir)
        self.assertTrue(result)
        
        # Verify database file exists
        db_path = Path(self.test_dir) / "forensics_db.sqlite"
        self.assertTrue(db_path.exists())
        
        # Verify common PINs wordlist was created
        pins_file = Path(self.test_dir) / "wordlists" / "common_pins.txt"
        self.assertTrue(pins_file.exists())
        
        # Verify database contains expected data
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Check for common_pins wordlist
            cursor.execute("SELECT * FROM wordlists WHERE name = ?", ("common_pins",))
            pins_data = cursor.fetchone()
            self.assertIsNotNone(pins_data)
            
            # Check for Android patterns
            cursor.execute("SELECT * FROM patterns WHERE name = ?", ("common_android_patterns",))
            patterns_data = cursor.fetchone()
            self.assertIsNotNone(patterns_data)


if __name__ == '__main__':
    unittest.main()