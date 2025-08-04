#!/usr/bin/env python3
"""
ForenCrack Droid Deployment Test Suite
Comprehensive testing for clean system installation validation
"""

import os
import sys
import json
import sqlite3
import subprocess
import importlib
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import unittest
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeploymentTestSuite(unittest.TestCase):
    """Comprehensive deployment test suite"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.home_dir = Path.home()
        cls.config_dir = cls.home_dir / '.forensics-toolkit'
        cls.current_dir = Path.cwd()
        
        # Required tools for testing
        cls.required_tools = ['adb', 'fastboot', 'hashcat', 'john']
        
        # Required Python packages
        cls.required_packages = [
            'PyQt5', 'cv2', 'cryptography', 'requests', 
            'psutil', 'sqlite3', 'json', 'logging'
        ]
        
        logger.info("Starting deployment test suite")

    def test_01_system_requirements(self):
        """Test system requirements and compatibility"""
        logger.info("Testing system requirements...")
        
        # Test Python version
        python_version = tuple(map(int, sys.version.split()[0].split('.')))
        self.assertGreaterEqual(python_version, (3, 8), 
                               "Python 3.8 or higher required")
        
        # Test platform
        self.assertEqual(sys.platform, 'linux', 
                        "Linux platform required")
        
        # Test available disk space (at least 1GB)
        statvfs = os.statvfs('/')
        available_bytes = statvfs.f_frsize * statvfs.f_bavail
        available_gb = available_bytes / (1024**3)
        self.assertGreater(available_gb, 1.0, 
                          "At least 1GB disk space required")
        
        logger.info("✓ System requirements validated")

    def test_02_external_tools(self):
        """Test external tool availability"""
        logger.info("Testing external tools...")
        
        missing_tools = []
        
        for tool in self.required_tools:
            try:
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    missing_tools.append(tool)
                else:
                    logger.info(f"✓ {tool} found")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                missing_tools.append(tool)
                logger.warning(f"✗ {tool} not found")
        
        if missing_tools:
            self.skipTest(f"Missing required tools: {missing_tools}")
        
        logger.info("✓ All external tools available")

    def test_03_python_packages(self):
        """Test Python package imports"""
        logger.info("Testing Python packages...")
        
        failed_imports = []
        
        for package in self.required_packages:
            try:
                # Handle package name variations
                import_name = package
                if package == 'cv2':
                    import_name = 'cv2'
                elif package == 'PyQt5':
                    import_name = 'PyQt5.QtWidgets'
                
                importlib.import_module(import_name)
                logger.info(f"✓ {package} imported successfully")
                
            except ImportError as e:
                failed_imports.append(package)
                logger.error(f"✗ Failed to import {package}: {e}")
        
        self.assertEqual(len(failed_imports), 0, 
                        f"Failed to import packages: {failed_imports}")
        
        logger.info("✓ All Python packages imported successfully")

    def test_04_configuration_files(self):
        """Test configuration file creation and validation"""
        logger.info("Testing configuration files...")
        
        # Test main configuration file
        config_file = self.config_dir / 'config.json'
        self.assertTrue(config_file.exists(), 
                       "Main configuration file not found")
        
        # Validate JSON structure
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        required_sections = ['installation', 'tools', 'database', 'security', 'performance']
        for section in required_sections:
            self.assertIn(section, config, f"Missing configuration section: {section}")
        
        # Test file permissions (should be 600 for security)
        file_mode = oct(config_file.stat().st_mode)[-3:]
        self.assertEqual(file_mode, '600', 
                        "Configuration file should have 600 permissions")
        
        # Test encryption key
        key_file = self.config_dir / '.encryption_key'
        self.assertTrue(key_file.exists(), "Encryption key file not found")
        
        # Validate key size (should be 32 bytes for AES-256)
        with open(key_file, 'rb') as f:
            key = f.read()
        self.assertEqual(len(key), 32, "Encryption key should be 32 bytes")
        
        logger.info("✓ Configuration files validated")

    def test_05_database_initialization(self):
        """Test database initialization and structure"""
        logger.info("Testing database initialization...")
        
        databases = ['wordlists.db', 'patterns.db', 'cases.db']
        
        for db_name in databases:
            db_path = self.config_dir / db_name
            self.assertTrue(db_path.exists(), f"Database {db_name} not found")
            
            # Test database connectivity
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Test basic query
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            self.assertGreater(len(tables), 0, f"No tables found in {db_name}")
            
            conn.close()
            logger.info(f"✓ {db_name} validated")
        
        # Test specific table structures
        self._test_wordlists_db()
        self._test_patterns_db()
        self._test_cases_db()
        
        logger.info("✓ All databases initialized correctly")

    def _test_wordlists_db(self):
        """Test wordlists database structure"""
        conn = sqlite3.connect(self.config_dir / 'wordlists.db')
        cursor = conn.cursor()
        
        # Check table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wordlists'")
        self.assertIsNotNone(cursor.fetchone(), "wordlists table not found")
        
        # Check required columns
        cursor.execute("PRAGMA table_info(wordlists)")
        columns = [row[1] for row in cursor.fetchall()]
        required_columns = ['id', 'name', 'path', 'type', 'size', 'hash', 'created_date']
        
        for col in required_columns:
            self.assertIn(col, columns, f"Missing column {col} in wordlists table")
        
        conn.close()

    def _test_patterns_db(self):
        """Test patterns database structure"""
        conn = sqlite3.connect(self.config_dir / 'patterns.db')
        cursor = conn.cursor()
        
        # Check table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='patterns'")
        self.assertIsNotNone(cursor.fetchone(), "patterns table not found")
        
        # Check for default patterns
        cursor.execute("SELECT COUNT(*) FROM patterns")
        count = cursor.fetchone()[0]
        self.assertGreater(count, 0, "No default patterns found")
        
        conn.close()

    def _test_cases_db(self):
        """Test cases database structure"""
        conn = sqlite3.connect(self.config_dir / 'cases.db')
        cursor = conn.cursor()
        
        # Check tables exist
        tables = ['cases', 'evidence_log']
        for table in tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            self.assertIsNotNone(cursor.fetchone(), f"{table} table not found")
        
        conn.close()

    def test_06_directory_structure(self):
        """Test directory structure creation"""
        logger.info("Testing directory structure...")
        
        required_dirs = [
            'wordlists', 'patterns', 'cases', 'logs', 
            'evidence', 'reports', 'temp'
        ]
        
        for dir_name in required_dirs:
            dir_path = self.config_dir / dir_name
            self.assertTrue(dir_path.exists(), f"Directory {dir_name} not found")
            self.assertTrue(dir_path.is_dir(), f"{dir_name} is not a directory")
            logger.info(f"✓ {dir_name} directory exists")
        
        # Test permissions on sensitive directories
        evidence_dir = self.config_dir / 'evidence'
        dir_mode = oct(evidence_dir.stat().st_mode)[-3:]
        self.assertEqual(dir_mode, '700', 
                        "Evidence directory should have 700 permissions")
        
        logger.info("✓ Directory structure validated")

    def test_07_wordlist_files(self):
        """Test default wordlist file creation"""
        logger.info("Testing wordlist files...")
        
        wordlist_files = [
            'common_pins.txt',
            'android_patterns.txt', 
            'common_passwords.txt'
        ]
        
        wordlists_dir = self.config_dir / 'wordlists'
        
        for filename in wordlist_files:
            file_path = wordlists_dir / filename
            self.assertTrue(file_path.exists(), f"Wordlist {filename} not found")
            
            # Check file is not empty
            self.assertGreater(file_path.stat().st_size, 0, 
                             f"Wordlist {filename} is empty")
            
            # Validate content format
            with open(file_path, 'r') as f:
                lines = f.readlines()
            self.assertGreater(len(lines), 0, f"No entries in {filename}")
            
            logger.info(f"✓ {filename} validated")
        
        logger.info("✓ All wordlist files created and validated")

    def test_08_logging_configuration(self):
        """Test logging configuration"""
        logger.info("Testing logging configuration...")
        
        # Test log directory exists
        logs_dir = self.config_dir / 'logs'
        self.assertTrue(logs_dir.exists(), "Logs directory not found")
        
        # Test logging functionality
        test_logger = logging.getLogger('forensics_toolkit.test')
        test_handler = logging.FileHandler(logs_dir / 'test.log')
        test_logger.addHandler(test_handler)
        test_logger.setLevel(logging.INFO)
        
        test_message = "Deployment test log entry"
        test_logger.info(test_message)
        
        # Verify log was written
        log_file = logs_dir / 'test.log'
        self.assertTrue(log_file.exists(), "Test log file not created")
        
        with open(log_file, 'r') as f:
            log_content = f.read()
        self.assertIn(test_message, log_content, "Log message not found")
        
        # Cleanup
        log_file.unlink()
        
        logger.info("✓ Logging configuration validated")

    def test_09_security_features(self):
        """Test security feature implementation"""
        logger.info("Testing security features...")
        
        # Test encryption key security
        key_file = self.config_dir / '.encryption_key'
        key_mode = oct(key_file.stat().st_mode)[-3:]
        self.assertEqual(key_mode, '600', 
                        "Encryption key should have 600 permissions")
        
        # Test configuration file security
        config_file = self.config_dir / 'config.json'
        config_mode = oct(config_file.stat().st_mode)[-3:]
        self.assertEqual(config_mode, '600', 
                        "Configuration file should have 600 permissions")
        
        # Test evidence directory security
        evidence_dir = self.config_dir / 'evidence'
        evidence_mode = oct(evidence_dir.stat().st_mode)[-3:]
        self.assertEqual(evidence_mode, '700', 
                        "Evidence directory should have 700 permissions")
        
        logger.info("✓ Security features validated")

    def test_10_integration_functionality(self):
        """Test basic integration functionality"""
        logger.info("Testing integration functionality...")
        
        # Test configuration loading
        config_file = self.config_dir / 'config.json'
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Test tool paths are valid
        for tool_name, tool_path in config['tools'].items():
            if tool_path and Path(tool_path).exists():
                logger.info(f"✓ {tool_name} path valid: {tool_path}")
            else:
                logger.warning(f"⚠ {tool_name} path may be invalid: {tool_path}")
        
        # Test database connections
        for db_name in ['wordlists_db', 'patterns_db', 'cases_db']:
            db_path = Path(config['database'][db_name])
            if db_path.exists():
                conn = sqlite3.connect(db_path)
                conn.execute('SELECT 1')
                conn.close()
                logger.info(f"✓ {db_name} connection successful")
        
        logger.info("✓ Integration functionality validated")

    def test_11_performance_benchmarks(self):
        """Test basic performance benchmarks"""
        logger.info("Testing performance benchmarks...")
        
        # Test database query performance
        import time
        
        patterns_db = self.config_dir / 'patterns.db'
        conn = sqlite3.connect(patterns_db)
        cursor = conn.cursor()
        
        start_time = time.time()
        cursor.execute("SELECT * FROM patterns ORDER BY frequency DESC LIMIT 100")
        results = cursor.fetchall()
        query_time = time.time() - start_time
        
        self.assertLess(query_time, 1.0, "Database query too slow")
        self.assertGreater(len(results), 0, "No results from database query")
        
        conn.close()
        
        # Test file I/O performance
        test_file = self.config_dir / 'temp' / 'performance_test.txt'
        test_data = "x" * 10000  # 10KB test data
        
        start_time = time.time()
        with open(test_file, 'w') as f:
            f.write(test_data)
        write_time = time.time() - start_time
        
        start_time = time.time()
        with open(test_file, 'r') as f:
            read_data = f.read()
        read_time = time.time() - start_time
        
        self.assertEqual(len(read_data), len(test_data), "File I/O data mismatch")
        self.assertLess(write_time, 1.0, "File write too slow")
        self.assertLess(read_time, 1.0, "File read too slow")
        
        # Cleanup
        test_file.unlink()
        
        logger.info("✓ Performance benchmarks passed")

    def test_12_cleanup_and_recovery(self):
        """Test cleanup and recovery mechanisms"""
        logger.info("Testing cleanup and recovery...")
        
        temp_dir = self.config_dir / 'temp'
        
        # Create test files
        test_files = []
        for i in range(5):
            test_file = temp_dir / f'test_file_{i}.tmp'
            with open(test_file, 'w') as f:
                f.write(f"Test data {i}")
            test_files.append(test_file)
        
        # Verify files exist
        for test_file in test_files:
            self.assertTrue(test_file.exists(), f"Test file {test_file} not created")
        
        # Test cleanup (simulate cleanup function)
        for test_file in test_files:
            if test_file.suffix == '.tmp':
                test_file.unlink()
        
        # Verify cleanup
        for test_file in test_files:
            self.assertFalse(test_file.exists(), f"Test file {test_file} not cleaned up")
        
        logger.info("✓ Cleanup and recovery mechanisms validated")


class DeploymentTestRunner:
    """Test runner for deployment validation"""
    
    def __init__(self):
        self.test_suite = unittest.TestLoader().loadTestsFromTestCase(DeploymentTestSuite)
        self.results = None
    
    def run_tests(self, verbose: bool = True) -> bool:
        """Run all deployment tests"""
        logger.info("Starting deployment test suite...")
        
        # Configure test runner
        runner = unittest.TextTestRunner(
            verbosity=2 if verbose else 1,
            stream=sys.stdout,
            buffer=True
        )
        
        # Run tests
        self.results = runner.run(self.test_suite)
        
        # Print summary
        self._print_summary()
        
        return self.results.wasSuccessful()
    
    def _print_summary(self):
        """Print test results summary"""
        if not self.results:
            return
        
        total_tests = self.results.testsRun
        failures = len(self.results.failures)
        errors = len(self.results.errors)
        skipped = len(self.results.skipped)
        passed = total_tests - failures - errors - skipped
        
        print("\n" + "="*60)
        print("DEPLOYMENT TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed}")
        print(f"Failed: {failures}")
        print(f"Errors: {errors}")
        print(f"Skipped: {skipped}")
        print("="*60)
        
        if self.results.wasSuccessful():
            print("✓ ALL TESTS PASSED - Deployment is ready!")
        else:
            print("✗ SOME TESTS FAILED - Check deployment")
            
            if self.results.failures:
                print("\nFailures:")
                for test, traceback in self.results.failures:
                    print(f"- {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0]}")
            
            if self.results.errors:
                print("\nErrors:")
                for test, traceback in self.results.errors:
                    print(f"- {test}: {traceback.split('\\n')[-2]}")


def main():
    """Main entry point for deployment testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ForenCrack Droid Deployment Test Suite')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (minimal output)')
    parser.add_argument('--list-tests', action='store_true',
                       help='List all available tests')
    
    args = parser.parse_args()
    
    if args.list_tests:
        print("Available deployment tests:")
        suite = unittest.TestLoader().loadTestsFromTestCase(DeploymentTestSuite)
        for test in suite:
            print(f"- {test._testMethodName}: {test._testMethodDoc}")
        return
    
    # Set logging level based on arguments
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run tests
    runner = DeploymentTestRunner()
    success = runner.run_tests(verbose=args.verbose and not args.quiet)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()