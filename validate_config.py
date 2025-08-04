#!/usr/bin/env python3
"""
ForenCrack Droid Configuration Validation Script
Validates configuration files and system setup
"""

import os
import sys
import json
import sqlite3
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigValidator:
    """Configuration validation class"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / '.forensics-toolkit'
        self.validation_errors = []
        self.validation_warnings = []
        
        # Expected configuration schema
        self.config_schema = {
            'installation': {
                'required': ['version', 'install_date', 'install_dir', 'config_dir'],
                'types': {'version': str, 'install_date': str, 'install_dir': str, 'config_dir': str}
            },
            'tools': {
                'required': ['adb_path', 'fastboot_path', 'hashcat_path', 'john_path'],
                'types': {'adb_path': str, 'fastboot_path': str, 'hashcat_path': str, 'john_path': str}
            },
            'database': {
                'required': ['wordlists_db', 'patterns_db', 'cases_db'],
                'types': {'wordlists_db': str, 'patterns_db': str, 'cases_db': str}
            },
            'security': {
                'required': ['require_authentication', 'session_timeout', 'audit_logging', 'evidence_encryption'],
                'types': {'require_authentication': bool, 'session_timeout': int, 'audit_logging': bool, 'evidence_encryption': bool}
            },
            'performance': {
                'required': ['max_threads', 'gpu_acceleration'],
                'types': {'max_threads': int, 'gpu_acceleration': bool}
            }
        }

    def validate_config_file(self) -> bool:
        """Validate main configuration file"""
        logger.info("Validating configuration file...")
        
        config_file = self.config_dir / 'config.json'
        
        # Check file exists
        if not config_file.exists():
            self.validation_errors.append("Configuration file not found")
            return False
        
        # Check file permissions
        file_mode = oct(config_file.stat().st_mode)[-3:]
        if file_mode != '600':
            self.validation_warnings.append(f"Configuration file permissions should be 600, found {file_mode}")
        
        try:
            # Load and validate JSON
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Validate schema
            self._validate_config_schema(config)
            
            # Validate tool paths
            self._validate_tool_paths(config.get('tools', {}))
            
            # Validate database paths
            self._validate_database_paths(config.get('database', {}))
            
            # Validate security settings
            self._validate_security_settings(config.get('security', {}))
            
            logger.info("✓ Configuration file validation completed")
            return len(self.validation_errors) == 0
            
        except json.JSONDecodeError as e:
            self.validation_errors.append(f"Invalid JSON in configuration file: {e}")
            return False
        except Exception as e:
            self.validation_errors.append(f"Error validating configuration: {e}")
            return False

    def _validate_config_schema(self, config: Dict[str, Any]) -> None:
        """Validate configuration against expected schema"""
        for section_name, section_schema in self.config_schema.items():
            if section_name not in config:
                self.validation_errors.append(f"Missing configuration section: {section_name}")
                continue
            
            section = config[section_name]
            
            # Check required fields
            for required_field in section_schema['required']:
                if required_field not in section:
                    self.validation_errors.append(f"Missing required field: {section_name}.{required_field}")
                    continue
                
                # Check field type
                expected_type = section_schema['types'].get(required_field)
                if expected_type and not isinstance(section[required_field], expected_type):
                    self.validation_errors.append(
                        f"Invalid type for {section_name}.{required_field}: "
                        f"expected {expected_type.__name__}, got {type(section[required_field]).__name__}"
                    )

    def _validate_tool_paths(self, tools_config: Dict[str, str]) -> None:
        """Validate external tool paths"""
        for tool_name, tool_path in tools_config.items():
            if not tool_path:
                self.validation_warnings.append(f"Empty path for tool: {tool_name}")
                continue
            
            path = Path(tool_path)
            if not path.exists():
                self.validation_warnings.append(f"Tool path does not exist: {tool_name} -> {tool_path}")
            elif not path.is_file():
                self.validation_warnings.append(f"Tool path is not a file: {tool_name} -> {tool_path}")
            elif not os.access(path, os.X_OK):
                self.validation_warnings.append(f"Tool is not executable: {tool_name} -> {tool_path}")

    def _validate_database_paths(self, database_config: Dict[str, str]) -> None:
        """Validate database file paths"""
        for db_name, db_path in database_config.items():
            if not db_path:
                self.validation_errors.append(f"Empty database path: {db_name}")
                continue
            
            path = Path(db_path)
            if not path.exists():
                self.validation_errors.append(f"Database file does not exist: {db_name} -> {db_path}")
            elif not path.is_file():
                self.validation_errors.append(f"Database path is not a file: {db_name} -> {db_path}")
            else:
                # Test database connectivity
                try:
                    conn = sqlite3.connect(db_path)
                    conn.execute('SELECT 1')
                    conn.close()
                except sqlite3.Error as e:
                    self.validation_errors.append(f"Database connection failed: {db_name} -> {e}")

    def _validate_security_settings(self, security_config: Dict[str, Any]) -> None:
        """Validate security configuration"""
        # Check session timeout
        timeout = security_config.get('session_timeout', 0)
        if timeout < 300:  # 5 minutes minimum
            self.validation_warnings.append("Session timeout should be at least 300 seconds (5 minutes)")
        elif timeout > 86400:  # 24 hours maximum
            self.validation_warnings.append("Session timeout should not exceed 86400 seconds (24 hours)")
        
        # Check encryption settings
        if not security_config.get('evidence_encryption', False):
            self.validation_warnings.append("Evidence encryption is disabled - this may not be secure")

    def validate_encryption_key(self) -> bool:
        """Validate encryption key file"""
        logger.info("Validating encryption key...")
        
        key_file = self.config_dir / '.encryption_key'
        
        # Check file exists
        if not key_file.exists():
            self.validation_errors.append("Encryption key file not found")
            return False
        
        # Check file permissions
        file_mode = oct(key_file.stat().st_mode)[-3:]
        if file_mode != '600':
            self.validation_errors.append(f"Encryption key permissions should be 600, found {file_mode}")
        
        # Check key size
        try:
            with open(key_file, 'rb') as f:
                key = f.read()
            
            if len(key) != 32:
                self.validation_errors.append(f"Encryption key should be 32 bytes, found {len(key)} bytes")
            
            # Check key entropy (basic check)
            if len(set(key)) < 16:
                self.validation_warnings.append("Encryption key may have low entropy")
            
            logger.info("✓ Encryption key validation completed")
            return len(self.validation_errors) == 0
            
        except Exception as e:
            self.validation_errors.append(f"Error reading encryption key: {e}")
            return False

    def validate_databases(self) -> bool:
        """Validate database structure and content"""
        logger.info("Validating databases...")
        
        databases = {
            'wordlists.db': self._validate_wordlists_db,
            'patterns.db': self._validate_patterns_db,
            'cases.db': self._validate_cases_db
        }
        
        all_valid = True
        
        for db_name, validator_func in databases.items():
            db_path = self.config_dir / db_name
            if not db_path.exists():
                self.validation_errors.append(f"Database not found: {db_name}")
                all_valid = False
                continue
            
            try:
                validator_func(db_path)
                logger.info(f"✓ {db_name} validation completed")
            except Exception as e:
                self.validation_errors.append(f"Database validation failed for {db_name}: {e}")
                all_valid = False
        
        return all_valid

    def _validate_wordlists_db(self, db_path: Path) -> None:
        """Validate wordlists database structure"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wordlists'")
        if not cursor.fetchone():
            raise ValueError("wordlists table not found")
        
        # Check required columns
        cursor.execute("PRAGMA table_info(wordlists)")
        columns = [row[1] for row in cursor.fetchall()]
        required_columns = ['id', 'name', 'path', 'type', 'created_date']
        
        missing_columns = set(required_columns) - set(columns)
        if missing_columns:
            raise ValueError(f"Missing columns in wordlists table: {missing_columns}")
        
        # Check for default entries
        cursor.execute("SELECT COUNT(*) FROM wordlists")
        count = cursor.fetchone()[0]
        if count == 0:
            self.validation_warnings.append("No wordlists found in database")
        
        conn.close()

    def _validate_patterns_db(self, db_path: Path) -> None:
        """Validate patterns database structure"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='patterns'")
        if not cursor.fetchone():
            raise ValueError("patterns table not found")
        
        # Check for default patterns
        cursor.execute("SELECT COUNT(*) FROM patterns")
        count = cursor.fetchone()[0]
        if count == 0:
            self.validation_warnings.append("No patterns found in database")
        
        conn.close()

    def _validate_cases_db(self, db_path: Path) -> None:
        """Validate cases database structure"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check required tables
        required_tables = ['cases', 'evidence_log']
        for table in required_tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if not cursor.fetchone():
                raise ValueError(f"{table} table not found")
        
        conn.close()

    def validate_directory_structure(self) -> bool:
        """Validate directory structure"""
        logger.info("Validating directory structure...")
        
        required_dirs = [
            'wordlists', 'patterns', 'cases', 'logs',
            'evidence', 'reports', 'temp'
        ]
        
        all_valid = True
        
        for dir_name in required_dirs:
            dir_path = self.config_dir / dir_name
            if not dir_path.exists():
                self.validation_errors.append(f"Required directory not found: {dir_name}")
                all_valid = False
            elif not dir_path.is_dir():
                self.validation_errors.append(f"Path is not a directory: {dir_name}")
                all_valid = False
        
        # Check sensitive directory permissions
        sensitive_dirs = ['evidence', 'logs']
        for dir_name in sensitive_dirs:
            dir_path = self.config_dir / dir_name
            if dir_path.exists():
                dir_mode = oct(dir_path.stat().st_mode)[-3:]
                if dir_mode != '700':
                    self.validation_warnings.append(
                        f"Directory {dir_name} should have 700 permissions, found {dir_mode}"
                    )
        
        logger.info("✓ Directory structure validation completed")
        return all_valid

    def validate_wordlist_files(self) -> bool:
        """Validate wordlist files"""
        logger.info("Validating wordlist files...")
        
        wordlists_dir = self.config_dir / 'wordlists'
        if not wordlists_dir.exists():
            self.validation_errors.append("Wordlists directory not found")
            return False
        
        expected_files = [
            'common_pins.txt',
            'android_patterns.txt',
            'common_passwords.txt'
        ]
        
        all_valid = True
        
        for filename in expected_files:
            file_path = wordlists_dir / filename
            if not file_path.exists():
                self.validation_warnings.append(f"Default wordlist not found: {filename}")
                continue
            
            # Check file is not empty
            if file_path.stat().st_size == 0:
                self.validation_warnings.append(f"Wordlist file is empty: {filename}")
                continue
            
            # Validate content format
            try:
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                
                if len(lines) == 0:
                    self.validation_warnings.append(f"No entries in wordlist: {filename}")
                
                # Check for common issues
                empty_lines = sum(1 for line in lines if not line.strip())
                if empty_lines > len(lines) * 0.1:  # More than 10% empty lines
                    self.validation_warnings.append(f"Many empty lines in wordlist: {filename}")
                
            except Exception as e:
                self.validation_errors.append(f"Error reading wordlist {filename}: {e}")
                all_valid = False
        
        logger.info("✓ Wordlist files validation completed")
        return all_valid

    def validate_tool_functionality(self) -> bool:
        """Validate external tool functionality"""
        logger.info("Validating tool functionality...")
        
        # Load configuration to get tool paths
        config_file = self.config_dir / 'config.json'
        if not config_file.exists():
            self.validation_errors.append("Cannot validate tools: configuration file not found")
            return False
        
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        tools = config.get('tools', {})
        all_functional = True
        
        # Test each tool
        tool_tests = {
            'adb_path': ['adb', 'version'],
            'fastboot_path': ['fastboot', '--version'],
            'hashcat_path': ['hashcat', '--version'],
            'john_path': ['john', '--list=formats']
        }
        
        for tool_config, test_args in tool_tests.items():
            tool_path = tools.get(tool_config)
            if not tool_path:
                self.validation_warnings.append(f"Tool path not configured: {tool_config}")
                continue
            
            try:
                # Use the configured path for the first argument
                test_command = [tool_path] + test_args[1:]
                result = subprocess.run(test_command, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    logger.info(f"✓ {tool_config} functional")
                else:
                    self.validation_warnings.append(f"Tool test failed: {tool_config}")
                    all_functional = False
                    
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                self.validation_warnings.append(f"Tool test error: {tool_config} -> {e}")
                all_functional = False
        
        logger.info("✓ Tool functionality validation completed")
        return all_functional

    def run_full_validation(self) -> bool:
        """Run complete validation suite"""
        logger.info("Starting full configuration validation...")
        
        validation_steps = [
            ("Configuration file", self.validate_config_file),
            ("Encryption key", self.validate_encryption_key),
            ("Databases", self.validate_databases),
            ("Directory structure", self.validate_directory_structure),
            ("Wordlist files", self.validate_wordlist_files),
            ("Tool functionality", self.validate_tool_functionality)
        ]
        
        all_passed = True
        
        for step_name, step_func in validation_steps:
            logger.info(f"Validating: {step_name}")
            try:
                if not step_func():
                    all_passed = False
            except Exception as e:
                logger.error(f"Validation step failed: {step_name} -> {e}")
                self.validation_errors.append(f"Validation step failed: {step_name} -> {e}")
                all_passed = False
        
        # Print summary
        self._print_validation_summary()
        
        return all_passed

    def _print_validation_summary(self) -> None:
        """Print validation results summary"""
        print("\n" + "="*60)
        print("CONFIGURATION VALIDATION SUMMARY")
        print("="*60)
        
        if not self.validation_errors and not self.validation_warnings:
            print("✓ ALL VALIDATIONS PASSED")
            print("Configuration is ready for use!")
        else:
            if self.validation_errors:
                print(f"✗ ERRORS: {len(self.validation_errors)}")
                for error in self.validation_errors:
                    print(f"  - {error}")
            
            if self.validation_warnings:
                print(f"⚠ WARNINGS: {len(self.validation_warnings)}")
                for warning in self.validation_warnings:
                    print(f"  - {warning}")
            
            if self.validation_errors:
                print("\nConfiguration has critical errors that must be fixed!")
            else:
                print("\nConfiguration is functional but has warnings.")
        
        print("="*60)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ForenCrack Droid Configuration Validator')
    parser.add_argument('--config-dir', type=Path,
                       help='Configuration directory path (default: ~/.forensics-toolkit)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--fix-permissions', action='store_true',
                       help='Attempt to fix file/directory permissions')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize validator
    validator = ConfigValidator(args.config_dir)
    
    # Fix permissions if requested
    if args.fix_permissions:
        logger.info("Attempting to fix permissions...")
        try:
            # Fix config file permissions
            config_file = validator.config_dir / 'config.json'
            if config_file.exists():
                os.chmod(config_file, 0o600)
            
            # Fix encryption key permissions
            key_file = validator.config_dir / '.encryption_key'
            if key_file.exists():
                os.chmod(key_file, 0o600)
            
            # Fix sensitive directory permissions
            for dir_name in ['evidence', 'logs']:
                dir_path = validator.config_dir / dir_name
                if dir_path.exists():
                    os.chmod(dir_path, 0o700)
            
            logger.info("Permissions fixed")
        except Exception as e:
            logger.error(f"Failed to fix permissions: {e}")
    
    # Run validation
    success = validator.run_full_validation()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()