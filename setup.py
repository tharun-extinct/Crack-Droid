#!/usr/bin/env python3
"""
ForenCrack Droid Setup Script
Advanced configuration and validation for forensics toolkit
"""

import os
import sys
import json
import sqlite3
import hashlib
import subprocess
import platform
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ForensicsSetup:
    """Main setup class for ForenCrack Droid toolkit"""
    
    def __init__(self):
        self.home_dir = Path.home()
        self.config_dir = self.home_dir / '.forensics-toolkit'
        self.install_dir = Path('/opt/forensics-toolkit')
        self.current_dir = Path.cwd()
        
        # Supported OS versions
        self.supported_os = {
            'kali': ['2023.1', '2023.2', '2023.3', '2023.4'],
            'ubuntu': ['20.04', '22.04', '23.04', '23.10']
        }
        
        # Required tools and their minimum versions
        self.required_tools = {
            'python3': '3.8.0',
            'adb': '1.0.39',
            'fastboot': '1.0.39',
            'hashcat': '6.0.0',
            'john': '1.9.0'
        }
        
        # Python packages with versions
        self.python_packages = {
            'PyQt5': '5.15.0',
            'opencv-python': '4.5.0',
            'cryptography': '3.4.0',
            'requests': '2.25.0',
            'psutil': '5.8.0',
            'pycryptodome': '3.10.0'
        }

    def detect_system(self) -> Dict[str, str]:
        """Detect system information"""
        logger.info("Detecting system information...")
        
        system_info = {
            'platform': platform.system(),
            'machine': platform.machine(),
            'python_version': platform.python_version(),
            'distribution': 'unknown',
            'version': 'unknown'
        }
        
        # Detect Linux distribution
        if system_info['platform'] == 'Linux':
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read()
                    
                for line in os_release.split('\n'):
                    if line.startswith('ID='):
                        system_info['distribution'] = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION_ID='):
                        system_info['version'] = line.split('=')[1].strip('"')
                        
            except FileNotFoundError:
                logger.warning("Could not detect Linux distribution")
        
        logger.info(f"System: {system_info['distribution']} {system_info['version']}")
        return system_info

    def validate_system_compatibility(self, system_info: Dict[str, str]) -> bool:
        """Validate system compatibility"""
        logger.info("Validating system compatibility...")
        
        if system_info['platform'] != 'Linux':
            logger.error(f"Unsupported platform: {system_info['platform']}")
            return False
            
        dist = system_info['distribution'].lower()
        version = system_info['version']
        
        if dist == 'kali':
            if version not in self.supported_os['kali']:
                logger.warning(f"Kali Linux {version} not officially supported")
        elif 'ubuntu' in dist:
            if version not in self.supported_os['ubuntu']:
                logger.warning(f"Ubuntu {version} not officially supported")
        else:
            logger.error(f"Unsupported distribution: {dist}")
            return False
            
        # Check Python version
        python_version = tuple(map(int, system_info['python_version'].split('.')))
        required_python = tuple(map(int, self.required_tools['python3'].split('.')))
        
        if python_version < required_python:
            logger.error(f"Python {self.required_tools['python3']} or higher required")
            return False
            
        logger.info("System compatibility validated")
        return True

    def check_dependencies(self) -> Dict[str, bool]:
        """Check for required dependencies"""
        logger.info("Checking dependencies...")
        
        results = {}
        
        for tool, min_version in self.required_tools.items():
            if tool == 'python3':
                continue  # Already checked
                
            try:
                # Check if tool exists
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    results[tool] = True
                    logger.info(f"✓ {tool} found")
                else:
                    results[tool] = False
                    logger.warning(f"✗ {tool} not found or not working")
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                results[tool] = False
                logger.warning(f"✗ {tool} not found")
                
        return results

    def install_python_packages(self) -> bool:
        """Install required Python packages"""
        logger.info("Installing Python packages...")
        
        try:
            # Upgrade pip first
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                          check=True, capture_output=True)
            
            # Install packages
            for package, version in self.python_packages.items():
                logger.info(f"Installing {package}>={version}")
                subprocess.run([sys.executable, '-m', 'pip', 'install', f'{package}>={version}'],
                              check=True, capture_output=True)
                              
            logger.info("Python packages installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Python packages: {e}")
            return False

    def create_directory_structure(self) -> bool:
        """Create necessary directory structure"""
        logger.info("Creating directory structure...")
        
        directories = [
            self.config_dir,
            self.config_dir / 'wordlists',
            self.config_dir / 'patterns',
            self.config_dir / 'cases',
            self.config_dir / 'logs',
            self.config_dir / 'evidence',
            self.config_dir / 'reports',
            self.config_dir / 'temp'
        ]
        
        try:
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created directory: {directory}")
                
            # Set appropriate permissions
            os.chmod(self.config_dir, 0o700)  # Owner only
            os.chmod(self.config_dir / 'evidence', 0o700)  # Secure evidence storage
            
            logger.info("Directory structure created successfully")
            return True
            
        except OSError as e:
            logger.error(f"Failed to create directories: {e}")
            return False

    def generate_configuration(self) -> bool:
        """Generate configuration files"""
        logger.info("Generating configuration files...")
        
        try:
            # Main configuration
            config = {
                "installation": {
                    "version": "1.0.0",
                    "install_date": subprocess.run(['date', '-Iseconds'], 
                                                 capture_output=True, text=True).stdout.strip(),
                    "install_dir": str(self.install_dir),
                    "config_dir": str(self.config_dir)
                },
                "tools": {
                    "adb_path": shutil.which('adb') or '/usr/bin/adb',
                    "fastboot_path": shutil.which('fastboot') or '/usr/bin/fastboot',
                    "hashcat_path": shutil.which('hashcat') or '/usr/bin/hashcat',
                    "john_path": shutil.which('john') or '/usr/bin/john',
                    "edl_path": str(self.current_dir / 'tools' / 'edl' / 'edl.py')
                },
                "database": {
                    "wordlists_db": str(self.config_dir / 'wordlists.db'),
                    "patterns_db": str(self.config_dir / 'patterns.db'),
                    "cases_db": str(self.config_dir / 'cases.db')
                },
                "security": {
                    "require_authentication": True,
                    "session_timeout": 3600,
                    "audit_logging": True,
                    "evidence_encryption": True,
                    "encryption_algorithm": "AES-256-GCM"
                },
                "performance": {
                    "max_threads": min(os.cpu_count() or 4, 8),
                    "gpu_acceleration": True,
                    "memory_limit_mb": 2048,
                    "temp_cleanup": True
                },
                "logging": {
                    "level": "INFO",
                    "max_file_size_mb": 100,
                    "backup_count": 5,
                    "evidence_log_retention_days": 365
                }
            }
            
            # Write main config
            config_file = self.config_dir / 'config.json'
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            os.chmod(config_file, 0o600)  # Owner read/write only
            
            # Generate encryption key for evidence
            self._generate_encryption_key()
            
            logger.info("Configuration files generated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate configuration: {e}")
            return False

    def _generate_encryption_key(self) -> None:
        """Generate encryption key for evidence protection"""
        key_file = self.config_dir / '.encryption_key'
        
        if not key_file.exists():
            # Generate 256-bit key
            key = os.urandom(32)
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            logger.info("Encryption key generated")

    def initialize_databases(self) -> bool:
        """Initialize SQLite databases"""
        logger.info("Initializing databases...")
        
        try:
            # Wordlists database
            wordlists_db = self.config_dir / 'wordlists.db'
            self._create_wordlists_db(wordlists_db)
            
            # Patterns database
            patterns_db = self.config_dir / 'patterns.db'
            self._create_patterns_db(patterns_db)
            
            # Cases database
            cases_db = self.config_dir / 'cases.db'
            self._create_cases_db(cases_db)
            
            logger.info("Databases initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize databases: {e}")
            return False

    def _create_wordlists_db(self, db_path: Path) -> None:
        """Create wordlists database"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wordlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                path TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('pin', 'password', 'pattern')),
                size INTEGER,
                hash TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_wordlist_type ON wordlists(type)
        ''')
        
        # Insert default wordlists
        default_wordlists = [
            ('common_pins', 'wordlists/common_pins.txt', 'pin'),
            ('android_patterns', 'wordlists/android_patterns.txt', 'pattern'),
            ('common_passwords', 'wordlists/common_passwords.txt', 'password')
        ]
        
        cursor.executemany('''
            INSERT OR IGNORE INTO wordlists (name, path, type) VALUES (?, ?, ?)
        ''', default_wordlists)
        
        conn.commit()
        conn.close()

    def _create_patterns_db(self, db_path: Path) -> None:
        """Create patterns database"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE NOT NULL,
                frequency INTEGER DEFAULT 1,
                category TEXT,
                complexity INTEGER,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_pattern_frequency ON patterns(frequency DESC)
        ''')
        
        # Insert common Android patterns
        common_patterns = [
            ('1234', 1000, 'pin', 1),
            ('0000', 800, 'pin', 1),
            ('1111', 600, 'pin', 1),
            ('L-shape', 500, 'gesture', 2),
            ('Z-pattern', 300, 'gesture', 3)
        ]
        
        cursor.executemany('''
            INSERT OR IGNORE INTO patterns (pattern, frequency, category, complexity) 
            VALUES (?, ?, ?, ?)
        ''', common_patterns)
        
        conn.commit()
        conn.close()

    def _create_cases_db(self, db_path: Path) -> None:
        """Create cases database"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                investigator TEXT NOT NULL,
                device_serial TEXT,
                device_model TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'suspended')),
                evidence_hash TEXT,
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                operation TEXT NOT NULL,
                details TEXT,
                hash TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def create_default_wordlists(self) -> bool:
        """Create default wordlist files"""
        logger.info("Creating default wordlists...")
        
        try:
            wordlists_dir = self.config_dir / 'wordlists'
            
            # Common PINs
            common_pins = [
                '1234', '0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
                '1212', '2121', '1010', '2020', '1122', '2211', '1221', '2112',
                '0123', '1230', '2301', '3012', '9876', '8765', '7654', '6543',
                '1357', '2468', '1379', '2580', '1470', '2580', '3690'
            ]
            
            pins_file = wordlists_dir / 'common_pins.txt'
            with open(pins_file, 'w') as f:
                f.write('\n'.join(common_pins))
            
            # Android gesture patterns (encoded)
            android_patterns = [
                '0123456789',  # L-shape
                '01234',       # Top row
                '147',         # Left column
                '258',         # Middle column
                '369',         # Right column
                '048',         # Cross pattern
                '0246',        # Square
                '02468',       # Z-pattern
            ]
            
            patterns_file = wordlists_dir / 'android_patterns.txt'
            with open(patterns_file, 'w') as f:
                f.write('\n'.join(android_patterns))
            
            # Common passwords
            common_passwords = [
                'password', '123456', 'password123', 'admin', 'letmein',
                'welcome', 'monkey', 'dragon', 'qwerty', 'abc123',
                'android', 'samsung', 'google', 'unlock', 'secret'
            ]
            
            passwords_file = wordlists_dir / 'common_passwords.txt'
            with open(passwords_file, 'w') as f:
                f.write('\n'.join(common_passwords))
            
            logger.info("Default wordlists created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create wordlists: {e}")
            return False

    def validate_installation(self) -> bool:
        """Validate the installation"""
        logger.info("Validating installation...")
        
        validation_results = []
        
        # Check configuration files
        config_file = self.config_dir / 'config.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    json.load(f)
                validation_results.append(("Configuration file", True))
            except json.JSONDecodeError:
                validation_results.append(("Configuration file", False))
        else:
            validation_results.append(("Configuration file", False))
        
        # Check databases
        for db_name in ['wordlists.db', 'patterns.db', 'cases.db']:
            db_path = self.config_dir / db_name
            if db_path.exists():
                try:
                    conn = sqlite3.connect(db_path)
                    conn.execute('SELECT 1')
                    conn.close()
                    validation_results.append((f"{db_name}", True))
                except sqlite3.Error:
                    validation_results.append((f"{db_name}", False))
            else:
                validation_results.append((f"{db_name}", False))
        
        # Check Python packages
        for package in self.python_packages:
            try:
                __import__(package.replace('-', '_'))
                validation_results.append((f"Python {package}", True))
            except ImportError:
                validation_results.append((f"Python {package}", False))
        
        # Print results
        all_passed = True
        for item, passed in validation_results:
            status = "✓" if passed else "✗"
            logger.info(f"{status} {item}")
            if not passed:
                all_passed = False
        
        if all_passed:
            logger.info("Installation validation passed")
        else:
            logger.warning("Some validation checks failed")
        
        return all_passed

    def run_setup(self) -> bool:
        """Run the complete setup process"""
        logger.info("Starting ForenCrack Droid setup...")
        
        try:
            # System detection and validation
            system_info = self.detect_system()
            if not self.validate_system_compatibility(system_info):
                return False
            
            # Check dependencies
            deps = self.check_dependencies()
            missing_deps = [tool for tool, found in deps.items() if not found]
            if missing_deps:
                logger.warning(f"Missing dependencies: {missing_deps}")
                logger.info("Please install missing dependencies and run setup again")
            
            # Setup steps
            steps = [
                ("Installing Python packages", self.install_python_packages),
                ("Creating directory structure", self.create_directory_structure),
                ("Generating configuration", self.generate_configuration),
                ("Initializing databases", self.initialize_databases),
                ("Creating default wordlists", self.create_default_wordlists),
                ("Validating installation", self.validate_installation)
            ]
            
            for step_name, step_func in steps:
                logger.info(f"Step: {step_name}")
                if not step_func():
                    logger.error(f"Failed: {step_name}")
                    return False
            
            logger.info("Setup completed successfully!")
            logger.info(f"Configuration directory: {self.config_dir}")
            logger.info("Run 'python3 forencracks.py --help' to get started")
            
            return True
            
        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False


def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("ForenCrack Droid Setup Script")
        print("Usage: python3 setup.py")
        print("\nThis script will:")
        print("- Validate system compatibility")
        print("- Install Python dependencies")
        print("- Create configuration files")
        print("- Initialize databases")
        print("- Set up default wordlists")
        return
    
    setup = ForensicsSetup()
    success = setup.run_setup()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()