"""
Configuration management for tool paths and settings
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class ToolPaths:
    """External tool paths configuration"""
    adb_path: str = "adb"
    fastboot_path: str = "fastboot"
    hashcat_path: str = "hashcat"
    john_path: str = "john"
    opencv_path: Optional[str] = None
    edl_py_path: Optional[str] = None


@dataclass
class ForensicsSettings:
    """General forensics settings"""
    max_concurrent_attacks: int = 4
    default_timeout: int = 300
    evidence_directory: str = "./evidence"
    wordlist_directory: str = "./wordlists"
    log_level: str = "INFO"
    gpu_acceleration: bool = True
    auto_delay_handling: bool = True


@dataclass
class SecuritySettings:
    """Security and compliance settings"""
    require_case_id: bool = True
    require_legal_disclaimer: bool = True
    encrypt_evidence: bool = True
    audit_all_operations: bool = True
    authorized_users: list = None
    session_timeout: int = 3600
    
    def __post_init__(self):
        if self.authorized_users is None:
            self.authorized_users = []


class ConfigManager:
    """Configuration manager for the forensics toolkit"""
    
    def __init__(self, config_path: str = "./config/forensics_config.json"):
        self.config_path = Path(config_path)
        self.tool_paths = ToolPaths()
        self.forensics_settings = ForensicsSettings()
        self.security_settings = SecuritySettings()
        
        # Create config directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing configuration
        self.load_config()
    
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Load tool paths
                if 'tool_paths' in config_data:
                    tool_data = config_data['tool_paths']
                    self.tool_paths = ToolPaths(**tool_data)
                
                # Load forensics settings
                if 'forensics_settings' in config_data:
                    forensics_data = config_data['forensics_settings']
                    self.forensics_settings = ForensicsSettings(**forensics_data)
                
                # Load security settings
                if 'security_settings' in config_data:
                    security_data = config_data['security_settings']
                    self.security_settings = SecuritySettings(**security_data)
                
                return True
        except Exception as e:
            print(f"Error loading config: {e}")
            return False
        
        return False
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            config_data = {
                'tool_paths': asdict(self.tool_paths),
                'forensics_settings': asdict(self.forensics_settings),
                'security_settings': asdict(self.security_settings)
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def validate_tool_paths(self) -> Dict[str, bool]:
        """Validate that external tools are accessible"""
        validation_results = {}
        
        # Check ADB
        validation_results['adb'] = self._check_tool_exists(self.tool_paths.adb_path)
        
        # Check Fastboot
        validation_results['fastboot'] = self._check_tool_exists(self.tool_paths.fastboot_path)
        
        # Check Hashcat
        validation_results['hashcat'] = self._check_tool_exists(self.tool_paths.hashcat_path)
        
        # Check John the Ripper
        validation_results['john'] = self._check_tool_exists(self.tool_paths.john_path)
        
        # Check optional tools
        if self.tool_paths.edl_py_path:
            validation_results['edl_py'] = self._check_tool_exists(self.tool_paths.edl_py_path)
        
        return validation_results
    
    def _check_tool_exists(self, tool_path: str) -> bool:
        """Check if a tool exists and is executable"""
        try:
            # Try to run the tool with --version or --help
            import subprocess
            result = subprocess.run([tool_path, '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            try:
                # Try with --help if --version fails
                result = subprocess.run([tool_path, '--help'], 
                                      capture_output=True, 
                                      timeout=5)
                return result.returncode == 0
            except:
                return False
    
    def get_evidence_path(self, case_id: str) -> Path:
        """Get evidence directory path for a case"""
        evidence_dir = Path(self.forensics_settings.evidence_directory) / case_id
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return evidence_dir
    
    def get_wordlist_path(self, wordlist_name: str) -> Path:
        """Get path to a wordlist file"""
        return Path(self.forensics_settings.wordlist_directory) / wordlist_name
    
    def update_tool_path(self, tool_name: str, path: str) -> bool:
        """Update a specific tool path"""
        if hasattr(self.tool_paths, f"{tool_name}_path"):
            setattr(self.tool_paths, f"{tool_name}_path", path)
            return self.save_config()
        return False
    
    def update_setting(self, category: str, setting: str, value: Any) -> bool:
        """Update a specific setting"""
        try:
            if category == "forensics":
                if hasattr(self.forensics_settings, setting):
                    setattr(self.forensics_settings, setting, value)
                    return self.save_config()
            elif category == "security":
                if hasattr(self.security_settings, setting):
                    setattr(self.security_settings, setting, value)
                    return self.save_config()
            return False
        except Exception:
            return False


# Global configuration instance
config_manager = ConfigManager()