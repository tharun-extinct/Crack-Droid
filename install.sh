#!/bin/bash

# Crack Droid Installation Script
# Supports Kali Linux and Ubuntu Forensic Edition

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/forensics-toolkit"
CONFIG_DIR="$HOME/.forensics-toolkit"
LOG_FILE="/tmp/forensics-toolkit-install.log"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons"
        print_status "Please run as a regular user with sudo privileges"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    print_status "Detected OS: $OS $VERSION"
    
    case $OS in
        "Kali GNU/Linux")
            OS_TYPE="kali"
            ;;
        "Ubuntu"*)
            OS_TYPE="ubuntu"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            print_status "This installer supports Kali Linux and Ubuntu only"
            exit 1
            ;;
    esac
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$PYTHON_VERSION < 3.8" | bc -l) -eq 1 ]]; then
        print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
        exit 1
    fi
    
    print_success "Python $PYTHON_VERSION found"
    
    # Check available disk space (minimum 2GB)
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 2097152 ]]; then
        print_warning "Low disk space. At least 2GB recommended"
    fi
    
    # Check memory (minimum 4GB recommended)
    TOTAL_MEM=$(free -m | awk 'NR==2{print $2}')
    if [[ $TOTAL_MEM -lt 4096 ]]; then
        print_warning "Low memory. At least 4GB RAM recommended for optimal performance"
    fi
}

# Function to install system dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    
    # Update package lists
    sudo apt update >> $LOG_FILE 2>&1
    
    # Common dependencies for both Kali and Ubuntu
    COMMON_DEPS=(
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "git"
        "curl"
        "wget"
        "unzip"
        "android-tools-adb"
        "android-tools-fastboot"
        "hashcat"
        "john"
        "sqlite3"
        "libssl-dev"
        "libffi-dev"
        "libjpeg-dev"
        "libpng-dev"
        "libopencv-dev"
        "python3-opencv"
        "python3-pyqt5"
        "python3-pyqt5.qtwidgets"
    )
    
    # OS-specific dependencies
    if [[ $OS_TYPE == "kali" ]]; then
        SPECIFIC_DEPS=(
            "kali-linux-forensic"
            "volatility3"
        )
    elif [[ $OS_TYPE == "ubuntu" ]]; then
        SPECIFIC_DEPS=(
            "forensics-all"
        )
    fi
    
    # Install dependencies
    for dep in "${COMMON_DEPS[@]}" "${SPECIFIC_DEPS[@]}"; do
        print_status "Installing $dep..."
        if sudo apt install -y "$dep" >> $LOG_FILE 2>&1; then
            print_success "$dep installed"
        else
            print_warning "Failed to install $dep (may not be available)"
        fi
    done
}

# Function to setup Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip >> $LOG_FILE 2>&1
    
    # Install Python dependencies
    if [[ -f requirements.txt ]]; then
        print_status "Installing Python packages from requirements.txt..."
        pip install -r requirements.txt >> $LOG_FILE 2>&1
    else
        print_status "Installing core Python packages..."
        pip install PyQt5 opencv-python cryptography requests psutil >> $LOG_FILE 2>&1
    fi
    
    print_success "Python environment setup complete"
}

# Function to download and setup external tools
setup_external_tools() {
    print_status "Setting up external tools..."
    
    # Create tools directory
    mkdir -p tools
    cd tools
    
    # Download EDL.py if not present
    if [[ ! -d "edl" ]]; then
        print_status "Downloading EDL.py..."
        git clone https://github.com/bkerler/edl.git >> $LOG_FILE 2>&1
        cd edl
        pip install -r requirements.txt >> $LOG_FILE 2>&1
        cd ..
        print_success "EDL.py setup complete"
    fi
    
    cd ..
}

# Function to create configuration files
create_config_files() {
    print_status "Creating configuration files..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Create main configuration file
    cat > "$CONFIG_DIR/config.json" << EOF
{
    "installation": {
        "install_dir": "$INSTALL_DIR",
        "config_dir": "$CONFIG_DIR",
        "version": "1.0.0",
        "install_date": "$(date -Iseconds)"
    },
    "tools": {
        "adb_path": "$(which adb)",
        "fastboot_path": "$(which fastboot)",
        "hashcat_path": "$(which hashcat)",
        "john_path": "$(which john)",
        "edl_path": "./tools/edl/edl.py"
    },
    "database": {
        "wordlists_dir": "$CONFIG_DIR/wordlists",
        "patterns_dir": "$CONFIG_DIR/patterns",
        "cases_dir": "$CONFIG_DIR/cases"
    },
    "security": {
        "require_authentication": true,
        "session_timeout": 3600,
        "audit_logging": true,
        "evidence_encryption": true
    },
    "performance": {
        "max_threads": 4,
        "gpu_acceleration": true,
        "memory_limit": "2GB"
    }
}
EOF
    
    # Create logging configuration
    cat > "$CONFIG_DIR/logging.json" << EOF
{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "evidence": {
            "format": "%(asctime)s - EVIDENCE - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "detailed"
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "$CONFIG_DIR/forensics.log",
            "level": "DEBUG",
            "formatter": "detailed"
        },
        "evidence": {
            "class": "logging.FileHandler",
            "filename": "$CONFIG_DIR/evidence.log",
            "level": "INFO",
            "formatter": "evidence"
        }
    },
    "loggers": {
        "forensics_toolkit": {
            "level": "DEBUG",
            "handlers": ["console", "file"]
        },
        "evidence": {
            "level": "INFO",
            "handlers": ["evidence"]
        }
    }
}
EOF
    
    print_success "Configuration files created"
}

# Function to initialize databases
initialize_databases() {
    print_status "Initializing databases..."
    
    # Create database directories
    mkdir -p "$CONFIG_DIR/wordlists"
    mkdir -p "$CONFIG_DIR/patterns"
    mkdir -p "$CONFIG_DIR/cases"
    
    # Create wordlists database
    python3 -c "
import sqlite3
import os

db_path = '$CONFIG_DIR/wordlists.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create wordlists table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS wordlists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        path TEXT NOT NULL,
        type TEXT NOT NULL,
        size INTEGER,
        created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create patterns table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE NOT NULL,
        frequency INTEGER DEFAULT 1,
        category TEXT,
        created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()
conn.close()
print('Database initialized successfully')
"
    
    print_success "Databases initialized"
}

# Function to run deployment tests
run_deployment_tests() {
    print_status "Running deployment tests..."
    
    # Test Python imports
    python3 -c "
import sys
import importlib

modules = ['PyQt5', 'cv2', 'cryptography', 'sqlite3', 'json', 'logging']
failed = []

for module in modules:
    try:
        importlib.import_module(module)
        print(f'✓ {module}')
    except ImportError:
        print(f'✗ {module}')
        failed.append(module)

if failed:
    print(f'Failed to import: {failed}')
    sys.exit(1)
else:
    print('All Python modules imported successfully')
"
    
    # Test external tools
    TOOLS=("adb" "fastboot" "hashcat" "john")
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_success "$tool found"
        else
            print_warning "$tool not found in PATH"
        fi
    done
    
    # Test configuration files
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        python3 -c "
import json
with open('$CONFIG_DIR/config.json', 'r') as f:
    config = json.load(f)
print('Configuration file is valid JSON')
"
        print_success "Configuration validation passed"
    else
        print_error "Configuration file not found"
        return 1
    fi
    
    print_success "Deployment tests completed"
}

# Main installation function
main() {
    print_status "Starting Crack Droid installation..."
    echo "Installation log: $LOG_FILE"
    
    # Create log file
    touch $LOG_FILE
    
    # Run installation steps
    check_root
    detect_os
    check_requirements
    install_dependencies
    setup_python_env
    setup_external_tools
    create_config_files
    initialize_databases
    run_deployment_tests
    
    print_success "Installation completed successfully!"
    print_status "Configuration directory: $CONFIG_DIR"
    print_status "To start the toolkit, run: python3 crackdroid.py"
    print_status "For GUI mode, run: python3 crackdroid.py --gui"
}

# Run main function
main "$@"