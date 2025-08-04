# ForenCrack Droid Installation Guide

This guide provides comprehensive instructions for installing and setting up ForenCrack Droid on supported Linux distributions.

## System Requirements

### Supported Operating Systems
- Kali Linux 2023.1 or later
- Ubuntu 20.04 LTS or later
- Ubuntu Forensic Edition

### Hardware Requirements
- **CPU**: x64 architecture, 4+ cores recommended
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 2GB free disk space minimum
- **GPU**: NVIDIA GPU recommended for hash cracking acceleration

### Software Prerequisites
- Python 3.8 or higher
- sudo privileges
- Internet connection for downloading dependencies

## Quick Installation

For a complete automated installation, run:

```bash
# Clone the repository
git clone <repository-url>
cd forensics-toolkit

# Run automated installation
make install
```

## Manual Installation

### Step 1: System Preparation

1. **Update system packages:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install basic dependencies:**
   ```bash
   sudo apt install -y python3 python3-pip python3-venv git curl wget
   ```

### Step 2: Run Installation Script

1. **Make the installation script executable:**
   ```bash
   chmod +x install.sh
   ```

2. **Run the installation script:**
   ```bash
   ./install.sh
   ```

   The script will:
   - Detect your operating system
   - Check system requirements
   - Install system dependencies
   - Set up Python virtual environment
   - Download external tools
   - Create configuration files

### Step 3: Python Setup

1. **Run the Python setup script:**
   ```bash
   python3 setup.py
   ```

   This will:
   - Install Python packages
   - Create directory structure
   - Initialize databases
   - Generate configuration files
   - Create default wordlists

### Step 4: Validation

1. **Run deployment tests:**
   ```bash
   python3 test_deployment.py -v
   ```

2. **Validate configuration:**
   ```bash
   python3 validate_config.py -v
   ```

## Installation Components

### System Dependencies

The installation includes the following system packages:

**Core Tools:**
- `android-tools-adb` - Android Debug Bridge
- `android-tools-fastboot` - Android Fastboot tool
- `hashcat` - GPU-accelerated password cracking
- `john` - John the Ripper password cracker

**Development Libraries:**
- `python3-dev` - Python development headers
- `build-essential` - Compilation tools
- `libssl-dev` - SSL development library
- `libffi-dev` - Foreign Function Interface library

**Image Processing:**
- `libopencv-dev` - OpenCV development library
- `python3-opencv` - OpenCV Python bindings
- `libjpeg-dev` - JPEG library
- `libpng-dev` - PNG library

**GUI Framework:**
- `python3-pyqt5` - PyQt5 GUI framework
- `python3-pyqt5.qtwidgets` - PyQt5 widgets

### Python Packages

The following Python packages are installed:

- `PyQt5>=5.15.0` - GUI framework
- `opencv-python>=4.5.0` - Computer vision library
- `cryptography>=3.4.0` - Cryptographic operations
- `requests>=2.25.0` - HTTP library
- `psutil>=5.8.0` - System monitoring
- `pycryptodome>=3.10.0` - Additional cryptographic functions

### External Tools

**EDL.py:**
- Emergency Download Mode tool
- Automatically downloaded from GitHub
- Used for devices with USB debugging disabled

### Configuration Structure

The installation creates the following directory structure:

```
~/.forensics-toolkit/
├── config.json              # Main configuration file
├── logging.json             # Logging configuration
├── .encryption_key          # Evidence encryption key
├── wordlists/               # Password wordlists
│   ├── common_pins.txt
│   ├── android_patterns.txt
│   └── common_passwords.txt
├── patterns/                # Pattern analysis data
├── cases/                   # Case management
├── logs/                    # Application logs
├── evidence/                # Evidence storage
├── reports/                 # Generated reports
└── temp/                    # Temporary files
```

### Database Initialization

Three SQLite databases are created:

1. **wordlists.db** - Manages password wordlists
2. **patterns.db** - Stores Android unlock patterns
3. **cases.db** - Tracks forensic cases and evidence

## Verification

### Automated Testing

Run the complete test suite:

```bash
make test
```

### Manual Verification

1. **Check tool availability:**
   ```bash
   adb version
   fastboot --version
   hashcat --version
   john --list=formats
   ```

2. **Test Python imports:**
   ```bash
   python3 -c "import PyQt5, cv2, cryptography; print('All imports successful')"
   ```

3. **Verify configuration:**
   ```bash
   python3 validate_config.py
   ```

## Troubleshooting

### Common Issues

**1. Permission Denied Errors**
```bash
# Fix file permissions
make fix-permissions
```

**2. Missing Dependencies**
```bash
# Reinstall system dependencies
sudo apt install -f
./install.sh
```

**3. Python Import Errors**
```bash
# Reinstall Python packages
python3 setup.py
```

**4. Database Connection Issues**
```bash
# Reinitialize databases
rm ~/.forensics-toolkit/*.db
python3 setup.py
```

### Log Files

Check installation logs for detailed error information:

```bash
# Installation log
cat /tmp/forensics-toolkit-install.log

# Application logs
ls ~/.forensics-toolkit/logs/

# View recent logs
make logs
```

### System Information

Get system information for troubleshooting:

```bash
make info
```

## Advanced Configuration

### GPU Acceleration

For NVIDIA GPU acceleration with Hashcat:

1. **Install NVIDIA drivers:**
   ```bash
   sudo apt install nvidia-driver-470
   ```

2. **Install CUDA toolkit:**
   ```bash
   sudo apt install nvidia-cuda-toolkit
   ```

3. **Verify GPU detection:**
   ```bash
   hashcat -I
   ```

### Custom Wordlists

Add custom wordlists to the system:

1. **Copy wordlist files to:**
   ```
   ~/.forensics-toolkit/wordlists/
   ```

2. **Register in database:**
   ```bash
   python3 -c "
   import sqlite3
   conn = sqlite3.connect('~/.forensics-toolkit/wordlists.db')
   cursor = conn.cursor()
   cursor.execute('INSERT INTO wordlists (name, path, type) VALUES (?, ?, ?)', 
                  ('custom_list', 'wordlists/custom.txt', 'password'))
   conn.commit()
   conn.close()
   "
   ```

### Security Hardening

1. **Restrict file permissions:**
   ```bash
   chmod 700 ~/.forensics-toolkit
   chmod 600 ~/.forensics-toolkit/config.json
   chmod 600 ~/.forensics-toolkit/.encryption_key
   ```

2. **Enable audit logging:**
   Edit `~/.forensics-toolkit/config.json`:
   ```json
   {
     "security": {
       "audit_logging": true,
       "require_authentication": true,
       "session_timeout": 1800
     }
   }
   ```

## Uninstallation

To completely remove ForenCrack Droid:

```bash
make uninstall
```

This will:
- Create a backup of your configuration
- Remove all configuration files
- Clean up temporary files
- Remove the virtual environment

## Getting Help

### Documentation
- Check the main README.md for usage instructions
- Review the design document for architecture details
- Examine the requirements document for feature specifications

### Support
- Check the troubleshooting section above
- Review installation logs for error details
- Run validation scripts to identify issues

### Health Check

Run a quick health check:

```bash
make health-check
```

## Next Steps

After successful installation:

1. **Start the toolkit:**
   ```bash
   python3 forencracks.py
   ```

2. **Launch GUI mode:**
   ```bash
   python3 forencracks.py --gui
   ```

3. **View help:**
   ```bash
   python3 forencracks.py --help
   ```

4. **Run a test case:**
   ```bash
   python3 forencracks.py --demo
   ```

## Security Notice

ForenCrack Droid is designed for authorized forensic investigations only. Ensure you have proper legal authorization before using this toolkit on any device. The tool includes built-in compliance features, but users are responsible for following all applicable laws and regulations.

## Version Information

Check your installation version:

```bash
make version
```

For updates and new releases, check the project repository regularly.