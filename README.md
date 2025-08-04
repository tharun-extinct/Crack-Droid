# ForenCrack Droid - Android Forensics Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-green.svg)](https://www.linux.org/)

**ForenCrack Droid** is a comprehensive Android forensics toolkit designed for authorized security professionals and forensic investigators. It provides advanced capabilities for Android device analysis, lock screen bypass, evidence collection, and forensic reporting with full legal compliance features.

## ⚠️ Legal Notice

**AUTHORIZED USE ONLY**: This toolkit is designed exclusively for authorized forensic investigations, security research, and educational purposes. Users must have explicit legal authorization before using this tool on any device. Unauthorized use may violate local, state, and federal laws.

## 🚀 Key Features

### 🔓 Lock Screen Analysis
- **PIN/Password Brute Force**: Advanced dictionary and brute force attacks
- **Pattern Analysis**: Computer vision-based Android pattern recognition
- **Hash Cracking**: GPU-accelerated hash cracking with Hashcat integration
- **Multi-Attack Strategy**: Intelligent attack orchestration and optimization

### 📱 Device Management
- **ADB Integration**: Full Android Debug Bridge support
- **Fastboot Operations**: Bootloader and recovery mode interactions
- **Device Detection**: Automatic device identification and profiling
- **Multiple Interface Support**: USB, WiFi, and emergency download modes

### 🔒 Security & Compliance
- **Legal Compliance Workflow**: Built-in disclaimer and consent management
- **Chain of Custody**: Cryptographic evidence integrity tracking
- **Access Control**: Role-based authentication and authorization
- **Audit Logging**: Comprehensive forensic audit trails

### 📊 Evidence Management
- **Automated Evidence Collection**: Timestamped operation logging
- **Hash Verification**: SHA-256 integrity verification
- **Encrypted Storage**: AES-256 evidence encryption
- **Report Generation**: Professional forensic reports in multiple formats

### 🖥️ User Interfaces
- **Command Line Interface**: Full-featured CLI for automation
- **Graphical Interface**: PyQt5-based GUI for interactive operations
- **Web Interface**: Browser-based remote access (optional)

## 📋 System Requirements

### Supported Operating Systems
- **Kali Linux** 2023.1 or later (Recommended)
- **Ubuntu** 20.04 LTS or later
- **Ubuntu Forensic Edition**

### Hardware Requirements
- **CPU**: x64 architecture, 4+ cores recommended
- **Memory**: 4GB RAM minimum, 8GB recommended for hash cracking
- **Storage**: 2GB free disk space minimum
- **GPU**: NVIDIA GPU recommended for accelerated hash cracking

### Software Prerequisites
- Python 3.8 or higher
- Android SDK tools (ADB/Fastboot)
- OpenCV 4.5+ for pattern analysis
- Hashcat 6.0+ for hash cracking
- John the Ripper for password cracking

## 🛠️ Installation

### Quick Installation

```bash
# Clone the repository
git clone <repository-url>
cd forensics-toolkit

# Run automated installation
make install

# Verify installation
make test
```

### Manual Installation

1. **Install system dependencies:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

2. **Set up Python environment:**
   ```bash
   python3 setup.py
   ```

3. **Validate installation:**
   ```bash
   python3 validate_config.py -v
   ```

For detailed installation instructions, see [INSTALLATION.md](INSTALLATION.md).

## 🎯 Quick Start

### 1. Launch the Toolkit

**Command Line Interface:**
```bash
python3 forencracks.py
```

**Graphical Interface:**
```bash
python3 forencracks.py --gui
```

**Help and Options:**
```bash
python3 forencracks.py --help
```

### 2. Legal Compliance Setup

Before using the toolkit, you must complete the legal compliance workflow:

1. **Accept Legal Disclaimer**: Review and accept the legal terms
2. **Provide Case Information**: Enter formal case ID and investigator details
3. **Environment Verification**: Confirm authorized investigation environment

### 3. Device Connection

Connect your Android device using one of these methods:

**USB Debugging (Preferred):**
```bash
# Enable USB debugging on device
# Connect via USB cable
adb devices  # Verify connection
```

**Fastboot Mode:**
```bash
# Boot device into fastboot mode
# Connect via USB cable
fastboot devices  # Verify connection
```

**Emergency Download Mode (EDL):**
```bash
# For devices with disabled USB debugging
# Requires special cable or hardware
```

### 4. Basic Attack Workflow

**Interactive CLI Mode:**
```bash
python3 forencracks.py --interactive
```

**Automated Attack:**
```bash
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --device-serial "ABC123456" \
  --attack-type brute_force \
  --wordlist common_pins.txt
```

## 📖 Usage Guide

### Command Line Interface

The CLI provides comprehensive forensic capabilities:

#### Basic Commands

```bash
# Show help
python3 forencracks.py --help

# List connected devices
python3 forencracks.py --list-devices

# Device information
python3 forencracks.py --device-info <serial>

# Run demo mode
python3 forencracks.py --demo
```

#### Attack Operations

```bash
# PIN brute force attack
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --attack-type brute_force \
  --target-type pin \
  --wordlist wordlists/common_pins.txt \
  --max-attempts 1000

# Pattern analysis attack
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --attack-type pattern_analysis \
  --capture-screen \
  --analyze-gestures

# Hash cracking attack
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --attack-type hash_cracking \
  --hash-file extracted_hashes.txt \
  --gpu-acceleration
```

#### Evidence Management

```bash
# Generate forensic report
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --generate-report \
  --format json \
  --output reports/

# Verify evidence integrity
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --verify-integrity

# Export case data
python3 forencracks.py \
  --case-id "CASE-2024-001" \
  --export-case \
  --output case_export.zip
```

### Graphical User Interface

The GUI provides an intuitive interface for forensic operations:

1. **Launch GUI**: `python3 forencracks.py --gui`
2. **Complete Compliance**: Follow the legal compliance wizard
3. **Connect Device**: Use the device manager to establish connection
4. **Configure Attack**: Select attack type and parameters
5. **Monitor Progress**: Real-time progress and status updates
6. **Review Results**: Analyze attack results and evidence
7. **Generate Report**: Create professional forensic reports

### Configuration

#### Main Configuration File

Location: `~/.forensics-toolkit/config.json`

```json
{
  "security": {
    "require_authentication": true,
    "session_timeout": 3600,
    "audit_logging": true,
    "evidence_encryption": true
  },
  "performance": {
    "max_threads": 8,
    "gpu_acceleration": true,
    "memory_limit_mb": 2048
  },
  "tools": {
    "adb_path": "/usr/bin/adb",
    "fastboot_path": "/usr/bin/fastboot",
    "hashcat_path": "/usr/bin/hashcat"
  }
}
```

#### Wordlists and Patterns

The toolkit includes default wordlists and supports custom additions:

```bash
# Default wordlists location
~/.forensics-toolkit/wordlists/
├── common_pins.txt          # Common PIN codes
├── android_patterns.txt     # Android unlock patterns
└── common_passwords.txt     # Common passwords

# Add custom wordlist
cp custom_wordlist.txt ~/.forensics-toolkit/wordlists/
```

## 🔧 Advanced Usage

### Custom Attack Strategies

Create custom attack configurations:

```python
from forensics_toolkit.models.attack import AttackStrategy
from forensics_toolkit.interfaces import AttackType

# Define custom strategy
strategy = AttackStrategy(
    strategy_type=AttackType.BRUTE_FORCE,
    target_device=device,
    wordlists=['custom_pins.txt'],
    max_attempts=5000,
    gpu_acceleration=True,
    thread_count=4
)

# Execute attack
orchestrator = ForensicsOrchestrator()
result = orchestrator.execute_attack(strategy)
```

### Batch Processing

Process multiple devices or cases:

```bash
# Batch processing script
for device in $(adb devices | grep device | cut -f1); do
    python3 forencracks.py \
      --case-id "BATCH-$(date +%Y%m%d)-${device}" \
      --device-serial "${device}" \
      --attack-type brute_force \
      --wordlist common_pins.txt \
      --auto-report
done
```

### Integration with External Tools

The toolkit integrates with popular forensic tools:

```bash
# Export to Cellebrite format
python3 forencracks.py --export-cellebrite

# Import from MSAB XRY
python3 forencracks.py --import-xry data.xml

# Integration with Autopsy
python3 forencracks.py --autopsy-plugin
```

## 📊 Reporting and Evidence

### Report Formats

The toolkit generates reports in multiple formats:

- **JSON**: Machine-readable structured data
- **PDF**: Professional forensic reports
- **HTML**: Interactive web-based reports
- **CSV**: Tabular data for analysis
- **XML**: Standard forensic exchange format

### Evidence Integrity

All evidence is protected with:

- **SHA-256 Hashing**: File integrity verification
- **AES-256 Encryption**: Evidence confidentiality
- **Chain of Custody**: Cryptographic audit trail
- **Timestamp Verification**: Tamper detection

### Sample Report Structure

```json
{
  "case_info": {
    "case_id": "CASE-2024-001",
    "investigator": "Detective Smith",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "device_info": {
    "serial": "ABC123456",
    "model": "Samsung Galaxy S21",
    "android_version": "12"
  },
  "attack_results": {
    "attack_type": "brute_force",
    "success": true,
    "attempts": 1247,
    "duration": "00:05:23",
    "discovered_pin": "1234"
  },
  "evidence": {
    "hash_verification": "sha256:abc123...",
    "chain_of_custody": [...],
    "integrity_status": "verified"
  }
}
```

## 🧪 Testing and Validation

### Run Test Suite

```bash
# Complete test suite
make test

# Specific test categories
make test-unit          # Unit tests
make test-integration   # Integration tests
make test-security      # Security compliance tests
make test-performance   # Performance benchmarks
```

### Validation Scripts

```bash
# Validate configuration
python3 validate_config.py -v

# Test deployment
python3 test_deployment.py -v

# Health check
make health-check
```

### Demo Mode

Test the toolkit safely with demo mode:

```bash
# Interactive demo
python3 forencracks.py --demo

# Automated demo
python3 forencracks.py --demo --auto
```

## 🔒 Security Considerations

### Authentication and Authorization

- **Role-Based Access**: Admin, Investigator, Analyst, Viewer roles
- **Session Management**: Secure session handling with timeouts
- **Multi-Factor Authentication**: Optional 2FA support
- **Audit Logging**: Complete operation audit trails

### Evidence Protection

- **Encryption at Rest**: AES-256 evidence encryption
- **Secure Transmission**: TLS for network operations
- **Access Controls**: File-level permission management
- **Tamper Detection**: Cryptographic integrity verification

### Compliance Features

- **Legal Disclaimer**: Mandatory legal acknowledgment
- **Case Authorization**: Formal case ID validation
- **Environment Verification**: Authorized environment checks
- **Violation Logging**: Compliance violation tracking

## 🐛 Troubleshooting

### Common Issues

**Device Not Detected:**
```bash
# Check USB debugging
adb devices

# Restart ADB server
adb kill-server && adb start-server

# Check device permissions
lsusb
```

**Permission Errors:**
```bash
# Fix file permissions
make fix-permissions

# Add user to required groups
sudo usermod -a -G plugdev,dialout $USER
```

**GPU Acceleration Issues:**
```bash
# Check NVIDIA drivers
nvidia-smi

# Test Hashcat GPU support
hashcat -I

# Install CUDA toolkit
sudo apt install nvidia-cuda-toolkit
```

### Log Files

Check logs for detailed error information:

```bash
# Application logs
tail -f ~/.forensics-toolkit/logs/forensics.log

# Evidence logs
tail -f ~/.forensics-toolkit/logs/evidence.log

# Audit logs
tail -f ~/.forensics-toolkit/logs/audit.log
```

### Getting Help

```bash
# Built-in help
python3 forencracks.py --help

# Verbose diagnostics
python3 forencracks.py --debug --verbose

# System information
make info
```

## 🤝 Contributing

We welcome contributions from the forensic and security community:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-feature`
3. **Make your changes** with appropriate tests
4. **Run the test suite**: `make test`
5. **Submit a pull request**

### Development Setup

```bash
# Clone for development
git clone <repository-url>
cd forensics-toolkit

# Install development dependencies
pip install -r requirements-dev.txt

# Run pre-commit hooks
pre-commit install

# Run development tests
make test-dev
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Android Open Source Project** for ADB/Fastboot tools
- **Hashcat Team** for GPU-accelerated hash cracking
- **OpenCV Community** for computer vision capabilities
- **Forensic Community** for testing and feedback

## 📞 Support

For support and questions:

- **Documentation**: Check this README and [INSTALLATION.md](INSTALLATION.md)
- **Issues**: Use the GitHub issue tracker
- **Security**: Report security issues privately
- **Community**: Join our forensic community discussions

## 🔄 Version History

- **v1.0.0** - Initial release with core forensic capabilities
- **v1.1.0** - Added GUI interface and enhanced reporting
- **v1.2.0** - Improved security and compliance features
- **v1.3.0** - Performance optimizations and GPU acceleration

---

**Remember**: This toolkit is for authorized forensic investigations only. Always ensure you have proper legal authorization before use.