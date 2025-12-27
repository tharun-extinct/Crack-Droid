# Changelog

## Version 1.0.0 - Project Renamed to "Crack Droid"

### Major Changes

#### Project Renaming
- **Old Name**: ForenCrack Droid / forencracks
- **New Name**: Crack Droid / crackdroid
- Main entry point renamed from `forencracks.py` to `crackdroid.py`
- All references updated across the entire codebase

#### Authentication System Removed
- Removed authentication requirements for simplified MVP
- Removed role-based access control (admin, investigator, analyst)
- Removed legal compliance workflow
- Application now runs in simplified mode without login
- All forensic features remain intact and accessible immediately

#### Files Deleted
**Authentication-related:**
- `forensics_toolkit/services/authentication.py`
- `forensics_toolkit/services/legal_compliance.py`
- `forensics_toolkit/services/auth_decorators.py`
- `config/users.json`
- `config/consent_records.json`
- `config/legal_disclaimer.json`
- `config/cases.json`
- `tests/test_authentication.py`
- `tests/test_legal_compliance.py`
- `tests/test_security_compliance.py`

**Demo and irrelevant files:**
- `demo_evidence/` (entire folder)
- `demo_logs/` (entire folder)
- `demo_reports/` (entire folder)
- `test_logs/` (entire folder)
- `Task summaries/` (entire folder)
- `assests/` (entire folder)
- All debug images (`*debug*.png`, `*preprocessing*.png`)
- `examples/cli_demo.py`
- `examples/authentication_demo.py`
- `examples/database_setup_demo.py`
- `examples/report_generator_demo.py`
- Various test/debug scripts

#### Updated Files
**Core files:**
- `crackdroid.py` - New main entry point
- `README.md` - Complete rewrite with new project name
- `setup.py` - Updated project name and references
- `Makefile` - Updated all commands and references
- `install.sh` - Updated installation script
- `install.bat` - Updated Windows installation script

**Toolkit files:**
- `forensics_toolkit/__init__.py` - Updated project name
- `forensics_toolkit/ui/cli.py` - Updated to "Crack Droid", removed authentication
- `forensics_toolkit/ui/gui.py` - Updated all UI references
- `forensics_toolkit/ui/README.md` - Updated documentation
- `forensics_toolkit/ui/launch_gui.py` - Updated launcher
- `forensics_toolkit/services/forensics_orchestrator.py` - Disabled authentication
- `forensics_toolkit/services/report_generator.py` - Updated references
- `forensics_toolkit/database_setup.py` - Updated documentation

**Test and script files:**
- `tests/integration_test_framework.py` - Updated references
- `scripts/setup_databases.py` - Updated project name
- `.kiro/specs/android-forensics-toolkit/requirements.md` - Updated project name

### Current Features
- Device detection (ADB, Fastboot, EDL)
- Lock screen analysis (PIN, password, pattern)
- Brute force attacks
- Pattern analysis with OpenCV
- Hash cracking integration
- Evidence logging and integrity verification
- Chain of custody tracking
- Report generation (JSON, PDF, HTML, CSV)
- CLI and GUI interfaces
- Comprehensive test suite

### Usage
```bash
# Show help
python crackdroid.py --help

# Show version
python crackdroid.py --version

# Detect devices
python crackdroid.py detect

# Interactive mode
python crackdroid.py interactive

# GUI mode
python crackdroid.py --gui
```

### System Requirements
- Python 3.8+
- Android SDK tools (ADB/Fastboot)
- OpenCV 4.5+ (optional, for pattern analysis)
- Hashcat 6.0+ (optional, for hash cracking)
- Windows/Linux/macOS

### Installation
```bash
# Quick install
python setup.py

# Or use make (Linux/macOS)
make install
```

### Notes
- Authentication system removed for MVP - can be added back later
- All core forensic functionality remains intact
- Simplified workflow for immediate use
- Focus on essential features for Android forensics
