# ForenCrack Droid - Android Forensics Toolkit

A comprehensive digital forensics tool for authorized Android device analysis by government-authorized forensic investigators and departments.

## Project Structure

```
forensics_toolkit/
├── __init__.py                 # Package initialization
├── interfaces.py              # Core interfaces and abstract classes
├── config.py                  # Configuration management
├── logging_system.py          # Evidence logging with integrity
├── models/                    # Data models
│   └── __init__.py
├── services/                  # Device communication services
│   └── __init__.py
├── attack_engines/            # Attack engine implementations
│   └── __init__.py
└── ui/                        # User interface components
    └── __init__.py
```

## Core Components

### Interfaces (`interfaces.py`)
- `IDeviceHandler`: Interface for device communication
- `IAttackEngine`: Interface for attack engines
- `IEvidenceManager`: Interface for evidence management
- `IForensicsEngine`: Main forensics engine interface
- Core data models: `AndroidDevice`, `AttackStrategy`, `AttackResult`, `EvidenceRecord`

### Configuration (`config.py`)
- `ConfigManager`: Centralized configuration management
- Tool path validation and management
- Security and forensics settings
- Evidence directory management

### Logging System (`logging_system.py`)
- `EvidenceLogger`: Evidence logging with integrity verification
- Cryptographic hash verification for all log entries
- Encrypted log storage for sensitive operations
- Audit trail generation and verification

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure tool paths in `config/forensics_config.json`

3. Verify tool installations:
```python
from forensics_toolkit.config import config_manager
validation = config_manager.validate_tool_paths()
print(validation)
```

## Legal Notice

This tool is designed for authorized forensic investigators only. Ensure proper legal authorization before use.
