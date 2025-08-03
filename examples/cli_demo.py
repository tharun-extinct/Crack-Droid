#!/usr/bin/env python3
"""
CLI Demo Script for ForenCrack Droid

This script demonstrates the CLI functionality of the ForenCrack Droid
Android forensics toolkit.
"""

import sys
import os
import subprocess
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def run_cli_command(command_args):
    """Run a CLI command and display the output"""
    print(f"\n{'='*60}")
    print(f"Running: forencracks {' '.join(command_args)}")
    print(f"{'='*60}")
    
    try:
        # Run the command
        result = subprocess.run(
            [sys.executable, str(project_root / "forencracks.py")] + command_args,
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        # Display output
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        print(f"Exit Code: {result.returncode}")
        
    except Exception as e:
        print(f"Error running command: {e}")

def main():
    """Main demo function"""
    print("ForenCrack Droid CLI Demo")
    print("=" * 40)
    
    # Demo commands
    demo_commands = [
        ["--help"],
        ["--version"],
        ["config", "show"],
        ["config", "validate"],
        ["auth", "whoami"],
    ]
    
    for cmd in demo_commands:
        run_cli_command(cmd)
    
    print(f"\n{'='*60}")
    print("Demo completed!")
    print("To try interactive mode, run: python forencracks.py interactive")
    print("Note: Interactive mode requires user authentication and legal compliance")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()