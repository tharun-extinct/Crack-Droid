#!/usr/bin/env python3
"""
Database setup demonstration for ForenCrack Droid
Shows how to use the wordlist and pattern database functionality
"""

import sys
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensics_toolkit.database_setup import DatabaseSetupManager, setup_default_databases


def demo_database_setup():
    """Demonstrate database setup functionality"""
    print("=== ForenCrack Droid Database Setup Demo ===\n")
    
    # Create temporary directory for demo
    demo_dir = tempfile.mkdtemp(prefix="forensics_demo_")
    print(f"Demo directory: {demo_dir}")
    
    try:
        # Initialize database manager
        print("\n1. Initializing database manager...")
        db_manager = DatabaseSetupManager(demo_dir)
        print("✓ Database manager initialized")
        
        # Setup default databases
        print("\n2. Setting up default databases...")
        if setup_default_databases(demo_dir):
            print("✓ Default databases setup completed")
        else:
            print("✗ Failed to setup default databases")
            return
        
        # Show statistics
        print("\n3. Database statistics:")
        stats = db_manager.get_wordlist_stats()
        print(f"   Total words indexed: {stats.get('total_words', 0):,}")
        print(f"   Total patterns: {stats.get('total_patterns', 0):,}")
        
        if 'categories' in stats:
            print("   Wordlist categories:")
            for category, info in stats['categories'].items():
                print(f"     {category}: {info['count']} wordlists, {info['size']:,} bytes")
        
        # Create a custom wordlist
        print("\n4. Creating custom wordlist...")
        custom_wordlist = Path(demo_dir) / "demo_passwords.txt"
        with open(custom_wordlist, 'w') as f:
            demo_passwords = [
                "password123", "admin", "letmein", "welcome", "monkey",
                "dragon", "master", "shadow", "qwerty123", "football"
            ]
            for pwd in demo_passwords:
                f.write(f"{pwd}\n")
        
        # Import the custom wordlist
        if db_manager.import_custom_wordlist(str(custom_wordlist), "demo_passwords"):
            print("✓ Custom wordlist imported successfully")
        else:
            print("✗ Failed to import custom wordlist")
            return
        
        # Search for words by length
        print("\n5. Searching words by length (4-6 characters):")
        words = db_manager.search_words_by_length(4, 6, limit=10)
        for word in words[:5]:  # Show first 5
            print(f"   {word}")
        if len(words) > 5:
            print(f"   ... and {len(words) - 5} more")
        
        # Get patterns by complexity
        print("\n6. Getting patterns by complexity (1-3):")
        patterns = db_manager.get_patterns_by_complexity(1, 3)
        for i, pattern in enumerate(patterns[:3]):  # Show first 3
            print(f"   Pattern {i+1}: {pattern}")
        if len(patterns) > 3:
            print(f"   ... and {len(patterns) - 3} more patterns")
        
        # Verify database integrity
        print("\n7. Verifying database integrity...")
        integrity = db_manager.verify_database_integrity()
        
        all_good = True
        for check, result in integrity.items():
            status = "✓" if result else "✗"
            print(f"   {check.replace('_', ' ').title()}: {status}")
            if not result:
                all_good = False
        
        if all_good:
            print("\n✓ All database setup operations completed successfully!")
        else:
            print("\n⚠ Some integrity checks failed")
        
        # Show final statistics
        print("\n8. Final database statistics:")
        final_stats = db_manager.get_wordlist_stats()
        print(f"   Total words indexed: {final_stats.get('total_words', 0):,}")
        print(f"   Total patterns: {final_stats.get('total_patterns', 0):,}")
        
        print(f"\nDemo completed. Database files created in: {demo_dir}")
        print("You can inspect the SQLite database using any SQLite browser.")
        
    except Exception as e:
        print(f"✗ Demo failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up (optional - comment out to keep files for inspection)
        # import shutil
        # shutil.rmtree(demo_dir)
        pass


if __name__ == '__main__':
    demo_database_setup()