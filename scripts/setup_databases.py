#!/usr/bin/env python3
"""
Database setup script for Crack Droid
Sets up wordlists and pattern databases for forensic operations
"""

import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensics_toolkit.database_setup import DatabaseSetupManager, setup_default_databases


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('database_setup.log')
        ]
    )


def main():
    """Main function for database setup"""
    parser = argparse.ArgumentParser(
        description='Setup wordlists and pattern databases for Crack Droid'
    )
    
    parser.add_argument(
        '--base-path', 
        default='./wordlists',
        help='Base path for database storage (default: ./wordlists)'
    )
    
    parser.add_argument(
        '--setup-defaults',
        action='store_true',
        help='Setup default databases and wordlists'
    )
    
    parser.add_argument(
        '--load-wordlist',
        help='Load a specific wordlist file'
    )
    
    parser.add_argument(
        '--wordlist-name',
        help='Name for the loaded wordlist'
    )
    
    parser.add_argument(
        '--wordlist-category',
        default='custom',
        help='Category for the loaded wordlist (default: custom)'
    )
    
    parser.add_argument(
        '--import-custom',
        help='Import a custom wordlist file'
    )
    
    parser.add_argument(
        '--verify-integrity',
        action='store_true',
        help='Verify database integrity'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show database statistics'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize database manager
        db_manager = DatabaseSetupManager(args.base_path)
        logger.info(f"Database manager initialized with base path: {args.base_path}")
        
        # Setup default databases
        if args.setup_defaults:
            logger.info("Setting up default databases...")
            if setup_default_databases(args.base_path):
                print("✓ Default databases setup completed successfully")
            else:
                print("✗ Failed to setup default databases")
                return 1
        
        # Load specific wordlist
        if args.load_wordlist:
            wordlist_path = Path(args.load_wordlist)
            if not wordlist_path.exists():
                print(f"✗ Wordlist file not found: {args.load_wordlist}")
                return 1
            
            name = args.wordlist_name or wordlist_path.stem
            logger.info(f"Loading wordlist: {args.load_wordlist} as '{name}'")
            
            if db_manager.load_wordlist(
                str(wordlist_path), 
                name, 
                f"Loaded from {wordlist_path}",
                args.wordlist_category
            ):
                print(f"✓ Wordlist '{name}' loaded successfully")
            else:
                print(f"✗ Failed to load wordlist '{name}'")
                return 1
        
        # Import custom wordlist
        if args.import_custom:
            custom_path = Path(args.import_custom)
            if not custom_path.exists():
                print(f"✗ Custom wordlist file not found: {args.import_custom}")
                return 1
            
            name = args.wordlist_name or custom_path.stem
            logger.info(f"Importing custom wordlist: {args.import_custom} as '{name}'")
            
            if db_manager.import_custom_wordlist(str(custom_path), name):
                print(f"✓ Custom wordlist '{name}' imported successfully")
            else:
                print(f"✗ Failed to import custom wordlist '{name}'")
                return 1
        
        # Verify database integrity
        if args.verify_integrity:
            logger.info("Verifying database integrity...")
            integrity = db_manager.verify_database_integrity()
            
            print("\nDatabase Integrity Check:")
            print(f"  Database accessible: {'✓' if integrity['database_accessible'] else '✗'}")
            print(f"  Wordlists valid: {'✓' if integrity['wordlists_valid'] else '✗'}")
            print(f"  Patterns valid: {'✓' if integrity['patterns_valid'] else '✗'}")
            print(f"  Indexes valid: {'✓' if integrity['indexes_valid'] else '✗'}")
            
            if not all(integrity.values()):
                print("\n⚠ Some integrity checks failed. Check logs for details.")
                return 1
            else:
                print("\n✓ All integrity checks passed")
        
        # Show statistics
        if args.stats:
            logger.info("Gathering database statistics...")
            stats = db_manager.get_wordlist_stats()
            
            print("\nDatabase Statistics:")
            print(f"  Total words indexed: {stats.get('total_words', 0):,}")
            print(f"  Total patterns: {stats.get('total_patterns', 0):,}")
            
            if 'categories' in stats:
                print("\n  Wordlist categories:")
                for category, info in stats['categories'].items():
                    print(f"    {category}: {info['count']} wordlists, {info['size']:,} bytes")
        
        # If no specific action was requested, show help
        if not any([
            args.setup_defaults, 
            args.load_wordlist, 
            args.import_custom,
            args.verify_integrity, 
            args.stats
        ]):
            parser.print_help()
            return 0
        
        logger.info("Database setup operations completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Database setup failed: {e}")
        print(f"✗ Database setup failed: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())