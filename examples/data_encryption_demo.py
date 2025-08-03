#!/usr/bin/env python3
"""
Data Encryption Demo

Demonstrates the DataEncryption module for protecting recovered forensic data
in compliance with requirement 5.3: "WHEN recovering user data THEN the system 
SHALL immediately encrypt all recovered information"
"""

import os
import tempfile
import shutil
from pathlib import Path

from forensics_toolkit.services.data_encryption import DataEncryption, DataEncryptionError


def demo_forensic_data_encryption():
    """
    Demonstrate encryption of recovered forensic data
    """
    print("=== Forensic Data Encryption Demo ===\n")
    
    # Create temporary directories for demo
    temp_dir = tempfile.mkdtemp()
    key_storage = os.path.join(temp_dir, "keys")
    encrypted_storage = os.path.join(temp_dir, "encrypted_evidence")
    
    try:
        # Initialize encryption service
        print("1. Initializing DataEncryption service...")
        encryption_service = DataEncryption(
            key_storage_path=key_storage,
            encrypted_storage_path=encrypted_storage,
            key_rotation_days=90
        )
        print("   ✓ Encryption service initialized with secure key storage")
        
        # Simulate forensic case
        case_id = "FORENSIC_CASE_2024_001"
        print(f"\n2. Starting forensic case: {case_id}")
        
        # Generate encryption key for the case
        print("   Generating encryption key for case...")
        key_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="AES-256",
            expires_in_days=90
        )
        print(f"   ✓ Generated encryption key: {key_id}")
        
        # Simulate recovered user data (requirement 5.3)
        print("\n3. Simulating recovered user data...")
        recovered_data_samples = [
            {
                "type": "SMS Messages",
                "data": "Contact: John Doe\nMessage: Meet me at the location we discussed\nTimestamp: 2024-01-15 14:30:00",
                "filename": "sms_messages.txt"
            },
            {
                "type": "Call Logs",
                "data": "Outgoing call to +1-555-0123\nDuration: 5:23\nTimestamp: 2024-01-15 14:25:00",
                "filename": "call_logs.txt"
            },
            {
                "type": "Browser History",
                "data": "https://suspicious-website.com\nVisited: 2024-01-15 13:45:00\nDuration: 15 minutes",
                "filename": "browser_history.txt"
            },
            {
                "type": "Photos Metadata",
                "data": "IMG_001.jpg\nLocation: 40.7128° N, 74.0060° W\nTimestamp: 2024-01-15 12:00:00\nDevice: Android Phone",
                "filename": "photos_metadata.txt"
            }
        ]
        
        encrypted_data_list = []
        
        # Encrypt all recovered data immediately (compliance with requirement 5.3)
        print("   Encrypting recovered data immediately...")
        for sample in recovered_data_samples:
            print(f"   - Encrypting {sample['type']}...")
            
            # Encrypt the recovered data
            encrypted_data = encryption_service.encrypt_data(
                data=sample['data'],
                key_id=key_id,
                case_id=case_id,
                original_filename=sample['filename']
            )
            
            # Store encrypted data securely
            storage_path = encryption_service.store_encrypted_data(encrypted_data)
            encrypted_data_list.append({
                'type': sample['type'],
                'encrypted_data': encrypted_data,
                'storage_path': storage_path
            })
            
            print(f"     ✓ {sample['type']} encrypted and stored securely")
            print(f"       Data ID: {encrypted_data.data_id}")
            print(f"       Storage: {storage_path}")
            print(f"       Original size: {encrypted_data.original_size} bytes")
            print(f"       Encrypted size: {len(encrypted_data.encrypted_content)} bytes")
        
        print(f"\n   ✓ All {len(recovered_data_samples)} data samples encrypted and stored")
        
        # Demonstrate secure access to encrypted data
        print("\n4. Demonstrating secure data access...")
        for item in encrypted_data_list[:2]:  # Show first 2 items
            print(f"   Accessing encrypted {item['type']}...")
            
            # Load encrypted data from storage
            loaded_data = encryption_service.load_encrypted_data(
                data_id=item['encrypted_data'].data_id,
                case_id=case_id
            )
            
            # Verify integrity
            if loaded_data.verify_integrity():
                print("     ✓ Data integrity verified")
                
                # Decrypt for authorized access
                decrypted_data = encryption_service.decrypt_data(loaded_data)
                print(f"     ✓ Data decrypted successfully")
                print(f"     Preview: {decrypted_data.decode('utf-8')[:50]}...")
            else:
                print("     ✗ Data integrity check failed!")
        
        # Demonstrate key management
        print("\n5. Key management operations...")
        
        # List keys for the case
        case_keys = encryption_service.list_keys(case_id=case_id)
        print(f"   Active keys for case {case_id}: {len(case_keys)}")
        
        for key in case_keys:
            print(f"   - Key ID: {key.key_id}")
            print(f"     Algorithm: {key.algorithm}")
            print(f"     Created: {key.created_at}")
            print(f"     Expires: {key.expires_at}")
            print(f"     Active: {key.is_active}")
        
        # Demonstrate secure deletion
        print("\n6. Demonstrating secure data disposal...")
        if encrypted_data_list:
            sample_to_delete = encrypted_data_list[0]
            print(f"   Securely deleting {sample_to_delete['type']}...")
            
            success = encryption_service.secure_delete_data(
                data_id=sample_to_delete['encrypted_data'].data_id,
                case_id=case_id
            )
            
            if success:
                print("     ✓ Data securely deleted and overwritten")
                
                # Verify deletion
                try:
                    encryption_service.load_encrypted_data(
                        data_id=sample_to_delete['encrypted_data'].data_id,
                        case_id=case_id
                    )
                    print("     ✗ Data still accessible (deletion failed)")
                except DataEncryptionError:
                    print("     ✓ Data confirmed inaccessible after deletion")
        
        # Generate case summary
        print("\n7. Case encryption summary...")
        remaining_keys = encryption_service.list_keys(case_id=case_id)
        print(f"   Case ID: {case_id}")
        print(f"   Encryption keys: {len(remaining_keys)}")
        print(f"   Data samples processed: {len(recovered_data_samples)}")
        print(f"   Data samples encrypted: {len(encrypted_data_list)}")
        print(f"   Data samples securely deleted: 1")
        print(f"   Compliance status: ✓ All recovered data immediately encrypted")
        
        print("\n=== Demo completed successfully ===")
        print("✓ Requirement 5.3 compliance demonstrated:")
        print("  'WHEN recovering user data THEN the system SHALL immediately encrypt all recovered information'")
        
    except Exception as e:
        print(f"\n✗ Demo failed with error: {e}")
        raise
    
    finally:
        # Cleanup temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"\n✓ Temporary files cleaned up: {temp_dir}")


def demo_key_rotation():
    """
    Demonstrate key rotation for long-running cases
    """
    print("\n=== Key Rotation Demo ===\n")
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Initialize with short rotation period for demo
        encryption_service = DataEncryption(
            key_storage_path=os.path.join(temp_dir, "keys"),
            encrypted_storage_path=os.path.join(temp_dir, "encrypted"),
            key_rotation_days=1  # Short period for demo
        )
        
        case_id = "LONG_RUNNING_CASE_001"
        
        # Generate initial keys
        print("1. Generating initial encryption keys...")
        key1_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="AES-256"
        )
        
        key2_id = encryption_service.generate_encryption_key(
            case_id=case_id,
            key_type="symmetric",
            algorithm="Fernet"
        )
        
        print(f"   ✓ Generated keys: {key1_id}, {key2_id}")
        
        # Simulate aging keys (for demo purposes)
        print("\n2. Simulating key aging...")
        from datetime import datetime, timedelta
        
        key1_info = encryption_service.get_key_info(key1_id)
        key2_info = encryption_service.get_key_info(key2_id)
        
        # Age the keys
        old_date = datetime.now() - timedelta(days=2)
        key1_info.created_at = old_date
        key2_info.created_at = old_date
        
        print("   ✓ Keys aged beyond rotation threshold")
        
        # Perform key rotation
        print("\n3. Performing key rotation...")
        new_key_ids = encryption_service.rotate_keys(case_id)
        
        print(f"   ✓ Generated {len(new_key_ids)} new keys")
        print(f"   ✓ Deactivated {2} old keys")
        
        # Verify rotation
        all_keys = encryption_service.list_keys(case_id=case_id, active_only=False)
        active_keys = encryption_service.list_keys(case_id=case_id, active_only=True)
        
        print(f"\n4. Key rotation summary:")
        print(f"   Total keys: {len(all_keys)}")
        print(f"   Active keys: {len(active_keys)}")
        print(f"   Inactive keys: {len(all_keys) - len(active_keys)}")
        
        print("\n✓ Key rotation completed successfully")
        
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    try:
        demo_forensic_data_encryption()
        demo_key_rotation()
    except Exception as e:
        print(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()