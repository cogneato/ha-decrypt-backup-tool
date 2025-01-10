#!/usr/bin/env python3
"""
Home Assistant Backup Decryption Tool
-----------------------------------
This script automatically decrypts Home Assistant backups using the emergency kit.
Place this script in the same directory as:
- Your Home Assistant emergency kit text file
- Your backup .tar file(s)

Requirements:
pip install cryptography

Usage:
1. Place this script in a directory with your backup files
2. Make it executable: chmod +x decrypt_backup.py
3. Run it: ./decrypt_backup.py
"""

import sys
import tarfile
import glob
import os
import shutil
import re
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
import hashlib

def check_requirements():
    """Check if required packages are installed."""
    try:
        import cryptography
    except ImportError:
        print("Error: Required package 'cryptography' is not installed.")
        print("Please install it using: pip install cryptography")
        sys.exit(1)

def extract_key_from_kit(kit_path):
    """Extract encryption key from emergency kit file."""
    try:
        with open(kit_path, 'r') as f:
            content = f.read()
            # Look for the key pattern: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
            match = re.search(r'\b([A-Z0-9]{4}-){6}[A-Z0-9]{4}\b', content)
            if match:
                return match.group(0)
    except Exception as e:
        print(f"Error reading emergency kit file: {e}")
    return None

def password_to_key(password):
    """Convert password/key to encryption key."""
    password = password.encode()
    for _ in range(100):
        password = hashlib.sha256(password).digest()
    return password[:16]

def generate_iv(key, salt):
    """Generate initialization vector."""
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    return temp_iv[:16]

class SecureTarFile:
    """Handle encrypted tar files."""
    def __init__(self, filename, password):
        self._file = None
        self._name = Path(filename)
        self._tar = None
        self._tar_mode = "r|gz"
        self._aes = None
        self._key = password_to_key(password)
        self._decrypt = None

    def __enter__(self):
        self._file = self._name.open("rb")
        cbc_rand = self._file.read(16)
        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(generate_iv(self._key, cbc_rand)),
            backend=default_backend(),
        )
        self._decrypt = self._aes.decryptor()
        self._tar = tarfile.open(fileobj=self, mode=self._tar_mode)
        return self._tar

    def __exit__(self, exc_type, exc_value, traceback):
        if self._tar:
            self._tar.close()
        if self._file:
            self._file.close()

    def read(self, size=0):
        return self._decrypt.update(self._file.read(size))

def extract_tar(filename):
    """Extract regular tar file."""
    _dirname = '.'.join(filename.split('.')[:-1])
    try:
        shutil.rmtree(_dirname)
    except FileNotFoundError:
        pass
    print(f'📦 Extracting {filename}...')
    _tar = tarfile.open(name=filename, mode="r")
    _tar.extractall(path=_dirname)
    return _dirname

def extract_secure_tar(filename, password):
    """Extract encrypted tar file."""
    _dirname = '.'.join(filename.split('.')[:-2])
    print(f'🔓 Decrypting {filename.split("/")[-1]}...')
    try:
        with SecureTarFile(filename, password) as _tar:
            _tar.extractall(path=_dirname)
    except tarfile.ReadError:
        print("❌ Error: Unable to extract SecureTar - possible wrong password or file is not encrypted")
        return None
    except Exception as e:
        print(f"❌ Error during extraction: {str(e)}")
        return None
    return _dirname

def main():
    print("\n🏠 Home Assistant Backup Decryption Tool")
    print("=======================================")
    
    # Check requirements first
    check_requirements()
    
    # Look for emergency kit file
    kit_files = glob.glob('*emergency*kit*.txt')
    if not kit_files:
        print("❌ Error: No emergency kit file found!")
        print("Please place your emergency kit text file in this directory.")
        sys.exit(1)
    
    # Try to extract key from the kit file first
    key = None
    if kit_files:
        key = extract_key_from_kit(kit_files[0])
        if key:
            print(f"✅ Found encryption key in {kit_files[0]}")
        else:
            print("⚠️  Could not find encryption key in emergency kit file.")
    else:
        print("⚠️  No emergency kit file found.")
    
    # If key not found, ask for manual entry
    if not key:
        print("\nPlease enter your encryption key manually.")
        print("It should be in the format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        while True:
            manual_key = input("Key: ").strip()
            if re.match(r'^([A-Z0-9]{4}-){6}[A-Z0-9]{4}', manual_key):
                key = manual_key
                print("✅ Key format verified")
                break
            else:
                print("❌ Invalid key format. Please try again.")

                # Look for tar files
    tar_files = glob.glob('*.tar')
    if not tar_files:
        print("❌ Error: No .tar files found!")
        print("Please place your backup .tar files in this directory.")
        sys.exit(3)

    print(f"📁 Found {len(tar_files)} backup file(s) to process")

    success_count = 0
    for tar_file in tar_files:
        try:
            _dirname = extract_tar(tar_file)
            # Look for encrypted tar.gz files in the extracted directory
            secure_tars = glob.glob(f'{_dirname}/*.tar.gz')
            if not secure_tars:
                print(f"ℹ️  No encrypted files found in {tar_file}")
                continue

            for secure_tar in secure_tars:
                if extract_secure_tar(secure_tar, key):
                    os.remove(secure_tar)  # Remove the encrypted file after successful extraction
                    success_count += 1
        except Exception as e:
            print(f"❌ Error processing {tar_file}: {str(e)}")

    if success_count > 0:
        print(f"\n✅ Successfully decrypted {success_count} backup file(s)!")
        print("You can find the decrypted files in the extracted directories.")
    else:
        print("\n⚠️  No files were successfully decrypted.")
        print("Please check that your backup files and emergency kit are correct.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)
