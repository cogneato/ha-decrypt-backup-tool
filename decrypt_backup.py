#!/usr/bin/env python3
"""
Home Assistant Backup Decryption Tool
-----------------------------------
This script automatically decrypts Home Assistant backups using the emergency kit.
Place this script in the same directory as:
- Your Home Assistant emergency kit text file
- Your backup .tar file(s)

Requirements:
pip install cryptography pynacl

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
import platform
import argparse
import struct
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
import hashlib
import hmac
import nacl.bindings.crypto_secretstream as nss
import nacl.encoding
from nacl.hash import blake2b
from nacl.pwhash.argon2id import kdf as argon2id_kdf, SALTBYTES as ARGON2_SALT_SIZE

def check_requirements():
    """Check if required packages are installed."""
    try:
        import cryptography
        import nacl
    except ImportError:
        print("Error: Required package(s) not installed.")
        print("Please install them using: pip install cryptography pynacl")
        sys.exit(1)

# SecureTar v2/v3 header: 16 bytes file ID (9-byte magic + 1-byte version +
# 6 reserved) followed by 16 bytes metadata (8-byte plaintext size + 8 reserved).
SECURETAR_MAGIC = b"SecureTar"
SECURETAR_FILE_ID_FORMAT = "!9sB6s"
SECURETAR_FILE_METADATA_FORMAT = "!Q8x"

AES_IV_SIZE = 16

# Real gzip streams always start with this; SecureTar's own encrypted output
# never coincidentally does, so it doubles as an "is this actually
# unencrypted?" check (same heuristic Home Assistant's own securetar package
# uses internally).
GZIP_MAGIC_BYTES = b"\x1f\x8b\x08"

# SecureTar v3 (XChaCha20-Poly1305 secretstream) cipher-init layout:
# root salt + validation salt + validation key + derivation salt + stream header
V3_DERIVED_KEY_SALT_SIZE = 16
V3_DERIVED_KEY_SIZE = 32
V3_CHACHA20_HEADER_SIZE = nss.crypto_secretstream_xchacha20poly1305_HEADERBYTES
V3_SECRETSTREAM_ABYTES = nss.crypto_secretstream_xchacha20poly1305_ABYTES
V3_SECRETSTREAM_CHUNK_SIZE = 1024 * 1024
V3_KDF_OPSLIMIT = 8
V3_KDF_MEMLIMIT = 16 * 1024 * 1024

SECURETAR_V3_CIPHER_INIT_FORMAT = (
    f"!{ARGON2_SALT_SIZE}s"
    f"{V3_DERIVED_KEY_SALT_SIZE}s"
    f"{V3_DERIVED_KEY_SIZE}s"
    f"{V3_DERIVED_KEY_SALT_SIZE}s"
    f"{V3_CHACHA20_HEADER_SIZE}s"
)
SECURETAR_V3_CIPHER_INIT_SIZE = struct.calcsize(SECURETAR_V3_CIPHER_INIT_FORMAT)

def sanitize_filename(name):
    """Sanitize filename for Windows compatibility."""
    if platform.system() == 'Windows':
        # Replace characters that are invalid in Windows filenames
        invalid_chars = '<>:"|?*'
        for char in invalid_chars:
            name = name.replace(char, '_')
    return name

def tar_filter(member, dest_path):
    """Filter for tar extraction: sanitizes filenames for Windows and blocks
    path traversal / symlink escapes. Passing a custom filter to extractall()
    bypasses tarfile's built-in 'data' filter protections entirely, so those
    checks have to be reimplemented here instead of assumed.

    Unsafe members are skipped (not extracted) rather than aborting the whole
    archive: real HA add-on backups legitimately contain symlinks with
    absolute link targets (e.g. "/config", "/backup") that reflect the
    add-on container's own mount layout and are meaningless/unsafe once
    extracted onto a different filesystem."""
    member.name = sanitize_filename(member.name)

    dest_root = os.path.realpath(dest_path)
    target_path = os.path.realpath(os.path.join(dest_path, member.name))
    if os.path.commonpath([dest_root, target_path]) != dest_root:
        print(f"⚠️  Skipping tar member with path traversal attempt: {member.name}")
        return None

    if member.issym() or member.islnk():
        link_target = os.path.realpath(
            os.path.join(dest_path, os.path.dirname(member.name), member.linkname)
        )
        if os.path.commonpath([dest_root, link_target]) != dest_root:
            print(
                f"⚠️  Skipping tar member with unsafe link target: "
                f"{member.name} -> {member.linkname}"
            )
            return None

    return member

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

def derive_v3_root_key(password, root_salt):
    """Derive the SecureTar v3 root key from the password using Argon2id."""
    return argon2id_kdf(
        nss.crypto_secretstream_xchacha20poly1305_KEYBYTES,
        password.encode(),
        root_salt,
        opslimit=V3_KDF_OPSLIMIT,
        memlimit=V3_KDF_MEMLIMIT,
    )

def derive_v3_stream_key(root_key, salt):
    """Derive a per-file SecureTar v3 stream key from the root key."""
    return blake2b(
        b"",
        key=root_key,
        salt=salt,
        person=b"SecureTarv3",
        encoder=nacl.encoding.RawEncoder,
    )

class SecureTarFile:
    """Handle encrypted tar files (SecureTar v1/v2 AES-CBC and v3 XChaCha20-Poly1305)."""
    def __init__(self, filename, password):
        self._file = None
        self._name = Path(filename)
        self._tar = None
        self._tar_mode = "r|gz"
        self._password = password
        self._decrypt = None
        # SecureTar v3 secretstream state
        self._v3_state = None
        self._v3_buffer = b""
        self._v3_pos = 0
        self._v3_ciphertext_size = 0
        self._v3_done = False

    def __enter__(self):
        self._file = self._name.open("rb")
        version, plaintext_size, cipher_init = self.read_header(self._file)

        if version == 3:
            self._init_v3(cipher_init, plaintext_size)
        else:
            key = password_to_key(self._password)
            aes = Cipher(
                algorithms.AES(key),
                modes.CBC(generate_iv(key, cipher_init)),
                backend=default_backend(),
            )
            self._decrypt = aes.decryptor()

        self._tar = tarfile.open(fileobj=self, mode=self._tar_mode)
        return self._tar

    def __exit__(self, exc_type, exc_value, traceback):
        if self._tar:
            self._tar.close()
        if self._file:
            self._file.close()

    def read_header(self, st_file):
        """Parse the SecureTar header, returning (version, plaintext_size, cipher_init)."""
        id_bytes = st_file.read(struct.calcsize(SECURETAR_FILE_ID_FORMAT))
        magic, version, reserved = struct.unpack(SECURETAR_FILE_ID_FORMAT, id_bytes)

        if magic != SECURETAR_MAGIC:
            # Legacy (v1) format: no header, the bytes read are the CBC salt
            return 1, None, id_bytes

        if version not in (2, 3):
            raise tarfile.ReadError(f"Unsupported SecureTar version: {version}")

        metadata = st_file.read(struct.calcsize(SECURETAR_FILE_METADATA_FORMAT))
        (plaintext_size,) = struct.unpack(SECURETAR_FILE_METADATA_FORMAT, metadata)

        if version == 2:
            cipher_init = st_file.read(AES_IV_SIZE)
        else:
            cipher_init = st_file.read(SECURETAR_V3_CIPHER_INIT_SIZE)

        return version, plaintext_size, cipher_init

    def _init_v3(self, cipher_init, plaintext_size):
        """Set up XChaCha20-Poly1305 secretstream decryption state (SecureTar v3)."""
        (
            root_salt,
            validation_salt,
            stored_validation_key,
            derivation_salt,
            stream_header,
        ) = struct.unpack(SECURETAR_V3_CIPHER_INIT_FORMAT, cipher_init)

        root_key = derive_v3_root_key(self._password, root_salt)
        validation_key = derive_v3_stream_key(root_key, validation_salt)
        if not hmac.compare_digest(validation_key, stored_validation_key):
            raise tarfile.ReadError("Invalid password for SecureTar v3 file")

        stream_key = derive_v3_stream_key(root_key, derivation_salt)

        self._v3_state = nss.crypto_secretstream_xchacha20poly1305_state()
        nss.crypto_secretstream_xchacha20poly1305_init_pull(
            self._v3_state, stream_header, stream_key
        )

        num_chunks = max(1, -(-plaintext_size // V3_SECRETSTREAM_CHUNK_SIZE))
        self._v3_ciphertext_size = plaintext_size + num_chunks * V3_SECRETSTREAM_ABYTES

    def read(self, size=0):
        if self._v3_state is not None:
            return self._read_v3(size)
        return self._decrypt.update(self._file.read(size))

    def _read_v3(self, size):
        """Fill the plaintext buffer by pulling and decrypting secretstream chunks."""
        while len(self._v3_buffer) < size and not self._v3_done:
            frame_size = V3_SECRETSTREAM_CHUNK_SIZE + V3_SECRETSTREAM_ABYTES
            remaining = self._v3_ciphertext_size - self._v3_pos
            frame_size = min(frame_size, max(remaining, 0))
            if frame_size == 0:
                break
            encrypted = self._file.read(frame_size)
            if not encrypted:
                break
            self._v3_pos += len(encrypted)
            plaintext, tag = nss.crypto_secretstream_xchacha20poly1305_pull(
                self._v3_state, encrypted
            )
            self._v3_buffer += plaintext
            if tag == nss.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
                self._v3_done = True

        data, self._v3_buffer = self._v3_buffer[:size], self._v3_buffer[size:]
        return data

def is_unencrypted_tar_gz(filename):
    """Check whether filename is already a plain (unencrypted) gzip stream."""
    with open(filename, 'rb') as f:
        return f.read(len(GZIP_MAGIC_BYTES)) == GZIP_MAGIC_BYTES

def extract_tar(filename):
    """Extract regular tar file."""
    _dirname = '.'.join(filename.split('.')[:-1])
    try:
        shutil.rmtree(_dirname)
    except FileNotFoundError:
        pass
    print(f'📦 Extracting {filename}...')
    _tar = tarfile.open(name=filename, mode="r")
    _tar.extractall(path=_dirname, filter=tar_filter)
    return _dirname

def extract_plain_tar_gz(filename):
    """Extract an unencrypted tar.gz component (no SecureTar wrapping)."""
    _dirname = '.'.join(filename.split('.')[:-2])
    print(f'📦 Extracting {filename.split("/")[-1]} (unencrypted)...')
    try:
        with tarfile.open(name=filename, mode="r:gz") as _tar:
            _tar.extractall(path=_dirname, filter=tar_filter)
    except tarfile.ReadError as e:
        print(f"❌ Error: Unable to extract {filename.split('/')[-1]}: {e}")
        return None
    except Exception as e:
        print(f"❌ Error during extraction: {str(e)}")
        return None
    return _dirname

def extract_secure_tar(filename, password):
    """Extract encrypted tar file."""
    if is_unencrypted_tar_gz(filename):
        return extract_plain_tar_gz(filename)

    _dirname = '.'.join(filename.split('.')[:-2])
    print(f'🔓 Decrypting {filename.split("/")[-1]}...')
    try:
        with SecureTarFile(filename, password) as _tar:
            _tar.extractall(path=_dirname, filter=tar_filter)
    except tarfile.ReadError:
        print("❌ Error: Unable to extract SecureTar - possible wrong password or file is not encrypted")
        return None
    except Exception as e:
        print(f"❌ Error during extraction: {str(e)}")
        return None
    return _dirname

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Decrypt Home Assistant backup files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
  %(prog)s --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --file backup.tar
  %(prog)s --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --output-dir ./decrypted

  # Third-party add-on backup (e.g. Google Drive Backup) using its own
  # non-standard key/password instead of a Home Assistant emergency-kit key:
  %(prog)s --key 'my-google-drive-backup-password' --file 584e4299.tar
        """
    )
    parser.add_argument(
        '--key',
        '-k',
        help='Encryption key. Home Assistant emergency-kit keys use the '
             'format XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX, but that format is '
             'only enforced when the key is read from an emergency kit file '
             'or entered interactively. A key passed here via --key is used '
             'verbatim with no format check, since some third-party add-ons '
             '(e.g. Google Drive Backup) let users set an arbitrary '
             'password instead.'
    )
    parser.add_argument(
        '--file',
        '-f',
        help='Specific backup .tar file to decrypt (defaults to all .tar files in current directory)'
    )
    parser.add_argument(
        '--output-dir',
        '-o',
        help='Output directory for decrypted files (defaults to current directory)'
    )
    parser.add_argument(
        '--cleanup',
        '-c',
        action='store_true',
        help='Remove encrypted .tar.gz files after successful decryption (default behavior)'
    )
    parser.add_argument(
        '--keep-encrypted',
        action='store_true',
        help='Keep encrypted .tar.gz files after decryption'
    )
    return parser.parse_args()

def main():
    print("\n🏠 Home Assistant Backup Decryption Tool")
    print("=======================================")

    # Check requirements first
    check_requirements()

    # Change to the directory where the script/executable is located
    # This allows double-clicking the executable to work properly
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller executable
        script_dir = os.path.dirname(sys.executable)
    else:
        # Running as Python script
        script_dir = os.path.dirname(os.path.abspath(__file__))

    if script_dir:
        os.chdir(script_dir)
        print(f"📂 Working directory: {os.getcwd()}")

    # Parse command line arguments
    args = parse_args()

    # Handle key: CLI arg > emergency kit > manual input
    # --key is unrestricted (empty/blank is treated as "not provided" and
    # falls through to kit detection / manual entry): third-party add-ons
    # (e.g. Google Drive Backup) let users set an arbitrary password, not
    # necessarily HA's own emergency-kit format, so we only enforce that
    # format where it's actually guaranteed to apply.
    key = args.key
    key_from_cli = bool(key)

    if not key:
        # Look for emergency kit file
        kit_files = glob.glob('*emergency*kit*.txt')

        # Try to extract key from the kit file first
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
            if re.match(r'^([A-Z0-9]{4}-){6}[A-Z0-9]{4}$', manual_key):
                key = manual_key
                print("✅ Key format verified")
                break
            else:
                print("❌ Invalid key format. Please try again.")
    elif key_from_cli:
        # --key is used verbatim as the password, no format restriction
        print("✅ Using provided key")
    else:
        # Key came from the emergency kit, already extracted via the strict
        # format regex in extract_key_from_kit() - re-validate defensively.
        if not re.match(r'^([A-Z0-9]{4}-){6}[A-Z0-9]{4}$', key):
            print("❌ Error: Invalid key format!")
            print("Key should be in the format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
            sys.exit(1)
        print("✅ Key format verified")

    # Change to output directory if specified
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)
        print(f"📂 Output directory: {args.output_dir}")

    # Look for tar files
    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ Error: File '{args.file}' not found!")
            sys.exit(1)
        tar_files = [args.file]
    else:
        tar_files = glob.glob('*.tar')

    if not tar_files:
        print("❌ Error: No .tar files found!")
        print("Please place your backup .tar files in this directory.")
        sys.exit(1)

    print(f"📁 Found {len(tar_files)} backup file(s) to process")

    # Determine cleanup behavior
    should_cleanup = not args.keep_encrypted
    
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
                    if should_cleanup:
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
