# Home Assistant Backup Decryption Tool

Decrypt Home Assistant backups outside of Home Assistant for disaster recovery, inspection, or manual restoration.

## Quick Start

### Option 1: Download Executable (Easiest)

**No Python installation required!**

1. Download the latest release for your platform:
   - **Windows**: `decrypt_backup-windows-amd64.exe`
   - **macOS**: `decrypt_backup-macos-amd64`
   - **Linux**: `decrypt_backup-linux-amd64`

2. Place the executable in the same folder as your backup files

3. **Windows**: Double-click the `.exe` file

   **macOS/Linux**: Open Terminal and run:
   ```bash
   chmod +x decrypt_backup
   xattr -d com.apple.quarantine decrypt_backup  # macOS only
   ./decrypt_backup
   ```

That's it! The tool will automatically find your emergency kit and backup files.

### Option 2: Run Python Script

**Requirements:**
- Python 3.7 or newer
- `cryptography` and `pynacl` packages: `pip install cryptography pynacl`

**Usage:**
```bash
python3 decrypt_backup.py
```

## Usage Examples

### Interactive Mode (Default)
```bash
./decrypt_backup
```
The tool will:
- Automatically find your emergency kit file
- Search for backup `.tar` files in the current directory
- Prompt for your encryption key if needed
- Decrypt all backups found

### Command-Line Mode
```bash
# Provide encryption key directly
./decrypt_backup --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX

# Decrypt specific file
./decrypt_backup --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --file backup.tar

# Specify output directory
./decrypt_backup --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --output-dir ./my-backups

# Keep encrypted files after decryption (default removes them)
./decrypt_backup --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --keep-encrypted

# See all options
./decrypt_backup --help
```

## File Organization

For best results, organize your files like this:
```
my-backup-folder/
├── decrypt_backup                    # The executable
├── caa3ca81f524436da04edea103302316.tar  # Your backup
└── home_assistant_backup_emergency_kit.txt  # Your emergency kit (optional)
```

The tool will:
1. Automatically detect and read your emergency kit
2. Extract the outer `.tar` file
3. Decrypt all encrypted `.tar.gz` files inside
4. Create directories with decrypted contents

## Troubleshooting

### macOS: "Cannot verify developer"
This happens because the executable is not signed with an Apple Developer certificate.

**Solution:**
```bash
xattr -d com.apple.quarantine decrypt_backup
```

Or go to **System Preferences → Privacy & Security** and click "Allow Anyway"

### "No emergency kit file found"
- Make sure the emergency kit filename contains both "emergency" and "kit"
- Or provide the key manually with `--key` flag

### "No .tar files found"
- Ensure you have the backup `.tar` file in the same directory
- Or use `--file` to specify the exact path

## Supported Backup Formats

Supports all SecureTar versions used by Home Assistant: v1 and v2 (AES-CBC) and v3 (XChaCha20-Poly1305, the default since Home Assistant 2026.4).

Also handles backup components that aren't encrypted at all (detected automatically) and third-party add-ons like Google Drive Backup that use their own non-standard key/password format — pass their key with `--key` and it's used as-is, without Home Assistant's `XXXX-XXXX-...` format check.

## Security Notes

- Keep your emergency kit secure - it contains your encryption key
- After decryption, store the decrypted files in a secure location
- The tool removes encrypted `.tar.gz` files after successful decryption by default
  - Use `--keep-encrypted` if you want to keep them

## Contributing

Issues and pull requests welcome! This tool was created to solve the problem of accessing encrypted HA backups when your instance is unavailable.

## License

MIT License - feel free to use, modify, and distribute.
