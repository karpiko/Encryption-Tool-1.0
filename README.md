# File Encryption/Decryption Tool

A powerful and user-friendly command-line utility for encrypting and decrypting files using multiple encryption algorithms.

## ⚠️ DISCLAIMER

**This tool is for educational and legitimate purposes only.** It demonstrates encryption concepts and best practices in cryptography. Users are responsible for:
- Using this tool only on files they own or have permission to encrypt/decrypt
- Keeping encryption keys safe and secure
- Understanding the legal implications of encryption in their jurisdiction
- Complying with local laws and regulations regarding cryptography

**The creators assume no liability for misuse or damage caused by this tool.**

## Features

### Encryption Algorithms

- **Fernet** (Default)
  - Symmetric encryption based on AES-128 with HMAC authentication
  - Simple, secure, and recommended for most use cases
  - Provides built-in authentication
  - Fast performance

- **AES-256** (Advanced Encryption Standard)
  - Military-grade symmetric encryption
  - 256-bit key size for maximum security
  - CBC mode with PKCS7 padding
  - Ideal for large files
  - Industry standard encryption method

- **RSA** (Rivest-Shamir-Adleman)
  - Asymmetric encryption using public/private key pairs
  - Public key for encryption, private key for decryption
  - Suitable for key exchange and small data encryption
  - 2048-bit keys (good security/performance balance)

### Features

**User Interfaces:**
- Modern graphical user interface (GUI)
- Full-featured command-line interface (CLI) for advanced users
- Both interfaces share the same encryption engines

**Core Features:**
- Multiple encryption algorithms to choose from (Fernet, AES-256, RSA)
- Automatic key generation and management
- Support for any file type (text, binary, images, PDFs, etc.)
- Clear error messages and validation
- Color-coded output for better UX
- File size information and validation
- Comprehensive help documentation
- Background processing for large file operations
- Real-time status updates during encryption/decryption

## Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)

### Setup Steps

1. **Clone or download the project**
   ```bash
   cd /path/to/Encryption\ Tool
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify installation (CLI)**
   ```bash
   python3 src/main.py --help
   ```

5. **Launch GUI (optional)**
   ```bash
   python3 gui_main.py
   ```

## Getting Started

### Option 1: Graphical User Interface (GUI) - Recommended

The GUI provides a beautiful, easy-to-use interface.

**Start the GUI:**
```bash
python3 gui_main.py
```

**Features:**
- Beautiful, modern interface with Davenport branding
- Intuitive tabs for Encrypt, Decrypt, and Key Generation
- File browse dialogs for easy file selection
- Real-time file size information
- Color-coded status messages
- Drag-and-drop support (coming soon)
- Background processing with status updates

**GUI Workflow:**
1. Click "Key Generation" tab to create encryption keys
2. Click "Encrypt" tab to encrypt files
3. Click "Decrypt" tab to decrypt files
4. Check status bar for operation results

### Option 2: Command-Line Interface (CLI)

For advanced users who prefer terminal-based operation.

## Quick Start

### 1. Generate an Encryption Key

**Fernet (Recommended):**
```bash
python src/main.py generate-key --algorithm fernet --output mykey.key
```

**AES-256:**
```bash
python src/main.py generate-key --algorithm aes --output aeskey.key
```

**RSA Keypair:**
```bash
python src/main.py generate-keypair --output rsa_keys
```
This creates `rsa_keys_private.pem` and `rsa_keys_public.pem`

### 2. Encrypt a File

**Using Fernet:**
```bash
python src/main.py encrypt --algorithm fernet \
  --input myfile.txt \
  --output myfile.txt.enc \
  --key mykey.key
```

**Using AES-256:**
```bash
python src/main.py encrypt --algorithm aes \
  --input myfile.txt \
  --output myfile.txt.enc \
  --key aeskey.key
```

### 3. Decrypt a File

**Using Fernet:**
```bash
python src/main.py decrypt --algorithm fernet \
  --input myfile.txt.enc \
  --output myfile_decrypted.txt \
  --key mykey.key
```

**Using AES-256:**
```bash
python src/main.py decrypt --algorithm aes \
  --input myfile.txt.enc \
  --output myfile_decrypted.txt \
  --key aeskey.key
```

## Usage Examples

### Example 1: Encrypt and Decrypt a Text File

```bash
# Generate a Fernet key
python src/main.py generate-key --algorithm fernet --output secret.key

# Encrypt the example file
python src/main.py encrypt --algorithm fernet \
  --input examples/sample.txt \
  --output examples/sample.txt.enc \
  --key secret.key

# Verify the encrypted file is unreadable
cat examples/sample.txt.enc  # Shows binary gibberish

# Decrypt the file
python src/main.py decrypt --algorithm fernet \
  --input examples/sample.txt.enc \
  --output examples/sample_decrypted.txt \
  --key secret.key

# Verify the decrypted content matches original
diff examples/sample.txt examples/sample_decrypted.txt  # No differences
```

### Example 2: AES-256 Encryption for Large Files

```bash
# Generate AES key
python src/main.py generate-key --algorithm aes --output large_file.key

# Encrypt a large file
python src/main.py encrypt --algorithm aes \
  --input mydocument.pdf \
  --output mydocument.pdf.enc \
  --key large_file.key

# Decrypt
python src/main.py decrypt --algorithm aes \
  --input mydocument.pdf.enc \
  --output mydocument_decrypted.pdf \
  --key large_file.key
```

### Example 3: RSA Public/Private Key Encryption

```bash
# Generate RSA keypair
python src/main.py generate-keypair --output myrsa

# Encrypt a small file with public key (can be shared)
python src/main.py encrypt --algorithm rsa \
  --input secret.txt \
  --output secret.txt.enc \
  --key myrsa_public.pem

# Only the holder of the private key can decrypt
python src/main.py decrypt --algorithm rsa \
  --input secret.txt.enc \
  --output secret_decrypted.txt \
  --key myrsa_private.pem
```

## Command Reference

### Main Commands

#### `generate-key`
Generate an encryption key for Fernet or AES.

```bash
python src/main.py generate-key [OPTIONS]

Options:
  --algorithm {fernet,aes}    Algorithm for key generation (default: fernet)
  --output, -o FILE           Output file path for the key (optional)
```

#### `generate-keypair`
Generate an RSA public/private keypair.

```bash
python src/main.py generate-keypair [OPTIONS]

Options:
  --output, -o FILE           Output file prefix (required)
                             Creates: prefix_public.pem, prefix_private.pem
```

#### `encrypt`
Encrypt a file.

```bash
python src/main.py encrypt [OPTIONS]

Options:
  --algorithm {fernet,aes,rsa}  Encryption algorithm (default: fernet)
  --input, -i FILE              Input file path (required)
  --output, -o FILE             Output file path (required)
  --key, -k FILE                Key file path (required)
  --overwrite                   Overwrite if output file exists
```

#### `decrypt`
Decrypt a file.

```bash
python src/main.py decrypt [OPTIONS]

Options:
  --algorithm {fernet,aes,rsa}  Encryption algorithm (default: fernet)
  --input, -i FILE              Input file path (required)
  --output, -o FILE             Output file path (required)
  --key, -k FILE                Key file path (required)
  --overwrite                   Overwrite if output file exists
```

## Security Considerations

### Key Management

1. **Store Keys Securely**
   - Never commit keys to version control
   - Use file permissions to restrict access: `chmod 600 mykey.key`
   - Consider storing keys in dedicated key management systems
   - Never share private keys (RSA) or symmetric keys

2. **Key Generation**
   - Always use the `generate-key` command for cryptographic keys
   - Don't use weak or predictable keys
   - Different algorithms have different key requirements
   - Rotate keys periodically for sensitive data

3. **Key Loss**
   - Keep backups of keys in secure locations
   - Without the key, encrypted files are unrecoverable
   - Consider key escrow for critical files

### Algorithm Selection

| Algorithm | Best For | Limitations | Advantages |
|-----------|----------|------------|-----------|
| **Fernet** | Most general use | - | Simple, fast, authenticated |
| **AES-256** | Large files, performance | - | Military-grade, fast, scalable |
| **RSA** | Key exchange, small data | ~190 byte limit | Asymmetric, shareable keys |

### File Integrity

- **Fernet** provides built-in authentication (HMAC)
- **AES** does not include authentication (consider separate HMAC)
- **RSA** does not include authentication
- Always verify file integrity separately for AES/RSA

### Best Practices

1. **Use Fernet by default** unless you have specific needs
2. **Keep encryption keys separate** from encrypted files
3. **Test key recovery** before relying on encrypted backups
4. **Never hardcode keys** in source code or scripts
5. **Use environment variables** or key files for production
6. **Rotate keys** for long-term sensitive data
7. **Document your key management** policy

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_fernet.py -v

# Run with coverage
python -m pytest tests/ --cov=src
```

### Test Coverage

- **Fernet Tests** (`test_fernet.py`)
  - Key generation and management
  - File encryption/decryption
  - Error handling and validation

- **AES Tests** (`test_aes.py`)
  - AES-256 key generation
  - Large file encryption
  - IV handling and padding

- **RSA Tests** (`test_rsa.py`)
  - Keypair generation
  - Public/private key encryption
  - Key size limitations

## GUI Interface Overview

### Encrypt Tab
- Select file to encrypt
- Choose algorithm (Fernet or AES-256)
- Select encryption key
- Specify output file location
- Real-time file size display
- Status updates during encryption

### Decrypt Tab
- Select encrypted file
- Choose decryption algorithm
- Select decryption key
- Specify output file location
- File integrity verification
- Clear error messages for wrong keys

### Key Generation Tab
**Symmetric Keys:**
- Generate Fernet keys
- Generate AES-256 keys
- Save keys to specified location

**RSA Keypair:**
- Generate 2048-bit RSA keypairs
- Creates both public and private keys
- Security warnings about key protection

### Features
- Modern UI (red/black/white color scheme)
- Intuitive tabbed interface
- File browse dialogs
- Real-time status bar with color-coded messages
- Background processing for large files
- Professional error handling and validation
- Responsive design

## Architecture

### Project Structure

```
encryption-tool/
├── src/
│   ├── main.py                 # CLI interface
│   ├── gui/                    # GUI modules
│   │   ├── main_window.py      # Main application window
│   │   ├── encrypt_tab.py      # Encrypt tab UI
│   │   ├── decrypt_tab.py      # Decrypt tab UI
│   │   ├── keygen_tab.py       # Key generation tab UI
│   │   ├── styles.py           # UI theme and styling
│   │   ├── utils.py            # GUI utility functions
│   │   └── create_logo.py      # Logo generation
│   ├── encryptors/             # Encryption algorithms
│   │   ├── fernet_encryptor.py
│   │   ├── aes_encryptor.py
│   │   └── rsa_encryptor.py
│   └── utils/
│       └── file_handler.py     # File operations
├── tests/                       # Unit tests
│   ├── test_fernet.py
│   ├── test_aes.py
│   └── test_rsa.py
├── assets/
│   └── app_logo.png            # Application logo
├── examples/
│   └── sample.txt             # Example file
├── gui_main.py                # GUI entry point
├── requirements.txt            # Dependencies
├── README.md                  # This file
└── LICENSE                    # MIT License
```

### Design Patterns

- **Separate Encryptor Classes**: Each algorithm has its own module
- **Static Methods**: All encryption operations are stateless
- **Error Handling**: Clear, informative error messages
- **File Abstraction**: FileHandler utility for consistent file operations
- **CLI Interface**: Argparse-based command structure

## Troubleshooting

### Issue: "Module not found" errors

**Solution:**
```bash
# Install dependencies
pip install -r requirements.txt

# Ensure you're in the project directory
cd /path/to/Encryption\ Tool
```

### Issue: Key file not found

**Solution:**
```bash
# Check if key file exists
ls -la mykey.key

# Regenerate if necessary
python src/main.py generate-key --algorithm fernet --output mykey.key
```

### Issue: Decryption fails with "Invalid key or corrupted file"

**Causes:**
- Using wrong key for decryption
- File was corrupted during transfer
- File was encrypted with different algorithm
- Key format mismatch

**Solution:**
- Verify using correct key
- Check file integrity (file size, checksum)
- Use correct algorithm for decryption

### Issue: RSA file too large

**Problem:**
RSA can only encrypt ~190 bytes with 2048-bit keys

**Solution:**
- Use Fernet or AES for large files
- Use RSA only for encrypting keys, not files

## Future Enhancements

Potential improvements for future versions:

1. **Hybrid Encryption** - RSA for key encryption + AES for file encryption
2. **Password-Based Key Derivation** - Derive keys from passwords
3. **File Compression** - Compress before encryption
4. **Batch Operations** - Encrypt multiple files at once
5. **Progress Bars** - Show progress for large files
6. **Checksum Verification** - Built-in integrity checking
7. **GUI Interface** - Graphical user interface
8. **Cloud Integration** - Upload/download encrypted files
9. **Key Rotation** - Automatic key management
10. **Metadata** - Store encryption algorithm in encrypted file

## Technologies Used

### Core Libraries

- **cryptography** - Fernet and RSA implementation
- **pycryptodome** - AES implementation
- **argparse** - Command-line interface
- **colorama** - Colored terminal output (optional)

### Testing

- **unittest** - Built-in Python testing framework
- **pytest** - Advanced testing framework (optional)

## Contributing

Contributions are welcome! Areas for improvement:

- Additional encryption algorithms
- Performance optimizations
- Better error messages
- GUI implementation
- Documentation improvements

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

### MIT License Summary

- **Permissions**: Commercial use, distribution, modification, private use
- **Conditions**: License and copyright notice must be included
- **Limitations**: No liability, no warranty

## References

### Cryptography Standards

- [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) - AES Block Cipher Modes
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HMAC-based Extract-and-Expand Key Derivation Function
- [RFC 3394](https://tools.ietf.org/html/rfc3394) - AES Key Wrap Algorithm

### Libraries Documentation

- [cryptography.io](https://cryptography.io/) - Python cryptography library
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/) - AES implementation

### Security Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

## Support

For issues, questions, or suggestions:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review test files for usage examples
3. Read the code documentation and docstrings
4. Create an issue on GitHub with detailed information

## Credits

Created as an educational tool to demonstrate:
- Cryptographic concepts
- Python best practices
- CLI application design
- Test-driven development

---

**Remember: Encryption is a tool. Use it responsibly and ethically.**

Last Updated: November 2025
