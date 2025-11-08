#!/usr/bin/env python3
"""
File Encryption/Decryption Tool - Main CLI Interface.

A command-line utility for encrypting and decrypting files using multiple
algorithms (Fernet, AES-256, RSA).

⚠️  DISCLAIMER: This tool is for educational purposes only. Use responsibly
and only on files you own or have permission to encrypt/decrypt.
"""

import argparse
import sys
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    # Fallback if colorama is not available
    class Fore:
        GREEN = ""
        RED = ""
        YELLOW = ""
        BLUE = ""

    class Style:
        RESET_ALL = ""

    def colorama_init():
        pass


from encryptors import FernetEncryptor, AESEncryptor, RSAEncryptor
from utils import FileHandler


def print_header():
    """Print application header."""
    colorama_init()
    print(f"\n{Fore.BLUE}{'=' * 60}")
    print("  File Encryption/Decryption Tool")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")


def print_success(message: str):
    """Print success message."""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")


def print_error(message: str):
    """Print error message."""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")


def print_info(message: str):
    """Print info message."""
    print(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")


def cmd_encrypt(args):
    """Handle encryption command."""
    try:
        # Validate inputs
        FileHandler.validate_input_file(args.input)
        FileHandler.validate_output_path(args.output)

        # Get file size
        file_size = FileHandler.get_file_size(args.input)
        size_str = FileHandler.format_file_size(file_size)

        print_info(f"Encrypting file: {args.input} ({size_str})")

        # Load key if not generating new one
        if args.key:
            print_info(f"Loading key from: {args.key}")
            key = _load_key(args.algorithm, args.key)
        else:
            print_error("No key provided. Use --key to specify key file.")
            return 1

        # Perform encryption based on algorithm
        algorithm = args.algorithm.lower()

        if algorithm == "fernet":
            FernetEncryptor.encrypt_file(args.input, args.output, key)
        elif algorithm == "aes":
            AESEncryptor.encrypt_file(args.input, args.output, key)
        elif algorithm == "rsa":
            print_error("RSA encryption requires public key file.")
            return 1
        else:
            print_error(f"Unknown algorithm: {algorithm}")
            return 1

        print_success(
            f"File encrypted successfully: {args.output}"
        )
        return 0

    except FileNotFoundError as e:
        print_error(str(e))
        return 1
    except Exception as e:
        print_error(f"Encryption failed: {e}")
        return 1


def cmd_decrypt(args):
    """Handle decryption command."""
    try:
        # Validate inputs
        FileHandler.validate_input_file(args.input)
        FileHandler.validate_output_path(args.output)

        # Get file size
        file_size = FileHandler.get_file_size(args.input)
        size_str = FileHandler.format_file_size(file_size)

        print_info(f"Decrypting file: {args.input} ({size_str})")

        # Load key
        if args.key:
            print_info(f"Loading key from: {args.key}")
            key = _load_key(args.algorithm, args.key)
        else:
            print_error("No key provided. Use --key to specify key file.")
            return 1

        # Perform decryption based on algorithm
        algorithm = args.algorithm.lower()

        if algorithm == "fernet":
            FernetEncryptor.decrypt_file(args.input, args.output, key)
        elif algorithm == "aes":
            AESEncryptor.decrypt_file(args.input, args.output, key)
        elif algorithm == "rsa":
            print_error("RSA decryption requires private key file.")
            return 1
        else:
            print_error(f"Unknown algorithm: {algorithm}")
            return 1

        print_success(f"File decrypted successfully: {args.output}")
        return 0

    except FileNotFoundError as e:
        print_error(str(e))
        return 1
    except Exception as e:
        print_error(f"Decryption failed: {e}")
        return 1


def cmd_generate_key(args):
    """Handle key generation command."""
    try:
        algorithm = args.algorithm.lower()

        print_info(f"Generating {algorithm.upper()} key...")

        # Generate key based on algorithm
        if algorithm == "fernet":
            key = FernetEncryptor.generate_key()
        elif algorithm == "aes":
            key = AESEncryptor.generate_key()
        elif algorithm == "rsa":
            print_error(
                "Use 'generate-keypair' for RSA. "
                "RSA requires public/private key pair."
            )
            return 1
        else:
            print_error(f"Unknown algorithm: {algorithm}")
            return 1

        # Save key
        if args.output:
            FernetEncryptor.save_key(key, args.output)
            print_success(f"Key saved to: {args.output}")
            print_warning("Keep this key safe! Do not share or lose it.")
        else:
            print_info(f"Generated key: {key.decode()}")

        return 0

    except Exception as e:
        print_error(f"Key generation failed: {e}")
        return 1


def cmd_generate_keypair(args):
    """Handle RSA keypair generation command."""
    try:
        print_info("Generating RSA keypair (this may take a moment)...")

        private_key, public_key = RSAEncryptor.generate_key_pair()

        # Save keys
        if not args.output:
            print_error("Use --output to specify key file prefix")
            return 1

        private_path = f"{args.output}_private.pem"
        public_path = f"{args.output}_public.pem"

        RSAEncryptor.save_private_key(private_key, private_path)
        RSAEncryptor.save_public_key(public_key, public_path)

        print_success(f"Private key saved to: {private_path}")
        print_success(f"Public key saved to: {public_path}")
        print_warning("Keep the private key safe! Do not share or lose it.")

        return 0

    except Exception as e:
        print_error(f"Keypair generation failed: {e}")
        return 1


def _load_key(algorithm: str, keyfile: str) -> bytes:
    """
    Load a key from file based on algorithm.

    Args:
        algorithm: The encryption algorithm
        keyfile: Path to the key file

    Returns:
        The loaded key

    Raises:
        ValueError: If key cannot be loaded
    """
    algorithm = algorithm.lower()

    if algorithm == "fernet":
        return FernetEncryptor.load_key(keyfile)
    elif algorithm == "aes":
        return AESEncryptor.load_key(keyfile)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def main():
    """Main entry point for the CLI."""
    print_header()

    parser = argparse.ArgumentParser(
        description=(
            "File encryption/decryption tool supporting Fernet, AES-256, and RSA. "
            "⚠️  For educational purposes only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate Fernet key
  python main.py generate-key --algorithm fernet --output my.key

  # Encrypt file with Fernet
  python main.py encrypt --algorithm fernet --input file.txt --output file.enc --key my.key

  # Decrypt file with Fernet
  python main.py decrypt --algorithm fernet --input file.enc --output file.txt --key my.key

  # Generate RSA keypair
  python main.py generate-keypair --output mykeys

  # AES encryption
  python main.py encrypt --algorithm aes --input file.txt --output file.enc --key aes.key

For more information: https://github.com/username/encryption-tool
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument(
        "--algorithm",
        choices=["fernet", "aes", "rsa"],
        default="fernet",
        help="Encryption algorithm (default: fernet)",
    )
    encrypt_parser.add_argument(
        "--input", "-i", required=True, help="Input file path"
    )
    encrypt_parser.add_argument(
        "--output", "-o", required=True, help="Output file path"
    )
    encrypt_parser.add_argument("--key", "-k", help="Key file path")
    encrypt_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing output file"
    )
    encrypt_parser.set_defaults(func=cmd_encrypt)

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument(
        "--algorithm",
        choices=["fernet", "aes", "rsa"],
        default="fernet",
        help="Encryption algorithm (default: fernet)",
    )
    decrypt_parser.add_argument(
        "--input", "-i", required=True, help="Input file path"
    )
    decrypt_parser.add_argument(
        "--output", "-o", required=True, help="Output file path"
    )
    decrypt_parser.add_argument("--key", "-k", help="Key file path")
    decrypt_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing output file"
    )
    decrypt_parser.set_defaults(func=cmd_decrypt)

    # Generate key command
    genkey_parser = subparsers.add_parser("generate-key", help="Generate encryption key")
    genkey_parser.add_argument(
        "--algorithm",
        choices=["fernet", "aes"],
        default="fernet",
        help="Key algorithm (default: fernet)",
    )
    genkey_parser.add_argument(
        "--output", "-o", help="Output key file path (optional)"
    )
    genkey_parser.set_defaults(func=cmd_generate_key)

    # Generate keypair command
    genkp_parser = subparsers.add_parser(
        "generate-keypair", help="Generate RSA keypair"
    )
    genkp_parser.add_argument(
        "--output", "-o", required=True, help="Output key file prefix"
    )
    genkp_parser.set_defaults(func=cmd_generate_keypair)

    # Parse arguments
    args = parser.parse_args()

    # Execute command
    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
