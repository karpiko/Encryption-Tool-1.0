"""Fernet symmetric encryption implementation."""

from cryptography.fernet import Fernet
import os


class FernetEncryptor:
    """
    Fernet symmetric encryption/decryption.

    Fernet is a symmetric encryption method that:
    - Uses AES-128 in CBC mode under the hood
    - Provides authentication (HMAC)
    - Is simple and secure for file encryption
    """

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new Fernet encryption key.

        Returns:
            A new Fernet key as bytes
        """
        return Fernet.generate_key()

    @staticmethod
    def save_key(key: bytes, filepath: str) -> None:
        """
        Save a Fernet key to a file.

        Args:
            key: The Fernet key to save
            filepath: Path where the key should be saved

        Raises:
            IOError: If key cannot be saved
        """
        try:
            with open(filepath, "wb") as f:
                f.write(key)
        except IOError as e:
            raise IOError(f"Error saving key to {filepath}: {e}")

    @staticmethod
    def load_key(filepath: str) -> bytes:
        """
        Load a Fernet key from a file.

        Args:
            filepath: Path to the key file

        Returns:
            The loaded Fernet key

        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key is invalid
        """
        try:
            with open(filepath, "rb") as f:
                key = f.read()

            # Validate the key format
            try:
                Fernet(key)
            except Exception:
                raise ValueError(
                    f"Invalid Fernet key in {filepath}. "
                    "Key must be a valid Fernet key."
                )

            return key
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file not found: {filepath}")

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
        """
        Encrypt a file using Fernet.

        Args:
            input_path: Path to the file to encrypt
            output_path: Path where encrypted file should be saved
            key: The Fernet encryption key

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If key is invalid
            IOError: If file operations fail
        """
        try:
            # Read the input file
            with open(input_path, "rb") as f:
                plaintext = f.read()

            # Create cipher and encrypt
            cipher = Fernet(key)
            ciphertext = cipher.encrypt(plaintext)

            # Write encrypted data
            with open(output_path, "wb") as f:
                f.write(ciphertext)

        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except Exception as e:
            raise IOError(f"Error during encryption: {e}")

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
        """
        Decrypt a file using Fernet.

        Args:
            input_path: Path to the encrypted file
            output_path: Path where decrypted file should be saved
            key: The Fernet decryption key

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If key is invalid or decryption fails
            IOError: If file operations fail
        """
        try:
            # Read the encrypted file
            with open(input_path, "rb") as f:
                ciphertext = f.read()

            # Create cipher and decrypt
            cipher = Fernet(key)
            plaintext = cipher.decrypt(ciphertext)

            # Write decrypted data
            with open(output_path, "wb") as f:
                f.write(plaintext)

        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except Exception as e:
            raise ValueError(f"Decryption failed. Invalid key or corrupted file: {e}")
