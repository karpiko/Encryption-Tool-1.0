"""AES symmetric encryption implementation."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os


class AESEncryptor:
    """
    AES-256 symmetric encryption/decryption in CBC mode.

    AES (Advanced Encryption Standard):
    - Uses 256-bit key for AES-256
    - Operates in CBC (Cipher Block Chaining) mode
    - Uses PKCS7 padding for block alignment
    - Requires an Initialization Vector (IV) for each encryption
    """

    KEY_SIZE = 32  # 256 bits
    BLOCK_SIZE = 16  # 128 bits
    IV_SIZE = 16  # 128 bits

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new AES-256 encryption key.

        Returns:
            A new 256-bit AES key as bytes
        """
        return get_random_bytes(AESEncryptor.KEY_SIZE)

    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate a new Initialization Vector for CBC mode.

        Returns:
            A new 128-bit IV as bytes
        """
        return get_random_bytes(AESEncryptor.IV_SIZE)

    @staticmethod
    def save_key(key: bytes, filepath: str) -> None:
        """
        Save an AES key to a file.

        Args:
            key: The AES key to save (should be 32 bytes)
            filepath: Path where the key should be saved

        Raises:
            ValueError: If key size is invalid
            IOError: If key cannot be saved
        """
        if len(key) != AESEncryptor.KEY_SIZE:
            raise ValueError(
                f"Invalid key size. AES-256 requires {AESEncryptor.KEY_SIZE} bytes"
            )

        try:
            with open(filepath, "wb") as f:
                f.write(key)
        except IOError as e:
            raise IOError(f"Error saving key to {filepath}: {e}")

    @staticmethod
    def load_key(filepath: str) -> bytes:
        """
        Load an AES key from a file.

        Args:
            filepath: Path to the key file

        Returns:
            The loaded AES key (256 bits)

        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key size is invalid
        """
        try:
            with open(filepath, "rb") as f:
                key = f.read()

            if len(key) != AESEncryptor.KEY_SIZE:
                raise ValueError(
                    f"Invalid key size in {filepath}. "
                    f"Expected {AESEncryptor.KEY_SIZE} bytes, got {len(key)}"
                )

            return key
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file not found: {filepath}")

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
        """
        Encrypt a file using AES-256 in CBC mode.

        The encrypted file format:
        [IV (16 bytes)][Encrypted Data (padded)]

        Args:
            input_path: Path to the file to encrypt
            output_path: Path where encrypted file should be saved
            key: The AES-256 encryption key

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If key is invalid
            IOError: If file operations fail
        """
        if len(key) != AESEncryptor.KEY_SIZE:
            raise ValueError(f"Invalid key size. Expected {AESEncryptor.KEY_SIZE} bytes")

        try:
            # Read the input file
            with open(input_path, "rb") as f:
                plaintext = f.read()

            # Generate IV and create cipher
            iv = AESEncryptor.generate_iv()
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Pad plaintext and encrypt
            padded_plaintext = pad(plaintext, AESEncryptor.BLOCK_SIZE)
            ciphertext = cipher.encrypt(padded_plaintext)

            # Write IV + ciphertext to output file
            with open(output_path, "wb") as f:
                f.write(iv)
                f.write(ciphertext)

        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except Exception as e:
            raise IOError(f"Error during encryption: {e}")

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
        """
        Decrypt a file encrypted with AES-256 in CBC mode.

        Expects file format:
        [IV (16 bytes)][Encrypted Data (padded)]

        Args:
            input_path: Path to the encrypted file
            output_path: Path where decrypted file should be saved
            key: The AES-256 decryption key

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If key is invalid or decryption fails
            IOError: If file operations fail
        """
        if len(key) != AESEncryptor.KEY_SIZE:
            raise ValueError(f"Invalid key size. Expected {AESEncryptor.KEY_SIZE} bytes")

        try:
            # Read the encrypted file
            with open(input_path, "rb") as f:
                encrypted_data = f.read()

            # Extract IV and ciphertext
            if len(encrypted_data) < AESEncryptor.IV_SIZE:
                raise ValueError("Encrypted file is too small or corrupted")

            iv = encrypted_data[: AESEncryptor.IV_SIZE]
            ciphertext = encrypted_data[AESEncryptor.IV_SIZE :]

            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)

            # Unpad plaintext
            plaintext = unpad(padded_plaintext, AESEncryptor.BLOCK_SIZE)

            # Write decrypted data
            with open(output_path, "wb") as f:
                f.write(plaintext)

        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except ValueError as e:
            raise ValueError(f"Decryption failed. Invalid key or corrupted file: {e}")
        except Exception as e:
            raise IOError(f"Error during decryption: {e}")
