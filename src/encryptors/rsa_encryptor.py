"""RSA asymmetric encryption implementation."""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os


class RSAEncryptor:
    """
    RSA asymmetric encryption/decryption.

    RSA (Rivest-Shamir-Adleman):
    - Uses public/private key pairs
    - Encrypts with public key, decrypts with private key
    - Uses OAEP padding for security
    - Limited to small amounts of data per encryption
    - Better for encrypting keys than large files
    """

    KEY_SIZE = 2048  # 2048-bit RSA key (good balance of security and performance)

    @staticmethod
    def generate_key_pair() -> tuple:
        """
        Generate a new RSA key pair.

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSAEncryptor.KEY_SIZE,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def save_private_key(private_key, filepath: str, password: bytes = None) -> None:
        """
        Save a private key to a file.

        Args:
            private_key: The private key object
            filepath: Path where the key should be saved
            password: Optional password to encrypt the private key

        Raises:
            IOError: If key cannot be saved
        """
        try:
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()

            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )

            with open(filepath, "wb") as f:
                f.write(pem)
        except IOError as e:
            raise IOError(f"Error saving private key to {filepath}: {e}")

    @staticmethod
    def save_public_key(public_key, filepath: str) -> None:
        """
        Save a public key to a file.

        Args:
            public_key: The public key object
            filepath: Path where the key should be saved

        Raises:
            IOError: If key cannot be saved
        """
        try:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            with open(filepath, "wb") as f:
                f.write(pem)
        except IOError as e:
            raise IOError(f"Error saving public key to {filepath}: {e}")

    @staticmethod
    def load_private_key(filepath: str, password: bytes = None):
        """
        Load a private key from a file.

        Args:
            filepath: Path to the private key file
            password: Password if key is encrypted

        Returns:
            The loaded private key

        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key is invalid or password is wrong
        """
        try:
            with open(filepath, "rb") as f:
                pem = f.read()

            try:
                private_key = serialization.load_pem_private_key(
                    pem, password=password, backend=default_backend()
                )
                return private_key
            except ValueError as e:
                raise ValueError(f"Invalid private key or wrong password: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Private key file not found: {filepath}")

    @staticmethod
    def load_public_key(filepath: str):
        """
        Load a public key from a file.

        Args:
            filepath: Path to the public key file

        Returns:
            The loaded public key

        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key is invalid
        """
        try:
            with open(filepath, "rb") as f:
                pem = f.read()

            try:
                public_key = serialization.load_pem_public_key(
                    pem, backend=default_backend()
                )
                return public_key
            except ValueError as e:
                raise ValueError(f"Invalid public key: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Public key file not found: {filepath}")

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, public_key) -> None:
        """
        Encrypt a file using RSA public key.

        Note: RSA can only encrypt data smaller than the key size.
        For files larger than ~190 bytes (with 2048-bit key), consider:
        1. Using hybrid encryption (RSA for key, AES for data)
        2. Encrypting in chunks
        3. Using a different algorithm

        Args:
            input_path: Path to the file to encrypt
            output_path: Path where encrypted file should be saved
            public_key: The RSA public key

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If file is too large for RSA
            IOError: If file operations fail
        """
        try:
            # Read the input file
            with open(input_path, "rb") as f:
                plaintext = f.read()

            # RSA can only encrypt limited data
            max_size = (RSAEncryptor.KEY_SIZE // 8) - 42  # OAEP overhead
            if len(plaintext) > max_size:
                raise ValueError(
                    f"File too large for direct RSA encryption. "
                    f"Max size: {max_size} bytes. "
                    f"File size: {len(plaintext)} bytes. "
                    f"Consider using AES or Fernet for large files."
                )

            # Encrypt using OAEP padding
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Write encrypted data
            with open(output_path, "wb") as f:
                f.write(ciphertext)

        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except Exception as e:
            raise IOError(f"Error during encryption: {e}")

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, private_key) -> None:
        """
        Decrypt a file using RSA private key.

        Args:
            input_path: Path to the encrypted file
            output_path: Path where decrypted file should be saved
            private_key: The RSA private key

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If decryption fails
            IOError: If file operations fail
        """
        try:
            # Read the encrypted file
            with open(input_path, "rb") as f:
                ciphertext = f.read()

            # Decrypt using OAEP padding
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Write decrypted data
            with open(output_path, "wb") as f:
                f.write(plaintext)

        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except Exception as e:
            raise ValueError(f"Decryption failed. Invalid key or corrupted file: {e}")
