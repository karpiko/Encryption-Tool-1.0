"""Unit tests for Fernet encryption."""

import unittest
import tempfile
import os
from pathlib import Path

from src.encryptors import FernetEncryptor


class TestFernetEncryptor(unittest.TestCase):
    """Test cases for Fernet encryption/decryption."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.key = FernetEncryptor.generate_key()

    def tearDown(self):
        """Clean up test files."""
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def test_key_generation(self):
        """Test that key generation produces valid key."""
        key = FernetEncryptor.generate_key()
        self.assertIsInstance(key, bytes)
        self.assertTrue(len(key) > 0)

    def test_key_save_and_load(self):
        """Test saving and loading keys."""
        key_path = os.path.join(self.temp_dir, "test.key")
        original_key = FernetEncryptor.generate_key()

        # Save key
        FernetEncryptor.save_key(original_key, key_path)
        self.assertTrue(os.path.exists(key_path))

        # Load key
        loaded_key = FernetEncryptor.load_key(key_path)
        self.assertEqual(original_key, loaded_key)

    def test_encrypt_decrypt_text(self):
        """Test encrypting and decrypting a text file."""
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        test_data = b"Hello, World! This is a test message."

        # Write test file
        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt
        FernetEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        self.assertTrue(os.path.exists(encrypted_path))

        # Verify encrypted file is different
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        self.assertNotEqual(test_data, encrypted_data)

        # Decrypt
        FernetEncryptor.decrypt_file(encrypted_path, output_path, self.key)
        self.assertTrue(os.path.exists(output_path))

        # Verify decrypted content matches original
        with open(output_path, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(test_data, decrypted_data)

    def test_encrypt_decrypt_binary(self):
        """Test encrypting and decrypting binary data."""
        input_path = os.path.join(self.temp_dir, "test.bin")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.bin")

        # Create binary test data
        test_data = bytes(range(256))

        # Write test file
        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt and decrypt
        FernetEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        FernetEncryptor.decrypt_file(encrypted_path, output_path, self.key)

        # Verify
        with open(output_path, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(test_data, decrypted_data)

    def test_decrypt_with_wrong_key(self):
        """Test that decryption fails with wrong key."""
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        test_data = b"Secret message"

        # Write and encrypt
        with open(input_path, "wb") as f:
            f.write(test_data)

        FernetEncryptor.encrypt_file(input_path, encrypted_path, self.key)

        # Try to decrypt with wrong key
        wrong_key = FernetEncryptor.generate_key()

        with self.assertRaises(ValueError):
            FernetEncryptor.decrypt_file(encrypted_path, output_path, wrong_key)

    def test_empty_file_encryption(self):
        """Test encrypting an empty file."""
        input_path = os.path.join(self.temp_dir, "empty.txt")
        encrypted_path = os.path.join(self.temp_dir, "empty.enc")
        output_path = os.path.join(self.temp_dir, "empty_decrypted.txt")

        # Create empty file
        open(input_path, "wb").close()

        # Encrypt and decrypt
        FernetEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        FernetEncryptor.decrypt_file(encrypted_path, output_path, self.key)

        # Verify empty file
        with open(output_path, "rb") as f:
            data = f.read()
        self.assertEqual(b"", data)

    def test_load_invalid_key(self):
        """Test loading invalid key raises error."""
        invalid_key_path = os.path.join(self.temp_dir, "invalid.key")

        with open(invalid_key_path, "wb") as f:
            f.write(b"not a valid key")

        with self.assertRaises(ValueError):
            FernetEncryptor.load_key(invalid_key_path)

    def test_encrypt_nonexistent_file(self):
        """Test encrypting nonexistent file raises error."""
        with self.assertRaises(FileNotFoundError):
            FernetEncryptor.encrypt_file(
                "/nonexistent/file.txt",
                "/tmp/out.enc",
                self.key
            )


if __name__ == "__main__":
    unittest.main()
