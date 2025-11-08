"""Unit tests for AES encryption."""

import unittest
import tempfile
import os

from src.encryptors import AESEncryptor


class TestAESEncryptor(unittest.TestCase):
    """Test cases for AES encryption/decryption."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.key = AESEncryptor.generate_key()

    def tearDown(self):
        """Clean up test files."""
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def test_key_generation(self):
        """Test that key generation produces valid AES-256 key."""
        key = AESEncryptor.generate_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # 256 bits

    def test_iv_generation(self):
        """Test that IV generation produces valid IV."""
        iv = AESEncryptor.generate_iv()
        self.assertIsInstance(iv, bytes)
        self.assertEqual(len(iv), 16)  # 128 bits

    def test_key_save_and_load(self):
        """Test saving and loading AES keys."""
        key_path = os.path.join(self.temp_dir, "aes.key")
        original_key = AESEncryptor.generate_key()

        # Save key
        AESEncryptor.save_key(original_key, key_path)
        self.assertTrue(os.path.exists(key_path))

        # Load key
        loaded_key = AESEncryptor.load_key(key_path)
        self.assertEqual(original_key, loaded_key)

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with self.assertRaises(ValueError):
            invalid_key = b"too short"
            AESEncryptor.save_key(invalid_key, "/tmp/test.key")

    def test_encrypt_decrypt_text(self):
        """Test encrypting and decrypting a text file."""
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        test_data = b"Hello, AES World! This is a secure message."

        # Write test file
        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt
        AESEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        self.assertTrue(os.path.exists(encrypted_path))

        # Verify IV is prepended (file should be at least 16 bytes longer)
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        self.assertGreater(len(encrypted_data), len(test_data))

        # Decrypt
        AESEncryptor.decrypt_file(encrypted_path, output_path, self.key)
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
        test_data = bytes(range(256)) * 10  # Larger binary data

        # Write test file
        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt and decrypt
        AESEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        AESEncryptor.decrypt_file(encrypted_path, output_path, self.key)

        # Verify
        with open(output_path, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(test_data, decrypted_data)

    def test_decrypt_with_wrong_key(self):
        """Test that decryption fails with wrong key."""
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        test_data = b"Secret AES message"

        # Write and encrypt
        with open(input_path, "wb") as f:
            f.write(test_data)

        AESEncryptor.encrypt_file(input_path, encrypted_path, self.key)

        # Try to decrypt with wrong key
        wrong_key = AESEncryptor.generate_key()

        with self.assertRaises(ValueError):
            AESEncryptor.decrypt_file(encrypted_path, output_path, wrong_key)

    def test_corrupted_file_decryption(self):
        """Test that decryption fails with corrupted file."""
        encrypted_path = os.path.join(self.temp_dir, "corrupted.enc")
        output_path = os.path.join(self.temp_dir, "output.txt")

        # Create a corrupted encrypted file (missing IV)
        with open(encrypted_path, "wb") as f:
            f.write(b"short")  # Too short to contain IV

        with self.assertRaises(ValueError):
            AESEncryptor.decrypt_file(encrypted_path, output_path, self.key)

    def test_large_file_encryption(self):
        """Test encrypting a large file."""
        input_path = os.path.join(self.temp_dir, "large.bin")
        encrypted_path = os.path.join(self.temp_dir, "large.enc")
        output_path = os.path.join(self.temp_dir, "large_decrypted.bin")

        # Create a 1MB file
        test_data = os.urandom(1024 * 1024)

        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt and decrypt
        AESEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        AESEncryptor.decrypt_file(encrypted_path, output_path, self.key)

        # Verify
        with open(output_path, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(test_data, decrypted_data)

    def test_empty_file_encryption(self):
        """Test encrypting an empty file."""
        input_path = os.path.join(self.temp_dir, "empty.txt")
        encrypted_path = os.path.join(self.temp_dir, "empty.enc")
        output_path = os.path.join(self.temp_dir, "empty_decrypted.txt")

        # Create empty file
        open(input_path, "wb").close()

        # Encrypt and decrypt
        AESEncryptor.encrypt_file(input_path, encrypted_path, self.key)
        AESEncryptor.decrypt_file(encrypted_path, output_path, self.key)

        # Verify empty file
        with open(output_path, "rb") as f:
            data = f.read()
        self.assertEqual(b"", data)

    def test_encrypt_nonexistent_file(self):
        """Test encrypting nonexistent file raises error."""
        with self.assertRaises(FileNotFoundError):
            AESEncryptor.encrypt_file(
                "/nonexistent/file.txt",
                "/tmp/out.enc",
                self.key
            )

    def test_load_invalid_key(self):
        """Test loading invalid key raises error."""
        invalid_key_path = os.path.join(self.temp_dir, "invalid.key")

        # Save wrong size key
        with open(invalid_key_path, "wb") as f:
            f.write(b"short key")

        with self.assertRaises(ValueError):
            AESEncryptor.load_key(invalid_key_path)


if __name__ == "__main__":
    unittest.main()
