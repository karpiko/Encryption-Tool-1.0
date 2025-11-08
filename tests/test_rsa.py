"""Unit tests for RSA encryption."""

import unittest
import tempfile
import os

from src.encryptors import RSAEncryptor


class TestRSAEncryptor(unittest.TestCase):
    """Test cases for RSA encryption/decryption."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.private_key, self.public_key = RSAEncryptor.generate_key_pair()

    def tearDown(self):
        """Clean up test files."""
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def test_key_pair_generation(self):
        """Test that keypair generation produces valid keys."""
        private_key, public_key = RSAEncryptor.generate_key_pair()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_save_and_load_keys(self):
        """Test saving and loading RSA keys."""
        private_path = os.path.join(self.temp_dir, "private.pem")
        public_path = os.path.join(self.temp_dir, "public.pem")

        # Save keys
        RSAEncryptor.save_private_key(self.private_key, private_path)
        RSAEncryptor.save_public_key(self.public_key, public_path)

        # Verify files exist
        self.assertTrue(os.path.exists(private_path))
        self.assertTrue(os.path.exists(public_path))

        # Load keys
        loaded_private = RSAEncryptor.load_private_key(private_path)
        loaded_public = RSAEncryptor.load_public_key(public_path)

        self.assertIsNotNone(loaded_private)
        self.assertIsNotNone(loaded_public)

    def test_encrypt_decrypt_small_data(self):
        """Test encrypting and decrypting small data."""
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        # Small test data (RSA limited to ~190 bytes with 2048-bit key)
        test_data = b"Hello, RSA!"

        # Write test file
        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt with public key
        RSAEncryptor.encrypt_file(input_path, encrypted_path, self.public_key)
        self.assertTrue(os.path.exists(encrypted_path))

        # Verify encrypted data is different
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        self.assertNotEqual(test_data, encrypted_data)

        # Decrypt with private key
        RSAEncryptor.decrypt_file(encrypted_path, output_path, self.private_key)
        self.assertTrue(os.path.exists(output_path))

        # Verify decrypted content
        with open(output_path, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(test_data, decrypted_data)

    def test_max_size_limitation(self):
        """Test that large files raise error."""
        input_path = os.path.join(self.temp_dir, "large.txt")

        # Create a file larger than RSA max
        large_data = b"x" * 300  # Too large for RSA-2048

        with open(input_path, "wb") as f:
            f.write(large_data)

        encrypted_path = os.path.join(self.temp_dir, "large.enc")

        # Should raise ValueError
        with self.assertRaises(ValueError):
            RSAEncryptor.encrypt_file(input_path, encrypted_path, self.public_key)

    def test_decrypt_with_wrong_key(self):
        """Test that decryption fails with wrong key."""
        input_path = os.path.join(self.temp_dir, "test.txt")
        encrypted_path = os.path.join(self.temp_dir, "test.enc")
        output_path = os.path.join(self.temp_dir, "test_decrypted.txt")

        test_data = b"Secret RSA data"

        # Write and encrypt with first keypair
        with open(input_path, "wb") as f:
            f.write(test_data)

        RSAEncryptor.encrypt_file(input_path, encrypted_path, self.public_key)

        # Generate different keypair
        wrong_private, _ = RSAEncryptor.generate_key_pair()

        # Try to decrypt with wrong key - should fail
        with self.assertRaises(Exception):
            RSAEncryptor.decrypt_file(encrypted_path, output_path, wrong_private)

    def test_empty_file_encryption(self):
        """Test encrypting an empty file."""
        input_path = os.path.join(self.temp_dir, "empty.txt")
        encrypted_path = os.path.join(self.temp_dir, "empty.enc")
        output_path = os.path.join(self.temp_dir, "empty_decrypted.txt")

        # Create empty file
        open(input_path, "wb").close()

        # Encrypt and decrypt
        RSAEncryptor.encrypt_file(input_path, encrypted_path, self.public_key)
        RSAEncryptor.decrypt_file(encrypted_path, output_path, self.private_key)

        # Verify empty file
        with open(output_path, "rb") as f:
            data = f.read()
        self.assertEqual(b"", data)

    def test_save_private_key_with_password(self):
        """Test saving and loading encrypted private key."""
        private_path = os.path.join(self.temp_dir, "private_encrypted.pem")
        password = b"mypassword123"

        # Save with password
        RSAEncryptor.save_private_key(self.private_key, private_path, password)
        self.assertTrue(os.path.exists(private_path))

        # Load with correct password
        loaded_key = RSAEncryptor.load_private_key(private_path, password)
        self.assertIsNotNone(loaded_key)

        # Try to load with wrong password
        with self.assertRaises(ValueError):
            RSAEncryptor.load_private_key(private_path, b"wrongpassword")

    def test_load_invalid_key_file(self):
        """Test loading invalid key file raises error."""
        invalid_path = os.path.join(self.temp_dir, "invalid.pem")

        with open(invalid_path, "wb") as f:
            f.write(b"not a valid key")

        with self.assertRaises(ValueError):
            RSAEncryptor.load_private_key(invalid_path)

    def test_encrypt_nonexistent_file(self):
        """Test encrypting nonexistent file raises error."""
        with self.assertRaises(FileNotFoundError):
            RSAEncryptor.encrypt_file(
                "/nonexistent/file.txt",
                "/tmp/out.enc",
                self.public_key
            )


if __name__ == "__main__":
    unittest.main()
