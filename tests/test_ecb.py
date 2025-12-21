import unittest
import os
import tempfile
import sys
# Добавляем путь к src в sys.path для импортов
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptocore.modes.ecb import ECBMode
from cryptocore.file_io import read_file, write_file

from Crypto.Random import get_random_bytes


class TestECBMode(unittest.TestCase):
    def setUp(self):
        self.key = get_random_bytes(16)
        self.ecb = ECBMode(self.key)

    def test_padding_unpadding(self):
        """Test PKCS#7 padding and unpadding"""
        # Test with different data lengths
        test_data = [
            b"",  # Empty data
            b"A" * 1,
            b"B" * 15,
            b"C" * 16,
            b"D" * 17,
            b"E" * 31,
        ]

        for data in test_data:
            padded = self.ecb._pad(data)
            # Check padding length is multiple of 16
            self.assertEqual(len(padded) % 16, 0)

            unpadded = self.ecb._unpad(padded)
            self.assertEqual(unpadded, data)

    def test_encrypt_decrypt(self):
        """Test encryption and decryption roundtrip"""
        test_plaintexts = [
            b"Hello, World!",
            b"A" * 50,  # More than one block
            b"B" * 16,  # Exactly one block
            b"C" * 32,  # Exactly two blocks
            get_random_bytes(100),  # Random data
        ]

        for plaintext in test_plaintexts:
            ciphertext = self.ecb.encrypt(plaintext)
            decrypted = self.ecb.decrypt(ciphertext)

            self.assertEqual(decrypted, plaintext)

    def test_invalid_key_length(self):
        """Test with invalid key length"""
        with self.assertRaises(ValueError):
            ECBMode(b"short")

    def test_invalid_ciphertext_length(self):
        """Test decryption with invalid ciphertext length"""
        with self.assertRaises(ValueError):
            self.ecb.decrypt(b"not multiple of 16")


class TestFileIO(unittest.TestCase):
    def test_read_write(self):
        """Test file reading and writing"""
        test_data = b"Test file content"

        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_file = f.name

        try:
            # Write data
            write_file(test_file, test_data)

            # Read data back
            read_data = read_file(test_file)

            self.assertEqual(read_data, test_data)
        finally:
            os.unlink(test_file)


if __name__ == "__main__":
    unittest.main()