# tests/test_hmac.py
"""
Tests for HMAC implementation.
"""

import unittest
import os
import tempfile
from cryptocore.mac.hmac import HMAC


class TestHMAC(unittest.TestCase):
    """Test cases for HMAC implementation."""

    def setUp(self):
        """Set up test data."""
        self.test_message = b"Hello, world!"
        self.test_key = "00112233445566778899aabbccddeeff"

        # Create temporary file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        self.temp_file.write(self.test_message)
        self.temp_file.close()

    def tearDown(self):
        """Clean up test data."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_hmac_creation(self):
        """Test HMAC object creation."""
        hmac = HMAC(self.test_key)
        self.assertIsNotNone(hmac)

    def test_hmac_compute_bytes(self):
        """Test HMAC computation with bytes output."""
        hmac = HMAC(self.test_key)
        result = hmac.compute(self.test_message)

        # Should return 32 bytes for SHA-256
        self.assertEqual(len(result), 32)
        self.assertIsInstance(result, bytes)

    def test_hmac_compute_hex(self):
        """Test HMAC computation with hex output."""
        hmac = HMAC(self.test_key)
        result = hmac.compute_hex(self.test_message)

        # Should return 64 hex characters
        self.assertEqual(len(result), 64)
        self.assertIsInstance(result, str)
        # Should be valid hex
        int(result, 16)  # Will raise ValueError if not valid hex

    def test_hmac_verification_success(self):
        """Test successful HMAC verification."""
        hmac = HMAC(self.test_key)
        computed = hmac.compute(self.test_message)

        # Should verify successfully
        self.assertTrue(hmac.verify(self.test_message, computed))
        self.assertTrue(hmac.verify(self.test_message, computed.hex()))

    def test_hmac_verification_failure(self):
        """Test failed HMAC verification."""
        hmac = HMAC(self.test_key)
        computed = hmac.compute(self.test_message)

        # Different message should fail
        different_message = b"Hello, world?"
        self.assertFalse(hmac.verify(different_message, computed))

        # Different key should fail
        different_key = "ffeeddccbbaa99887766554433221100"
        hmac2 = HMAC(different_key)
        computed2 = hmac2.compute(self.test_message)
        self.assertFalse(hmac.verify(self.test_message, computed2))

    def test_hmac_with_different_key_lengths(self):
        """Test HMAC with various key lengths."""
        test_cases = [
            ("01" * 8, "Short key (16 bytes)"),
            ("01" * 32, "Key equal to block size (64 bytes)"),
            ("01" * 50, "Key longer than block size (100 bytes)"),
        ]

        for key_hex, description in test_cases:
            with self.subTest(description=description):
                hmac = HMAC(key_hex)
                result = hmac.compute(self.test_message)
                self.assertEqual(len(result), 32)

    def test_rfc_4231_test_vector_1(self):
        """Test HMAC with RFC 4231 test vector 1."""
        # Test Case 1: Key = 20 bytes of 0x0b
        key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"  # 20 bytes of 0x0b
        data = b"Hi There"
        expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)
        self.assertEqual(result, expected)

    def test_rfc_4231_test_vector_2(self):
        """Test HMAC with RFC 4231 test vector 2."""
        # Test Case 2: Key = "Jefe"
        key = "4a656665"  # "Jefe" in hex
        data = b"what do ya want for nothing?"
        # CORRECTED expected value:
        expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)
        self.assertEqual(result, expected)

    def test_rfc_4231_test_vector_3(self):
        """Test HMAC with RFC 4231 test vector 3."""
        # Test Case 3: Key = 20 bytes of 0xaa
        key = "aa" * 20  # 20 bytes of 0xaa
        data = bytes.fromhex("dd" * 50)  # 50 bytes of 0xdd
        expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"

        hmac = HMAC(key)
        result = hmac.compute_hex(data)
        self.assertEqual(result, expected)

    def test_empty_file_hmac(self):
        """Test HMAC computation for empty file."""
        # Create empty file
        empty_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        empty_file.close()

        try:
            # Create HMAC
            hmac = HMAC(self.test_key)

            # Read empty file
            with open(empty_file.name, 'rb') as f:
                file_data = f.read()

            # Compute HMAC
            result = hmac.compute_hex(file_data)

            # Should return valid HMAC
            self.assertEqual(len(result), 64)

        finally:
            os.unlink(empty_file.name)

    def test_cli_hmac_computation(self):
        """Test HMAC computation via command line simulation."""
        # This is a simulation of CLI usage
        from cryptocore.hash_handler import compute_hash

        result = compute_hash(
            algorithm='sha256',
            input_file=self.temp_file.name,
            hmac_key=self.test_key
        )

        # Should return "HMAC_VALUE  FILENAME"
        parts = result.split()
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[1], self.temp_file.name)
        self.assertEqual(len(parts[0]), 64)  # 64 hex chars

    def test_cli_hmac_verification(self):
        """Test HMAC verification via command line simulation."""
        from cryptocore.hash_handler import compute_hash, verify_hmac

        # First compute HMAC
        hmac_result = compute_hash(
            algorithm='sha256',
            input_file=self.temp_file.name,
            hmac_key=self.test_key
        )

        # Write HMAC to file
        hmac_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        hmac_file.write(hmac_result + '\n')
        hmac_file.close()

        try:
            # Verify should succeed
            success = verify_hmac(
                algorithm='sha256',
                input_file=self.temp_file.name,
                hmac_key=self.test_key,
                hmac_file=hmac_file.name
            )
            self.assertTrue(success)

            # Modify file
            with open(self.temp_file.name, 'wb') as f:
                f.write(b"Modified content")

            # Verify should fail
            success = verify_hmac(
                algorithm='sha256',
                input_file=self.temp_file.name,
                hmac_key=self.test_key,
                hmac_file=hmac_file.name
            )
            self.assertFalse(success)

        finally:
            os.unlink(hmac_file.name)


if __name__ == '__main__':
    unittest.main()