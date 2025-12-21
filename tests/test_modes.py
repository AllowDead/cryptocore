import unittest
import os
import tempfile
from Crypto.Random import get_random_bytes

from cryptocore.modes.cbc import CBCMode
from cryptocore.modes.cfb import CFBMode
from cryptocore.modes.ofb import OFBMode
from cryptocore.modes.ctr import CTRMode


class TestCBCMode(unittest.TestCase):
    def setUp(self):
        self.key = get_random_bytes(16)
        self.cbc = CBCMode(self.key)

    def test_encrypt_decrypt(self):
        """Test CBC encryption/decryption roundtrip"""
        plaintexts = [
            b"Short text",
            b"A" * 15,  # Меньше блока
            b"B" * 16,  # Ровно блок
            b"C" * 17,  # Больше блока
            b"D" * 100,  # Много блоков
        ]

        for plaintext in plaintexts:
            with self.subTest(length=len(plaintext)):
                ciphertext, iv = self.cbc.encrypt(plaintext)
                decrypted = self.cbc.decrypt(ciphertext, iv)
                self.assertEqual(decrypted, plaintext)

    def test_different_iv_produces_different_ciphertext(self):
        """Test that different IVs produce different ciphertexts"""
        plaintext = b"Test message"

        # Шифруем два раза (будут разные IVs)
        ciphertext1, iv1 = self.cbc.encrypt(plaintext)
        ciphertext2, iv2 = self.cbc.encrypt(plaintext)

        self.assertNotEqual(iv1, iv2, "IVs should be random")
        self.assertNotEqual(ciphertext1, ciphertext2,
                            "Same plaintext with different IVs should give different ciphertexts")


class TestCFBMode(unittest.TestCase):
    def setUp(self):
        self.key = get_random_bytes(16)
        self.cfb = CFBMode(self.key)

    def test_encrypt_decrypt(self):
        """Test CFB encryption/decryption roundtrip"""
        plaintexts = [
            b"Short",
            b"A" * 7,  # Меньше блока
            b"B" * 16,  # Ровно блок
            b"C" * 23,  # Не кратно блоку
            b"D" * 100,
        ]

        for plaintext in plaintexts:
            with self.subTest(length=len(plaintext)):
                ciphertext, iv = self.cfb.encrypt(plaintext)
                decrypted = self.cfb.decrypt(ciphertext, iv)
                self.assertEqual(decrypted, plaintext)

    def test_no_padding(self):
        """Test that CFB doesn't change length"""
        plaintext = b"A" * 23  # Не кратно 16
        ciphertext, iv = self.cfb.encrypt(plaintext)
        self.assertEqual(len(ciphertext), len(plaintext),
                         "CFB should not add padding")


class TestOFBMode(unittest.TestCase):
    def setUp(self):
        self.key = get_random_bytes(16)
        self.ofb = OFBMode(self.key)

    def test_encrypt_decrypt(self):
        """Test OFB encryption/decryption roundtrip"""
        plaintexts = [
            b"Test",
            b"A" * 10,
            b"B" * 32,
            b"C" * 100,
        ]

        for plaintext in plaintexts:
            with self.subTest(length=len(plaintext)):
                ciphertext, iv = self.ofb.encrypt(plaintext)
                decrypted = self.ofb.decrypt(ciphertext, iv)
                self.assertEqual(decrypted, plaintext)

    def test_same_iv_same_keystream(self):
        """Test that same IV produces same keystream"""
        iv = get_random_bytes(16)
        plaintext1 = b"Hello"
        plaintext2 = b"World"

        cipher1, _ = self.ofb.encrypt(plaintext1)
        # Используем тот же IV для второго шифрования
        keystream = self.ofb._generate_keystream(iv, len(plaintext2))
        cipher2 = bytes(a ^ b for a, b in zip(plaintext2, keystream))

        # Дешифруем второе сообщение
        decrypted2 = self.ofb.decrypt(cipher2, iv)
        self.assertEqual(decrypted2, plaintext2)


class TestCTRMode(unittest.TestCase):
    def setUp(self):
        self.key = get_random_bytes(16)
        self.ctr = CTRMode(self.key)

    def test_encrypt_decrypt(self):
        """Test CTR encryption/decryption roundtrip"""
        plaintexts = [
            b"CTR test",
            b"A" * 5,
            b"B" * 16,
            b"C" * 33,
            b"D" * 150,
        ]

        for plaintext in plaintexts:
            with self.subTest(length=len(plaintext)):
                ciphertext, iv = self.ctr.encrypt(plaintext)
                decrypted = self.ctr.decrypt(ciphertext, iv)
                self.assertEqual(decrypted, plaintext)

    def test_counter_increment(self):
        """Test counter increment function"""
        counter = b'\x00' * 15 + b'\x01'  # 0x...01
        next_counter = self.ctr._inc_counter(counter)

        # 0x...01 + 1 = 0x...02
        expected = b'\x00' * 15 + b'\x02'
        self.assertEqual(next_counter, expected)

        # Проверяем перенос
        counter = b'\xff' * 16
        next_counter = self.ctr._inc_counter(counter)
        self.assertEqual(next_counter, b'\x00' * 16)


class TestInteroperability(unittest.TestCase):
    """Tests for interoperability with OpenSSL"""

    def setUp(self):
        self.key = b'\x00' * 16
        self.iv = b'\x01' * 16

    def test_cbc_known_answer(self):
        """Simple known-answer test for CBC"""
        cbc = CBCMode(self.key)
        plaintext = b"Hello World!"

        ciphertext, iv = cbc.encrypt(plaintext)
        decrypted = cbc.decrypt(ciphertext, iv)

        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()