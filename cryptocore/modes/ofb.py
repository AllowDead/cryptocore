from Crypto.Cipher import AES
from cryptocore.csprng import generate_random_bytes
import os


class OFBMode:
    """Output Feedback (OFB) mode - stream cipher"""

    def __init__(self, key):
        """Initialize OFB mode with given key"""
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key

    def _generate_keystream(self, iv, length):
        """Generate keystream of given length"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        keystream = b""
        feedback = iv

        # Генерируем пока не получим нужную длину
        while len(keystream) < length:
            encrypted = cipher.encrypt(feedback)
            keystream += encrypted
            feedback = encrypted

        return keystream[:length]

    def encrypt(self, plaintext):
        """Encrypt data using AES-OFB mode (no padding needed)"""
        # Генерируем случайный IV
        iv = generate_random_bytes(16)

        # Генерируем keystream
        keystream = self._generate_keystream(iv, len(plaintext))

        # XOR с plaintext
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

        return ciphertext, iv

    def decrypt(self, ciphertext, iv):
        """Decrypt data using AES-OFB mode (симметрично шифрованию)"""
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        # Генерируем тот же keystream
        keystream = self._generate_keystream(iv, len(ciphertext))

        # XOR с ciphertext (OFB симметричен)
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

        return plaintext