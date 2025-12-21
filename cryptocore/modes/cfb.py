from Crypto.Cipher import AES
from cryptocore.csprng import generate_random_bytes
import os


class CFBMode:
    """Cipher Feedback (CFB) mode - stream cipher"""

    def __init__(self, key):
        """Initialize CFB mode with given key"""
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key

    def encrypt(self, plaintext):
        """Encrypt data using AES-CFB mode (no padding needed)"""
        # Генерируем случайный IV
        iv = generate_random_bytes(16)

        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = b""
        feedback = iv

        # CFB как stream cipher
        for i in range(0, len(plaintext), 16):
            # Шифруем feedback
            encrypted_feedback = cipher.encrypt(feedback)

            # Берем столько байт, сколько нужно
            block = plaintext[i:i + 16]
            keystream = encrypted_feedback[:len(block)]

            # XOR с plaintext
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext += cipher_block

            # Обновляем feedback (в CFB8 это было бы по-другому)
            # В CFB-128 (полный блок) feedback = cipher_block
            feedback = cipher_block.ljust(16, b'\x00')  # Pad если блок неполный

        return ciphertext, iv

    def decrypt(self, ciphertext, iv):
        """Decrypt data using AES-CFB mode"""
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = b""
        feedback = iv

        # Дешифровка CFB симметрична шифрованию
        for i in range(0, len(ciphertext), 16):
            # Шифруем feedback
            encrypted_feedback = cipher.encrypt(feedback)

            # Берем столько байт, сколько нужно
            block = ciphertext[i:i + 16]
            keystream = encrypted_feedback[:len(block)]

            # XOR с ciphertext
            plain_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext += plain_block

            # Обновляем feedback
            feedback = block.ljust(16, b'\x00')

        return plaintext