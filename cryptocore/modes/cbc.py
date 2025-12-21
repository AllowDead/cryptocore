from Crypto.Cipher import AES
from cryptocore.csprng import generate_random_bytes
import os


class CBCMode:
    """Cipher Block Chaining (CBC) mode"""

    def __init__(self, key):
        """Initialize CBC mode with given key"""
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key

    def _pad(self, data):
        """PKCS#7 padding"""
        padding_len = 16 - (len(data) % 16)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def _unpad(self, data):
        """Remove PKCS#7 padding"""
        if len(data) == 0:
            raise ValueError("Data is empty")

        padding_len = data[-1]

        if padding_len < 1 or padding_len > 16:
            raise ValueError("Invalid padding")

        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding")

        return data[:-padding_len]

    def encrypt(self, plaintext):
        """Encrypt data using AES-CBC mode"""
        # Генерируем случайный IV
        iv = generate_random_bytes(16)

        # Добавляем padding (CBC требует padding)
        padded_data = self._pad(plaintext)

        ciphertext = b""
        prev_block = iv

        # Шифруем по блокам
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]

            # XOR с предыдущим блоком (или IV для первого)
            block_xor = bytes(a ^ b for a, b in zip(block, prev_block))

            # Шифруем
            cipher = AES.new(self.key, AES.MODE_ECB)
            encrypted_block = cipher.encrypt(block_xor)

            ciphertext += encrypted_block
            prev_block = encrypted_block

        return ciphertext, iv

    def decrypt(self, ciphertext, iv):
        """Decrypt data using AES-CBC mode"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16 bytes")

        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        plaintext = b""
        prev_block = iv

        # Дешифруем по блокам
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]

            # Дешифруем
            cipher = AES.new(self.key, AES.MODE_ECB)
            decrypted_block = cipher.decrypt(block)

            # XOR с предыдущим блоком
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plaintext += plain_block

            prev_block = block

        # Удаляем padding
        unpadded_plaintext = self._unpad(plaintext)

        return unpadded_plaintext