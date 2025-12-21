from Crypto.Cipher import AES
import struct


class ECBMode:
    def __init__(self, key):
        """Initialize ECB mode with given key"""
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

        # Проверка корректности padding
        if padding_len < 1 or padding_len > 16:
            raise ValueError("Invalid padding")

        # Проверка что все байты padding одинаковы
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding")

        return data[:-padding_len]

    def encrypt(self, plaintext):
        """Encrypt data using AES-ECB mode"""
        # Добавляем padding
        padded_data = self._pad(plaintext)

        # Создаем шифр
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Шифруем по блокам
        ciphertext = cipher.encrypt(padded_data)

        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt data using AES-ECB mode"""
        # Проверяем что размер данных кратен размеру блока
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16 bytes")

        # Создаем шифр
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Расшифровываем
        padded_plaintext = cipher.decrypt(ciphertext)

        # Удаляем padding
        plaintext = self._unpad(padded_plaintext)

        return plaintext