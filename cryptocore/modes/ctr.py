from Crypto.Cipher import AES
from cryptocore.csprng import generate_random_bytes
import os
import struct


class CTRMode:
    """Counter (CTR) mode - stream cipher"""

    def __init__(self, key):
        """Initialize CTR mode with given key"""
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key

    def _inc_counter(self, counter):
        """Increment 128-bit counter (big-endian) with overflow handling"""
        # Преобразуем байты в список для ручного инкремента
        counter_list = list(counter)

        # Инкрементируем с конца (младший байт)
        for i in range(15, -1, -1):
            if counter_list[i] < 0xFF:
                counter_list[i] += 1
                break
            else:
                counter_list[i] = 0
                # Продолжаем перенос

        return bytes(counter_list)

    def encrypt(self, plaintext):
        """Encrypt data using AES-CTR mode (no padding needed)"""
        # Генерируем случайный nonce/IV (первые 8 байт), остальное - нули
        nonce = generate_random_bytes(8)
        counter = nonce + b'\x00' * 8  # 16-байтный счетчик

        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = b""
        current_counter = counter

        # Шифруем по блокам
        for i in range(0, len(plaintext), 16):
            # Шифруем текущее значение счетчика
            keystream_block = cipher.encrypt(current_counter)

            # Берем столько байт, сколько нужно
            block = plaintext[i:i + 16]
            keystream = keystream_block[:len(block)]

            # XOR с plaintext
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext += cipher_block

            # Инкрементируем счетчик
            current_counter = self._inc_counter(current_counter)

        # В CTR IV = nonce (первые 8 байт счетчика)
        return ciphertext, counter

    def decrypt(self, ciphertext, iv):
        """Decrypt data using AES-CTR mode (симметрично шифрованию)"""
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = b""
        current_counter = iv

        # Дешифровка CTR симметрична шифрованию
        for i in range(0, len(ciphertext), 16):
            # Шифруем текущее значение счетчика
            keystream_block = cipher.encrypt(current_counter)

            # Берем столько байт, сколько нужно
            block = ciphertext[i:i + 16]
            keystream = keystream_block[:len(block)]

            # XOR с ciphertext
            plain_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext += plain_block

            # Инкрементируем счетчик
            current_counter = self._inc_counter(current_counter)

        return plaintext

    def encrypt_with_iv(self, plaintext, iv):
        """Шифрование с указанным IV"""
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        # Используем ECB для шифрования счетчика
        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = b""
        current_counter = iv  # Используем предоставленный IV как начальный счетчик

        # Шифруем по блокам
        for i in range(0, len(plaintext), 16):
            # Шифруем текущее значение счетчика
            keystream_block = cipher.encrypt(current_counter)

            # Берем столько байт, сколько нужно
            block = plaintext[i:i + 16]
            keystream = keystream_block[:len(block)]

            # XOR с plaintext
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext += cipher_block

            # Инкрементируем счетчик
            current_counter = self._inc_counter(current_counter)

        return ciphertext  # Только ciphertext, без IV

    def decrypt_with_iv(self, ciphertext, iv):
        """Дешифрование с указанным IV"""
        # Устанавливаем IV
        self.iv = iv

        # Вызываем обычный decrypt
        plaintext = self.decrypt(ciphertext, iv)

        return plaintext