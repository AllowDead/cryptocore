import os
from typing import Tuple
from Crypto.Cipher import AES


class GCM:
    """Реализация режима GCM (Galois/Counter Mode) по NIST SP 800-38D"""

    def __init__(self, key: bytes, nonce: bytes = None):
        self.key = key
        self.nonce = nonce or os.urandom(12)

        # Создаем начальное значение для счетчика
        if len(self.nonce) == 12:
            # Для 12-байтового nonce: J0 = nonce || [0,0,0,1]
            self.j0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            # Для других размеров: GHASH(nonce || zeros)
            raise ValueError("Only 12-byte nonce is implemented")

        # Инициализируем AES шифр
        self.aes_cipher = AES.new(self.key, AES.MODE_ECB)

        # Предвычисляем H = E_K(0^128)
        self.H = self._aes_encrypt(bytes(16))
        self.H_int = int.from_bytes(self.H, 'big')

    def _aes_encrypt(self, data: bytes) -> bytes:
        """Шифрование одного блока AES"""
        if len(data) != 16:
            raise ValueError("Block must be 16 bytes")
        return self.aes_cipher.encrypt(data)

    def _mult_gf(self, x: int, y: int) -> int:
        """Умножение в GF(2^128) по полиному x^128 + x^7 + x^2 + x + 1"""
        z = 0
        v = y

        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1

        return z

    def _ghash(self, auth_data: bytes, ciphertext: bytes) -> int:
        """Вычисление GHASH"""

        # Подготовка данных
        def pad_to_16(data):
            if len(data) % 16 != 0:
                return data + bytes(16 - len(data) % 16)
            return data

        # Конкатенация: auth_data || ciphertext || len(auth_data) || len(ciphertext)
        data = pad_to_16(auth_data) + pad_to_16(ciphertext)

        # Добавляем длины (64 бита каждая)
        len_auth = len(auth_data) * 8
        len_cipher = len(ciphertext) * 8
        data += len_auth.to_bytes(8, 'big') + len_cipher.to_bytes(8, 'big')

        # GHASH вычисление
        y = 0
        for i in range(0, len(data), 16):
            block = int.from_bytes(data[i:i + 16], 'big')
            y ^= block
            y = self._mult_gf(y, self.H_int)

        return y

    def _generate_keystream(self, length: int) -> bytes:
        """Генерация keystream в режиме CTR"""
        keystream = b''
        counter = 2  # Начинаем с 2, так как 1 используется для J0

        while len(keystream) < length:
            # Создаем счетчик: J0 + counter
            ctr = (int.from_bytes(self.j0, 'big') + counter) & ((1 << 128) - 1)
            ctr_bytes = ctr.to_bytes(16, 'big')

            # Шифруем счетчик
            keystream_block = self._aes_encrypt(ctr_bytes)
            keystream += keystream_block

            counter += 1

        return keystream[:length]

    def _ctr_crypt(self, ciphertext: bytes, initial_counter: bytes) -> bytes:
        """Шифрование/дешифрование в режиме CTR"""
        keystream = self._generate_keystream(len(ciphertext))
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        return plaintext

    def _derive_counter0(self) -> bytes:
        """Получить начальное значение счетчика (J0)"""
        return self.j0

    def _compute_tag(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Вычисление аутентификационного тега (дублирует логику из encrypt)"""
        # Вычисление GHASH
        s = self._ghash(aad, ciphertext)

        # T = MSB_t(GCTR_K(J0, S))
        tag_input = self._aes_encrypt(self.j0)
        tag_input_int = int.from_bytes(tag_input, 'big')
        tag_int = s ^ tag_input_int

        # Обрезаем до 16 байт
        tag = tag_int.to_bytes(16, 'big')
        return tag

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Шифрование с аутентификацией"""
        # Генерация keystream
        keystream = self._generate_keystream(len(plaintext))

        # XOR для шифрования
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

        # Вычисление аутентификационного тега
        s = self._ghash(aad, ciphertext)

        # T = MSB_t(GCTR_K(J0, S))
        tag_input = self._aes_encrypt(self.j0)
        tag_input_int = int.from_bytes(tag_input, 'big')
        tag_int = s ^ tag_input_int

        # Обрезаем до 16 байт
        tag = tag_int.to_bytes(16, 'big')

        return self.nonce + ciphertext + tag

    def decrypt(self, data, aad=b""):
        """Дешифрование с проверкой аутентификации"""
        # Проверяем минимальную длину (nonce + ciphertext + tag)
        if len(data) < 12 + 16:  # 12 bytes nonce + 16 bytes tag
            raise ValueError("Data too short for GCM")

        # Извлекаем nonce (первые 12 байт)
        nonce = data[:12]
        # Обновляем nonce и j0 для дешифрования
        self.nonce = nonce
        self.j0 = nonce + b'\x00\x00\x00\x01'

        # Извлекаем tag (последние 16 байт) и ciphertext
        tag_received = data[-16:]
        ciphertext = data[12:-16]

        # Вычисляем ожидаемый тег
        tag_computed = self._compute_tag(ciphertext, aad)

        # Сравниваем теги
        if tag_received != tag_computed:
            return b"", False

        # Расшифровываем
        plaintext = self._ctr_crypt(ciphertext, self.j0)

        return plaintext, True


class AuthenticationError(Exception):
    """Исключение для ошибок аутентификации"""
    pass