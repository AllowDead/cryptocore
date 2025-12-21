# cryptocore/hash/sha256.py

import struct
import numpy as np


class SHA256:
    """Реализация SHA-256 с нуля согласно FIPS 180-4"""

    def __init__(self):
        # Инициализация хэш-значений (первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
        self.h0 = 0x6a09e667
        self.h1 = 0xbb67ae85
        self.h2 = 0x3c6ef372
        self.h3 = 0xa54ff53a
        self.h4 = 0x510e527f
        self.h5 = 0x9b05688c
        self.h6 = 0x1f83d9ab
        self.h7 = 0x5be0cd19

        # Константы раундов (первые 32 бита дробных частей кубических корней первых 64 простых чисел)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        self.data = bytearray()
        self.total_bits = 0

    def _rotr(self, x, n):
        """Циклический сдвиг вправо"""
        return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

    def _shr(self, x, n):
        """Логический сдвиг вправо"""
        return x >> n

    def _ch(self, x, y, z):
        """Choice function"""
        return (x & y) ^ (~x & z)

    def _maj(self, x, y, z):
        """Majority function"""
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x):
        """Σ0 function"""
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)

    def _sigma1(self, x):
        """Σ1 function"""
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)

    def _gamma0(self, x):
        """σ0 function"""
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ self._shr(x, 3)

    def _gamma1(self, x):
        """σ1 function"""
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ self._shr(x, 10)

    def _padding(self):
        """Добавление padding согласно стандарту SHA-256"""
        message = self.data

        # Добавляем бит '1' (0x80)
        message.append(0x80)

        # Добавляем нули пока длина не станет ≡ 56 mod 64
        while (len(message) % 64) != 56:
            message.append(0x00)

        # Добавляем длину исходного сообщения в БИТАХ (64 бита, big-endian)
        # self.total_bits - это количество БАЙТОВ
        message_length_bits = self.total_bits * 8  # ← Правильно: байты → биты
        message += struct.pack('>Q', message_length_bits)

        return message

    def _process_block(self, block):
        """Обработка одного 512-битного блока"""
        # Инициализация рабочего массива w
        w = [0] * 64

        # Разбиваем блок на 16 слов по 32 бита
        for i in range(16):
            w[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

        # Расширяем до 64 слов
        for i in range(16, 64):
            s0 = self._gamma0(w[i - 15])
            s1 = self._gamma1(w[i - 2])
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        # Инициализация рабочих переменных
        a, b, c, d, e, f, g, h = self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7

        # Основной цикл сжатия
        for i in range(64):
            S1 = self._sigma1(e)
            ch = self._ch(e, f, g)
            temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            S0 = self._sigma0(a)
            maj = self._maj(a, b, c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Добавляем сжатый блок к текущему хэшу
        self.h0 = (self.h0 + a) & 0xFFFFFFFF
        self.h1 = (self.h1 + b) & 0xFFFFFFFF
        self.h2 = (self.h2 + c) & 0xFFFFFFFF
        self.h3 = (self.h3 + d) & 0xFFFFFFFF
        self.h4 = (self.h4 + e) & 0xFFFFFFFF
        self.h5 = (self.h5 + f) & 0xFFFFFFFF
        self.h6 = (self.h6 + g) & 0xFFFFFFFF
        self.h7 = (self.h7 + h) & 0xFFFFFFFF

    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.data.extend(data)
        self.total_bits += len(data)

    def digest(self):
        """Возвращает итоговый хэш в виде байтов"""
        # Создаем копию для padding
        padded_data = self._padding()

        # Обрабатываем блоки по 64 байта
        for i in range(0, len(padded_data), 64):
            block = padded_data[i:i + 64]
            self._process_block(block)

        # Формируем итоговый хэш
        return struct.pack('>IIIIIIII',
                           self.h0, self.h1, self.h2, self.h3,
                           self.h4, self.h5, self.h6, self.h7)

    def hexdigest(self):
        """Возвращает хэш в виде hex-строки"""
        return self.digest().hex()

    @staticmethod
    def hash(data):
        """Удобный статический метод для быстрого хэширования"""
        sha256 = SHA256()
        sha256.update(data)
        return sha256.hexdigest()