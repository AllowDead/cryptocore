# cryptocore/mac/hmac.py
"""
HMAC (Hash-based Message Authentication Code) implementation.
Follows RFC 2104 specification.
ОПТИМИЗИРОВАННАЯ ВЕРСИЯ для производительности PBKDF2.
"""

from typing import Union
from cryptocore.hash.sha256 import SHA256


class HMAC:
    """
    HMAC implementation using SHA-256 as the underlying hash function.
    ОПТИМИЗАЦИИ:
    1. Предварительное вычисление ipad и opad
    2. Быстрое XOR через bytes comprehension
    3. Кэширование объектов хэша для повторного использования
    """

    def __init__(self, key: Union[bytes, str], hash_name: str = 'sha256'):
        if isinstance(key, str):
            # Assume hex string
            try:
                key = bytes.fromhex(key)
            except ValueError:
                raise ValueError("Key must be a valid hexadecimal string")

        if not key:
            raise ValueError("Key cannot be empty")

        # Только SHA256 согласно требованиям
        if hash_name.lower() != 'sha256':
            raise ValueError(f"Only SHA256 is supported, got: {hash_name}")

        self.hash_class = SHA256
        self.block_size = 64  # SHA-256 block size in bytes
        self.hash_size = 32  # SHA-256 output size in bytes

        # ОПТИМИЗАЦИЯ: Обработка ключа сразу при создании
        processed_key = self._process_key(key)

        # ⭐ ОПТИМИЗАЦИЯ: Предварительно вычисляем ipad и opad
        # Это исключает повторное вычисление для каждого вызова compute()
        self.ipad = self._xor_bytes_fast(processed_key, b'\x36' * self.block_size)
        self.opad = self._xor_bytes_fast(processed_key, b'\x5c' * self.block_size)

    def _process_key(self, key: bytes) -> bytes:
        """
        Process the key according to RFC 2104:
        - If key is longer than block size: hash it
        - If key is shorter than block size: pad with zeros
        """
        if len(key) > self.block_size:
            # Hash the key if it's too long
            hash_obj = self.hash_class()
            hash_obj.update(key)
            key = hash_obj.digest()

        if len(key) < self.block_size:
            # Pad with zeros if it's too short
            key = key + b'\x00' * (self.block_size - len(key))

        return key

    def _xor_bytes_fast(self, a: bytes, b: bytes) -> bytes:
        """Быстрый XOR двух byte строк одинаковой длины."""
        # ОПТИМИЗАЦИЯ: Используем comprehension вместо zip
        return bytes(a[i] ^ b[i] for i in range(len(a)))

    def compute(self, message: bytes) -> bytes:
        """
        Вычисляет HMAC для сообщения, возвращает bytes.
        ОПТИМИЗИРОВАННАЯ ВЕРСИЯ:
        1. Использует предварительно вычисленные ipad/opad
        2. Минимизирует создание объектов
        """
        # Внутренний хэш: H((K ⊕ ipad) ∥ message)
        inner_hash_obj = self.hash_class()
        inner_hash_obj.update(self.ipad)
        inner_hash_obj.update(message)
        inner_hash = inner_hash_obj.digest()

        # Внешний хэш: H((K ⊕ opad) ∥ inner_hash)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(self.opad)
        outer_hash_obj.update(inner_hash)
        return outer_hash_obj.digest()

    def compute_fast(self, message: bytes) -> bytes:
        """
        Сверхоптимизированная версия для PBKDF2.
        Предполагает, что ipad уже добавлен к сообщению где нужно.
        """
        # Эта функция для внутреннего использования в PBKDF2
        # Внешний хэш: H((K ⊕ opad) ∥ message)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(self.opad)
        outer_hash_obj.update(message)
        return outer_hash_obj.digest()

    def compute_incremental(self):
        """
        Start incremental HMAC computation.
        Returns an object that can be updated with data in chunks.
        """
        # Create inner hash object with ipad already added
        inner_hash_obj = self.hash_class()
        inner_hash_obj.update(self.ipad)

        # Create incremental HMAC object
        return _IncrementalHMAC(inner_hash_obj, self.opad, self.hash_class)

    def compute_incremental_final(self, message: bytes) -> bytes:
        """
        Compute HMAC for message, optimized for single call.
        """
        # Внутренний хэш: H((K ⊕ ipad) || message)
        inner_hash_obj = self.hash_class()
        inner_hash_obj.update(self.ipad)
        inner_hash_obj.update(message)
        inner_hash = inner_hash_obj.digest()

        # Внешний хэш: H((K ⊕ opad) || inner_hash)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(self.opad)
        outer_hash_obj.update(inner_hash)
        return outer_hash_obj.digest()

    def compute_hex(self, message: bytes) -> str:
        """Compute HMAC and return as hexadecimal string."""
        return self.compute_incremental_final(message).hex()

    def compute_file(self, file_path: str, chunk_size: int = 8192) -> bytes:
        """
        Compute HMAC for a file, reading it in chunks.
        """
        incremental = self.compute_incremental()

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                incremental.update(chunk)

        return incremental.finalize()

    def compute_file_hex(self, file_path: str, chunk_size: int = 8192) -> str:
        """Compute HMAC for a file and return as hex string."""
        return self.compute_file(file_path, chunk_size).hex()

    def verify(self, message: bytes, hmac_to_check: Union[bytes, str]) -> bool:
        """
        Verify an HMAC value with constant-time comparison.
        """
        computed_hmac = self.compute(message)

        if isinstance(hmac_to_check, str):
            # Assume hex string
            try:
                hmac_to_check = bytes.fromhex(hmac_to_check)
            except ValueError:
                return False

        # Constant-time comparison to prevent timing attacks
        if len(computed_hmac) != len(hmac_to_check):
            return False

        # ОПТИМИЗАЦИЯ: Используем быстрый XOR сравнение
        result = 0
        for i in range(len(computed_hmac)):
            result |= computed_hmac[i] ^ hmac_to_check[i]

        return result == 0

    def compute_bytes(self, message: Union[bytes, str]) -> bytes:
        """Compute HMAC and return as bytes."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return self.compute(message)

    def verify_file(self, file_path: str, hmac_to_check: Union[bytes, str],
                    chunk_size: int = 8192) -> bool:
        """
        Verify HMAC for a file.
        """
        computed_hmac = self.compute_file(file_path, chunk_size)

        if isinstance(hmac_to_check, str):
            try:
                hmac_to_check = bytes.fromhex(hmac_to_check)
            except ValueError:
                return False

        # Constant-time comparison
        if len(computed_hmac) != len(hmac_to_check):
            return False

        result = 0
        for i in range(len(computed_hmac)):
            result |= computed_hmac[i] ^ hmac_to_check[i]

        return result == 0

    # Методы для использования в PBKDF2
    def get_inner_hash_func(self):
        """Возвращает функцию для быстрого вычисления внутреннего хэша."""

        def inner_hash(data):
            hash_obj = self.hash_class()
            hash_obj.update(self.ipad)
            hash_obj.update(data)
            return hash_obj.digest()

        return inner_hash

    def get_outer_hash_func(self):
        """Возвращает функцию для быстрого вычисления внешнего хэша."""

        def outer_hash(data):
            hash_obj = self.hash_class()
            hash_obj.update(self.opad)
            hash_obj.update(data)
            return hash_obj.digest()

        return outer_hash


class _IncrementalHMAC:
    """Helper class for incremental HMAC computation."""

    def __init__(self, inner_hash_obj, opad: bytes, hash_class):
        self.inner_hash_obj = inner_hash_obj
        self.opad = opad
        self.hash_class = hash_class

    def update(self, data: bytes):
        """Update HMAC with more data."""
        self.inner_hash_obj.update(data)

    def finalize(self) -> bytes:
        """Finalize HMAC computation and return result."""
        inner_hash = self.inner_hash_obj.digest()

        # Outer hash: H((K ⊕ opad) || inner_hash)
        outer_hash_obj = self.hash_class()
        outer_hash_obj.update(self.opad)
        outer_hash_obj.update(inner_hash)
        return outer_hash_obj.digest()