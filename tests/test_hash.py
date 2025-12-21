# tests/test_hash.py

import unittest
import subprocess
import os
import tempfile
import hashlib
from cryptocore.hash.sha256 import SHA256
from cryptocore.hash.sha3_256 import SHA3_256


class TestSHA256(unittest.TestCase):
    """Тесты для SHA-256 реализации"""

    def test_empty_string(self):
        """Тест пустой строки"""
        sha = SHA256()
        sha.update(b"")
        result = sha.hexdigest()
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(result, expected)

    def test_abc(self):
        """Тест 'abc'"""
        sha = SHA256()
        sha.update(b"abc")
        result = sha.hexdigest()
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(result, expected)

    def test_long_message(self):
        """Тест длинного сообщения"""
        message = b"a" * 1000
        sha = SHA256()
        sha.update(message)
        result = sha.hexdigest()

        # Проверяем через стандартную библиотеку
        expected = hashlib.sha256(message).hexdigest()
        self.assertEqual(result, expected)

    def test_chunk_processing(self):
        """Тест обработки по частям"""
        message = b"The quick brown fox jumps over the lazy dog"

        # Полностью
        sha1 = SHA256()
        sha1.update(message)
        full_hash = sha1.hexdigest()

        # По частям
        sha2 = SHA256()
        sha2.update(b"The quick brown fox ")
        sha2.update(b"jumps over the lazy dog")
        chunk_hash = sha2.hexdigest()

        self.assertEqual(full_hash, chunk_hash)

    def test_static_method(self):
        """Тест статического метода"""
        result = SHA256.hash(b"test")
        expected = hashlib.sha256(b"test").hexdigest()
        self.assertEqual(result, expected)


class TestSHA3_256(unittest.TestCase):
    """Тесты для SHA3-256 реализации"""

    def test_empty_string(self):
        """Тест пустой строки"""
        sha3 = SHA3_256()
        sha3.update(b"")
        result = sha3.hexdigest()
        expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        self.assertEqual(result, expected)

    def test_abc(self):
        """Тест 'abc'"""
        sha3 = SHA3_256()
        sha3.update(b"abc")
        result = sha3.hexdigest()
        expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        self.assertEqual(result, expected)

    def test_interoperability(self):
        """Тест интероперабельности с hashlib (если доступно)"""
        message = b"test message for sha3"

        # Наша реализация
        sha3_custom = SHA3_256()
        sha3_custom.update(message)
        custom_hash = sha3_custom.hexdigest()

        # Стандартная библиотека (Python 3.6+)
        try:
            import hashlib
            sha3_std = hashlib.sha3_256()
            sha3_std.update(message)
            std_hash = sha3_std.hexdigest()
            self.assertEqual(custom_hash, std_hash)
        except ImportError:
            # SHA3 не доступен в старой версии Python
            pass

    def test_avalanche_effect(self):
        """Тест лавинного эффекта"""
        original = b"Hello, world!"
        modified = b"Hello, world?"  # Изменен один байт

        sha3_orig = SHA3_256()
        sha3_orig.update(original)
        hash_orig = sha3_orig.hexdigest()

        sha3_mod = SHA3_256()
        sha3_mod.update(modified)
        hash_mod = sha3_mod.hexdigest()

        # Подсчитываем различающиеся биты
        bin_orig = bin(int(hash_orig, 16))[2:].zfill(256)
        bin_mod = bin(int(hash_mod, 16))[2:].zfill(256)

        diff_count = sum(1 for a, b in zip(bin_orig, bin_mod) if a != b)

        # Должно быть около 128 разных битов (50%)
        self.assertGreater(diff_count, 100)
        self.assertLess(diff_count, 156)


class TestFileHashing(unittest.TestCase):
    """Тесты хэширования файлов"""

    def test_small_file(self):
        """Тест маленького файла"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Test file content\n")
            temp_file = f.name

        try:
            # SHA-256
            sha = SHA256()
            with open(temp_file, 'rb') as f:
                while chunk := f.read(1024):
                    sha.update(chunk)
            hash_result = sha.hexdigest()

            # Проверка через hashlib
            with open(temp_file, 'rb') as f:
                expected = hashlib.sha256(f.read()).hexdigest()

            self.assertEqual(hash_result, expected)

        finally:
            os.unlink(temp_file)

    def test_large_file(self):
        """Тест большого файла (1MB)"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Генерируем 1MB данных
            data = os.urandom(1024 * 1024)  # 1MB
            f.write(data)
            temp_file = f.name

        try:
            # Наша реализация
            sha = SHA256()
            with open(temp_file, 'rb') as f:
                while chunk := f.read(8192):  # 8KB chunks
                    sha.update(chunk)
            custom_hash = sha.hexdigest()

            # Стандартная реализация
            with open(temp_file, 'rb') as f:
                std_hash = hashlib.sha256(f.read()).hexdigest()

            self.assertEqual(custom_hash, std_hash)

        finally:
            os.unlink(temp_file)


class TestNISTVectors(unittest.TestCase):
    """Тесты с известными векторами от NIST"""

    def test_sha256_empty(self):
        """Тест пустой строки (SHA-256)"""
        sha = SHA256()
        sha.update(b"")
        self.assertEqual(
            sha.hexdigest(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha256_abc(self):
        """Тест "abc" (SHA-256)"""
        sha = SHA256()
        sha.update(b"abc")
        self.assertEqual(
            sha.hexdigest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_sha256_double_block(self):
        """Тест сообщения длиннее одного блока"""
        # "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        # Это 56 символов, меньше 64 байт, но все равно хороший тест
        message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        sha = SHA256()
        sha.update(message)
        # Проверим через Python's hashlib
        import hashlib
        expected = hashlib.sha256(message).hexdigest()
        self.assertEqual(sha.hexdigest(), expected)

    def test_sha256_million_a(self):
        """Тест миллиона символов 'a' (SHA-256)"""
        # Этот тест проверяет обработку очень длинных сообщений
        sha = SHA256()
        # Создаем 1000 раз по 1000 'a' вместо миллиона для скорости
        chunk = b"a" * 1000
        for _ in range(1000):
            sha.update(chunk)

        # Ожидаемый хэш для миллиона 'a'
        # Источник: https://www.di-mgt.com.au/sha_testvectors.html
        expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        self.assertEqual(sha.hexdigest(), expected)

    def test_sha3_256_empty(self):
        """Тест пустой строки (SHA3-256)"""
        sha3 = SHA3_256()
        sha3.update(b"")
        self.assertEqual(
            sha3.hexdigest(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )

    def test_sha3_256_abc(self):
        """Тест "abc" (SHA3-256)"""
        sha3 = SHA3_256()
        sha3.update(b"abc")
        self.assertEqual(
            sha3.hexdigest(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )

    def test_sha3_256_hello_world(self):
        """Тест "hello world" (SHA3-256)"""
        sha3 = SHA3_256()
        sha3.update(b"hello world")
        # Проверяем через hashlib если доступно
        try:
            import hashlib
            expected = hashlib.sha3_256(b"hello world").hexdigest()
            self.assertEqual(sha3.hexdigest(), expected)
        except ImportError:
            # SHA3 не доступен в старом Python
            expected = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
            self.assertEqual(sha3.hexdigest(), expected)


class TestHashInteroperability(unittest.TestCase):
    """Тесты интероперабельности с Python hashlib"""

    def test_sha256_with_hashlib(self):
        """Сравнение SHA-256 с Python hashlib"""
        test_data = [
            b"",
            b"a",
            b"abc",
            b"hello world",
            b"The quick brown fox jumps over the lazy dog",
            b"a" * 1000,  # Большие данные
        ]

        for data in test_data:
            with self.subTest(data=data[:20] if len(data) > 20 else data):
                # Наша реализация
                sha_custom = SHA256()
                sha_custom.update(data)
                custom_hash = sha_custom.hexdigest().lower()

                # Стандартная реализация (hashlib)
                sha_std = hashlib.sha256()
                sha_std.update(data)
                std_hash = sha_std.hexdigest().lower()

                self.assertEqual(custom_hash, std_hash,
                                 f"Data: {data[:50]}...\n"
                                 f"Custom: {custom_hash}\n"
                                 f"Std:    {std_hash}")

    def test_sha3_256_with_hashlib(self):
        """Сравнение SHA3-256 с Python hashlib (если доступно)"""
        try:
            # Проверяем доступность SHA3 в hashlib
            hashlib.sha3_256(b"test")
            sha3_available = True
        except AttributeError:
            sha3_available = False
            print("Note: SHA3 not available in hashlib (Python < 3.6)")

        test_data = [
            b"",
            b"a",
            b"abc",
            b"hello world",
        ]

        for data in test_data:
            with self.subTest(data=data[:20] if len(data) > 20 else data):
                # Наша реализация
                sha3_custom = SHA3_256()
                sha3_custom.update(data)
                custom_hash = sha3_custom.hexdigest().lower()

                if sha3_available:
                    # Стандартная реализация
                    sha3_std = hashlib.sha3_256()
                    sha3_std.update(data)
                    std_hash = sha3_std.hexdigest().lower()

                    self.assertEqual(custom_hash, std_hash,
                                     f"Data: {data[:50]}...\n"
                                     f"Custom: {custom_hash}\n"
                                     f"Std:    {std_hash}")
                else:
                    # Проверяем известные тестовые векторы
                    if data == b"":
                        expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
                        self.assertEqual(custom_hash, expected)
                    elif data == b"abc":
                        expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
                        self.assertEqual(custom_hash, expected)
                    # Для других данных просто проверяем что хэш вычисляется без ошибок
                    self.assertIsInstance(custom_hash, str)
                    self.assertEqual(len(custom_hash), 64)  # 32 байта в hex = 64 символа

    def test_file_hashing_interop(self):
        """Тест хэширования файлов"""
        # Создаем тестовый файл
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Пишем разные данные
            f.write(b"Line 1: Test data for file hashing\n")
            f.write(b"Line 2: " + b"x" * 1000 + b"\n")
            f.write(b"Line 3: End of test file\n")
            temp_file = f.name

        try:
            # SHA-256: наша реализация
            sha_custom = SHA256()
            with open(temp_file, 'rb') as f:
                while chunk := f.read(8192):
                    sha_custom.update(chunk)
            custom_hash = sha_custom.hexdigest().lower()

            # SHA-256: hashlib
            sha_std = hashlib.sha256()
            with open(temp_file, 'rb') as f:
                while chunk := f.read(8192):
                    sha_std.update(chunk)
            std_hash = sha_std.hexdigest().lower()

            self.assertEqual(custom_hash, std_hash,
                             f"File: {temp_file}\n"
                             f"Custom SHA256: {custom_hash}\n"
                             f"Std SHA256:    {std_hash}")

            # SHA3-256 если доступно
            try:
                # Наша реализация
                sha3_custom = SHA3_256()
                with open(temp_file, 'rb') as f:
                    while chunk := f.read(8192):
                        sha3_custom.update(chunk)
                custom_sha3_hash = sha3_custom.hexdigest().lower()

                # hashlib
                sha3_std = hashlib.sha3_256()
                with open(temp_file, 'rb') as f:
                    while chunk := f.read(8192):
                        sha3_std.update(chunk)
                std_sha3_hash = sha3_std.hexdigest().lower()

                self.assertEqual(custom_sha3_hash, std_sha3_hash,
                                 f"File: {temp_file}\n"
                                 f"Custom SHA3-256: {custom_sha3_hash}\n"
                                 f"Std SHA3-256:    {std_sha3_hash}")
            except AttributeError:
                # SHA3 не доступен в hashlib
                pass

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_chunked_hashing_interop(self):
        """Тест что чанкованное хэширование дает тот же результат"""
        data = b"x" * 10000  # 10KB данных

        # 1. Полностью
        sha1 = SHA256()
        sha1.update(data)
        full_hash = sha1.hexdigest()

        # 2. Разными чанками
        sha2 = SHA256()
        chunk_sizes = [1, 10, 100, 1000, 5000]  # Разные размеры чанков
        for chunk_size in chunk_sizes:
            sha_test = SHA256()
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + chunk_size]
                sha_test.update(chunk)
                offset += chunk_size
            self.assertEqual(sha_test.hexdigest(), full_hash,
                             f"Chunk size {chunk_size} failed")

if __name__ == '__main__':
    unittest.main()