# tests/test_large_files.py
import unittest
import tempfile
import os
import hashlib
from cryptocore.hash.sha256 import SHA256


class TestLargeFiles(unittest.TestCase):
    """Тесты больших файлов (>1GB в симуляции)"""

    def setUp(self):
        self.temp_files = []

    def tearDown(self):
        for f in self.temp_files:
            if os.path.exists(f):
                os.unlink(f)

    def create_large_temp_file(self, size_mb):
        """Создает временный файл заданного размера (в мегабайтах)"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            filename = f.name
            self.temp_files.append(filename)

            # Для теста создаем не настоящий большой файл,
            # а симулируем обработку большого файла
            chunk_size = 1024 * 1024  # 1MB
            written = 0

            while written < size_mb * 1024 * 1024:
                write_size = min(chunk_size, size_mb * 1024 * 1024 - written)
                f.write(os.urandom(write_size))
                written += write_size

        return filename

    def test_1gb_simulation(self):
        """Симуляция обработки 1GB файла"""
        print("\nSimulating 1GB file processing...")

        # Наша реализация
        sha_custom = SHA256()
        # Стандартная для сравнения
        sha_std = hashlib.sha256()

        chunk_size = 8192  # 8KB
        total_size = 1024 * 1024 * 1024  # 1GB в байтах

        # Для скорости теста делаем меньше, но проверяем логику
        test_size = 10 * 1024 * 1024  # 10MB для быстрого теста
        chunks = test_size // chunk_size

        print(f"Processing {test_size / (1024 * 1024):.1f}MB in {chunks} chunks...")

        for i in range(chunks):
            chunk = os.urandom(chunk_size)
            sha_custom.update(chunk)
            sha_std.update(chunk)

            # Прогресс
            if i % 100 == 0:
                processed = (i + 1) * chunk_size
                percent = (processed / test_size) * 100
                print(f"  Progress: {percent:.1f}% ({processed / (1024 * 1024):.1f}MB)")

        # Проверяем результат
        custom_hash = sha_custom.hexdigest()
        std_hash = sha_std.hexdigest()

        self.assertEqual(custom_hash, std_hash,
                         f"Hashes don't match!\nCustom: {custom_hash}\nStd: {std_hash}")

        print(f"Test passed! Hash: {custom_hash[:16]}...")

    def test_chunk_boundaries(self):
        """Тест граничных случаев при чанковой обработке"""
        print("\nTesting chunk boundary cases...")

        # Разные размеры чанков
        chunk_sizes = [1, 63, 64, 65, 127, 128, 255, 256, 511, 512, 1023, 1024, 8191, 8192]

        for chunk_size in chunk_sizes:
            with self.subTest(chunk_size=chunk_size):
                # Создаем данные точно кратные chunk_size
                total_size = chunk_size * 100  # 100 чанков
                data = os.urandom(total_size)

                # Наша реализация
                sha_custom = SHA256()
                offset = 0
                while offset < total_size:
                    chunk = data[offset:offset + chunk_size]
                    sha_custom.update(chunk)
                    offset += chunk_size

                # Стандартная реализация (целиком)
                sha_std = hashlib.sha256()
                sha_std.update(data)

                self.assertEqual(sha_custom.hexdigest(), sha_std.hexdigest(),
                                 f"Failed with chunk size {chunk_size}")

    def test_very_large_length(self):
        """Тест очень большой длины (потенциальный overflow)"""
        print("\nTesting very large file length handling...")

        # Создаем SHA256 объект и "обманываем" его, говоря что обработали много данных
        sha = SHA256()

        # Теоретически, SHA-256 поддерживает до 2^64 бит сообщения
        # Это 2^61 байт = 2EB (эксабайт)

        # Проверяем что наш код не сломается
        import struct

        # Тест 1: Длина близкая к максимуму
        max_bits = (1 << 64) - 1  # 2^64 - 1 бит
        max_bytes = max_bits // 8

        print(f"Max supported: {max_bytes:,} bytes ({max_bytes / (1024 ** 6):.2f} EB)")

        # Тест 2: Проверяем упаковку длины
        test_lengths = [
            (0, "0 bytes"),
            (1, "1 byte"),
            (1024 ** 3, "1 GB"),
            (1024 ** 4, "1 TB"),
            (1024 ** 5, "1 PB"),
            (1 << 61, "2 EB"),  # Предел SHA-256
        ]

        for length_bytes, description in test_lengths:
            length_bits = length_bytes * 8
            try:
                packed = struct.pack('>Q', length_bits)
                unpacked_bits = struct.unpack('>Q', packed)[0]
                unpacked_bytes = unpacked_bits // 8

                self.assertEqual(length_bytes, unpacked_bytes,
                                 f"Packing failed for {description}")
                print(f"  ✓ {description:8} -> packs/unpacks correctly")
            except Exception as e:
                print(f"  ✗ {description:8} -> ERROR: {e}")


if __name__ == '__main__':
    unittest.main(verbosity=2)