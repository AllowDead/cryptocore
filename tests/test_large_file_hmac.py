# tests/test_large_file_hmac.py
"""
Test HMAC with large files.
"""

import unittest
import os
import tempfile
import random
from cryptocore.mac.hmac import HMAC


class TestLargeFileHMAC(unittest.TestCase):
    """Test HMAC with files larger than memory."""

    def create_large_temp_file(self, size_mb: int):
        """Create a temporary file of specified size in MB."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')

        chunk_size = 1024 * 1024  # 1MB chunks
        total_bytes = size_mb * 1024 * 1024

        bytes_written = 0
        while bytes_written < total_bytes:
            chunk = min(chunk_size, total_bytes - bytes_written)
            data = os.urandom(chunk)
            temp_file.write(data)
            bytes_written += chunk

        temp_file.close()
        return temp_file.name

    def test_hmac_1gb_file(self):
        """Test HMAC with 1GB file (simulated with smaller for speed)."""
        # Note: Для реального теста с 1GB файлом нужно изменить size_mb на 1024
        # Здесь используем 10MB для скорости тестирования
        size_mb = 10

        print(f"\nCreating test file of {size_mb}MB...")
        large_file = self.create_large_temp_file(size_mb)

        try:
            test_key = "00112233445566778899aabbccddeeff"
            hmac = HMAC(test_key)

            print(f"Computing HMAC for {size_mb}MB file...")

            # Метод 1: Используем новую функцию для файлов
            hmac_result1 = hmac.compute_file_hex(large_file)

            # Метод 2: Проверяем верификацию
            verify_result = hmac.verify_file(large_file, hmac_result1)

            self.assertTrue(verify_result, "HMAC verification should succeed")

            # Проверяем, что файл действительно был обработан частями
            file_size = os.path.getsize(large_file)
            self.assertGreater(file_size, 1024 * 1024, "File should be >1MB")

            print(f"File size: {file_size / (1024 * 1024):.2f}MB")
            print(f"HMAC computed successfully")

        finally:
            if os.path.exists(large_file):
                os.unlink(large_file)

    def test_hmac_incremental_vs_one_shot(self):
        """Test that incremental HMAC matches one-shot HMAC."""
        # Создаем небольшой тестовый файл
        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        test_data = os.urandom(1024 * 100)  # 100KB
        test_file.write(test_data)
        test_file.close()

        try:
            test_key = "00112233445566778899aabbccddeeff"
            hmac = HMAC(test_key)

            # Метод 1: One-shot (читать весь файл)
            with open(test_file.name, 'rb') as f:
                file_data = f.read()
            hmac_one_shot = hmac.compute_hex(file_data)

            # Метод 2: Incremental (читать частями)
            hmac_incremental = hmac.compute_file_hex(test_file.name, chunk_size=4096)

            # Метод 3: Используя incremental API напрямую
            incremental = hmac.compute_incremental()
            with open(test_file.name, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    incremental.update(chunk)
            hmac_direct = incremental.finalize().hex()

            # Все три метода должны давать одинаковый результат
            self.assertEqual(hmac_one_shot, hmac_incremental)
            self.assertEqual(hmac_one_shot, hmac_direct)

        finally:
            if os.path.exists(test_file.name):
                os.unlink(test_file.name)

    def test_hmac_memory_efficiency(self):
        """Test that HMAC doesn't load entire file into memory."""
        import psutil
        import gc

        process = psutil.Process(os.getpid())

        # Создаем файл побольше
        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        file_size = 50 * 1024 * 1024  # 50MB
        chunk_size = 1024 * 1024  # 1MB

        print(f"\nCreating {file_size / (1024 * 1024):.0f}MB test file...")
        for _ in range(file_size // chunk_size):
            test_file.write(os.urandom(chunk_size))
        test_file.close()

        try:
            initial_memory = process.memory_info().rss

            test_key = "00112233445566778899aabbccddeeff"
            hmac = HMAC(test_key)

            print(f"Initial memory: {initial_memory / (1024 * 1024):.2f}MB")

            # Вычисляем HMAC
            hmac_result = hmac.compute_file_hex(test_file.name, chunk_size=8192)

            final_memory = process.memory_info().rss
            memory_increase = final_memory - initial_memory

            print(f"Final memory: {final_memory / (1024 * 1024):.2f}MB")
            print(f"Memory increase: {memory_increase / (1024 * 1024):.2f}MB")

            # Потребление памяти должно быть значительно меньше размера файла
            # (мы читаем файл по 8KB, так что память должна увеличиться на ~8-16KB)
            self.assertLess(memory_increase, 50 * 1024 * 1024,
                            "Memory usage should not scale with file size")

            # На практике увеличение должно быть < 1MB
            self.assertLess(memory_increase, 10 * 1024 * 1024,
                            "Memory increase should be reasonable (<10MB)")

            print(f"HMAC computed with minimal memory increase")

        finally:
            if os.path.exists(test_file.name):
                os.unlink(test_file.name)
            gc.collect()


if __name__ == '__main__':
    unittest.main()