import os
import unittest
from cryptocore.csprng import generate_random_bytes


class TestCSPRNG(unittest.TestCase):

    def test_generate_random_bytes_length(self):
        """Тест корректности длины генерируемых данных"""
        for length in [1, 16, 100, 256]:
            with self.subTest(length=length):
                result = generate_random_bytes(length)
                self.assertEqual(len(result), length)

    def test_hamming_weight(self):
        """TEST-4: Check that bits are ~50% ones (Hamming weight)"""
        num_samples = 1000
        total_bits = 0
        total_ones = 0

        for _ in range(num_samples):
            data = generate_random_bytes(16)

            # Подсчет единичных битов в каждом байте
            for byte in data:
                # bin(byte) возвращает строку типа '0b1010'
                # count('1') считает единицы
                ones_in_byte = bin(byte).count('1')
                total_ones += ones_in_byte
                total_bits += 8  # 8 бит в каждом байте

        ratio = total_ones / total_bits
        print(f"  Total bits: {total_bits:,}")
        print(f"  Total ones: {total_ones:,}")
        print(f"  Ratio (ones/bits): {ratio:.4f} ({ratio * 100:.1f}%)")

        # Проверяем, что примерно 50% ± 5%
        self.assertGreaterEqual(ratio, 0.45,
                                f"Too few ones: {ratio:.4f} (< 0.45)")
        self.assertLessEqual(ratio, 0.55,
                             f"Too many ones: {ratio:.4f} (> 0.55)")

        print(f"✓ Hamming weight test passed: {ratio * 100:.1f}% ones")


    def test_key_uniqueness(self):
        """TEST-2: Generate 1000 keys and ensure all are unique"""
        num_keys = 1000
        keys_hex = set()

        for i in range(num_keys):
            key = generate_random_bytes(16)
            key_hex = key.hex()

            # Проверка на уникальность
            self.assertNotIn(key_hex, keys_hex,
                             f"Duplicate key found at iteration {i}: {key_hex}")
            keys_hex.add(key_hex)

            # Прогресс для больших тестов
            if i % 100 == 0:
                print(f"  Generated {i} unique keys...")

        print(f"✓ Successfully generated {len(keys_hex)} unique keys.")

    def test_randomness_basic(self):
        """Базовый тест на случайность (примерно 50% единичных битов)"""
        num_tests = 100
        total_bits = 0
        total_ones = 0

        for _ in range(num_tests):
            data = generate_random_bytes(16)
            # Подсчет единичных битов
            ones = sum(bin(byte).count('1') for byte in data)
            total_ones += ones
            total_bits += len(data) * 8

        ratio = total_ones / total_bits
        # Проверяем, что примерно 50% битов установлены в 1
        self.assertAlmostEqual(ratio, 0.5, delta=0.1)

    def test_negative_length(self):
        """Тест обработки некорректной длины"""
        with self.assertRaises(ValueError):
            generate_random_bytes(0)

        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_nist_preparation(self):
        """Generate file for NIST testing (10 MB)"""
        total_size = 10_000_000  # 10 MB
        filename = "nist_test_data.bin"

        with open(filename, 'wb') as f:
            bytes_written = 0
            chunk_size = 65536  # 64 KB

            while bytes_written < total_size:
                chunk = generate_random_bytes(
                    min(chunk_size, total_size - bytes_written)
                )
                f.write(chunk)
                bytes_written += len(chunk)

        print(f"✓ Generated {bytes_written:,} bytes in '{filename}'")
        print(f"  File size: {os.path.getsize(filename) / (1024 * 1024):.2f} MB")

        # Проверка что файл создан
        self.assertTrue(os.path.exists(filename))
        self.assertEqual(os.path.getsize(filename), total_size)

        return filename


if __name__ == '__main__':
    unittest.main()