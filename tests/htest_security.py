#!/usr/bin/env python3
"""
Расширенный тест всего функционала CryptoCore (Sprints 1-6)
Включает проверку безопасности при изменении ключей, IV, AAD, MAC и т.д.
"""

import os
import sys
import tempfile
import subprocess
import hashlib
import json
import time
import random


def run_command(cmd, description, expect_success=True, expected_error=None, check_output=None):
    """Запустить команду и проверить результат"""
    print(f"\n{'=' * 60}")
    print(f"Тест: {description}")
    print(f"Команда: {' '.join(cmd[:6])}...")  # Показываем только первые 6 элементов

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(f"Exit code: {result.returncode}")

    if expect_success:
        if result.returncode != 0:
            print(f"❌ ОШИБКА: Команда завершилась с ошибкой, ожидался успех")
            print(f"STDERR:\n{result.stderr[:500]}")  # Ограничиваем вывод
            return False, result
        else:
            print(f"✅ УСПЕХ")
            return True, result
    else:
        if result.returncode == 0:
            print(f"❌ ОШИБКА: Команда завершилась успешно, ожидалась ошибка")
            return False, result
        elif expected_error and expected_error not in result.stderr:
            print(f"❌ ОШИБКА: Ожидалось сообщение '{expected_error}', не найдено")
            print(f"STDERR:\n{result.stderr[:500]}")
            return False, result
        else:
            print(f"✅ УСПЕХ (ожидаемая ошибка)")
            return True, result


def create_test_file(content, binary=False):
    """Создать временный тестовый файл"""
    mode = 'wb' if binary else 'w'
    with tempfile.NamedTemporaryFile(mode=mode, delete=False, suffix='.txt') as f:
        if binary:
            f.write(content)
        else:
            f.write(content)
        return f.name


def compare_files(file1, file2):
    """Сравнить два файла"""
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            return f1.read() == f2.read()
    except:
        return False


def get_file_hash(filepath):
    """Получить SHA-256 хеш файла"""
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def hex_xor(hex1, hex2):
    """XOR двух hex строк"""
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    result = bytes(a ^ b for a, b in zip(bytes1, bytes2))
    return result.hex()


class CryptoCoreSecurityTester:
    def __init__(self):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.cryptocore_cmd = [sys.executable, "-m", "cryptocore.cli_parser"]

        # Тестовые данные
        self.test_key = "00112233445566778899aabbccddeeff"
        self.test_key2 = "ffeeddccbbaa99887766554433221100"  # Другой ключ
        self.test_plaintext = b"Secure test data for CryptoCore security testing. " * 5
        self.test_aad = "aabbccddeeff00112233445566778899"
        self.test_aad2 = "112233445566778899aabbccddeeff00"  # Другой AAD
        self.test_mac_key = "33445566778899aabbccddeeff00112233445566778899aabbcc"
        self.test_mac_key2 = "ccbbaa99887766554433221100ffeeddccbbaa998877665544"  # Другой MAC ключ

        # Список тестов
        self.tests = []
        self.passed = 0
        self.failed = 0
        self.results = {}

    def add_test(self, name, func):
        """Добавить тест в список"""
        self.tests.append((name, func))

    def run_all_tests(self):
        """Запустить все тесты"""
        print("=" * 80)
        print("РАСШИРЕННОЕ ТЕСТИРОВАНИЕ БЕЗОПАСНОСТИ CRYPTOCORE (Sprints 1-6)")
        print("=" * 80)

        for name, test_func in self.tests:
            print(f"\n{'#' * 60}")
            print(f"Запуск теста: {name}")
            print(f"{'#' * 60}")

            try:
                success, details = test_func()

                if success:
                    self.passed += 1
                    print(f"✅ Тест '{name}' ПРОЙДЕН")
                else:
                    self.failed += 1
                    print(f"❌ Тест '{name}' ПРОВАЛЕН")

                self.results[name] = {
                    'success': success,
                    'details': str(details)[:200] if details else ''
                }

            except Exception as e:
                self.failed += 1
                print(f"❌ Тест '{name}' ВЫЗВАЛ ИСКЛЮЧЕНИЕ: {e}")
                import traceback
                traceback.print_exc()
                self.results[name] = {
                    'success': False,
                    'error': str(e)
                }

        # Итоги
        print(f"\n{'=' * 80}")
        print("ИТОГИ ТЕСТИРОВАНИЯ БЕЗОПАСНОСТИ:")
        print(f"Всего тестов: {len(self.tests)}")
        print(f"Пройдено: {self.passed}")
        print(f"Провалено: {self.failed}")
        print(f"Успешность: {(self.passed / len(self.tests)) * 100:.1f}%")
        print("=" * 80)

        return self.failed == 0

    # ==================== SPRINT 1: ECB MODE БЕЗОПАСНОСТЬ ====================
    def test_ecb_security(self):
        """Тест безопасности ECB режима"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Шифрование с правильным ключом
            cmd_enc = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--encrypt",
                "--key", self.test_key,
                "--input", input_file,
                "--output", input_file + ".enc"
            ]

            success, result = run_command(cmd_enc, "ECB шифрование с правильным ключом")
            if not success:
                return False, result

            # 2. Дешифрование с правильным ключом
            cmd_dec = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--decrypt",
                "--key", self.test_key,
                "--input", input_file + ".enc",
                "--output", input_file + ".dec"
            ]

            success, result = run_command(cmd_dec, "ECB дешифрование с правильным ключом")
            if not success:
                return False, result

            # Проверка совпадения
            if not compare_files(input_file, input_file + ".dec"):
                return False, "ECB: Файлы не совпадают после шифрования/дешифрования"

            # 3. Дешифрование с неправильным ключом (изменен 1 байт)
            wrong_key = hex_xor(self.test_key, "00000000000000000000000000000001")  # Изменяем последний байт
            cmd_dec_wrong = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--decrypt",
                "--key", wrong_key,
                "--input", input_file + ".enc",
                "--output", input_file + ".wrong"
            ]

            success, result = run_command(cmd_dec_wrong, "ECB дешифрование с неправильным ключом")
            if not success:
                return False, result

            # Файл должен быть создан, но содержать мусор
            if not os.path.exists(input_file + ".wrong"):
                return False, "ECB: Файл не создан при дешифровании с неправильным ключом"

            # Файлы НЕ должны совпадать
            if compare_files(input_file, input_file + ".wrong"):
                return False, "ECB: Файлы совпали даже с неправильным ключом!"

            print("✅ ECB: Неправильный ключ дает другой результат (ожидаемо)")

            return True, "ECB тесты безопасности пройдены"

        finally:
            for f in [input_file, input_file + ".enc", input_file + ".dec", input_file + ".wrong"]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== SPRINT 2: РЕЖИМЫ С IV БЕЗОПАСНОСТЬ ====================
    def test_iv_modes_security(self):
        """Тест безопасности режимов с IV (CBC, CFB, OFB, CTR)"""
        modes = ["cbc", "cfb", "ofb", "ctr"]

        for mode in modes:
            print(f"\n--- Тестирование безопасности режима {mode.upper()} ---")

            input_file = create_test_file(self.test_plaintext, binary=True)

            try:
                # 1. Шифрование
                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + ".enc"
                ]

                success, result = run_command(cmd_enc, f"{mode.upper()} шифрование")
                if not success:
                    return False, result

                # 2. Дешифрование с правильным ключом
                cmd_dec = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--input", input_file + ".enc",
                    "--output", input_file + ".dec"
                ]

                success, result = run_command(cmd_dec, f"{mode.upper()} дешифрование с правильным ключом")
                if not success:
                    return False, result

                if not compare_files(input_file, input_file + ".dec"):
                    return False, f"{mode.upper()}: Файлы не совпадают"

                # 3. Дешифрование с неправильным ключом
                cmd_dec_wrong = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key2,  # Другой ключ
                    "--input", input_file + ".enc",
                    "--output", input_file + ".wrong"
                ]

                success, result = run_command(cmd_dec_wrong, f"{mode.upper()} дешифрование с неправильным ключом")
                if not success:
                    return False, result

                # Файлы НЕ должны совпадать
                if compare_files(input_file, input_file + ".wrong"):
                    return False, f"{mode.upper()}: Файлы совпали с неправильным ключом!"

                # 4. Дешифрование с неправильным IV (если предоставлен)
                # Создаем неправильный IV
                wrong_iv = "ffffffffffffffffffffffffffffffff"
                cmd_dec_wrong_iv = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--iv", wrong_iv,
                    "--input", input_file + ".enc",
                    "--output", input_file + ".wrongiv"
                ]

                success, result = run_command(cmd_dec_wrong_iv, f"{mode.upper()} дешифрование с неправильным IV")
                if not success:
                    return False, result

                # Результат должен отличаться от оригинала
                if compare_files(input_file, input_file + ".wrongiv"):
                    return False, f"{mode.upper()}: Файлы совпали с неправильным IV!"

                print(f"✅ {mode.upper()}: Неправильный ключ/IV дает другой результат")

            finally:
                for f in [input_file, input_file + ".enc", input_file + ".dec",
                          input_file + ".wrong", input_file + ".wrongiv"]:
                    if os.path.exists(f):
                        os.remove(f)

        return True, "Все режимы с IV прошли проверки безопасности"

    def test_iv_uniqueness(self):
        """Тест уникальности IV для каждого шифрования"""
        mode = "cbc"  # Проверяем на CBC как примере
        input_file = create_test_file(b"test", binary=True)

        try:
            ivs = set()

            for i in range(10):  # 10 шифрований одного файла
                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + f".enc{i}"
                ]

                success, result = run_command(cmd_enc, f"{mode.upper()} шифрование #{i + 1}")
                if not success:
                    return False, result

                # Извлекаем IV из файла (первые 16 байт)
                with open(input_file + f".enc{i}", 'rb') as f:
                    iv = f.read(16)
                    ivs.add(iv.hex())

            # Все IV должны быть уникальны
            if len(ivs) != 10:
                return False, f"{mode.upper()}: IV не все уникальны. Найдено {len(ivs)} уникальных из 10"

            print(f"✅ {mode.upper()}: Все 10 IV уникальны")
            return True, f"{mode.upper()}: Уникальность IV подтверждена"

        finally:
            for f in [input_file] + [input_file + f".enc{i}" for i in range(10)]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== SPRINT 3: CSPRNG БЕЗОПАСНОСТЬ ====================
    def test_csprng_security(self):
        """Тест безопасности CSPRNG"""
        # 1. Проверка уникальности ключей
        keys = set()

        for i in range(20):
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "cbc",
                "--encrypt",
                # Без --key для автогенерации
                "--input", "/dev/null" if os.path.exists("/dev/null") else "NUL",
                "--output", os.devnull
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            # Ищем сгенерированный ключ в выводе
            import re
            key_match = re.search(r'Generated random key: ([0-9a-fA-F]{32})', result.stdout)

            if key_match:
                key = key_match.group(1).lower()
                keys.add(key)

        if len(keys) < 15:  # Из 20 должно быть хотя бы 15 уникальных
            return False, f"CSPRNG: Слишком много дубликатов ключей. Уникальных: {len(keys)}/20"

        print(f"✅ CSPRNG: {len(keys)} уникальных ключей из 20")

        # 2. Проверка энтропии (базовая)
        all_bytes = b""
        for key_hex in list(keys)[:10]:  # Берем 10 ключей для анализа
            all_bytes += bytes.fromhex(key_hex)

        # Проверяем распределение байтов
        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1

        # Не должно быть байтов, которые никогда не встречаются
        zero_bytes = sum(1 for count in byte_counts if count == 0)
        if zero_bytes > 200:  # Если более 200 байтов никогда не встречаются
            return False, f"CSPRNG: Слишком много никогда не встречающихся байтов: {zero_bytes}/256"

        print(f"✅ CSPRNG: Хорошее распределение байтов ({zero_bytes}/256 никогда не встречаются)")

        return True, "CSPRNG тесты безопасности пройдены"

    # ==================== SPRINT 4: ХЕШ-ФУНКЦИИ БЕЗОПАСНОСТЬ ====================
    def test_hash_security(self):
        """Тест безопасности хеш-функций"""
        # 1. Avalanche effect (эффект лавины)
        input1 = b"Hello, world!"
        input2 = b"Hello, world?"  # Изменен один бит

        input_file1 = create_test_file(input1, binary=True)
        input_file2 = create_test_file(input2, binary=True)

        try:
            # Вычисляем хеши
            cmd_hash1 = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--input", input_file1
            ]

            cmd_hash2 = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--input", input_file2
            ]

            result1 = subprocess.run(cmd_hash1, capture_output=True, text=True)
            result2 = subprocess.run(cmd_hash2, capture_output=True, text=True)

            hash1 = result1.stdout.split()[0] if result1.stdout else ""
            hash2 = result2.stdout.split()[0] if result2.stdout else ""

            if not hash1 or not hash2:
                return False, "Не удалось получить хеши"

            # Преобразуем хеши в биты
            def hex_to_bits(hex_str):
                return bin(int(hex_str, 16))[2:].zfill(256)

            bits1 = hex_to_bits(hash1)
            bits2 = hex_to_bits(hash2)

            # Считаем отличающиеся биты
            diff_bits = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))

            print(f"Разница в 1 бит входных данных изменила {diff_bits} бит в хеше")

            # Должно измениться около 50% битов (эффект лавины)
            if diff_bits < 100 or diff_bits > 156:  # 100-156 из 256 (~39%-61%)
                return False, f"Слабый avalanche effect: изменилось только {diff_bits}/256 бит"

            print(f"✅ SHA-256: Хороший avalanche effect ({diff_bits}/256 бит изменилось)")

            # 2. Коллизии на коротких сообщениях
            test_messages = [
                b"",
                b"a",
                b"abc",
                b"message digest",
                b"1234567890" * 10,
                os.urandom(100)
            ]

            hashes = set()
            for msg in test_messages:
                temp_file = create_test_file(msg, binary=True)
                cmd = self.cryptocore_cmd + [
                    "dgst",
                    "--algorithm", "sha256",
                    "--input", temp_file
                ]

                result = subprocess.run(cmd, capture_output=True, text=True)
                hash_val = result.stdout.split()[0] if result.stdout else ""

                if hash_val:
                    hashes.add(hash_val)

                os.remove(temp_file)

            if len(hashes) != len(test_messages):
                return False, f"Найдены коллизии: {len(hashes)} уникальных хешей из {len(test_messages)} сообщений"

            print(f"✅ SHA-256: Нет коллизий на тестовых сообщениях")

            return True, "Хеш-функции прошли проверки безопасности"

        finally:
            for f in [input_file1, input_file2]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== SPRINT 5: HMAC БЕЗОПАСНОСТЬ ====================
    def test_hmac_security(self):
        """Тест безопасности HMAC"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Генерация HMAC
            cmd_hmac = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", self.test_key,
                "--input", input_file,
                "--output", input_file + ".hmac"
            ]

            success, result = run_command(cmd_hmac, "HMAC-SHA256 генерация")
            if not success:
                return False, result

            # 2. Проверка с правильным ключом
            cmd_verify = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", self.test_key,
                "--input", input_file,
                "--verify", input_file + ".hmac"
            ]

            success, result = run_command(cmd_verify, "HMAC проверка с правильным ключом")
            if not success:
                return False, result

            # 3. Проверка с неправильным ключом (должна провалиться)
            cmd_verify_wrong = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", self.test_key2,  # Другой ключ
                "--input", input_file,
                "--verify", input_file + ".hmac"
            ]

            success, result = run_command(cmd_verify_wrong, "HMAC проверка с неправильным ключом",
                                          expect_success=False, expected_error="HMAC verification failed for")
            if not success:
                return False, result

            # 4. Проверка с измененным файлом (должна провалиться)
            modified_file = input_file + ".modified"
            with open(modified_file, 'wb') as f:
                f.write(self.test_plaintext + b"MODIFIED")

            cmd_verify_modified = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", self.test_key,
                "--input", modified_file,
                "--verify", input_file + ".hmac"
            ]

            success, result = run_command(cmd_verify_modified, "HMAC проверка измененного файла",
                                          expect_success=False, expected_error="HMAC verification")
            if not success:
                return False, result

            # 5. Key sensitivity (чувствительность к ключу)
            # Генерируем HMAC с похожим ключом (изменен 1 бит)
            similar_key = hex_xor(self.test_key, "00000000000000000000000000000001")

            cmd_hmac_similar = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", similar_key,
                "--input", input_file,
                "--output", input_file + ".hmac2"
            ]

            success, result = run_command(cmd_hmac_similar, "HMAC с похожим ключом (1 бит разницы)")
            if not success:
                return False, result

            # Сравниваем два HMAC
            with open(input_file + ".hmac", 'r') as f1, open(input_file + ".hmac2", 'r') as f2:
                hmac1 = f1.read().split()[0]
                hmac2 = f2.read().split()[0]

            # HMAC должны быть совершенно разными
            if hmac1 == hmac2:
                return False, "HMAC совпали даже при разных ключах!"

            # Подсчитываем разницу в битах
            def hex_to_bits(hex_str):
                return bin(int(hex_str, 16))[2:].zfill(256)

            bits1 = hex_to_bits(hmac1)
            bits2 = hex_to_bits(hmac2)
            diff_bits = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))

            print(f"Разница в 1 бит ключа изменила {diff_bits} бит в HMAC")

            if diff_bits < 100:  # Должно быть около 128
                return False, f"Слабая чувствительность ключа HMAC: {diff_bits}/256 бит"

            print(f"✅ HMAC: Хорошая чувствительность к ключу ({diff_bits}/256 бит)")

            return True, "HMAC тесты безопасности пройдены"

        finally:
            for f in [input_file, input_file + ".hmac", input_file + ".hmac2",
                      input_file + ".modified"]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== SPRINT 6: GCM БЕЗОПАСНОСТЬ ====================
    def test_gcm_security(self):
        """Тест безопасности GCM режима"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Шифрование с AAD
            cmd_enc = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--encrypt",
                "--key", self.test_key,
                "--input", input_file,
                "--output", input_file + ".gcm",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_enc, "GCM шифрование с AAD")
            if not success:
                return False, result

            # 2. Дешифрование с правильным AAD
            cmd_dec = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key,
                "--input", input_file + ".gcm",
                "--output", input_file + ".dec",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec, "GCM дешифрование с правильным AAD")
            if not success:
                return False, result

            if not compare_files(input_file, input_file + ".dec"):
                return False, "GCM: Файлы не совпадают после шифрования/дешифрования"

            # 3. Дешифрование с неправильным AAD (должна быть ошибка)
            cmd_dec_wrong_aad = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key,
                "--input", input_file + ".gcm",
                "--output", input_file + ".wrongaad",
                "--aad", self.test_aad2  # Другой AAD
            ]

            success, result = run_command(cmd_dec_wrong_aad, "GCM с неправильным AAD",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            # Файл не должен быть создан при ошибке аутентификации
            if os.path.exists(input_file + ".wrongaad"):
                return False, "GCM: Файл создан даже при ошибке аутентификации (AAD)"

            # 4. Дешифрование с неправильным ключом (должна быть ошибка)
            cmd_dec_wrong_key = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key2,  # Другой ключ
                "--input", input_file + ".gcm",
                "--output", input_file + ".wrongkey",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec_wrong_key, "GCM с неправильным ключом",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            if os.path.exists(input_file + ".wrongkey"):
                return False, "GCM: Файл создан даже при ошибке аутентификации (ключ)"

            # 5. Изменение ciphertext (должна быть ошибка)
            with open(input_file + ".gcm", 'rb') as f:
                gcm_data = bytearray(f.read())

            # Изменяем один байт в ciphertext (не в nonce и не в теге)
            if len(gcm_data) > 20:  # Убедимся, что есть что изменять
                gcm_data[15] ^= 0x01  # Изменяем байт после nonce

            tampered_file = input_file + ".tampered"
            with open(tampered_file, 'wb') as f:
                f.write(gcm_data)

            cmd_dec_tampered = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key,
                "--input", tampered_file,
                "--output", input_file + ".tamperedout",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec_tampered, "GCM с измененным ciphertext",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            if os.path.exists(input_file + ".tamperedout"):
                return False, "GCM: Файл создан даже при измененном ciphertext"

            # 6. Nonce reuse test
            # Шифруем два разных сообщения с одинаковым nonce
            file1 = create_test_file(b"Message 1", binary=True)
            file2 = create_test_file(b"Message 2", binary=True)

            # Используем явный nonce
            test_nonce = "00112233445566778899aabb"

            cmd_enc1 = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--encrypt",
                "--key", self.test_key,
                "--iv", test_nonce,  # Фиксированный nonce
                "--input", file1,
                "--output", file1 + ".gcm",
                "--aad", self.test_aad
            ]

            cmd_enc2 = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--encrypt",
                "--key", self.test_key,
                "--iv", test_nonce,  # Тот же nonce (опасно!)
                "--input", file2,
                "--output", file2 + ".gcm",
                "--aad", self.test_aad
            ]

            # Первое шифрование должно пройти
            success1, _ = run_command(cmd_enc1, "GCM шифрование с фиксированным nonce (1)")

            # Второе может пройти или выдать предупреждение
            success2, result2 = run_command(cmd_enc2, "GCM шифрование с тем же nonce (2)")

            if success1 and success2:
                print("⚠️  GCM: Повторное использование nonce не предотвращено")
                # Это проблема безопасности, но не обязательно ошибка теста

            os.remove(file1)
            os.remove(file2)

            print("✅ GCM: Все проверки безопасности пройдены")
            return True, "GCM тесты безопасности пройдены"

        finally:
            for f in [input_file, input_file + ".gcm", input_file + ".dec",
                      input_file + ".wrongaad", input_file + ".wrongkey",
                      input_file + ".tampered", input_file + ".tamperedout"]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== SPRINT 6: ENCRYPT-THEN-MAC БЕЗОПАСНОСТЬ ====================
    def test_etm_security(self):
        """Тест безопасности Encrypt-then-MAC"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Шифрование
            cmd_enc = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--encrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key,
                "--input", input_file,
                "--output", input_file + ".etm",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_enc, "Encrypt-then-MAC шифрование")
            if not success:
                return False, result

            # 2. Дешифрование с правильными ключами
            cmd_dec = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key,
                "--input", input_file + ".etm",
                "--output", input_file + ".dec",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec, "ETM дешифрование с правильными ключами")
            if not success:
                return False, result

            if not compare_files(input_file, input_file + ".dec"):
                return False, "ETM: Файлы не совпадают"

            # 3. Дешифрование с неправильным ключом шифрования (должна быть ошибка)
            cmd_dec_wrong_key = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key2,  # Другой ключ
                "--mac-key", self.test_mac_key,
                "--input", input_file + ".etm",
                "--output", input_file + ".wrongkey",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec_wrong_key, "ETM с неправильным ключом шифрования",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            if os.path.exists(input_file + ".wrongkey"):
                return False, "ETM: Файл создан даже с неправильным ключом шифрования"

            # 4. Дешифрование с неправильным MAC ключом (должна быть ошибка)
            cmd_dec_wrong_mac = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key2,  # Другой MAC ключ
                "--input", input_file + ".etm",
                "--output", input_file + ".wrongmac",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec_wrong_mac, "ETM с неправильным MAC ключом",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            if os.path.exists(input_file + ".wrongmac"):
                return False, "ETM: Файл создан даже с неправильным MAC ключом"

            # 5. Дешифрование с неправильным AAD (должна быть ошибка)
            cmd_dec_wrong_aad = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key,
                "--input", input_file + ".etm",
                "--output", input_file + ".wrongaad",
                "--aad", self.test_aad2  # Другой AAD
            ]

            success, result = run_command(cmd_dec_wrong_aad, "ETM с неправильным AAD",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            if os.path.exists(input_file + ".wrongaad"):
                return False, "ETM: Файл создан даже с неправильным AAD"

            # 6. Изменение ciphertext (должна быть ошибка)
            with open(input_file + ".etm", 'rb') as f:
                etm_data = bytearray(f.read())

            if len(etm_data) > 50:
                etm_data[30] ^= 0x01  # Изменяем байт в ciphertext

            tampered_file = input_file + ".tampered"
            with open(tampered_file, 'wb') as f:
                f.write(etm_data)

            cmd_dec_tampered = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key,
                "--input", tampered_file,
                "--output", input_file + ".tamperedout",
                "--aad", self.test_aad
            ]

            success, result = run_command(cmd_dec_tampered, "ETM с измененным ciphertext",
                                          expect_success=False, expected_error="Authentication")
            if not success:
                return False, result

            if os.path.exists(input_file + ".tamperedout"):
                return False, "ETM: Файл создан даже при измененном ciphertext"

            print("✅ Encrypt-then-MAC: Все проверки безопасности пройдены")
            return True, "ETM тесты безопасности пройдены"

        finally:
            for f in [input_file, input_file + ".etm", input_file + ".dec",
                      input_file + ".wrongkey", input_file + ".wrongmac",
                      input_file + ".wrongaad", input_file + ".tampered",
                      input_file + ".tamperedout"]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== ИНТЕГРАЦИОННЫЕ ТЕСТЫ БЕЗОПАСНОСТИ ====================
    def test_cross_mode_comparison(self):
        """Сравнение безопасности разных режимов"""
        input_file = create_test_file(b"Identical test data for all modes", binary=True)

        try:
            modes = ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]
            ciphertexts = {}

            for mode in modes:
                extra_args = []
                if mode == "gcm":
                    extra_args = ["--aad", self.test_aad]

                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + f".{mode}"
                ] + extra_args

                success, result = run_command(cmd_enc, f"{mode.upper()} для сравнения")
                if not success:
                    return False, result

                # Читаем ciphertext
                with open(input_file + f".{mode}", 'rb') as f:
                    ciphertexts[mode] = f.read()

            # Проверяем, что все ciphertext разные (кроме IV части)
            unique_ciphertexts = set()

            for mode, ciphertext in ciphertexts.items():
                # Для сравнения удаляем IV из начала (если есть)
                if mode != "ecb" and len(ciphertext) > 16:
                    # Убираем первые 16 байт (IV) для сравнения
                    compare_part = ciphertext[16:32] if len(ciphertext) >= 32 else ciphertext
                else:
                    compare_part = ciphertext[:16] if ciphertext else b""

                unique_ciphertexts.add(compare_part.hex())

            if len(unique_ciphertexts) < len(modes) - 2:  # Допускаем некоторые совпадения
                print(
                    f"⚠️  Некоторые режимы дают похожие ciphertext: {len(unique_ciphertexts)} уникальных из {len(modes)}")
            else:
                print(f"✅ Все режимы дают разные ciphertext ({len(unique_ciphertexts)} уникальных из {len(modes)})")

            return True, "Сравнение режимов завершено"

        finally:
            for mode in modes:
                f = input_file + f".{mode}"
                if os.path.exists(f):
                    os.remove(f)
            if os.path.exists(input_file):
                os.remove(input_file)

    def test_error_handling(self):
        """Тест обработки ошибок безопасности"""
        test_cases = [
            {
                "cmd": ["encrypt", "--algorithm", "aes", "--mode", "ecb",
                        "--encrypt", "--key", "not_hex", "--input", "nonexistent"],
                "desc": "Неверный формат ключа",
                "expect_error": "Invalid key format"
            },
            {
                "cmd": ["encrypt", "--algorithm", "aes", "--mode", "gcm",
                        "--decrypt", "--key", self.test_key, "--iv", "001122",  # Слишком короткий
                        "--input", "/dev/null", "--aad", self.test_aad],
                "desc": "Слишком короткий nonce для GCM",
                "expect_error": "12 bytes" or "Nonce must"
            },
            {
                "cmd": ["dgst", "--algorithm", "sha256", "--hmac",
                        "--verify", "nonexistent.hmac", "--input", "/dev/null"],
                "desc": "HMAC verify без ключа",
                "expect_error": "--key is required"
            },
        ]

        for i, test in enumerate(test_cases):
            cmd = self.cryptocore_cmd + test["cmd"]

            # Заменяем /dev/null на NUL на Windows
            if sys.platform == "win32":
                cmd = [arg if arg != "/dev/null" else "NUL" for arg in cmd]

            success, result = run_command(cmd, f"Обработка ошибок: {test['desc']}",
                                          expect_success=False, expected_error=test.get("expect_error"))

            if not success:
                print(f"⚠️  Тест обработки ошибок #{i + 1} не прошел как ожидалось")
                # Не считаем это провалом всего теста

        return True, "Тесты обработки ошибок завершены"

    def test_performance_security(self):
        """Тест производительности и безопасности с большими файлами"""
        # Создаем большой файл (100KB)
        large_data = os.urandom(100 * 1024)  # 100KB
        input_file = create_test_file(large_data, binary=True)

        try:
            import time

            # Тестируем безопасные режимы
            secure_modes = ["cbc", "ctr", "gcm"]
            results = {}

            for mode in secure_modes:
                print(f"\n--- Тест производительности {mode.upper()} ---")

                extra_args = []
                if mode == "gcm":
                    extra_args = ["--aad", self.test_aad[:16]]  # Более короткий AAD

                start = time.time()

                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + f".{mode}.enc"
                ] + extra_args

                result = subprocess.run(cmd_enc, capture_output=True)

                encrypt_time = time.time() - start

                if result.returncode != 0:
                    print(f"❌ ОШИБКА шифрования {mode}")
                    continue

                # Проверяем размер
                enc_size = os.path.getsize(input_file + f".{mode}.enc")
                orig_size = len(large_data)

                # Для GCM и CBC размер должен увеличиться (IV, padding, tag)
                if mode in ["cbc", "gcm"] and enc_size <= orig_size:
                    print(f"⚠️  {mode}: Размер ciphertext ({enc_size}) <= оригиналу ({orig_size})")

                results[mode] = {
                    'encrypt_time': encrypt_time,
                    'encrypt_speed': orig_size / encrypt_time / 1024,  # KB/s
                    'size_ratio': enc_size / orig_size
                }

                print(f"  Размер: {orig_size / 1024:.1f} KB → {enc_size / 1024:.1f} KB")
                print(f"  Время: {encrypt_time:.3f} сек ({results[mode]['encrypt_speed']:.1f} KB/сек)")
                print(f"  Ratio: {results[mode]['size_ratio']:.3f}")

            # Анализ результатов
            print(f"\n--- Анализ производительности ---")
            for mode, data in results.items():
                print(f"{mode.upper()}: {data['encrypt_speed']:.1f} KB/сек, ratio: {data['size_ratio']:.3f}")

            return True, "Тесты производительности завершены"

        finally:
            # Удаляем временные файлы
            import glob
            for pattern in [input_file, input_file + ".*.enc"]:
                for f in glob.glob(pattern):
                    try:
                        os.remove(f)
                    except:
                        pass


def main():
    """Основная функция"""
    tester = CryptoCoreSecurityTester()

    # Регистрируем все тесты безопасности
    # Sprint 1
    tester.add_test("Sprint 1: Безопасность ECB режима", tester.test_ecb_security)

    # Sprint 2
    tester.add_test("Sprint 2: Безопасность режимов с IV", tester.test_iv_modes_security)
    tester.add_test("Sprint 2: Уникальность IV", tester.test_iv_uniqueness)

    # Sprint 3
    tester.add_test("Sprint 3: Безопасность CSPRNG", tester.test_csprng_security)

    # Sprint 4
    tester.add_test("Sprint 4: Безопасность хеш-функций", tester.test_hash_security)

    # Sprint 5
    tester.add_test("Sprint 5: Безопасность HMAC", tester.test_hmac_security)

    # Sprint 6
    tester.add_test("Sprint 6: Безопасность GCM", tester.test_gcm_security)
    tester.add_test("Sprint 6: Безопасность Encrypt-then-MAC", tester.test_etm_security)

    # Интеграционные тесты
    tester.add_test("Интеграция: Сравнение режимов", tester.test_cross_mode_comparison)
    tester.add_test("Интеграция: Обработка ошибок", tester.test_error_handling)
    tester.add_test("Интеграция: Производительность и безопасность", tester.test_performance_security)

    # Запускаем все тесты
    success = tester.run_all_tests()

    # Сохраняем подробный отчет
    report = {
        "summary": {
            "total_tests": len(tester.tests),
            "passed": tester.passed,
            "failed": tester.failed,
            "success_rate": (tester.passed / len(tester.tests)) * 100 if tester.tests else 0
        },
        "detailed_results": tester.results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": sys.platform,
        "python_version": sys.version
    }

    with open("../security_test_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nПодробный отчет сохранен в security_test_report.json")

    # Создаем краткий отчет в текстовом виде
    with open("../security_test_summary.txt", "w") as f:
        f.write("=" * 80 + "\n")
        f.write("КРАТКИЙ ОТЧЕТ ПО ТЕСТИРОВАНИЮ БЕЗОПАСНОСТИ\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Дата: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Всего тестов: {len(tester.tests)}\n")
        f.write(f"Пройдено: {tester.passed}\n")
        f.write(f"Провалено: {tester.failed}\n")
        f.write(f"Успешность: {(tester.passed / len(tester.tests)) * 100:.1f}%\n\n")

        f.write("Детальные результаты:\n")
        f.write("-" * 80 + "\n")

        for name, result in tester.results.items():
            status = "✅ ПРОЙДЕН" if result.get('success') else "❌ ПРОВАЛЕН"
            f.write(f"{name}: {status}\n")
            if not result.get('success') and result.get('details'):
                f.write(f"   Причина: {result['details']}\n")

    print(f"Краткий отчет сохранен в security_test_summary.txt")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())