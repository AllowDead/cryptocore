#!/usr/bin/env python3
"""
Комплексный тест всего функционала CryptoCore (Sprints 1-6)
Проверяет все режимы, функции и обработку ошибок.
"""

import os
import sys
import tempfile
import subprocess
import hashlib
import json


def run_command(cmd, description, expect_success=True, expected_error=None):
    """Запустить команду и проверить результат"""
    print(f"\n{'=' * 60}")
    print(f"Тест: {description}")
    print(f"Команда: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT:\n{result.stdout}")
    if result.stderr:
        print(f"STDERR:\n{result.stderr}")

    if expect_success:
        if result.returncode != 0:
            print(f"❌ ОШИБКА: Команда завершилась с ошибкой, ожидался успех")
            return False
        else:
            print(f"✅ УСПЕХ")
            return True
    else:
        if result.returncode == 0:
            print(f"❌ ОШИБКА: Команда завершилась успешно, ожидалась ошибка")
            return False
        elif expected_error and expected_error not in result.stderr:
            print(f"❌ ОШИБКА: Ожидалось сообщение '{expected_error}', не найдено")
            return False
        else:
            print(f"✅ УСПЕХ (ожидаемая ошибка)")
            return True


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
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        return f1.read() == f2.read()


def get_file_hash(filepath):
    """Получить SHA-256 хеш файла"""
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


class CryptoCoreTester:
    def __init__(self):
        # Определяем путь к cryptocore
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(self.script_dir)
        self.cryptocore_cmd = [sys.executable, os.path.join(project_root, "cryptocore", "cli_parser.py")]

        # Тестовые данные
        self.test_key = "00112233445566778899aabbccddeeff"
        self.test_plaintext = b"This is a test message for CryptoCore testing. " * 10
        self.test_aad = "aabbccddeeff00112233445566778899"
        self.test_mac_key = "33445566778899aabbccddeeff00112233445566778899aabbcc"

        # Список тестов
        self.tests = []
        self.passed = 0
        self.failed = 0

    def add_test(self, name, func):
        """Добавить тест в список"""
        self.tests.append((name, func))

    def run_all_tests(self):
        """Запустить все тесты"""
        print("=" * 80)
        print("НАЧАЛО КОМПЛЕКСНОГО ТЕСТИРОВАНИЯ CRYPTOCORE (Sprints 1-6)")
        print("=" * 80)

        for name, test_func in self.tests:
            print(f"\n{'#' * 60}")
            print(f"Запуск теста: {name}")
            print(f"{'#' * 60}")

            try:
                if test_func():
                    self.passed += 1
                    print(f"✅ Тест '{name}' ПРОЙДЕН")
                else:
                    self.failed += 1
                    print(f"❌ Тест '{name}' ПРОВАЛЕН")
            except Exception as e:
                self.failed += 1
                print(f"❌ Тест '{name}' ВЫЗВАЛ ИСКЛЮЧЕНИЕ: {e}")
                import traceback
                traceback.print_exc()

        # Итоги
        print(f"\n{'=' * 80}")
        print("ИТОГИ ТЕСТИРОВАНИЯ:")
        print(f"Всего тестов: {len(self.tests)}")
        print(f"Пройдено: {self.passed}")
        print(f"Провалено: {self.failed}")
        print(f"Успешность: {(self.passed / len(self.tests)) * 100:.1f}%")
        print("=" * 80)

        return self.failed == 0

    # ==================== SPRINT 1: ECB MODE ====================
    def test_sprint1_ecb_basic(self):
        """Тест базового ECB шифрования/дешифрования"""
        # Создаем тестовый файл
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # Шифрование ECB
            cmd_enc = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--encrypt",
                "--key", self.test_key,
                "--input", input_file,
                "--output", input_file + ".enc"
            ]

            if not run_command(cmd_enc, "ECB шифрование"):
                return False

            # Дешифрование ECB
            cmd_dec = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--decrypt",
                "--key", self.test_key,
                "--input", input_file + ".enc",
                "--output", input_file + ".dec"
            ]

            if not run_command(cmd_dec, "ECB дешифрование"):
                return False

            # Проверка, что файлы идентичны
            if not compare_files(input_file, input_file + ".dec"):
                print("❌ ОШИБКА: Расшифрованный файл не совпадает с оригиналом")
                return False

            return True

        finally:
            # Очистка
            for f in [input_file, input_file + ".enc", input_file + ".dec"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint1_errors(self):
        """Тест обработки ошибок в ECB режиме"""
        test_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Неверный формат ключа (не hex)
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--encrypt",
                "--key", "NOT_A_HEX_KEY",
                "--input", test_file,
                "--output", test_file + ".enc"
            ]

            if not run_command(cmd, "ECB с неверным форматом ключа (не hex)",
                               expect_success=False, expected_error="Invalid key format"):
                return False

            # 2. Неправильная длина ключа (не 16 байт)
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--encrypt",
                "--key", "001122",  # Слишком короткий
                "--input", test_file,
                "--output", test_file + ".enc"
            ]

            if not run_command(cmd, "ECB с неправильной длиной ключа",
                               expect_success=False, expected_error="requires 16-byte key"):
                return False

            # 3. Отсутствует обязательный аргумент --key при дешифровании
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--decrypt",
                "--input", test_file,
                "--output", test_file + ".dec"
            ]

            if not run_command(cmd, "ECB дешифрование без ключа",
                               expect_success=False, expected_error="Key is required"):
                return False

            # 4. Одновременно --encrypt и --decrypt
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "ecb",
                "--encrypt",
                "--decrypt",  # Конфликт
                "--key", self.test_key,
                "--input", test_file,
                "--output", test_file + ".enc"
            ]

            if not run_command(cmd, "ECB с одновременным --encrypt и --decrypt",
                               expect_success=False, expected_error="argument --decrypt: not allowed with argument --encrypt"):
                return False

            return True

        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    # ==================== SPRINT 2: MODES (CBC, CFB, OFB, CTR) ====================
    def test_sprint2_modes(self):
        """Тест всех режимов шифрования из Sprint 2"""
        modes = ["cbc", "cfb", "ofb", "ctr"]

        for mode in modes:
            print(f"\n--- Тестирование режима {mode.upper()} ---")

            input_file = create_test_file(self.test_plaintext, binary=True)

            try:
                # Шифрование
                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + ".enc"
                ]

                if not run_command(cmd_enc, f"{mode.upper()} шифрование"):
                    return False

                # Дешифрование
                cmd_dec = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--input", input_file + ".enc",
                    "--output", input_file + ".dec"
                ]

                if not run_command(cmd_dec, f"{mode.upper()} дешифрование"):
                    return False

                # Проверка
                if not compare_files(input_file, input_file + ".dec"):
                    print(f"❌ ОШИБКА: {mode.upper()} - файлы не совпадают")
                    return False

                print(f"✅ {mode.upper()} тест пройден")

            finally:
                for f in [input_file, input_file + ".enc", input_file + ".dec"]:
                    if os.path.exists(f):
                        os.remove(f)

        return True

    def test_sprint2_iv_handling(self):
        """Тест обработки IV в режимах с IV"""
        modes_with_iv = ["cbc", "cfb", "ofb", "ctr"]
        test_iv = "aabbccddeeff00112233445566778899"

        for mode in modes_with_iv:
            print(f"\n--- Тестирование IV в режиме {mode.upper()} ---")

            input_file = create_test_file(self.test_plaintext, binary=True)

            try:
                # 1. Шифрование (IV генерируется автоматически)
                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + ".enc"
                ]

                if not run_command(cmd_enc, f"{mode.upper()} шифрование с auto-IV"):
                    return False

                # 2. Дешифрование с указанием НЕПРАВИЛЬНОГО IV
                cmd_dec = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--iv", test_iv,  # Неправильный IV
                    "--input", input_file + ".enc",
                    "--output", input_file + ".dec"
                ]

                # Команда должна выполниться успешно
                if not run_command(cmd_dec, f"{mode.upper()} с неправильным IV"):
                    return False

                # НО: файл должен быть нечитаемым или отличаться от оригинала
                if compare_files(input_file, input_file + ".dec"):
                    print(f"❌ ОШИБКА: {mode.upper()} - файлы совпадают даже с неправильным IV!")
                    return False

                print(f"✅ {mode.upper()} правильно дешифровал с неправильным IV (но результат неверный)")

                # 3. Дешифрование без IV (читает из файла) - должно работать
                cmd_dec_no_iv = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--input", input_file + ".enc",
                    "--output", input_file + ".dec2"
                ]

                if not run_command(cmd_dec_no_iv, f"{mode.upper()} дешифрование без IV (читает из файла)"):
                    return False

                if not compare_files(input_file, input_file + ".dec2"):
                    print(f"❌ ОШИБКА: {mode.upper()} - дешифрование без IV не удалось")
                    return False

                print(f"✅ {mode.upper()} IV тест пройден")

            finally:
                for f in [input_file, input_file + ".enc", input_file + ".dec",
                          input_file + ".dec2"]:
                    if os.path.exists(f):
                        os.remove(f)

        return True

    # ==================== SPRINT 3: CSPRNG и генерация ключей ====================
    def test_sprint3_key_generation(self):
        """Тест автоматической генерации ключей"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # Шифрование с автоматической генерацией ключа
            cmd_enc = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "cbc",
                "--encrypt",
                # НЕТ --key! Должен сгенерироваться автоматически
                "--input", input_file,
                "--output", input_file + ".enc"
            ]

            if not run_command(cmd_enc, "Шифрование с автоматической генерацией ключа"):
                return False

            # Ключ должен быть напечатан в stdout
            # В реальном тесте нужно было бы извлечь его из вывода
            print("⚠️  Примечание: Для полного теста нужно извлечь сгенерированный ключ из вывода")

            return True

        finally:
            for f in [input_file, input_file + ".enc"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint3_weak_key_detection(self):
        """Тест обнаружения слабых ключей (предупреждение)"""
        weak_keys = [
            ("00000000000000000000000000000000", "all zeros"),
            ("ffffffffffffffffffffffffffffffff", "all ones"),
            ("00112233445566778899aabbccddeeff", "sequential"),
        ]

        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            for key_hex, description in weak_keys:
                cmd = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", "ecb",
                    "--encrypt",
                    "--key", key_hex,
                    "--input", input_file,
                    "--output", input_file + ".enc"
                ]

                # Должно выдать предупреждение, но не ошибку
                if not run_command(cmd, f"Слабый ключ ({description})", expect_success=True):
                    return False

                # Проверяем, что в stderr есть предупреждение
                result = subprocess.run(cmd, capture_output=True, text=True)
                if "warning" not in result.stderr.lower() and "Warning" not in result.stderr:
                    print(f"⚠️  Нет предупреждения для слабого ключа: {description}")

            return True

        finally:
            if os.path.exists(input_file):
                os.remove(input_file)

    # ==================== SPRINT 4: ХЕШ-ФУНКЦИИ ====================
    def test_sprint4_hash_functions(self):
        """Тест хеш-функций"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            algorithms = ["sha256", "sha3-256"]

            for algo in algorithms:
                # Вычисление хеша
                cmd_hash = self.cryptocore_cmd + [
                    "dgst",
                    "--algorithm", algo,
                    "--input", input_file
                ]

                if not run_command(cmd_hash, f"{algo.upper()} вычисление хеша"):
                    return False

                # Вычисление хеша с сохранением в файл
                cmd_hash_file = self.cryptocore_cmd + [
                    "dgst",
                    "--algorithm", algo,
                    "--input", input_file,
                    "--output", input_file + ".hash"
                ]

                if not run_command(cmd_hash_file, f"{algo.upper()} хеш в файл"):
                    return False

                # Проверяем, что файл создан
                if not os.path.exists(input_file + ".hash"):
                    print(f"❌ Файл хеша не создан для {algo}")
                    return False

                print(f"✅ {algo.upper()} тест пройден")

            return True

        finally:
            for f in [input_file, input_file + ".hash"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint4_hash_verification(self):
        """Тест проверки хешей (интероперабельность)"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Вычисляем хеш через cryptocore
            hash_file = input_file + ".sha256"
            cmd_hash = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--input", input_file,
                "--output", hash_file
            ]

            if not run_command(cmd_hash, "Вычисление SHA-256 для проверки"):
                return False

            # 2. Вычисляем хеш через системный sha256sum для сравнения
            result = subprocess.run(["sha256sum", input_file], capture_output=True, text=True)

            # ИСПРАВЛЕНИЕ: Обрабатываем разные форматы вывода sha256sum
            system_output = result.stdout.strip()

            # Варианты формата:
            # 1. "hash filename" (Linux/Mac)
            # 2. "\hash filename" (Windows git bash с экранированием)
            # 3. "hash *filename" (некоторые версии)

            # Извлекаем хеш (первые 64 hex символа, игнорируя начальный \ или *)
            import re
            hash_match = re.search(r'[\\\*]?([0-9a-fA-F]{64})', system_output)

            if not hash_match:
                print(f"❌ Не удалось извлечь хеш из вывода sha256sum: {system_output}")
                return False

            system_hash = hash_match.group(1).lower()  # Приводим к нижнему регистру

            # 3. Читаем хеш из файла cryptocore
            with open(hash_file, 'r') as f:
                cryptocore_output = f.read().strip()
                # Формат: HASH_VALUE FILENAME
                # Извлекаем первые 64 символа (хеш)
                cryptocore_hash = cryptocore_output[:64].lower()  # Приводим к нижнему регистру

            # 4. Сравниваем
            if system_hash != cryptocore_hash:
                print(f"❌ Хеши не совпадают!")
                print(f"   System: {system_hash}")
                print(f"   CryptoCore: {cryptocore_hash}")
                print(f"   Полный вывод sha256sum: {system_output}")
                print(f"   Полный вывод cryptocore: {cryptocore_output}")
                return False

            print(f"✅ SHA-256 интероперабельность подтверждена")
            print(f"   Hash: {system_hash}")
            return True

        finally:
            for f in [input_file, hash_file]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== SPRINT 5: HMAC ====================
    def test_sprint5_hmac(self):
        """Тест HMAC функций"""
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

            if not run_command(cmd_hmac, "Генерация HMAC-SHA256"):
                return False

            # 2. Проверка HMAC (должна пройти)
            cmd_verify = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", self.test_key,
                "--input", input_file,
                "--verify", input_file + ".hmac"
            ]

            if not run_command(cmd_verify, "Проверка HMAC (правильный ключ)", expect_success=True):
                return False

            # 3. Проверка с неправильным ключом (должна провалиться)
            wrong_key = "ffeeddccbbaa99887766554433221100"
            cmd_verify_wrong = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", wrong_key,
                "--input", input_file,
                "--verify", input_file + ".hmac"
            ]

            if not run_command(cmd_verify_wrong, "Проверка HMAC (неправильный ключ)",
                               expect_success=False, expected_error="HMAC verification failed"):
                return False

            # 4. Проверка с измененным файлом (должна провалиться)
            # Создаем измененный файл
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

            if not run_command(cmd_verify_modified, "Проверка HMAC (измененный файл)",
                               expect_success=False, expected_error="HMAC verification failed"):
                return False

            return True

        finally:
            for f in [input_file, input_file + ".hmac", input_file + ".modified"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint5_hmac_errors(self):
        """Тест ошибок HMAC"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. HMAC без ключа
            cmd = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",  # Нет --key
                "--input", input_file
            ]

            if not run_command(cmd, "HMAC без ключа",
                               expect_success=False, expected_error="--key is required"):
                return False

            # 2. --verify без --hmac
            cmd = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--verify", "somefile.txt",  # Нет --hmac
                "--input", input_file
            ]

            if not run_command(cmd, "--verify без --hmac",
                               expect_success=False, expected_error="can only be used with --hmac"):
                return False

            # 3. --verify и --output одновременно
            cmd = self.cryptocore_cmd + [
                "dgst",
                "--algorithm", "sha256",
                "--hmac",
                "--key", self.test_key,
                "--verify", "somefile.txt",
                "--output", "another.txt",
                "--input", input_file
            ]

            if not run_command(cmd, "--verify и --output одновременно",
                               expect_success=False, expected_error="cannot be used together"):
                return False

            return True

        finally:
            if os.path.exists(input_file):
                os.remove(input_file)

    # ==================== SPRINT 6: GCM и AEAD ====================
    def test_sprint6_gcm_basic(self):
        """Тест базового GCM режима"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Шифрование GCM с AAD
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

            if not run_command(cmd_enc, "GCM шифрование с AAD"):
                return False

            # 2. Дешифрование GCM с правильным AAD
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

            if not run_command(cmd_dec, "GCM дешифрование с правильным AAD"):
                return False

            # Проверка
            if not compare_files(input_file, input_file + ".dec"):
                print("❌ ОШИБКА: GCM - файлы не совпадают")
                return False

            return True

        finally:
            for f in [input_file, input_file + ".gcm", input_file + ".dec"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint6_gcm_auth_failure(self):
        """Тест аутентификационных ошибок GCM"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Шифруем с правильным AAD
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

            if not run_command(cmd_enc, "GCM шифрование (для теста ошибок)"):
                return False

            # 2. Пытаемся дешифровать с неправильным AAD
            wrong_aad = "00000000000000000000000000000000"
            cmd_dec_wrong = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key,
                "--input", input_file + ".gcm",
                "--output", input_file + ".dec",
                "--aad", wrong_aad
            ]

            if not run_command(cmd_dec_wrong, "GCM с неправильным AAD (ожидается ошибка)",
                               expect_success=False, expected_error="Authentication failed"):
                return False

            # Проверяем, что выходной файл не создан при ошибке
            if os.path.exists(input_file + ".dec"):
                print("❌ ОШИБКА: Выходной файл создан даже при ошибке аутентификации")
                return False

            # 3. Изменяем зашифрованный файл (повреждаем тег)
            with open(input_file + ".gcm", 'rb') as f:
                gcm_data = bytearray(f.read())

            # Изменяем последний байт тега
            gcm_data[-1] ^= 0x01

            with open(input_file + ".tampered", 'wb') as f:
                f.write(gcm_data)

            cmd_dec_tampered = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key,
                "--input", input_file + ".tampered",
                "--output", input_file + ".dec2",
                "--aad", self.test_aad
            ]

            if not run_command(cmd_dec_tampered, "GCM с измененным тегом (ожидается ошибка)",
                               expect_success=False, expected_error="Authentication failed"):
                return False

            return True

        finally:
            for f in [input_file, input_file + ".gcm", input_file + ".dec",
                      input_file + ".tampered", input_file + ".dec2"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint6_encrypt_then_mac(self):
        """Тест Encrypt-then-MAC режима"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. Шифрование Encrypt-then-MAC
            cmd_enc = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--encrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key,
                "--input", input_file,
                "--output", input_file + ".etm",
                "--aad", "636f6e7465787420696e666f"
            ]

            if not run_command(cmd_enc, "Encrypt-then-MAC шифрование"):
                return False

            # 2. Дешифрование Encrypt-then-MAC с правильными ключами
            cmd_dec = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key,
                "--mac-key", self.test_mac_key,
                "--input", input_file + ".etm",
                "--output", input_file + ".dec",
                "--aad", "636f6e7465787420696e666f"
            ]

            if not run_command(cmd_dec, "Encrypt-then-MAC дешифрование (правильные ключи)"):
                return False

            # Проверка
            if not compare_files(input_file, input_file + ".dec"):
                print("❌ ОШИБКА: ETM - файлы не совпадают")
                return False

            # 3. Дешифрование с неправильным MAC ключом
            wrong_mac_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            cmd_dec_wrong = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "etm",
                "--decrypt",
                "--key", self.test_key,
                "--mac-key", wrong_mac_key,
                "--input", input_file + ".etm",
                "--output", input_file + ".dec2",
                "--aad", "636f6e7465787420696e666f"
            ]

            if not run_command(cmd_dec_wrong, "ETM с неправильным MAC ключом (ожидается ошибка)",
                               expect_success=False, expected_error="Authentication failed"):
                return False

            return True

        finally:
            for f in [input_file, input_file + ".etm", input_file + ".dec", input_file + ".dec2"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_sprint6_gcm_errors(self):
        """Тест ошибок GCM"""
        input_file = create_test_file(self.test_plaintext, binary=True)

        try:
            # 1. GCM без ключа при шифровании (должен сгенерировать)
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--encrypt",
                # Нет --key! Должен сгенерироваться
                "--input", input_file,
                "--output", input_file + ".gcm",
                "--aad", self.test_aad
            ]

            if not run_command(cmd, "GCM шифрование с автогенерацией ключа", expect_success=True):
                return False

            # 2. GCM с неправильной длиной nonce (если поддерживается через --iv)
            cmd = self.cryptocore_cmd + [
                "encrypt",
                "--algorithm", "aes",
                "--mode", "gcm",
                "--decrypt",
                "--key", self.test_key,
                "--iv", "001122",  # Слишком короткий, не 12 байт
                "--input", input_file + ".gcm",
                "--output", input_file + ".dec",
                "--aad", self.test_aad
            ]

            if not run_command(cmd, "GCM с неправильной длиной nonce",
                               expect_success=False, expected_error="must be 12 bytes"):
                return False

            return True

        finally:
            for f in [input_file, input_file + ".gcm", input_file + ".dec"]:
                if os.path.exists(f):
                    os.remove(f)

    # ==================== ИНТЕГРАЦИОННЫЕ ТЕСТЫ ====================
    def test_integration_all_modes(self):
        """Интеграционный тест всех режимов"""
        modes = ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]

        for mode in modes:
            print(f"\n--- Интеграционный тест режима {mode.upper()} ---")

            input_file = create_test_file(self.test_plaintext, binary=True)

            try:
                # Настройки для каждого режима
                extra_args = []
                if mode == "gcm":
                    extra_args = ["--aad", self.test_aad]
                elif mode == "etm":
                    extra_args = ["--mac-key", self.test_mac_key, "--aad", "test context"]

                # Шифрование
                cmd_enc = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--key", self.test_key,
                    "--input", input_file,
                    "--output", input_file + ".enc"
                ] + extra_args

                if not run_command(cmd_enc, f"{mode.upper()} интеграционное шифрование"):
                    return False

                # Дешифрование
                cmd_dec = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--input", input_file + ".enc",
                    "--output", input_file + ".dec"
                ] + extra_args

                if not run_command(cmd_dec, f"{mode.upper()} интеграционное дешифрование"):
                    return False

                # Проверка (кроме etm - он уже проверен отдельно)
                if mode != "etm" and not compare_files(input_file, input_file + ".dec"):
                    print(f"❌ ОШИБКА: {mode.upper()} - файлы не совпадают")
                    return False

                print(f"✅ {mode.upper()} интеграционный тест пройден")

            finally:
                for f in [input_file, input_file + ".enc", input_file + ".dec"]:
                    if os.path.exists(f):
                        os.remove(f)

        return True

    def test_performance(self):
        """Тест производительности с большими файлами"""
        # Создаем большой файл (1MB)
        large_data = os.urandom(1024 * 1024)  # 1MB
        input_file = create_test_file(large_data, binary=True)

        try:
            import time

            modes_to_test = ["ecb", "cbc", "ctr", "gcm"]

            for mode in modes_to_test:
                print(f"\n--- Тест производительности {mode.upper()} ---")

                # Настройки
                extra_args = []
                if mode == "gcm":
                    extra_args = ["--aad", self.test_aad[:32]]  # Более короткий AAD для производительности

                # Шифрование
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
                    print(f"❌ ОШИБКА шифрования {mode}: {result.stderr}")
                    return False

                # Дешифрование
                start = time.time()

                cmd_dec = self.cryptocore_cmd + [
                    "encrypt",
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", self.test_key,
                    "--input", input_file + f".{mode}.enc",
                    "--output", input_file + f".{mode}.dec"
                ] + extra_args

                result = subprocess.run(cmd_dec, capture_output=True)

                decrypt_time = time.time() - start

                if result.returncode != 0:
                    print(f"❌ ОШИБКА дешифрования {mode}: {result.stderr}")
                    return False

                # Проверка
                if not compare_files(input_file, input_file + f".{mode}.dec"):
                    print(f"❌ ОШИБКА: {mode} - файлы не совпадают")
                    return False

                print(f"  Размер: {len(large_data) / 1024:.1f} KB")
                print(
                    f"  Время шифрования: {encrypt_time:.3f} сек ({len(large_data) / encrypt_time / 1024:.1f} KB/сек)")
                print(
                    f"  Время дешифрования: {decrypt_time:.3f} сек ({len(large_data) / decrypt_time / 1024:.1f} KB/сек)")
                print(f"✅ {mode.upper()} производительностный тест пройден")

            return True

        finally:
            # Удаляем все временные файлы
            for pattern in [input_file, input_file + ".*.enc", input_file + ".*.dec"]:
                import glob
                for f in glob.glob(pattern):
                    try:
                        os.remove(f)
                    except:
                        pass


def main():
    """Основная функция"""
    tester = CryptoCoreTester()

    # Регистрируем все тесты
    # Sprint 1
    tester.add_test("Sprint 1: Базовое ECB шифрование/дешифрование", tester.test_sprint1_ecb_basic)
    tester.add_test("Sprint 1: Обработка ошибок ECB", tester.test_sprint1_errors)

    # Sprint 2
    tester.add_test("Sprint 2: Все режимы шифрования", tester.test_sprint2_modes)
    tester.add_test("Sprint 2: Обработка IV", tester.test_sprint2_iv_handling)

    # Sprint 3
    tester.add_test("Sprint 3: Автогенерация ключей", tester.test_sprint3_key_generation)
    tester.add_test("Sprint 3: Обнаружение слабых ключей", tester.test_sprint3_weak_key_detection)

    # Sprint 4
    tester.add_test("Sprint 4: Хеш-функции", tester.test_sprint4_hash_functions)
    tester.add_test("Sprint 4: Проверка хешей", tester.test_sprint4_hash_verification)

    # Sprint 5
    tester.add_test("Sprint 5: HMAC функции", tester.test_sprint5_hmac)
    tester.add_test("Sprint 5: Ошибки HMAC", tester.test_sprint5_hmac_errors)

    # Sprint 6
    tester.add_test("Sprint 6: Базовый GCM", tester.test_sprint6_gcm_basic)
    tester.add_test("Sprint 6: Ошибки аутентификации GCM", tester.test_sprint6_gcm_auth_failure)
    tester.add_test("Sprint 6: Encrypt-then-MAC", tester.test_sprint6_encrypt_then_mac)
    tester.add_test("Sprint 6: Ошибки GCM", tester.test_sprint6_gcm_errors)

    # Интеграционные тесты
    tester.add_test("Интеграция: Все режимы", tester.test_integration_all_modes)
    tester.add_test("Производительность: Большие файлы", tester.test_performance)

    # Запускаем все тесты
    success = tester.run_all_tests()

    # Сохраняем отчет
    report = {
        "total_tests": len(tester.tests),
        "passed": tester.passed,
        "failed": tester.failed,
        "success_rate": (tester.passed / len(tester.tests)) * 100 if tester.tests else 0
    }

    with open("../test_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nОтчет сохранен в test_report.json")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())