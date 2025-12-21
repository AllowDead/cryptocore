# generate_test_keys.py
# !/usr/bin/env python3
"""
Скрипт для генерации тестовых ключей для HMAC
"""

import os


def generate_keys():
    """Генерация ключей для тестирования HMAC."""

    print("=== Генерация тестовых ключей для HMAC ===\n")

    # 1. Короткие ключи (16 байт)
    print("1. КЛЮЧИ КОРОЧЕ РАЗМЕРА БЛОКА (16 байт):")
    short_keys = [
        "00112233445566778899aabbccddeeff",  # Последовательные байты
        "fedcba98765432100123456789abcdef",  # Обратная последовательность
        "deadbeefcafebabe0123456789abcdef",  # Случайный паттерн
        "1234567890abcdef1234567890abcdef",  # Еще один вариант
    ]

    for i, key in enumerate(short_keys, 1):
        key_bytes = bytes.fromhex(key)
        print(f"   Ключ {i}: {key}")
        print(f"      Длина: {len(key_bytes)} байт, {len(key)} hex символов")
        print(f"      Пример использования:")
        print(f"      cryptocore dgst --algorithm sha256 --hmac --key {key} --input file.txt")
        print()

    # 2. Ключи размером с блок (64 байта)
    print("2. КЛЮЧИ РАЗМЕРОМ С БЛОК (64 байта):")

    # Генерация последовательного ключа 0x00-0x3F
    block_key_parts = []
    for i in range(4):
        start = i * 16
        row = "".join(f"{start + j:02x}" for j in range(16))
        block_key_parts.append(row)

    block_key = "".join(block_key_parts)

    block_keys = [
        block_key,  # 0x00-0x3F
        "00" * 64,  # Все нули
        "ff" * 64,  # Все 0xFF
        "0123456789abcdef" * 4,  # Паттерн повторяется 4 раза
    ]

    for i, key in enumerate(block_keys, 1):
        key_bytes = bytes.fromhex(key)
        print(f"   Ключ {i}: {key[:32]}...{key[-32:]}")
        print(f"      Длина: {len(key_bytes)} байт, {len(key)} hex символов")
        print(f"      Пример использования:")
        print(f"      cryptocore dgst --algorithm sha256 --hmac --key {key} --input file.txt")
        print()

    # 3. Длинные ключи (100+ байт)
    print("3. КЛЮЧИ ДЛИННЕЕ РАЗМЕРА БЛОКА (100 байт):")

    # Генерация длинного ключа 0x00-0x63
    long_key_parts = []
    for i in range(6):
        start = i * 16
        row = "".join(f"{start + j:02x}" for j in range(16))
        long_key_parts.append(row)
    # Добавляем последние 4 байта
    long_key_parts.append("".join(f"{96 + j:02x}" for j in range(4)))

    long_key_sequential = "".join(long_key_parts)

    long_keys = [
        long_key_sequential,  # 0x00-0x63
        "aa" * 100,  # 100 байт 0xAA
        "0123456789abcdef" * 12 + "deadbeef",  # Паттерн + окончание
    ]

    for i, key in enumerate(long_keys, 1):
        key_bytes = bytes.fromhex(key)
        print(f"   Ключ {i}: {key[:32]}...{key[-32:]}")
        print(f"      Длина: {len(key_bytes)} байт, {len(key)} hex символов")
        print(f"      Пример использования (обрезанный для наглядности):")
        short_key_display = key[:64] + "..." + key[-32:]
        print(f"      cryptocore dgst --algorithm sha256 --hmac --key {short_key_display} --input file.txt")
        print()

    print("=== Все ключи сгенерированы ===")

    # Сохранение ключей в файл для тестирования
    with open("test_hmac_keys.txt", "w") as f:
        f.write("# Test HMAC Keys\n\n")

        f.write("## Short Keys (16 bytes)\n")
        for key in short_keys:
            f.write(f"{key}\n")

        f.write("\n## Block-size Keys (64 bytes)\n")
        for key in block_keys:
            f.write(f"{key}\n")

        f.write("\n## Long Keys (100+ bytes)\n")
        for key in long_keys:
            f.write(f"{key}\n")

    print(f"\nКлючи сохранены в файл: test_hmac_keys.txt")


def test_hmac_with_keys():
    """Тестирование HMAC со сгенерированными ключами."""

    print("\n=== Тестирование HMAC с разными ключами ===")

    # Импортируем HMAC
    try:
        from cryptocore.mac.hmac import HMAC
    except ImportError:
        print("Ошибка: не удалось импортировать HMAC модуль")
        return

    test_data = b"Test message for HMAC verification"

    # Тестовые ключи из разных категорий
    test_keys = [
        ("short_key", "00112233445566778899aabbccddeeff"),
        ("block_key", "00" * 64),
        ("long_key", "aa" * 100),
    ]

    for name, key_hex in test_keys:
        print(f"\nТестирование с {name}:")
        print(f"  Длина ключа: {len(bytes.fromhex(key_hex))} байт")

        try:
            hmac = HMAC(key_hex)
            result = hmac.compute_hex(test_data)

            print(f"  HMAC успешно вычислен: {result[:16]}...{result[-16:]}")

            # Проверка верификации
            verify_result = hmac.verify(test_data, result)
            print(f"  Верификация: {'ПРОЙДЕНА' if verify_result else 'НЕ ПРОЙДЕНА'}")

        except Exception as e:
            print(f"  Ошибка: {e}")


if __name__ == "__main__":
    generate_keys()
    test_hmac_with_keys()