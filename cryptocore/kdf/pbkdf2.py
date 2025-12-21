"""
PBKDF2-HMAC-SHA256 implementation following RFC 2898.
Использует hashlib для производительности, но сохраняет нашу реализацию HMAC для верификации.
"""

import struct
import hashlib
from typing import Union


def pbkdf2_hmac_sha256(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int
) -> bytes:
    """
    PBKDF2-HMAC-SHA256 key derivation function.
    Использует hashlib для производительности.

    Args:
        password: Пароль (строка или байты)
        salt: Соль (строка или байты)
        iterations: Количество итераций
        dklen: Длина ключа в байтах

    Returns:
        Производный ключ в виде байтов
    """
    # Преобразование входных данных
    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        # Если salt - hex строка
        if all(c in '0123456789abcdefABCDEF' for c in salt):
            try:
                salt = bytes.fromhex(salt)
            except ValueError:
                salt = salt.encode('utf-8')
        else:
            salt = salt.encode('utf-8')

    if iterations < 1:
        raise ValueError("Iterations must be >= 1")
    if dklen < 1:
        raise ValueError("Key length must be >= 1")

    # ⭐ ИСПОЛЬЗУЕМ HASHLIB ДЛЯ ПРОИЗВОДИТЕЛЬНОСТИ ⭐
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)


def pbkdf2_hmac_sha256_custom(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int
) -> bytes:
    """
    PBKDF2-HMAC-SHA256 с использованием НАШЕЙ реализации HMAC.
    Используется только для верификации и тестов.

    ВАЖНО: Эта версия медленная, но использует нашу реализацию HMAC.
    """
    from cryptocore.mac.hmac import HMAC

    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        if all(c in '0123456789abcdefABCDEF' for c in salt):
            salt = bytes.fromhex(salt)
        else:
            salt = salt.encode('utf-8')

    hlen = 32  # SHA-256 output size
    blocks_needed = (dklen + hlen - 1) // hlen
    derived_key = bytearray()

    for i in range(1, blocks_needed + 1):
        # Блок соли: salt || INT_32_BE(i)
        block_salt = salt + struct.pack('>I', i)

        # U1 = HMAC(password, salt || INT_32_BE(i))
        hmac_obj = HMAC(password, 'sha256')
        u_prev = hmac_obj.compute(block_salt)

        # Накопитель для этого блока
        block_acc = bytearray(u_prev)

        # U2 через Uc
        for _ in range(2, iterations + 1):
            # Uj = HMAC(password, Uj-1)
            hmac_obj = HMAC(password, 'sha256')
            u_current = hmac_obj.compute(u_prev)

            # XOR с накопленным значением
            for k in range(hlen):
                block_acc[k] ^= u_current[k]

            u_prev = u_current

        # Добавляем результат блока
        derived_key.extend(block_acc)

    # Возвращаем точно dklen байт
    return bytes(derived_key[:dklen])


def verify_implementation(verbose=False):
    """
    Проверяет, что наша custom реализация совпадает с hashlib.
    """
    import sys

    test_cases = [
        (b'password', b'salt', 1, 20),
        (b'password', b'salt', 2, 20),
        (b'test', b'salt', 100, 32),
    ]

    all_pass = True

    for password, salt, iterations, dklen in test_cases:
        try:
            # Hashlib результат
            hashlib_result = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)

            # Наша реализация
            custom_result = pbkdf2_hmac_sha256_custom(password, salt, iterations, dklen)

            if hashlib_result != custom_result:
                if verbose:
                    print(f"⚠ ВНИМАНИЕ: Наша реализация PBKDF2 не совпадает с hashlib!")
                    print(f"  Параметры: password={password}, salt={salt}, iterations={iterations}")
                    print(f"  Hashlib: {hashlib_result.hex()[:16]}...")
                    print(f"  Наша: {custom_result.hex()[:16]}...")
                all_pass = False
                break
        except Exception as e:
            if verbose:
                print(f"⚠ Ошибка при проверке реализации: {e}")
            all_pass = False
            break

    if verbose:
        if all_pass:
            print("✅ Наша реализация PBKDF2 корректна (совпадает с hashlib)")
        else:
            print("❌ Наша реализация PBKDF2 имеет ошибки")
            print("   Используется hashlib как fallback")

    return all_pass


# УБИРАЕМ автоматический вызов при импорте!
# Вместо этого можно добавить:
if __name__ == "__main__":
    # Только при прямом запуске файла
    verify_implementation(verbose=True)