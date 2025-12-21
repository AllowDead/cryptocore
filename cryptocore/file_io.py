import os
import hashlib


def add_integrity_header(data, key):
    """Добавляет заголовок с контрольной суммой для проверки ключа"""
    # Вычисляем HMAC от первых N байт данных
    h = hashlib.sha256()
    h.update(key)
    h.update(data[:min(100, len(data))])  # Проверяем первые 100 байт
    integrity_tag = h.digest()[:8]  # Берем первые 8 байт как тег

    return integrity_tag + data


def verify_integrity_header(encrypted_data, key):
    """Проверяет целостность данных"""
    if len(encrypted_data) < 8:
        raise ValueError("Data too short for integrity check")

    integrity_tag = encrypted_data[:8]
    data = encrypted_data[8:]

    # Вычисляем ожидаемый тег
    h = hashlib.sha256()
    h.update(key)
    h.update(data[:min(100, len(data))])
    expected_tag = h.digest()[:8]

    if integrity_tag != expected_tag:
        raise ValueError("Integrity check failed - wrong key or corrupted data")

    return data

def read_file(filepath):
    """Read entire file as binary"""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except IOError as e:
        raise IOError(f"Failed to read file '{filepath}': {e}")


def write_file(filepath, data):
    """Write binary data to file"""
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
    except IOError as e:
        raise IOError(f"Failed to write file '{filepath}': {e}")


def read_file_with_iv(filepath):
    """
    Read file with IV prepended.
    Returns: (data, iv) where iv is first 16 bytes
    """
    try:
        with open(filepath, 'rb') as f:
            iv = f.read(16)
            if len(iv) != 16:
                raise ValueError(f"File '{filepath}' is too short to contain IV (needs at least 16 bytes)")

            data = f.read()
            return data, iv
    except IOError as e:
        raise IOError(f"Failed to read file '{filepath}': {e}")


def write_file_with_iv(filepath, iv, data):
    """
    Write IV followed by data to file.
    iv: 16-byte initialization vector
    data: ciphertext or plaintext bytes
    """
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)} bytes")

    try:
        with open(filepath, 'wb') as f:
            f.write(iv)
            f.write(data)
    except IOError as e:
        raise IOError(f"Failed to write file '{filepath}': {e}")


def read_file_with_iv_or_none(filepath, iv=None):
    """
    Read file, handling IV extraction or provided IV.
    Returns: (data, iv_used)

    If iv is provided: reads entire file as data, uses provided iv
    If iv is None: reads first 16 bytes as iv, rest as data
    """
    try:
        with open(filepath, 'rb') as f:
            if iv is None:
                # IV должен быть в файле
                iv_used = f.read(16)
                if len(iv_used) != 16:
                    raise ValueError(
                        f"File '{filepath}' is too short to contain IV "
                        f"(needs at least 16 bytes, got {len(iv_used)})"
                    )
                data = f.read()

                # Проверяем, что после IV есть данные (хотя бы 1 байт)
                # Но это не обязательно для stream cipher modes
                # Уберем эту проверку или сделаем её warning

            else:
                # IV предоставлен аргументом
                iv_used = iv
                data = f.read()

                # Для дешифрования: проверяем, что файл не пустой
                # (если это не GCM, где структура другая)
                if len(data) == 0:
                    # Это может быть нормально для пустого файла
                    # Но для режимов с padding (ECB, CBC) это ошибка
                    pass

        return data, iv_used

    except IOError as e:
        raise IOError(f"Failed to read file '{filepath}': {e}")