"""
Key hierarchy function for deriving multiple keys from a master key.
Simplified HMAC-based derivation similar to HKDF.
"""

import struct
from typing import Union
from cryptocore.mac.hmac import HMAC


def derive_key(
        master_key: bytes,
        context: Union[str, bytes],
        length: int = 32
) -> bytes:
    """
    Derive a key from a master key using deterministic HMAC-based method.

    Args:
        master_key: Master key bytes
        context: Context string (identifies key purpose)
        length: Desired key length in bytes

    Returns:
        Derived key as bytes

    Note:
        Derivation formula: HMAC(master_key, context || counter)
        Different contexts produce completely different keys.
    """
    if isinstance(context, str):
        context = context.encode('utf-8')

    if length <= 0:
        raise ValueError("Key length must be positive")

    derived = b''
    counter = 1

    # ИСПРАВЛЕНИЕ: Создаем новый HMAC объект для каждой итерации
    # или используем один объект правильно

    while len(derived) < length:
        # T_i = HMAC(master_key, context || INT_32_BE(counter))
        counter_bytes = struct.pack('>I', counter)

        # Вариант 1: Создаем новый HMAC объект каждый раз (более безопасно)
        hmac = HMAC(master_key, 'sha256')
        block = hmac.compute(context + counter_bytes)

        derived += block
        counter += 1

    # Return exactly the requested length
    return derived[:length]


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract step (optional, for more complete HKDF).

    Args:
        salt: Optional salt
        ikm: Input key material

    Returns:
        Pseudo-random key (PRK)
    """
    if salt is None or len(salt) == 0:
        # Use zero salt
        salt = b'\x00' * 32

    hmac = HMAC(salt, 'sha256')
    return hmac.compute(ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand step (optional).

    Args:
        prk: Pseudo-random key from extract step
        info: Context and application specific information
        length: Length of output keying material in bytes

    Returns:
        Output keying material
    """
    hmac = HMAC(prk, 'sha256')

    n = (length + 31) // 32  # SHA-256 output is 32 bytes
    if n > 255:
        raise ValueError("Output length too large")

    okm = b''
    previous = b''

    for i in range(1, n + 1):
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        current_input = previous + info + bytes([i])
        current = hmac.compute(current_input)
        okm += current
        previous = current

    return okm[:length]


def derive_multiple_keys(
        master_key: bytes,
        context: Union[str, bytes],
        num_keys: int = 1,
        key_length: int = 32
) -> list:
    """
    Derive multiple unique keys from a master key and context.

    Args:
        master_key: Master key bytes
        context: Base context string
        num_keys: Number of keys to derive
        key_length: Length of each key in bytes

    Returns:
        List of derived keys

    Guarantee:
        All returned keys will be unique (with cryptographic probability)
    """
    if isinstance(context, str):
        context = context.encode('utf-8')

    if num_keys < 1:
        raise ValueError("Number of keys must be >= 1")

    keys = []

    for i in range(num_keys):
        # Добавляем индекс к контексту для уникальности
        unique_context = context + struct.pack('>I', i)
        key = derive_key(master_key, unique_context, key_length)
        keys.append(key)

    return keys


def test_key_uniqueness_internal():
    """Internal test for key uniqueness."""
    import secrets

    master_key = secrets.token_bytes(32)
    context = b"encryption"

    keys_set = set()

    for i in range(1000):
        key = derive_key(master_key, context + str(i).encode(), 32)
        key_hex = key.hex()

        if key_hex in keys_set:
            print(f"ERROR: Duplicate key at iteration {i}")
            return False

        keys_set.add(key_hex)

    print(f"SUCCESS: Generated {len(keys_set)} unique keys")
    return True