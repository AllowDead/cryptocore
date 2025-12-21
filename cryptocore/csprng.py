import os


def generate_random_bytes(num_bytes: int) -> bytes:
    """
    Генерирует криптографически стойкую случайную последовательность байт.

    Args:
        num_bytes: Количество байт для генерации

    Returns:
        bytes: Случайная байтовая строка

    Raises:
        RuntimeError: Если генерация случайных чисел не удалась
    """
    if num_bytes <= 0:
        raise ValueError("num_bytes must be positive")

    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise RuntimeError(f"Failed to generate random bytes: {str(e)}")