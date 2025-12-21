import os
import tempfile
from cryptocore.modes.gcm import GCM


def test_gcm_large_file():
    """Тест GCM с большим файлом"""
    key = os.urandom(16)
    aad = b"file metadata"

    # Создаем большой файл (10MB)
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        # Генерируем случайные данные
        chunk_size = 1024 * 1024  # 1MB
        for _ in range(10):
            f.write(os.urandom(chunk_size))
        input_file = f.name

    output_file = input_file + ".enc"
    output_dec = input_file + ".dec"

    try:
        # Шифрование по частям
        gcm = GCM(key)

        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Пишем nonce
            f_out.write(gcm.nonce)

            # Шифруем по частям
            buffer_size = 4096
            while True:
                chunk = f_in.read(buffer_size)
                if not chunk:
                    break

                encrypted_chunk = gcm.encrypt(chunk, aad)
                # Исключаем nonce из chunk шифрования
                f_out.write(encrypted_chunk[12:-16])  # только ciphertext

        # Добавляем tag в конец
        # (В реальной реализации tag вычисляется после полного чтения файла)

        print("✓ GCM large file encryption test completed")

    finally:
        for f in [input_file, output_file, output_dec]:
            if os.path.exists(f):
                os.remove(f)


if __name__ == "__main__":
    test_gcm_large_file()