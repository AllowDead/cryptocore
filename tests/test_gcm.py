import os
import sys
import tempfile
import subprocess
from cryptocore.modes.gcm import GCM, AuthenticationError


def test_gcm_encrypt_decrypt():
    """Тест шифрования и дешифрования GCM"""
    key = os.urandom(16)
    plaintext = b"Hello, GCM world!"
    aad = b"authenticated data"

    # Шифрование
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad)

    # Дешифрование
    gcm2 = GCM(key, gcm.nonce)
    decrypted, auth_ok = gcm2.decrypt(ciphertext, aad)

    assert auth_ok, "Authentication should succeed"
    assert decrypted == plaintext, "Decrypted text should match original"
    print("✓ GCM encrypt/decrypt test passed")


def test_gcm_aad_tamper():
    """Тест на изменение AAD"""
    key = os.urandom(16)
    plaintext = b"Secret message"
    aad_correct = b"correct"
    aad_wrong = b"wrong"

    # Шифрование с правильным AAD
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad_correct)

    # Попытка дешифрования с неправильным AAD
    gcm2 = GCM(key, gcm.nonce)
    decrypted, auth_ok = gcm2.decrypt(ciphertext, aad_wrong)

    assert not auth_ok, "Authentication should fail with wrong AAD"
    # ИЗМЕНЕНИЕ: проверяем что возвращается пустой bytes вместо None
    assert decrypted == b"", f"No plaintext should be returned on auth failure, got: {decrypted}"
    print("✓ GCM AAD tamper test passed")


def test_gcm_ciphertext_tamper():
    """Тест на изменение шифртекста"""
    key = os.urandom(16)
    plaintext = b"Another secret"
    aad = b"auth data"

    # Шифрование
    gcm = GCM(key)
    ciphertext = gcm.encrypt(plaintext, aad)

    # Изменение шифртекста
    ciphertext_array = bytearray(ciphertext)
    ciphertext_array[20] ^= 0x01  # Изменяем один бит
    tampered = bytes(ciphertext_array)

    # Попытка дешифрования
    gcm2 = GCM(key, gcm.nonce)
    decrypted, auth_ok = gcm2.decrypt(tampered, aad)

    assert not auth_ok, "Authentication should fail with tampered ciphertext"
    print("✓ GCM ciphertext tamper test passed")


def test_gcm_nist_vectors():
    """Тест с векторами из NIST SP 800-38D"""
    # Test Case 1 из NIST
    key = bytes.fromhex("00000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    aad = b""
    plaintext = b""

    gcm = GCM(key, nonce)
    ciphertext = gcm.encrypt(plaintext, aad)

    # Ожидаемый результат: nonce + tag
    # Для пустого plaintext и aad, tag = E_K(J0)
    expected_tag = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
    expected = nonce + expected_tag

    assert ciphertext == expected, f"Got {ciphertext.hex()}, expected {expected.hex()}"
    print("✓ GCM NIST test vector 1 passed")


def test_gcm_cli():
    """Тест командной строки для GCM"""
    import tempfile
    import os
    import sys
    import subprocess

    # Получаем путь к корню проекта
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Путь к основному скрипту (возможно cryptocore/__main__.py или cryptocore/cli.py)
    # Давайте создадим простой wrapper
    script_content = """
import sys
sys.path.insert(0, r'{}')
from cryptocore.cli_parser import main
if __name__ == "__main__":
    main()
""".format(project_root)

    # Создаем временный скрипт
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script_content)
        script_path = f.name

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        plaintext = b"Test data for CLI"
        f.write(plaintext)
        input_file = f.name

    output_enc = input_file + ".enc"
    output_dec = input_file + ".dec"

    key = "00112233445566778899aabbccddeeff"
    aad = "aabbccddeeff00112233445566778899"

    try:
        # Шифрование
        print(f"Input file: {input_file}")
        print(f"Output enc: {output_enc}")

        cmd_enc = [
            sys.executable,
            script_path,
            "encrypt",  # основная команда
            "--algorithm", "aes",
            "--mode", "gcm",
            "--encrypt",
            "--key", key,  # БЕЗ @ в начале!
            "--input", input_file,
            "--output", output_enc,
            "--aad", aad
        ]

        print(f"Encryption command: {' '.join(cmd_enc)}")
        result = subprocess.run(cmd_enc, capture_output=True, text=True)

        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")

        assert result.returncode == 0, f"Encryption failed: {result.stderr}"
        assert os.path.exists(output_enc), f"Output file not created: {output_enc}"

        # Проверяем размер файла
        file_size = os.path.getsize(output_enc)
        print(f"Output file size: {file_size} bytes")
        assert file_size > 0, "Output file is empty"

        with open(output_enc, 'rb') as f:
            encrypted_data = f.read()
            print(f"Encrypted file structure:")
            print(f"  Total size: {len(encrypted_data)} bytes")
            print(f"  First 12 bytes (nonce): {encrypted_data[:12].hex()}")
            print(f"  Last 16 bytes (tag): {encrypted_data[-16:].hex()}")
            print(f"  Middle part (ciphertext): {len(encrypted_data) - 12 - 16} bytes")

            # Проверим, что ciphertext имеет правильную длину
            original_len = len(plaintext)
            # Для GCM ciphertext должен быть той же длины, что и plaintext
            ciphertext_len = len(encrypted_data) - 12 - 16
            print(f"  Original plaintext length: {original_len} bytes")
            print(f"  Ciphertext length: {ciphertext_len} bytes")
            print(f"  Match: {original_len == ciphertext_len}")

        # Дешифрование
        cmd_dec = [
            sys.executable,
            script_path,
            "encrypt",
            "--algorithm", "aes",
            "--mode", "gcm",
            "--decrypt",
            "--key", key,
            "--input", output_enc,
            "--output", output_dec,
            "--aad", aad
        ]

        result = subprocess.run(cmd_dec, capture_output=True, text=True)
        print(f"Decryption return code: {result.returncode}")
        print(f"Decryption stderr: {result.stderr}")

        assert result.returncode == 0, f"Decryption failed: {result.stderr}"
        assert os.path.exists(output_dec), f"Decrypted file not created: {output_dec}"

        with open(output_dec, 'rb') as f:
            decrypted = f.read()

        print(f"Original: {plaintext}")
        print(f"Decrypted: {decrypted}")
        assert decrypted == plaintext, "Decrypted text doesn't match original"

        print("✓ CLI test passed")

    finally:
        # Уборка
        for f in [script_path, input_file, output_enc, output_dec]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass


def test_encrypt_then_mac():
    """Тест Encrypt-then-MAC"""
    from cryptocore.aead_handler import AEADHandler

    enc_key = os.urandom(16)
    mac_key = os.urandom(32)  # Для HMAC-SHA256 нужен ключ 32 байта
    plaintext = b"Data to protect"
    aad = b"Additional context"

    print(f"Enc key (hex): {enc_key.hex()}")
    print(f"MAC key (hex): {mac_key.hex()}")
    print(f"Plaintext: {plaintext}")
    print(f"AAD: {aad}")

    # Шифрование
    ciphertext = AEADHandler.encrypt_then_mac(
        plaintext, enc_key, mac_key, aad, 'ctr'
    )

    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Ciphertext (hex first 32 bytes): {ciphertext[:32].hex()}")

    # Проверяем структуру ciphertext
    # Должно быть: ciphertext + tag
    # Для CTR mode без IV в AEADHandler? Возможно нужно добавить IV

    # Дешифрование с правильными ключами
    try:
        decrypted = AEADHandler.decrypt_and_verify(
            ciphertext, enc_key, mac_key, aad, 'ctr'
        )
        print(f"Decrypted: {decrypted}")
        print(f"Decrypted matches original: {decrypted == plaintext}")

        assert decrypted == plaintext, "Decryption should succeed with correct keys"

    except Exception as e:
        print(f"Decryption failed with error: {e}")

        # Попробуем дебаг: выведем части ciphertext
        if len(ciphertext) >= 16:
            print(f"Last 16 bytes (tag?): {ciphertext[-16:].hex()}")

        raise


def test_gcm_nonce_uniqueness():
    """Тест на уникальность nonce при каждой генерации"""
    key = os.urandom(16)

    # Генерируем 1000 объектов GCM с автоматической генерацией nonce
    nonces = set()
    for i in range(1000):
        gcm = GCM(key)  # nonce генерируется автоматически
        nonces.add(gcm.nonce)

    # Проверяем, что все nonce уникальны
    assert len(nonces) == 1000, f"Expected 1000 unique nonces, got {len(nonces)}"

    # Дополнительно: проверяем, что nonce имеют правильную длину (12 байт)
    for nonce in nonces:
        assert len(nonce) == 12, f"Nonce should be 12 bytes, got {len(nonce)} bytes"

    print(f"✓ GCM nonce uniqueness test passed: {len(nonces)} unique nonces")


def test_gcm_nonce_randomness():
    """Статистический тест на случайность nonce"""
    key = os.urandom(16)
    num_nonces = 1000
    nonce_length = 12

    # Собираем статистику по байтам
    byte_counts = [0] * 256  # счетчики для каждого возможного байта (0-255)
    total_bytes = num_nonces * nonce_length

    # Генерируем nonce и собираем статистику
    for i in range(num_nonces):
        gcm = GCM(key)
        for byte in gcm.nonce:
            byte_counts[byte] += 1

    # Вычисляем ожидаемое количество каждого байта (равномерное распределение)
    expected_count = total_bytes / 256

    # Проверяем, что распределение не слишком отклоняется от равномерного
    # Используем простой критерий: каждый байт должен встречаться хотя бы несколько раз
    zero_count_bytes = sum(1 for count in byte_counts if count == 0)

    # В идеальном случайном распределении все байты должны встречаться
    # Но для 1000 nonce * 12 = 12000 байт ожидаем, что каждый байт встречается ~47 раз
    print(f"Total bytes analyzed: {total_bytes}")
    print(f"Bytes that never appeared: {zero_count_bytes}/256")
    print(f"Expected count per byte: {expected_count:.2f}")

    # Проверяем, что не более 10% байтов никогда не появляются
    # (это консервативный критерий для случайности)
    max_allowed_zero = 256 * 0.1  # 10%
    assert zero_count_bytes < max_allowed_zero, \
        f"Too many bytes never appear: {zero_count_bytes}, expected < {max_allowed_zero}"

    print(f"✓ GCM nonce randomness test passed")


if __name__ == "__main__":
    test_gcm_encrypt_decrypt()
    test_gcm_aad_tamper()
    test_gcm_ciphertext_tamper()
    test_gcm_nist_vectors()
    test_gcm_cli()
    test_encrypt_then_mac()
    print("\n✅ All GCM/AEAD tests passed!")