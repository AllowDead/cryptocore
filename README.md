# CryptoCore - Криптографический провайдер

Инструмент командной строки, реализующая шифрование AES-128 в режиме ECB, CBC, CRF, CTR, OFB с дополнением PKCS#7 хеширование.

## Требования

- Python 3.8 +
- Библиотеки pycryptodome

## Поддерживаемые режимы шифрования

- CBC - Cipher Block Chaining
- CFB - Cipher Feedback
- CTR - Counter Mode
- ECB - Electronic Code Book
- OFB - Output Feedback

##  Хэширование

- sha-256 по FIPS 180-4
- sha3-256 по FIPS 202 (Keccak)

## Аутентифицированное шифрование

- GCM (Galois/Counter Mode) Authenticated encryption with associated data
- GCM (Galois/Counter Mode) Generic authenticated encryption using any block cipher mode with HMAC
- AAD Support Additional authenticated data for integrity protection

## Key Derivation Functions



## Поддерживание HMAC

## Инструкция по сборке
```bash
git clone <https://github.com/AllowDead/CryptoCore>
cd cryptocore

# Установка зависимостей 
pip install -r requirements.txt

# Установка пакета в режиме разработчика
pip install -e .
```

## Инструкция к использованию
Базовый синтаксис
```bash
cryptocore -h, --help
cryptocore encrypt --algorithm aes --mode ecb (--encrypt | --decrypt) --key <hex_key> --input <input_file> [--output <output_file>]
Encryption Example
bash
# Encrypt a file
cryptocore encrypt --algorithm aes --mode ecb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.bin

# Or with auto-generated output filename
cryptocore encrypt --algorithm aes --mode ecb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt
# Creates: secret.txt.enc
Decryption Example
bash
# Decrypt a file
cryptocore encrypt --algorithm aes --mode ecb --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt

IV Handling
- **Encryption**: Random IV generated automatically, prepended to ciphertext
- **Decryption**: Read IV from file or provide via `--iv` argument

CBC mode
# Encryption (IV auto-generated)
cryptocore encrypt --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plain.txt --output cipher.bin

# Decryption (IV read from file)
cryptocore encrypt --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input cipher.bin --output decrypted.txt

# Decryption with explicit IV
cryptocore encrypt --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext_only.bin --output decrypted.txt
  
Stream Modes (CFB, OFB, CTR)
# CFB Encryption
cryptocore encrypt --algorithm aes --mode cfb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plain.txt --output cipher.bin

# CFB Decryption
cryptocore encrypt --algorithm aes --mode cfb --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input cipher.bin --output decrypted.txt
  
# Encryption with auto-generated key
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210

# Хэширование
# Вычисление SHA-256 хэша
cryptocore dgst --algorithm sha256 --input file.txt

# Вычисление SHA3-256 хэша с сохранением в файл
cryptocore dgst --algorithm sha3-256 --input document.pdf --output hash.txt

# Generate HMAC-SHA256 for a file
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.pdf

# Save HMAC to file
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input backup.tar --output backup.hmac

# Verify HMAC against stored value
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input backup.tar --verify backup.hmac
[OK] HMAC verification successful for backup.tar

# If verification fails:
[ERROR] HMAC verification failed for backup.tar

# GCM Encryption
# Encryption with AAD
cryptocore encrypt --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.gcm \
  --aad aabbccddeeff00112233445566778899
  
# Decryption (AAD must match)
cryptocore encrypt --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.gcm \
  --output decrypted.txt \
  --aad aabbccddeeff00112233445566778899
  
# Encryption with separate keys
cryptocore encrypt --mode etm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --mac-key 33445566778899aabbccddeeff00112233445566778899aabbcc \
  --input data.txt \
  --output data.etm \
  --aad "context information"

# Decryption and verification
cryptocore encrypt --mode etm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --mac-key 33445566778899aabbccddeeff00112233445566778899aabbcc \
  --input data.etm \
  --output verified.txt \
  --aad "context information"

# Derive key from password with specified salt
cryptocore derive --password "MySecurePassword123!" --salt a1b2c3d4e5f601234567890123456789 --iterations 100000 --length 32

# Derive key with auto-generated salt
cryptocore derive --password "AnotherPassword" --iterations 500000 --length 16

# Derive key and save to file
cryptocore derive --password "app_key" --salt fixedappsalt --iterations 10000 --length 32 --output secret_key.bin

# Read password from file
cryptocore derive --password-file password.txt --iterations 100000 --length 32

```
## Тест
```bash
cryptocore encrypt --algorithm aes --mode ecb --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test.enc
Success: Encrypted data written to test.enc

cryptocore encrypt --algorithm aes --mode ecb --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.enc \
  --output test.dec
Success: Decrypted data written to test.dec

diff test.txt test.dec

```
## Совместимость с OpenSSl
```bash
# Encrypt with CryptoCore
cryptocore encrypt --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt --output cipher.bin

# Extract IV and ciphertext
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1

# Decrypt with OpenSSL
openssl enc -aes-128-cbc -d \
  -K 000102030405060708090a0b0c0d0e0f \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext_only.bin -out decrypted.txt

# Encrypt with OpenSSL
openssl enc -aes-128-cbc \
  -K 000102030405060708090a0b0c0d0e0f \
  -iv aabbccddeeff00112233445566778899 \
  -in plain.txt -out openssl_cipher.bin

# Decrypt with CryptoCore
cryptocore encrypt --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv aabbccddeeff00112233445566778899 \
  --input openssl_cipher.bin --output decrypted.txt
```
## Структура проекта

cryptocore/
├── cryptocore/                    # Основной пакет Python
│   ├── __init__.py               # Инициализация пакета
│   ├── cli_parser.py             # Парсер командной строки 
│   ├── file_io.py                # Работа с файлами (чтение/запись)
│   ├── csprng.py                 # CSPRNG модуль (Sprint 3)
│   ├── hash_handler.py           # Обработчик хэш-команд (Sprint 4, Sprint 5)
│   ├── aead_handler.py           # Обработчик аутентифицированного шифрования (Sprint 6)
│   │                  
│   ├── modes/                    # Реализации режимов шифрования
│   │   ├── __init__.py
│   │   ├── ecb.py                # ECB mode (Sprint 1)
│   │   ├── cbc.py                # CBC mode (Sprint 2)
│   │   ├── cfb.py                # CFB mode (Sprint 2)
│   │   ├── ofb.py                # OFB mode (Sprint 2)
│   │   ├── ctr.py                # CTR mode (Sprint 2)
│   │   └── gcm.py                # GCM mode (Sprint 6)
│   ├── hash/                     # Реализации хэш-функций (Sprint 4)
│   │   ├── __init__.py
│   │   ├── sha256.py             # SHA-256  (FIPS 180-4)
│   │   └── sha3_256.py           # SHA3-256  (FIPS 202)
│   ├── mac/                      # Реализации MAC (Sprint 5)
│   │   ├── __init__.py
│   │   └── hmac.py               # HMAC  (RFC 2104)
│   └── kdf/                      # Реализации функций KDF (Sprint 7)
│       ├── __init__.py
│       ├── hkdf.py               # HKDF (RFC 5869)
│       └── pbkdf2.py             # PBKDF2  (RFC 8018)
│       └── pbkdf2.py             # PBKDF2  (RFC 8018)
│
├── docs/
│   ├── API.md
│   └── USERGUIDE.md 
│
│
├── tests/                        # Тесты
│   ├── __init__.py
│   ├── test_ecb.py              # Тесты ECB mode (Sprint 1)
│   ├── test_modes.py            # Тесты других режимов (Sprint 2)
│   ├── test_csprng.py           # Тесты CSPRNG (Sprint 3)
│   ├── test_hash.py             # Тесты хэш-функций (Sprint 4)
│   ├── test_hmac.py             # Тесты HMAC (Sprint 5)
│   ├── test_gcm.py              # Тесты GCM (Sprint 6)
│   ├── test_kdf.py              # Тесты KDF функций (Sprint 7)
│   ├── test_kdf_performance.py  # Тесты производительности KDF
│   ├── test_large_files.py      # Тесты больших файлов >1GB (Sprint 4)
│   ├── test_large_file_hmac.py  # Тесты HMAC с большими файлами (Sprint 5)
│   ├── test_large_gcm.py        # Тесты GCM с большими файлами (Sprint 6)
│   ├── test_openssl_compatibility.py # Тесты совместимости с OpenSSL
│   ├── test_security.py         # Тесты безопасности
│   ├── test_file_io.py          # Тесты работы с файлами
│   ├── test_all_functionality.py # Комплексные тесты всей функциональности
│   ├── hmac_key_test.py         # Тесты ключей HMAC
│   ├── vectors_sha256_hmac.py   # Тестовые векторы для SHA-256 HMAC
│   ├── kdf_openssl_compatibility.py # Тесты совместимости KDF с OpenSSL
│   └── nist_test_data.bin       # Тестовые данные для NIST STS (10 МБ)
│
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── TESTING.md                   # Результаты тестирования
├── setup.py                     # Установочный файл Python
├── requirements.txt             # Зависимости проекта
└── README.md       