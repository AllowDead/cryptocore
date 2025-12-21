# CryptoCore API Документация

## Введение

CryptoCore - это комплексная библиотека криптографических операций, реализованная на Python. Библиотека предоставляет функции для симметричного шифрования, хеширования, аутентификации сообщений и выведения ключей.

**Версия:** 1.0.0  
**Язык:** Python 3.8+

---

##  Структура пакета

cryptocore/
├── init.py # Инициализация пакета
├── cli_parser.py # Парсер командной строки
├── file_io.py # Утилиты для работы с файлами
├── csprng.py # Криптографически стойкий ГСЧ
├── hash_handler.py # Обработчик хеш-операций
├── aead_handler.py # Обработчик аутентифицированного шифрования
├── modes/ # Режимы шифрования
├── hash/ # Хеш-функции
├── mac/ # Коды аутентификации сообщений
└── kdf/ # Функции выведения ключей

---

##  Модули и классы

### 1. Модуль `cryptocore.csprng`

Криптографически стойкий генератор случайных чисел.
#### Функции

##### `generate_random_bytes(num_bytes)`
```python
def generate_random_bytes(num_bytes: int) -> bytes
```
Генерирует криптографически стойкие случайные байты.
Параметры:
num_bytes (int): Количество байтов для генерации
Возвращает:
bytes: Случайные байты
from cryptocore.csprng import generate_random_bytes
```python
# Генерация 16 случайных байтов
random_bytes = generate_random_bytes(16)
print(f"Случайные байты: {random_bytes.hex()}")
```
### 2. Модуль cryptocore.file_io

Функции
Читает содержимое файла в виде байтов.
read_file(filepath)
```python
def read_file(filepath: str) -> bytes
```
Читает содержимое файла в виде байтов.
write_file(filepath, data)
```python
def write_file(filepath: str, data: bytes) -> None
```
Записывает байты в файл.
read_file_with_iv(filepath)
```python
def read_file_with_iv(filepath: str) -> tuple[bytes, bytes]
```
Читает файл, содержащий IV (первые 16 байт) и данные.
Возвращает:
tuple[bytes, bytes]: (IV, данные)

write_file_with_iv(filepath, iv, data)
```python
def write_file_with_iv(filepath: str, iv: bytes, data: bytes) -> None
```

### 3. Пакет cryptocore.modes

Реализации различных режимов шифрования AES.

### 3.1 Класс ECBMode (модуль modes.ecb)

Режим Electronic Codebook (ECB).
```python
class ECBMode:
    def __init__(self, key: bytes)
    def encrypt(self, plaintext: bytes) -> bytes
    def decrypt(self, ciphertext: bytes) -> bytes
def write_file_with_iv(filepath: str, iv: bytes, data: bytes) -> None
```
Пример:
```python
from cryptocore.modes.ecb import ECBMode

key = b'0' * 16  # 128-битный ключ
ecb = ECBMode(key)

plaintext = b"Hello, World!"
ciphertext = ecb.encrypt(plaintext)
decrypted = ecb.decrypt(ciphertext)
```
## 3.2. Класс CBCMode (модуль modes.cbc)
```python
class CBCMode:
    def __init__(self, key: bytes)
    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes
    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes
```
##  Класс CTRMode (модуль modes.ctr)
Режим Counter (CTR).
```python
class CTRMode:
    def __init__(self, key: bytes)
    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes
    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes
    def encrypt_with_iv(self, plaintext: bytes, iv: bytes) -> bytes
    def decrypt_with_iv(self, ciphertext: bytes, iv: bytes) -> bytes
```
## 3.4. Класс GCM (модуль modes.gcm)
Режим Galois/Counter Mode (GCM) с аутентификацией
```python
class GCM:
    def __init__(self, key: bytes, nonce: bytes = None)
    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes
    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes
```
Исключение:
```python
class AuthenticationError(Exception)
```
Пример:
```python
from cryptocore.modes.gcm import GCM

key = b'0' * 16
nonce = b'1' * 12
gcm = GCM(key, nonce)

plaintext = b"Секретное сообщение"
aad = b"Дополнительные аутентифицированные данные"

# Шифрование
ciphertext_with_tag = gcm.encrypt(plaintext, aad)

# Дешифрование
try:
    decrypted = gcm.decrypt(ciphertext_with_tag, aad)
    print(f"Дешифровано: {decrypted}")
except AuthenticationError as e:
    print(f"Ошибка аутентификации: {e}")
```
## Пакет cryptocore.hash
Реализации хеш-функций.
## 4.1. Класс SHA256 (модуль hash.sha256)
SHA-256 хеш-функция (реализация с нуля).
```python
class SHA256:
    def __init__(self)
    def update(self, data: bytes) -> None
    def digest(self) -> bytes
    def hexdigest(self) -> str
    @staticmethod
    def hash(data: bytes) -> bytes
```
Пример:
```python
from cryptocore.hash.sha256 import SHA256

# Использование через объект
sha256 = SHA256()
sha256.update(b"Hello, ")
sha256.update(b"World!")
hash_result = sha256.hexdigest()
print(f"SHA-256: {hash_result}")

# Использование статического метода
hash_bytes = SHA256.hash(b"Hello, World!")
print(f"SHA-256 bytes: {hash_bytes.hex()}")
```
## 4.2. Класс SHA3_256 (модуль hash.sha3_256)
SHA3-256 хеш-функция (реализация с нуля).
```python
class SHA3_256:
    def __init__(self)
    def update(self, data: bytes) -> None
    def digest(self) -> bytes
    def hexdigest(self) -> str
    @staticmethod
    def hash(data: bytes) -> bytes
```
## 5. Пакет cryptocore.mac
Реализации кодов аутентификации сообщений.
## 5.1. Класс HMAC (модуль mac.hmac)
HMAC (Hash-based Message Authentication Code) с поддержкой SHA-256.
```python
class HMAC:
    def __init__(self, key: bytes, hash_name: str = "sha256")
    def compute(self, message: bytes) -> bytes
    def compute_hex(self, message: bytes) -> str
    def compute_file(self, file_path: str, chunk_size: int = 8192) -> bytes
    def verify(self, message: bytes, hmac_to_check: bytes) -> bool
    def verify_file(self, file_path: str, hmac_to_check: bytes, chunk_size: int = 8192) -> bool
```
Пример:
```python
from cryptocore.mac.hmac import HMAC

key = b"secret_key_12345"
hmac = HMAC(key)

message = b"Важное сообщение"
hmac_value = hmac.compute_hex(message)
print(f"HMAC: {hmac_value}")

# Проверка
is_valid = hmac.verify(message, bytes.fromhex(hmac_value))
print(f"HMAC действителен: {is_valid}")
```
## 6. Пакет cryptocore.kdf
Функции выведения ключей.
## 6.1. Функция pbkdf2_hmac_sha256 (модуль kdf.pbkdf2)
```python
def pbkdf2_hmac_sha256(
    password: bytes | str,
    salt: bytes | str,
    iterations: int,
    dklen: int
) -> bytes
```
Пример:
```python
from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256

password = b"MySecretPassword"
salt = b"RandomSalt123"
iterations = 100000
dklen = 32  # 256 бит

derived_key = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
print(f"Производный ключ: {derived_key.hex()}")
```
## 6.2. Функция derive_key (модуль kdf.hkdf)
```python
def derive_key(
    master_key: bytes,
    context: str | bytes,
    length: int = 32
) -> bytes
```
## 6.3. Функция hkdf_extract (модуль kdf.hkdf)
```python
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes
```
## 6.4. Функция hkdf_expand (модуль kdf.hkdf)
```python
def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes
```
## 7. Модуль cryptocore.aead_handler
Обработчик аутентифицированного шифрования.
## 7.1. Класс AEADHandler
```python
class AEADHandler:
    @staticmethod
    def encrypt_then_mac(
        plaintext: bytes,
        enc_key: bytes,
        mac_key: bytes,
        aad: bytes = b"",
        mode: str = "cbc"
    ) -> bytes
    
    @staticmethod
    def decrypt_and_verify(
        data: bytes,
        enc_key: bytes,
        mac_key: bytes,
        aad: bytes = b"",
        mode: str = "cbc"
    ) -> bytes
```
## 8. Модуль cryptocore.hash_handler
Обработчик хеш-операций и KDF.
## 8.1. Класс HashHandler
```python
class HashHandler:
    def compute_hash(
        self,
        algorithm: str,
        input_file: str,
        output_file: str = None,
        hmac_key: bytes = None,
        chunk_size: int = 8192
    ) -> str | None
    
    def verify_hmac(
        self,
        algorithm: str,
        input_file: str,
        hmac_key: bytes,
        hmac_file: str,
        chunk_size: int = 8192
    ) -> bool
    
    def handle_kdf_derivation(
        self,
        password: str,
        salt: str,
        iterations: int,
        dklen: int,
        algorithm: str = "pbkdf2"
    ) -> tuple[bytes, bytes]
```
## 9. Модуль cryptocore.cli_parser
Парсер командной строки (основная точка входа).
Основные функции:
parse_args()
```python
def parse_args() -> argparse.Namespace
```
main()
```python
def main() -> None
```
## Базовые примеры
Шифрование и дешифрование
```python
from cryptocore.modes.cbc import CBCMode
from cryptocore.csprng import generate_random_bytes

# Генерация ключа и IV
key = generate_random_bytes(16)
iv = generate_random_bytes(16)

# Шифрование
cbc = CBCMode(key)
plaintext = b"Секретное сообщение"
ciphertext = cbc.encrypt(plaintext, iv)

# Дешифрование
decrypted = cbc.decrypt(ciphertext, iv)
assert decrypted == plaintext
```
Хеширование файла
```python
from cryptocore.hash.sha256 import SHA256
from cryptocore.file_io import read_file

# Чтение файла
data = read_file("document.pdf")

# Вычисление хеша
sha256 = SHA256()
sha256.update(data)
file_hash = sha256.hexdigest()
print(f"SHA-256 файла: {file_hash}")
```
Создание и проверка HMAC
```python
from cryptocore.mac.hmac import HMAC

key = b"super_secret_key"
message = b"Важное финансовое сообщение"

# Создание HMAC
hmac = HMAC(key)
hmac_value = hmac.compute_hex(message)

# Проверка HMAC
is_valid = hmac.verify(message, bytes.fromhex(hmac_value))
print(f"HMAC действителен: {is_valid}")
```
## Исключения
AuthenticationError (модуль modes.gcm)
Вызывается при неудачной аутентификации в режиме GCM.

ValueError
Вызывается при неверных параметрах (неправильная длина ключа, IV и т.д.).
## Константы
```python
# Размеры блоков
AES_BLOCK_SIZE = 16
GCM_TAG_SIZE = 16
GCM_NONCE_SIZE = 12

# Размеры хешей
SHA256_DIGEST_SIZE = 32
SHA3_256_DIGEST_SIZE = 32

# Максимальные значения
PBKDF2_MAX_ITERATIONS = 1000000
```
## Безопасность
Рекомендации
1.Не используй слабые ключи при работе с утилитой
2.Избегайте режима ECB для шифрования конфиденциальных данных
3.Используйте аутентифицированные режимы (GCM) когда это возможно
4.Проверяйте HMAC перед использованием данных
5.Используйте достаточное количество итераций для PBKDF2 (≥100,000)
## Постоянные по времени операции
Библиотека использует постоянные по времени операции для сравнения HMAC и тегов аутентификации.
## Совместимость
-Windows
-Linux
-MacOS