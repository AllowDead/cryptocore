# Руководство пользователя CryptoCore

## Установка и настройка

### Требования
- **Python**: 3.8 или выше
- **Операционная система**: Windows, Linux, macOS
- **Дисковое пространство**: минимум 100 МБ
- **Память**: 512 МБ RAM (рекомендуется 1 ГБ)

### Установка из исходного кода

```bash
# 1. Клонирование репозитория
git clone https://github.com/AllowDead/CryptoCore.git
cd cryptocore

# 2. Создание виртуального окружения (рекомендуется)
python -m venv venv

# Активация виртуального окружения:
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Установка зависимостей
pip install -r requirements.txt

# 4. Установка пакета в режиме разработки
pip install -e .

# 5. Проверка установки
cryptocore 
# Ожидаемый вывод
usage: cryptocore [-h] {encrypt,dgst,derive} ...
cryptocore: error: the following arguments are required: command
```
# Быстрый старт
Проверка работоспособности
```bash
cryptocore --help
# Ожидаемый вывод
usage: cryptocore [-h] {encrypt,dgst,derive} ...

CryptoCore - Minimalist Cryptographic Provider

positional arguments:
  {encrypt,dgst,derive}
                        Available commands
    encrypt             Encrypt or decrypt a file
    dgst                Compute message digest (hash)
    derive              Derive cryptographic keys from passwords or other keys     

options:
  -h, --help            show this help message and exit

Examples:
  ENCRYPTION/DECRYPTION:
    Encryption with auto-generated key:
      cryptocore encrypt --algorithm aes --mode ctr --encrypt \
        --input plaintext.txt --output ciphertext.bin
```
Создание тестового файла
```bash
echo "Это тестовое сообщение для проверки работы CryptoCore" > test.txt
echo "Вторая строка с данными" >> test.txt
echo "Третья строка на русском языке: Test massage" >> test.txt
```
Шифрование и дешифрование
```bash
cryptocore encrypt --algorithm aes --mode <режим> [--encrypt|--decrypt] \
  --key <ключ_hex> \
  [--iv <iv_hex>] \
  --input <входной_файл> \
  --output <выходной_файл>
```
## Режимы шифрования
CryptoCore поддерживает следующие режимы AES:
ecb - Electronic Codebook (только для тестирования)
cbc - Cipher Block Chaining (рекомендуется для совместимости)
cfb - Cipher Feedback
ofb - Output Feedback
ctr - Counter (рекомендуется для производительности)
gcm - Galois/Counter Mode (аутентифицированное шифрование)

##  Базовое шифрование (ECB)
```bash
# Шифрование
cryptocore encrypt --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input test.txt \
  --output test_ecb.enc

# Дешифрование
cryptocore encrypt --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input test_ecb.enc \
  --output test_ecb_decrypted.txt

# Проверка результата
diff test.txt test_ecb_decrypted.txt
# Если файлы идентичны - команда не выведет ничего
```
## 2. Шифрование с использованием CBC режима
```bash
# Шифрование (IV генерируется автоматически)
cryptocore encrypt --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test_cbc.enc

# При успешном шифровании будет выведен IV:
# [INFO] Сгенерирован IV: a1b2c3d4e5f601234567890123456789

# Дешифрование (IV нужно указать вручную)
cryptocore encrypt --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv a1b2c3d4e5f601234567890123456789 \
  --input test_cbc.enc \
  --output test_cbc_decrypted.txt
  ```
## 3. Шифрование с автоматическим чтением IV из файла
```bash
# Альтернативный способ дешифрования (IV читается из файла)
cryptocore dgst --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_cbc.enc \
  --output test_cbc_decrypted2.txt
# IV автоматически читается из первых 16 байт файла
```
## 4. Потоковое шифрование в режиме CTR
```bash
# Шифрование (CTR не требует padding, размер сохраняется)
cryptocore encrypt --algorithm aes --mode ctr --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test_ctr.enc

# Дешифрование
cryptocore --algorithm aes --mode ctr --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_ctr.enc \
  --output test_ctr_decrypted.txt
```
## 5. Шифрование с автоматической генерацией ключа
```bash
# Шифрование с генерацией ключа
cryptocore encrypt --algorithm aes --mode cbc --encrypt \
  --input test.txt \
  --output test_auto.enc

# Будет выведен сгенерированный ключ:
# [INFO] Сгенерирован случайный ключ: 1a2b3c4d5e6f78901234567890abcdef

# Дешифрование с использованием сгенерированного ключа
cryptocore encrypt --algorithm aes --mode cbc --decrypt \
  --key 1a2b3c4d5e6f78901234567890abcdef \
  --input test_auto.enc \
  --output test_auto_decrypted.txt
```
## 6. Шифрование бинарных файлов
```bash
# Создаем тестовый бинарный файл (1 МБ)
dd if=/dev/urandom of=binary_test.bin bs=1M count=1

# Шифрование бинарного файла
cryptocore encrypt --algorithm aes --mode ctr --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input binary_test.bin \
  --output binary_test.enc

# Дешифрование
cryptocore encrypt --algorithm aes --mode ctr --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input binary_test.enc \
  --output binary_test_decrypted.bin

# Проверка целостности
sha256sum binary_test.bin binary_test_decrypted.bin
# Хеши должны совпадать
```
## 7. Пакетное шифрование нескольких файлов
```bash
# Шифрование всех .txt файлов в директории
for file in *.txt; do
  echo "Шифрование $file..."
  cryptocore dgst --algorithm aes --mode cbc --encrypt \
    --key 00112233445566778899aabbccddeeff \
    --input "$file" \
    --output "${file%.txt}.enc" 2>/dev/null
done

# Дешифрование всех .enc файлов
for file in *.enc; do
  echo "Дешифрование $file..."
  cryptocore dgst --algorithm aes --mode cbc --decrypt \
    --key 00112233445566778899aabbccddeeff \
    --input "$file" \
    --output "${file%.enc}.decrypted.txt" 2>/dev/null
done
```
## Работа с хешами
Общий синтаксис для хеширования
```bash
cryptocore dgst --algorithm <алгоритм> \
  --input <входной_файл> \
  [--output <выходной_файл>]
```
## Поддерживаемые алгоритмы хеширования
- sha256 - SHA-256
- sha3-256 - SHA3-256 

## 1. Базовое вычисление хеша
```bash
# Вычисление SHA-256
cryptocore dgst --algorithm sha256 --input test.txt

# Ожидаемый вывод:
# e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 test.txt

# Вычисление SHA3-256
cryptocore dgst --algorithm sha3-256 --input test.txt
```
## 2. Сохранение хеша в файл
```bash
# Сохранение хеша в файл
cryptocore dgst --algorithm sha256 \
  --input test.txt \
  --output test.sha256

# Просмотр сохраненного хеша
cat test.sha256

# Проверка хеша вручную
cryptocore dgst --algorithm sha256 --input test.txt > manual_check.sha256
diff test.sha256 manual_check.sha256
```
## Аутентификация сообщений (HMAC)
Общий синтаксис для HMAC

```bash
cryptocore dgst --algorithm sha256 --hmac \
  --key <ключ_hex> \
  --input <входной_файл> \
  [--verify <файл_с_hmac>] \
  [--output <выходной_файл>]
  ```
## 1. Генерация HMAC
```bash
# Генерация HMAC-SHA256
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --input test.txt

# Ожидаемый вывод:
# a1b2c3d4e5f6012345678901234567890123456789012345678901234567890123 test.txt

# Сохранение HMAC в файл
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test.hmac
  ```
## 2. Проверка HMAC
```bash
# Проверка с использованием --verify
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --input test.txt \
  --verify test.hmac

# Ожидаемый вывод при успехе:
# [OK] Проверка HMAC успешна

# Ожидаемый вывод при неудаче:
# [ERROR] Проверка HMAC не удалась
```
## Аутентифицированное шифрование (GCM)
Общий синтаксис для GCM
```bash
# Шифрование
cryptocore --algorithm aes --mode gcm --encrypt \
  --key <ключ_hex> \
  [--aad <aad_hex>] \
  --input <входной_файл> \
  --output <выходной_файл>

# Дешифрование
cryptocore --algorithm aes --mode gcm --decrypt \
  --key <ключ_hex> \
  [--aad <aad_hex>] \
  --input <входной_файл> \
  --output <выходной_файл>
  ```
## 1. Базовое шифрование в режиме GCM
```bash
# Шифрование без AAD
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test_gcm.enc

# Дешифрование
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_gcm.enc \
  --output test_gcm_decrypted.txt
  ```
## 2. Шифрование с дополнительными аутентифицированными данными (AAD)
```bash
# Шифрование с AAD
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad 0102030405060708090a0b0c0d0e0f10 \
  --input test.txt \
  --output test_gcm_aad.enc

# Успешное дешифрование с правильным AAD
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad 0102030405060708090a0b0c0d0e0f10 \
  --input test_gcm_aad.enc \
  --output test_gcm_aad_decrypted.txt

# Попытка дешифрования с неправильным AAD (должна завершиться ошибкой)
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad ffffffffffffffffffffffffffffffff \
  --input test_gcm_aad.enc \
  --output should_fail.txt 
```
## Выведение ключей (KDF)
Общий синтаксис для выведения ключей
```bash
cryptocore derive \
  --password "<пароль>" \
  [--salt <соль_hex>] \
  [--iterations <количество_итераций>] \
  [--length <длина_ключа_в_байтах>] \
  [--output <выходной_файл>]
  ```
## 1. Базовое выведение ключа из пароля
```bash
# Выведение ключа с указанной солью
cryptocore derive \
  --password "MySecurePassword123!" \
  --salt a1b2c3d4e5f601234567890123456789 \
  --iterations 100000 \
  --length 32

# Ожидаемый вывод:
# 5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abdffe5c8f9b8a8c7 a1b2c3d4e5f601234567890123456789
# ↑ производный ключ (hex)               ↑ использованная соль (hex)
2. Автоматическая генерация соли
bash
# Выведение ключа с автоматической генерацией соли
cryptocore derive \
  --password "AnotherSecurePassword" \
  --iterations 500000 \
  --length 16

# Будет выведена сгенерированная соль:
# 8d969eeff6ecad3c29a3a629280e686c e3b0c44298fc1c149afb
# ↑ производный ключ           ↑ сгенерированная соль
3. Сохранение производного ключа в файл
bash
# Сохранение ключа в бинарный файл
cryptocore derive \
  --password "app_secret_key" \
  --salt fixedappsalt123456 \
  --iterations 10000 \
  --length 32 \
  --output derived_key.bin

# Проверка содержимого файла
hexdump -C derived_key.bin 
```
## Генерация случайных данных
## 1. Генерация случайных ключей
```bash
# Ключи генерируются автоматически при опускании --key
cryptocore --algorithm aes --mode cbc --encrypt \
  --input test.txt \
  --output test_random_key.enc

# Будет выведено:
# [INFO] Сгенерирован случайный ключ: 7d8e9f0a1b2c3d4e5f60718293a4b5c6
```
## Устранение неполадок
## Общие ошибки и их решения
Ошибка: "File not found or cannot be read"
```bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input nonexistent.txt \
  --output output.enc

# Решение: Проверьте путь к файлу и права доступа
ls -la nonexistent.txt
```
Ошибка: "Invalid key length"
```bash
# Неправильная длина ключа (не 16, 24 или 32 байта)
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 001122  # Только 3 байта!
  --input test.txt \
  --output test.enc

# Решение: Используйте правильную длину ключа
# AES-128: 16 байт (32 hex символа)
# AES-192: 24 байта (48 hex символов)
# AES-256: 32 байта (64 hex символа)
Ошибка: "Invalid IV length"
```
```bash
# IV должен быть 16 байт для CBC, CFB, OFB, CTR
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv 001122  # Только 3 байта!
  --input test.enc \
  --output test_decrypted.txt

# Решение: Используйте IV длиной 16 байт (32 hex символа)
```
Ошибка: "Authentication failed" (GCM)

```bash
# Эта ошибка ожидаема при:
# 1. Неправильном AAD
# 2. Измененном зашифрованном тексте
# 3. Неправильном ключе

# Решение: Проверьте:
# - Правильность ключа
# - Правильность AAD (если используется)
# - Целостность зашифрованного файла
```
Ошибка: "Padding is incorrect"
```bash
# Возникает при дешифровании CBC/ECB с неправильным padding

# Решение:
# 1. Убедитесь, что используете тот же ключ и IV
# 2. Проверьте, что файл не был поврежден
# 3. Для потоковых режимов (CTR, CFB, OFB) используйте соответствующий режим
```
## Безопасность
Не используйте "слабые" ключи при работе с утилитой
## Управление ключами
НЕПРАВИЛЬНО:
```bash
# Хранение ключей в скриптах
KEY="00112233445566778899aabbccddeeff"
cryptocore --algorithm aes --mode cbc --encrypt \
  --key "$KEY" \
  --input data.txt \
  --output data.enc
```
ПРАВИЛЬНО:
```bash
# Загрузка ключей из защищенного хранилища
KEY=$(cat /secure/key_vault/aes.key)

# Или генерация ключа на лету
KEY=$(python3 -c "
from cryptocore.csprng import generate_random_bytes
print(generate_random_bytes(16).hex())
")

# Использование ключа
cryptocore --algorithm aes --mode cbc --encrypt \
  --key "$KEY" \
  --input data.txt \
  --output data.enc

# Немедленная очистка ключа из памяти
KEY="overwritten"
```
## Сравнение с OpenSSL
AES-CBC шифрование 

cryptocore encrypt --algorithm aes --mode cbc --encrypt --key KEY --input IN --output OUT
openssl enc -aes-256-cbc -K KEY -iv IV -in IN -out OUT

AES-GCM шифрование

cryptocore encrypt --algorithm aes --mode gcm --encrypt --key KEY --aad AAD --input IN --output OUT
openssl enc -aes-256-gcm -K KEY -iv IV -aad AAD -in IN -out OUT

SHA-256 хеш

cryptocore dgst --algorithm sha256 --input FILE
openssl dgst -sha256 FILE

HMAC-SHA256

cryptocore dgst --algorithm sha256 --hmac --key KEY --input FILE
openssl dgst -hmac KEY -sha256 FILE

## Преимущества CryptoCore
Единый интерфейс - все криптографические операции через одну команду
Образовательный аспект - реализации с нуля для понимания алгоритмов
Безопасность по умолчанию - использование безопасных параметров
Детальный контроль - над всеми параметрами операций
Совместимость - с промышленными стандартами (NIST, RFC)