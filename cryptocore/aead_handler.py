# aead_handler.py
import os
from typing import Optional
from cryptocore.mac.hmac import HMAC


class AEADHandler:
    """Обработчик аутентифицированного шифрования"""

    @staticmethod
    def encrypt_then_mac(plaintext: bytes,
                         enc_key: bytes,
                         mac_key: bytes,
                         aad: bytes = b"",
                         mode: str = 'ctr') -> bytes:
        """
        Реализация Encrypt-then-MAC
        MAC зависит от ключа шифрования для безопасности
        """
        if mode == 'ctr':
            from cryptocore.modes.ctr import CTRMode
        else:
            raise ValueError(f"Unsupported mode for ETM: {mode}")

        # Генерируем случайный IV/nonce
        iv = os.urandom(16)

        # Шифруем в режиме CTR
        cipher = CTRMode(enc_key)

        if hasattr(cipher, 'encrypt_with_iv'):
            ciphertext_without_iv = cipher.encrypt_with_iv(plaintext, iv)
        else:
            ciphertext_without_iv, _ = cipher.encrypt(plaintext)

        # Формируем полный ciphertext: IV + ciphertext
        ciphertext = iv + ciphertext_without_iv

        # ВАЖНОЕ ИСПРАВЛЕНИЕ: MAC включает ключ шифрования
        # Это предотвращает атаки с подменой ключа
        mac_data = enc_key + ciphertext
        if aad:
            mac_data += aad

        # Вычисляем HMAC
        hmac = HMAC(mac_key, 'sha256')
        tag = hmac.compute(mac_data)  # tag уже bytes

        # Возвращаем ciphertext + tag
        return ciphertext + tag

    @staticmethod
    def decrypt_and_verify(data: bytes,
                           enc_key: bytes,
                           mac_key: bytes,
                           aad: bytes = b"",
                           mode: str = 'ctr') -> Optional[bytes]:
        """
        Проверка и дешифрование Encrypt-then-MAC
        """
        if mode != 'ctr':
            raise ValueError("Only CTR mode is supported for Encrypt-then-MAC")

        from cryptocore.modes.ctr import CTRMode

        # Определяем размеры
        iv_len = 16
        tag_len = 32  # SHA-256 дает 32 байта

        if len(data) < iv_len + tag_len:
            raise ValueError("Data too short")

        # Разделяем данные
        ciphertext_with_iv = data[:-tag_len]
        tag_received = data[-tag_len:]

        # ВАЖНОЕ ИСПРАВЛЕНИЕ: те же данные для MAC (включая ключ)
        mac_data = enc_key + ciphertext_with_iv
        if aad:
            mac_data += aad

        # Проверка MAC
        hmac = HMAC(mac_key, 'sha256')
        tag_computed = hmac.compute(mac_data)

        # Сравниваем bytes
        if tag_received != tag_computed:
            return None

        # Извлекаем IV и ciphertext
        iv = ciphertext_with_iv[:iv_len]
        ciphertext = ciphertext_with_iv[iv_len:]

        # Дешифрование
        cipher = CTRMode(enc_key)

        if hasattr(cipher, 'decrypt_with_iv'):
            plaintext = cipher.decrypt_with_iv(ciphertext, iv)
        else:
            plaintext = cipher.decrypt(ciphertext, iv)

        return plaintext