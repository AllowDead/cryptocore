# cryptocore/hash_handler.py
import sys
import os
from typing import Optional
from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256
from cryptocore.kdf.hkdf import derive_key

class HashHandler:
    """Handler for hash and HMAC operations."""

    @staticmethod
    def compute_hash(algorithm, input_file, output_file=None, hmac_key: Optional[str] = None,
                     chunk_size: int = 8192):
        """
        Вычисляет хэш или HMAC файла с использованием указанного алгоритма

        Args:
            algorithm: Hash algorithm name
            input_file: Path to input file
            output_file: Optional output file path
            hmac_key: Optional HMAC key (hex string)
            chunk_size: Size of chunks to read (default: 8KB)
        """
        if not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' does not exist", file=sys.stderr)
            sys.exit(1)

        try:
            if hmac_key:
                # В режиме HMAC - обрабатываем файл частями
                from cryptocore.mac.hmac import HMAC
                hmac_obj = HMAC(hmac_key, algorithm)

                # Используем новую функцию для обработки файлов частями
                hash_value = hmac_obj.compute_file_hex(input_file, chunk_size)
            else:
                # В режиме обычного хэша
                if algorithm == "sha256":
                    from cryptocore.hash.sha256 import SHA256
                    hash_obj = SHA256()
                elif algorithm == "sha3-256":
                    from cryptocore.hash.sha3_256 import SHA3_256
                    hash_obj = SHA3_256()
                else:
                    print(f"Error: Unknown algorithm '{algorithm}'", file=sys.stderr)
                    sys.exit(1)

                # Читаем файл частями
                with open(input_file, 'rb') as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        hash_obj.update(chunk)

                hash_value = hash_obj.hexdigest()

            result = f"{hash_value}  {input_file}"

            if output_file:
                try:
                    with open(output_file, 'w') as f:
                        f.write(result + '\n')
                    print(f"Hash/HMAC saved to '{output_file}'")
                except IOError as e:
                    print(f"Error writing to output file: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                print(result)

            return result

        except ImportError as e:
            print(f"Error: Module not found: {e}", file=sys.stderr)
            print("Make sure hash and HMAC modules are properly installed.", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            sys.exit(1)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def verify_hmac(algorithm, input_file, hmac_key, hmac_file, chunk_size: int = 8192):
        """
        Проверяет HMAC файла

        Args:
            algorithm: Hash algorithm name
            input_file: Path to input file
            hmac_key: HMAC key (hex string)
            hmac_file: File containing expected HMAC
            chunk_size: Size of chunks to read (default: 8KB)
        """
        if not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' does not exist", file=sys.stderr)
            sys.exit(1)

        if not os.path.exists(hmac_file):
            print(f"Error: HMAC file '{hmac_file}' does not exist", file=sys.stderr)
            sys.exit(1)

        try:
            from cryptocore.mac.hmac import HMAC

            # Читаем ожидаемый HMAC из файла
            with open(hmac_file, 'r') as f:
                expected_line = f.read().strip()

            # Парсим ожидаемый HMAC (формат: "HMAC_VALUE  FILENAME")
            parts = expected_line.split()
            if not parts:
                print(f"Error: Invalid HMAC file format", file=sys.stderr)
                sys.exit(1)

            expected_hmac_hex = parts[0]

            # Создаем объект HMAC и проверяем файл частями
            hmac_obj = HMAC(hmac_key, algorithm)

            # Используем новую функцию для проверки файлов частями
            if hmac_obj.verify_file(input_file, expected_hmac_hex, chunk_size):
                print(f"[OK] HMAC verification successful for {input_file}")
                return True
            else:
                print(f"[ERROR] HMAC verification failed for {input_file}")
                return False

        except ImportError as e:
            print(f"Error: HMAC module not found: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during HMAC verification: {e}", file=sys.stderr)
            sys.exit(1)

    def handle_kdf_derivation(password, salt, iterations, dklen, algorithm='pbkdf2'):
        """
        Handle key derivation operations.
        """
        if algorithm == 'pbkdf2':
            return pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        else:
            raise ValueError(f"Unsupported KDF algorithm: {algorithm}")


# Для обратной совместимости
def compute_hash(algorithm, input_file, output_file=None, hmac_key: Optional[str] = None):
    """Алиас для обратной совместимости"""
    return HashHandler.compute_hash(algorithm, input_file, output_file, hmac_key)


def verify_hmac(algorithm, input_file, hmac_key, hmac_file):
    """Алиас для обратной совместимости"""
    return HashHandler.verify_hmac(algorithm, input_file, hmac_key, hmac_file)