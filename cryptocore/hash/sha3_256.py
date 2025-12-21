# cryptocore/hash/sha3_256.py

class SHA3_256:
    """Реализация SHA3-256 с нуля согласно FIPS 202"""

    # Константы для SHA3-256
    ROUND_CONSTANTS = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    # Rotation offsets для rho-шага
    RHO_OFFSETS = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

    def __init__(self):
        # Состояние Keccak: массив 5x5 64-битных слов
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self.rate = 1088  # 1088 бит для SHA3-256 (1600 - 512)
        self.output_length = 256  # 256 бит выход

    def _keccak_f(self, state):
        """Функция перестановки Keccak-f[1600]"""
        A = state

        for round_num in range(24):
            # θ шаг (theta)
            C = [0] * 5
            D = [0] * 5

            for x in range(5):
                C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

            for x in range(5):
                D[x] = C[(x - 1) % 5] ^ self._rot64(C[(x + 1) % 5], 1)

            for x in range(5):
                for y in range(5):
                    A[x][y] ^= D[x]

            # ρ и π шаги (rho and pi)
            B = [[0] * 5 for _ in range(5)]

            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = self._rot64(A[x][y], self.RHO_OFFSETS[x][y])

            # χ шаг (chi)
            for x in range(5):
                for y in range(5):
                    A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

            # ι шаг (iota)
            A[0][0] ^= self.ROUND_CONSTANTS[round_num]

        return A

    def _rot64(self, x, n):
        """Циклический сдвиг 64-битного числа"""
        n = n % 64
        return ((x << n) & ((1 << 64) - 1)) | (x >> (64 - n))

    def _absorb(self):
        """Фаза впитывания (absorbing phase)"""
        # Дополнение сообщения
        P = self.buffer

        # Добавляем байты 0x06 и 0x80 согласно SHA3 padding
        P.append(0x06)  # domain separation for SHA3
        while (len(P) * 8) % self.rate != 0:
            P.append(0x00)
        P[-1] ^= 0x80  # бит '1' в конце

        # Впитывание блоков
        block_size = self.rate // 8  # в байтах

        for i in range(0, len(P), block_size):
            block = P[i:i + block_size]

            # Преобразуем блок в состояние
            for j in range(len(block) // 8):
                lane = int.from_bytes(block[j * 8:(j + 1) * 8], 'little')
                x = j % 5
                y = j // 5
                self.state[x][y] ^= lane

            # Применяем перестановку
            self.state = self._keccak_f(self.state)

        # Очищаем буфер
        self.buffer.clear()

    def _squeeze(self):
        """Фаза выжимания (squeezing phase)"""
        output_bytes = self.output_length // 8
        result = bytearray()
        block_size = self.rate // 8

        while len(result) < output_bytes:
            # Извлекаем байты из состояния
            for y in range(5):
                for x in range(5):
                    if len(result) >= output_bytes:
                        break
                    lane_bytes = self.state[x][y].to_bytes(8, 'little')
                    result.extend(lane_bytes[:min(8, output_bytes - len(result))])

            if len(result) < output_bytes:
                self.state = self._keccak_f(self.state)

        return result[:output_bytes]

    def update(self, data):
        """Добавление данных"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.buffer.extend(data)

    def digest(self):
        """Возвращает итоговый хэш в виде байтов"""
        self._absorb()
        return bytes(self._squeeze())

    def hexdigest(self):
        """Возвращает хэш в виде hex-строки"""
        return self.digest().hex()

    @staticmethod
    def hash(data):
        """Удобный статический метод"""
        sha3 = SHA3_256()
        sha3.update(data)
        return sha3.hexdigest()