from hash_Streebog import streebog_hash  #


def pseudorandom_generator(seed: str, count: int, return_decimal: bool = False):
    """
    Генератор псевдослучайных чисел на основе хэш-функции ГОСТ Р 34.11-2018 (256 бит).

    :param seed: Строка-сид (имя и фамилия студента).
    :param count: Количество чисел, которые нужно сгенерировать.
    :param return_decimal: Если True — вернуть числа в десятичной системе, иначе hex.
    :return: Список псевдослучайных чисел.
    """
    # Преобразуем seed в байты, затем в hex-строку, затем дополняем до 512 бит (64 байта = 128 hex символов)
    seed_bytes = seed.encode('utf-8')[:64]  # ограничение до 64 байт
    seed_bytes += b'\x00' * (64 - len(seed_bytes))  # дополнение до 64 байт
    seed_hex = seed_bytes.hex()

    # h0 = H(seed)
    h0 = streebog_hash(seed_hex, is_hex=True)

    results = []
    for i in range(1, count + 1):
        # Преобразуем i в 256-битную hex-строку (64 hex символа)
        i_hex = format(i, '064x')

        # h0 ∥ i — объединение двух 256-битных hex-строк в одну 512-битную hex-строку
        combined_input = h0 + i_hex

        # hi = H(h0 ∥ i)
        hi = streebog_hash(combined_input, is_hex=True)

        if return_decimal:
            hi = int(hi, 16)

        results.append(hi)

    return results



if __name__ == "__main__":
    seed = "Glukhov Alexander"
    numbers = pseudorandom_generator(seed, count=5)

    print("Pseudorandom numbers:")
    for idx, num in enumerate(numbers, start=1):
        print(f"h{idx}: {num}")
