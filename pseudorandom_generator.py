from hash_Streebog import streebog_hash


def pseudorandom_generator(seed, num_cycles):
    # Преобразуем строку seed в байты и затем в биты
    name_bytes = seed.encode('utf-8')
    name_bits = []
    for byte in name_bytes:
        name_bits.extend([int(bit) for bit in format(byte, '08b')])

    # Дополняем или обрезаем до ровно 512 бит
    if len(name_bits) > 512:
        name_bits = name_bits[:512]
    else:
        name_bits = name_bits + [0] * (512 - len(name_bits))

    # Шаг 2: Вычисляем начальный хэш h0 (256 бит) из seed
    h0_hex = streebog_hash(''.join(map(str, name_bits)))

    # Преобразуем h0 из hex в биты для конкатенации
    h0_bits = []
    for char in h0_hex:
        h0_bits.extend([int(bit) for bit in format(int(char, 16), '04b')])

    # Инициализируем список для хранения псевдослучайных чисел
    random_numbers = [h0_hex]

    # Шаг 3: Генерация следующих псевдослучайных чисел
    for i in range(1, num_cycles):
        # Преобразуем номер цикла i в 256-битное бинарное число
        i_bits = [int(bit) for bit in format(i, '0256b')]

        # Объединяем h0 и i для получения 512-битного входа (h0 ∥ i)
        input_bits = h0_bits + i_bits

        # Вычисляем хэш: hi = H(h0 ∥ i)
        hi_hex = streebog_hash(''.join(map(str, input_bits)))
        random_numbers.append(hi_hex)

    return random_numbers


if __name__ == "__main__":
    seed = "Glukhov Alexander Sergeevich"
    num_cycles = 5  # Генерируем 5 псевдослучайных чисел для теста
    random_nums = pseudorandom_generator(seed, num_cycles)

    print("Pseudorandom numbers:")
    for i, num in enumerate(random_nums):
        print(f"h{i}: {num}")
