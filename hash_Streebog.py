import numpy as np


def streebog_hash(input_str, is_hex=False):
    """
        Реализация хэш-функции ГОСТ Р 34.11-2018 (Стрибог).

        Аргументы:
            input_str (str): Входная строка для хеширования.
            is_hex (bool): Указывает, интерпретировать ли вход как hex-строку (по умолчанию False).

        Возвращает:
            str: Хэш-сумма (256 бит) в шестнадцатеричном формате.
        """

    # S-блок (таблица подстановки)
    PI = (
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147,
        46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1,
        142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200,
        72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183,
        93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255,
        53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246,
        124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115,
        30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105,
        213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76,
        63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190,
        229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
    )

    # Начальный вектор хэша: 512 битов, чередующихся '00000001'
    INIT_VEC = [int(bit) for bit in '00000001' * 64]

    # Таблица перестановки байтов
    TAU = (
        0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27,
        35, 43, 51, 59, 4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61, 6, 14, 22, 30, 38, 46, 54, 62,
        7, 15, 23, 31, 39, 47, 55, 63
    )

    # 12 раундовых констант в 512-битном формате
    CONSTANTS = [
        0xb1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507,
        0x6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7,
        0xf574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2,
        0xef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e,
        0x4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57,
        0xae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e,
        0xf4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493,
        0x9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e,
        0x378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb,
        0xabbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced,
        0x7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b,
        0x378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720
    ]

    # Матрица L-преобразования
    MATRIX_DATA = [
        "8e20faa72ba0b470", "47107ddd9b505a38", "ad08b0e0c3282d1c", "d8045870ef14980e",
        "6c022c38f90a4c07", "3601161cf205268d", "1b8e0b0e798c13c8", "83478b07b2468764",
        "a011d380818e8f40", "5086e740ce47c920", "2843fd2067adea10", "14aff010bdd87508",
        "0ad97808d06cb404", "05e23c0468365a02", "8c711e02341b2d01", "46b60f011a83988e",
        "90dab52a387ae76f", "486dd4151c3dfdb9", "24b86a840e90f0d2", "125c354207487869",
        "092e94218d243cba", "8a174a9ec8121e5d", "4585254f64090fa0", "accc9ca9328a8950",
        "9d4df05d5f661451", "c0a878a0a1330aa6", "60543c50de970553", "302a1e286fc58ca7",
        "18150f14b9ec46dd", "0c84890ad27623e0", "0642ca05693b9f70", "0321658cba93c138",
        "86275df09ce8aaa8", "439da0784e745554", "afc0503c273aa42a", "d960281e9d1d5215",
        "e230140fc0802984", "71180a8960409a42", "b60c05ca30204d21", "5b068c651810a89e",
        "456c34887a3805b9", "ac361a443d1c8cd2", "561b0d22900e4669", "2b838811480723ba",
        "9bcf4486248d9f5d", "c3e9224312c8c1a0", "effa11af0964ee50", "f97d86d98a327728",
        "e4fa2054a80b329c", "727d102a548b194e", "39b008152acb8227", "9258048415eb419d",
        "492c024284fbaec0", "aa16012142f35760", "550b8e9e21f7a530", "a48b474f9ef5dc18",
        "70a6a56e2440598e", "3853dc371220a247", "1ca76e95091051ad", "0edd37c48a08a6d8",
        "07e095624504536c", "8d70c431ac02a736", "c83862965601dd1b", "641c314b2b8ee083"
    ]

    # Преобразование строки MATRIX_DATA в битовую матрицу
    TRANSFORM_MATRIX = []
    for hex_row in MATRIX_DATA:
        row_bits = []
        for char in hex_row:
            row_bits.extend([int(bit) for bit in format(int(char, 16), '04b')])
        TRANSFORM_MATRIX.append(row_bits)

    def to_binary_vector(size, value):
        """Переводит целое число в битовый вектор заданной длины."""
        return [int(bit) for bit in format(value, f'0{size}b')]

    def to_integer(bits):
        """Переводит битовый вектор в целое число."""
        return int(''.join(map(str, bits)), 2)

    def take_msb(count, data):
        """Возвращает count старших битов вектора data."""
        return data[:count]

    def xor_vectors(vec1, vec2):
        """Побитовая операция XOR двух векторов одинаковой длины."""
        return [vec1[i] ^ vec2[i] for i in range(min(len(vec1), len(vec2)))]

    def linear_transform(vec):
        """L-преобразование: перемножение каждого 64-битного блока на TRANSFORM_MATRIX."""
        blocks = [vec[i * 64:i * 64 + 64] for i in range(8)]
        result = []
        for block in blocks:
            result += [int(k) % 2 for k in np.array(block) @ np.array(TRANSFORM_MATRIX)]
        return result

    def substitute(vec):
        """S-преобразование: применение S-блока к каждому байту."""
        blocks = [to_integer(vec[i * 8:i * 8 + 8]) for i in range(64)]
        result = []
        for val in blocks:
            new_val_bin = format(PI[val], '08b')
            result += [int(bit) for bit in new_val_bin]
        return result

    def permute(vec):
        """P-преобразование: перестановка байтов по таблице TAU."""
        blocks = [to_integer(vec[i * 8:i * 8 + 8]) for i in range(64)]
        result = []
        for i in range(len(blocks)):
            new_val_bin = format(blocks[TAU[i]], '08b')
            result += [int(bit) for bit in new_val_bin]
        return result

    def expand_key(key, msg):
        """Расширение ключа (K_i) и применение 12 раундов к сообщению."""
        result = msg.copy()
        key_list = [key.copy()]
        for i in range(1, 13):
            key_xor_const = xor_vectors(key_list[i - 1], to_binary_vector(512, CONSTANTS[i - 1]))
            sub_key = substitute(key_xor_const)
            perm_key = permute(sub_key)
            lin_key = linear_transform(perm_key)
            key_list.append(lin_key)

        for i in range(12):
            result = linear_transform(permute(substitute(xor_vectors(key_list[i], result))))
        result = xor_vectors(key_list[12], result)
        return result

    def compress(nonce, hash_val, msg):
        """Функция сжатия g(N, h, m) — основа алгоритма."""
        hash_xor_nonce = xor_vectors(hash_val, nonce)
        sub_hash = substitute(hash_xor_nonce)
        perm_hash = permute(sub_hash)
        lin_hash = linear_transform(perm_hash)
        expanded = expand_key(lin_hash, msg)
        return xor_vectors(xor_vectors(expanded, hash_val), msg)

    def hash_message(bits):
        """Основная функция хэширования: реализует алгоритм обработки блока, обрабатывая сообщение поблочно."""
        hash_val = INIT_VEC
        nonce = [0] * 512
        checksum = nonce.copy()
        while len(bits) >= 512:
            block = bits[-512:]
            bits = bits[:-512]
            hash_val = compress(nonce, hash_val, block)
            nonce = to_binary_vector(512, (to_integer(nonce) + 512) % (2 ** 512))
            checksum = to_binary_vector(512, (to_integer(checksum) + to_integer(block)) % (2 ** 512))
        # Добавление padding
        padded = [0] * (511 - len(bits)) + [1] + bits
        hash_val = compress(nonce, hash_val, padded)
        nonce = to_binary_vector(512, (to_integer(nonce) + len(bits)) % (2 ** 512))
        checksum = to_binary_vector(512, (to_integer(checksum) + to_integer(padded)) % (2 ** 512))
        hash_val = compress(to_binary_vector(512, 0), hash_val, nonce)
        hash_val = take_msb(256, compress(to_binary_vector(512, 0), hash_val, checksum))
        return hash_val

    input_bits = []
    if not is_hex:
        utf8_bytes = input_str.encode('utf-8')
        for byte in utf8_bytes:
            input_bits += [int(bit) for bit in bin(byte)[2:].zfill(8)]
    else:
        input_bits = [int(bit) for bit in bin(int(input_str, 16))[2:].zfill(len(input_str) * 4)]

    hash_result = hash_message(input_bits)

    return ''.join(
        hex(val)[2:] for val in [
            to_integer(hash_result[i:i + 4]) for i in range(0, len(hash_result), 4)
        ]
    )

if __name__ == "__main__":
    '''
    Примеры из ГОСТ Р 34.11-2018
    '''
    test_msg1 = '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130'
    test_msg2 = 'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1'
    result1 = streebog_hash(test_msg1,is_hex=True)
    result2 = streebog_hash(test_msg2, is_hex=True)
    print("Примеры из ГОСТ Р 34.11-2018:")
    print(test_msg1, result1,sep=' -> ')
    print(test_msg2, result2, sep=' -> ')