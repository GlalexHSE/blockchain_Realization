from pseudorandom_generator import pseudorandom_generator
from hash_Streebog import streebog_hash


class SchnorrSignature:
    def __init__(self, seed: str):
        """
        :param seed: строка-сид (имя и фамилия студента)
        """
        self.seed = seed
        self._prng_counter = 0

        # Параметры схемы
        self.p = int(
            'EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3',16)
        self.q = int('98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D',16)
        self.g = int('9E96031500C8774A869582D4AFDE2127AFAD2538B4B6270A6F7C8837B50D50F206755984A49E509304D648BE2AB5AAB18EBE2CD46AC3D8495B142AA6CE23E21C',16)

        # Генерируем секретный ключ x = next_prng() mod q
        self.x = self._next_prng() % self.q
        # Открытый ключ P = g^x mod p
        self.P = pow(self.g, self.x, self.p)

    def _next_prng(self) -> int:
        """
        Возвращает следующее псевдослучайное число из генератора в десятичном виде.
        Мы каждый раз запрашиваем pseudorandom_generator(seed, count=self._prng_counter)
        и берём последний элемент списка.
        """
        self._prng_counter += 1
        vals = pseudorandom_generator(self.seed, count=self._prng_counter, return_decimal=True)
        return vals[-1]

    def sign(self, message: str) -> tuple:
        """
        Подписать строку message.
        Возвращает кортеж (R, s).
        """
        # 1) Нонс r
        r = self._next_prng() % self.q

        # 2) R = g^r mod p
        R = pow(self.g, r, self.p)

        # 3) Считаем e = H( R_hex || P_hex || message ) mod q
        R_hex = format(R, '0128x')
        P_hex = format(self.P, '0128x')
        h_input = R_hex + P_hex + message
        e_hex = streebog_hash(h_input, is_hex=False)
        e = int(e_hex, 16) % self.q

        # 4) s = (r + e ⋅ x) mod q
        s = (r + e * self.x) % self.q

        return R, s

    def verify(self, message: str, signature: tuple) -> bool:
        """
        Проверить подпись signature = (R, s) для строки message.
        """
        R, s = signature

        # Пересчитываем e
        R_hex = format(R, '0128x')
        P_hex = format(self.P, '0128x')
        h_input = R_hex + P_hex + message
        e_hex = streebog_hash(h_input, is_hex=False)
        e = int(e_hex, 16) % self.q

        # Проверка g^s ≡ R ⋅ P^e (mod p)
        left = pow(self.g, s, self.p)
        right = (R * pow(self.P, e, self.p)) % self.p
        if left == right:
            return True
        else:
            return False


if __name__ == "__main__":
    signer = SchnorrSignature("Glukhov Alexander")
    msg = "Glukhov Alexander"

    R, s = signer.sign(msg)
    print("Signature (R, s):", R, s)

    valid = signer.verify(msg, (R, s))
    print("Verification result:", valid)
