from pseudorandom_generator import pseudorandom_generator
from hash_Streebog import streebog_hash


class SchnorrSignature:
    def __init__(self, seed: str):
        """
        Инициализация объекта подписи Шнорра с использованием заданного сида.

        :param seed: строка-сид
        """
        self.seed = seed
        self._prng_counter = 0

        # Параметры схемы Шнорра
        self.p = int(
            'EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3', 16)
        self.q = int('98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D', 16)
        self.g = int('9E96031500C8774A869582D4AFDE2127AFAD2538B4B6270A6F7C8837B50D50F206755984A49E509304D648BE2AB5AAB18EBE2CD46AC3D8495B142AA6CE23E21C', 16)

        # Генерация секретного ключа
        self.x = self._next_prng() % self.q
        # Вычисление открытого ключа
        self.P = pow(self.g, self.x, self.p)

    def _next_prng(self) -> int:
        """
        Генерация следующего псевдослучайного числа на основе сида.

        :return: следующее псевдослучайное число в десятичном виде
        """
        self._prng_counter += 1
        vals = pseudorandom_generator(self.seed, count=self._prng_counter, return_decimal=True)
        return vals[-1]

    def sign(self, message: str) -> tuple:
        """
        Подписывает сообщение с использованием схемы Шнорра.

        :param message: строка сообщения, которое нужно подписать
        :return: кортеж (R, s), представляющий цифровую подпись
        """
        # Генерация nonce
        r = self._next_prng() % self.q
        R = pow(self.g, r, self.p)

        # Хэширование R, P и сообщения
        R_hex = format(R, '0128x')
        P_hex = format(self.P, '0128x')
        h_input = R_hex + P_hex + message
        e_hex = streebog_hash(h_input, is_hex=False)
        e = int(e_hex, 16) % self.q

        # Вычисление подписи
        s = (r + e * self.x) % self.q

        return R, s

    def verify(self, message: str, signature: tuple) -> bool:
        """
        Проверяет цифровую подпись для заданного сообщения.

        :param message: строка сообщения, для которого проверяется подпись
        :param signature: кортеж (R, s), представляющий цифровую подпись
        :return: True, если подпись корректна, иначе False
        """
        R, s = signature

        # Пересчёт хэша e
        R_hex = format(R, '0128x')
        P_hex = format(self.P, '0128x')
        h_input = R_hex + P_hex + message
        e_hex = streebog_hash(h_input, is_hex=False)
        e = int(e_hex, 16) % self.q

        # Проверка корректности подписи
        left = pow(self.g, s, self.p)
        right = (R * pow(self.P, e, self.p)) % self.p
        return left == right


if __name__ == "__main__":
    signer = SchnorrSignature("Glukhov Alexander")
    msg = "Glukhov Alexander"

    R, s = signer.sign(msg)
    print("Signature (R, s):", R, s)

    valid = signer.verify(msg, (R, s))
    print("Verification result:", valid)
