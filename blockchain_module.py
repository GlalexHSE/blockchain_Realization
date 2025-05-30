import os
from hash_Streebog import streebog_hash
from pseudorandom_generator import pseudorandom_generator

# --- Настройки ---
SEED = "Glukhov Alexander Sergeevich"
NUM_TX = 5
TX_HEX_LEN = 400

_estimated_calls = NUM_TX * ((TX_HEX_LEN + 63) // 64) + 5
_prng_cache = pseudorandom_generator(SEED, _estimated_calls, return_decimal=False)
_prng_index = 0

def next_rand() -> str:
    """
    Возвращает следующее псевдослучайное 256-битное значение (hex) из заранее рассчитанного списка.
    Это позволяет избежать повторных дорогих вызовов генератора.
    """
    global _prng_index
    if _prng_index >= len(_prng_cache):
        # подстраховка: догружаем ещё значений
        extra = pseudorandom_generator(SEED, _prng_index + 10, return_decimal=False)
        _prng_cache.extend(extra[len(_prng_cache):])
    val = _prng_cache[_prng_index]
    _prng_index += 1
    return val

# Функция генерации одной транзакции:
def generate_transaction(prefix: str = None) -> str:
    data_hex = ""
    # Если передан префикс, записываем его hex
    if prefix:
        data_hex += prefix.encode('utf-8').hex()
    # Дополняем до нужной длины
    while len(data_hex) < TX_HEX_LEN:
        data_hex += next_rand()
    return data_hex[:TX_HEX_LEN]

# Функция склеивания двух хэшей через сумму по модулю 2^256 и последующий хэш
def sum_of_hashes(h1: str, h2: str) -> str:
    total = (int(h1, 16) + int(h2, 16)) % (1 << 256)
    return hex(total)[2:].rjust(64, '0')


transactions = []
for i in range(NUM_TX):
    if i == 2:
        tx = generate_transaction(SEED)  # третья транзакция с ФИО
    else:
        tx = generate_transaction()
    transactions.append(tx)

# 2) Строим Merkle-дерево
# Листья - хэши транзакций
leaves = [streebog_hash(tx, is_hex=False) for tx in transactions]
# Дублируем последний, если нечёт
if len(leaves) % 2:
    leaves.append(leaves[-1])

# Уровень 2
h12 = streebog_hash(sum_of_hashes(leaves[0], leaves[1]), is_hex=True)
h34 = streebog_hash(sum_of_hashes(leaves[2], leaves[3]), is_hex=True)
if len(leaves) > 4:
    lvl2 = [h12, h34, leaves[4]]
else:
    lvl2 = [h12, h34]
if len(lvl2) % 2:
    lvl2.append(lvl2[-1])

# Корень
h1234 = streebog_hash(sum_of_hashes(lvl2[0], lvl2[1]), is_hex=True)
h12345 = streebog_hash(sum_of_hashes(h1234, lvl2[2]), is_hex=True)
merkle_root = h12345

# 3) Proof-of-Work
# block_size - 4 hex символа, первые биты ненулевые
size_hex = next_rand()[:8]
while bin(int(size_hex, 16))[2].zfill(4)[0] == '0':
    size_hex = next_rand()[:8]
# prev_hash - случайный 256 бит
prev_hash = next_rand()
# timestamp HHDDMMYY
timestamp = format(23, '02x') + format(30, '02x') + format(5, '02x') + format(25, '02x')

nonce_hex = None
for i in range(1, 1000):
    candidate = f"{size_hex}{prev_hash}{merkle_root}{timestamp}{format(i, '08x')}"
    h = streebog_hash(candidate, is_hex=True)
    bits = bin(int(h, 16))[2:].zfill(len(h) * 4)
    if bits.startswith('00000'):
        nonce_hex = format(i, '08x')
        print(f"Found PoW! nonce={nonce_hex}, hash={h}")
        break

# Вывод
print("Transactions (hex):", transactions)
print("Merkle root:", merkle_root)
print("Block header:")
print(" size:", size_hex)
print(" prev_hash:", prev_hash)
print(" timestamp:", timestamp)
print(" nonce:", nonce_hex)
