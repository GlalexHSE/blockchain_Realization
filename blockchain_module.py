from hash_Streebog import streebog_hash
from pseudorandom_generator import pseudorandom_generator
from Schnorr_sign import SchnorrSignature

SEED = "Glukhov Alexander"
NUM_TX = 6
TX_HEX_LEN = 400

PRNG_CACHE = pseudorandom_generator(SEED, 100, return_decimal=False)
PRNG_INDEX = 0

def next_rand():
    global PRNG_INDEX
    val = PRNG_CACHE[PRNG_INDEX]
    PRNG_INDEX += 1
    return val

def generate_transaction(prefix=None):
    tx = ""
    if prefix:
        tx += prefix.encode('utf-8').hex()
    while len(tx) < TX_HEX_LEN:
        tx += next_rand()
    return tx[:TX_HEX_LEN]

def sum_of_hashes(h1, h2):
    return hex((int(h1, 16) + int(h2, 16)) % (2**256))[2:].zfill(64)

# 1. Генерация транзакций и подписей
signer = SchnorrSignature(SEED)
transactions = [generate_transaction(SEED)] + [generate_transaction() for _ in range(5)]
signed = [signer.sign(tx) for tx in transactions]

# 2. Merkle Tree вручную
leaves = [streebog_hash(tx, is_hex=False) for tx in transactions]
if len(leaves) % 2:
    leaves.append(leaves[-1])

h12 = streebog_hash(sum_of_hashes(leaves[0], leaves[1]), is_hex=True)
h34 = streebog_hash(sum_of_hashes(leaves[2], leaves[3]), is_hex=True)
h1234 = streebog_hash(sum_of_hashes(h12, h34), is_hex=True)
h12345 = streebog_hash(sum_of_hashes(h1234, leaves[4]), is_hex=True)
merkle_root = h12345

# 3. Заголовок блока и PoW
size = next_rand()[:8]
while bin(int(size[0], 16))[2:].zfill(4)[0] == '0':
    size = next_rand()[:8]

prev_hash = next_rand()
timestamp = format(23, '02x') + format(30, '02x') + format(5, '02x') + format(25, '02x')


for nonce in range(1, 1000):
    block_header = f"{size}{prev_hash}{merkle_root}{timestamp}{format(nonce, '08x')}"
    h = streebog_hash(block_header, is_hex=True)
    if h.startswith('00') and h[2] in '01234567':
        print(f"PoW!!! Nonce: {format(nonce, '08x')} (dec: {nonce})")
        print("Block header:", block_header)
        print("Hash:", h)
        break

print("Merkle root:", merkle_root)
print("Transactions:", transactions)
print("Signatures:", signed)
