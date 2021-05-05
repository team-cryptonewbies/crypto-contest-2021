"""
prince_integral_attack.py -- Mount an attack based on integral cryptanalysis.
"""
from bitstring import BitArray, ConstBitStream
from functools import reduce
from operator import add
import reduced_prince_cipher

def get_nibble(bitstr, nibble_pos):
    return bitstr[nibble_pos * 4:nibble_pos * 4 + 4]

# pre-process data.
plaintext_file = ConstBitStream(filename='./data/pt.dat')
ciphertext_file = ConstBitStream(filename='./data/ct.dat')
plaintext_set = []
ciphertext_set = []
active_nibble_pos = []
for _ in range(0x500):
    plaintexts = []
    ciphertexts = []
    for _ in range(16):
        plaintexts.append(BitArray(plaintext_file.read(64)))
        ciphertexts.append(BitArray(ciphertext_file.read(64)))
    plaintext_set.append(plaintexts)
    ciphertext_set.append(ciphertexts)
    diff = plaintexts[0] ^ plaintexts[1]
    pos = diff.find('0b1')[0] % 4
    active_nibble_pos.append(pos)

# get k1 ^ k0'
candidates = []
for _ in range(16):
    candidates.append({'ok': set(), 'fail': set()})

tries = 5
for nibble_pos in range(16):
    for guess_value in range(16):
        for ciphertexts in ciphertext_set[:tries]:
            guess = BitArray(hex(guess_value))
            RC3_nibble = get_nibble(reduced_prince_cipher.RC[3], nibble_pos)
            xor_sum = BitArray(4)
            for ciphertext in ciphertexts:
                ciphertext_nibble = get_nibble(ciphertext, nibble_pos)
                xor_sum ^= reduced_prince_cipher.s_layer(
                    ciphertext_nibble ^ guess ^ RC3_nibble
                )
            if xor_sum.uint == 0 and \
                guess_value not in candidates[nibble_pos]['fail']:
                candidates[nibble_pos]['ok'].add(guess_value)
            elif xor_sum.uint != 0:
                if guess_value in candidates[nibble_pos]['ok']:
                    candidates[nibble_pos]['ok'].remove(guess_value)
                candidates[nibble_pos]['fail'].add(guess_value)
assert all([len(x['ok']) == 1 for x in candidates])
k1_xor_k0_prime = reduce(add,
                         [BitArray(hex(x['ok'].pop())) for x in candidates])
print(f'k1 ^ k0\' = 0x{k1_xor_k0_prime.hex}')
