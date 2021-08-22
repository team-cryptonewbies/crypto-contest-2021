"""
prince_integral_attack.py -- Mount an attack based on integral cryptanalysis.
"""
from bitstring import BitArray, ConstBitStream
from functools import reduce
from operator import add
import reduced_prince_cipher


def get_nibble(bitstr, nibble_pos):
    return bitstr[nibble_pos * 4 : nibble_pos * 4 + 4]


def k1_xor_k0_prime_candidate(ciphertext_set):
    candidates = []
    for _ in range(16):
        candidates.append({"ok": set(), "fail": set()})
    for nibble_pos in range(16):
        for guess_value in range(16):
            guess = BitArray(hex(guess_value))
            RC3_nibble = get_nibble(reduced_prince_cipher.RC[3], nibble_pos)
            for ciphertexts in ciphertext_set:
                xor_sum = BitArray(4)
                for ciphertext in ciphertexts:
                    ciphertext_nibble = get_nibble(ciphertext, nibble_pos)
                    xor_sum ^= reduced_prince_cipher.s_layer(
                        ciphertext_nibble ^ guess ^ RC3_nibble
                    )
                if (
                    xor_sum.uint == 0
                    and guess_value not in candidates[nibble_pos]["fail"]
                ):
                    candidates[nibble_pos]["ok"].add(guess_value)
                elif xor_sum.uint != 0:
                    if guess_value in candidates[nibble_pos]["ok"]:
                        candidates[nibble_pos]["ok"].remove(guess_value)
                    candidates[nibble_pos]["fail"].add(guess_value)
    return candidates


def get_result_from_candidate(candidate):
    assert all([len(x["ok"]) for x in candidate])
    return reduce(add, [BitArray(hex(x["ok"].pop())) for x in candidate])


def read_data_files(plaintext_path="./data/pt.dat", ciphertext_path="./data/ct.dat"):
    plaintext_file = ConstBitStream(filename=plaintext_path)
    ciphertext_file = ConstBitStream(filename=ciphertext_path)
    plaintext_set = []
    ciphertext_set = []
    for _ in range(0x500):
        plaintexts = []
        ciphertexts = []
        for _ in range(16):
            plaintexts.append(
                BitArray(uint=plaintext_file.read("uintle:64"), length=64)
            )
            ciphertexts.append(
                BitArray(uint=ciphertext_file.read("uintle:64"), length=64)
            )
        plaintext_set.append(plaintexts)
        ciphertext_set.append(ciphertexts)
    return plaintext_set, ciphertext_set


if __name__ == "__main__":
    # pre-process data.
    plaintext_set, ciphertext_set = read_data_files()
    candidates = k1_xor_k0_prime_candidate(ciphertext_set[:5])
    k1_xor_k0_prime = get_result_from_candidate(candidates)
    print(f"k1 ^ k0' = 0b{k1_xor_k0_prime.bin}")
