"""
reduced_prince_cipher.py -- Implementation for 4-round PRINCE cipher.
"""

import numpy as np
from bitstring import BitArray
from scipy.linalg import block_diag
from typing import Tuple

RC = [
    BitArray('0x0000000000000000'),
    BitArray('0x13198a2e03707344'),
    BitArray('0xa4093822299f31d0'),
    BitArray('0x082efa98ec4e6c89')
]

M0 = np.array([[0, 0, 0, 0],
               [0, 1, 0, 0],
               [0, 0, 1, 0],
               [0, 0, 0, 1]])
M1 = np.array([[1, 0, 0, 0],
               [0, 0, 0, 0],
               [0, 0, 1, 0],
               [0, 0, 0, 1]])
M2 = np.array([[1, 0, 0, 0],
               [0, 1, 0, 0],
               [0, 0, 0, 0],
               [0, 0, 0, 1]])
M3 = np.array([[1, 0, 0, 0],
               [0, 1, 0, 0],
               [0, 0, 1, 0],
               [0, 0, 0, 0]])
M_hat0 = np.vstack((np.hstack((M0, M1, M2, M3)),
                    np.hstack((M1, M2, M3, M0)),
                    np.hstack((M2, M3, M0, M1)),
                    np.hstack((M3, M0, M1, M2))))
M_hat1 = np.vstack((np.hstack((M1, M2, M3, M0)),
                    np.hstack((M2, M3, M0, M1)),
                    np.hstack((M3, M0, M1, M2)),
                    np.hstack((M0, M1, M2, M3))))
M_prime = block_diag(M_hat0, M_hat1, M_hat1, M_hat0)

def expand_key(key: BitArray) -> Tuple[BitArray, BitArray, BitArray]:
    """
    Key expansion for PRINCE cipher

    Params
    ------
    - key: BitArray
      - 128-bit key to expand. Its length must equal to 128 bits.
    """
    assert len(key) == 128
    key0 = key[:64]
    key1 = key[64:]
    key0_prime = key0.copy().ror(1) ^ (key0 >> 63)
    return key0, key0_prime, key1

def s_layer(state: BitArray) -> BitArray:
    """
    Substitution layer for PRINCE cipher

    Params
    ------
    - state: BitArray
      - A state bit-array to apply the substitution. Its length must be a
        multiple of 4.
    """
    assert len(state) % 4 == 0
    sbox = [0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1,  # 01234567
            0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4]  # 89abcdef
    result = BitArray()
    for nibble in state.cut(4):
        result.append(BitArray(hex(sbox[nibble.int])))
    return result

def inverse_s_layer(state: BitArray) -> BitArray:
    """
    Inverse substitution layer for PRINCE cipher

    Params
    ------
    - state: BitArray
      - A state bit-array to apply the inverse substitution. Its length must be
        a multiple of 4.
    """
    assert len(state) % 4 == 0
    sbox = [0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9,  # 01234567
            0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1]  # 89abcdef
    result = BitArray()
    for nibble in state.cut(4):
        result.append(BitArray(hex(sbox[nibble.int])))
    return result

def m_layer(state: BitArray) -> BitArray:
    """
    Matrix multiplication layer for PRINCE cipher

    Params
    ------
    - state: BitArray
      - A state bit-array to apply matrix multiplications. Its length must
        equal to 64 bits.
    """
    assert len(state) == 64

def encrypt(plaintext: BitArray, key: BitArray) -> BitArray:
    """
    Encrypt a block using 4-round PRINCE cipher.

    Params
    ------
    - plaintext: BitArray
      - A plaintext block to encrypt. The length must equal to 64 bits.
    - key: BitArray
      - 128-bit key for encryption. The length must equal to 128 bits.
    """
    assert len(plaintext) == 64
    assert len(key) == 128
    key0, key0_prime, key1 = expand_key(key)
    state = plaintext.copy()

    # round 1
    state ^= key0
    state ^= key1
    state ^= RC[0]

    # round 2
    state = s_layer(state)
    return state
