import unittest
from bitstring import BitArray

import reduced_prince_cipher


class TestCipher(unittest.TestCase):
    def test_s_layer(self):
        arr = BitArray("0x0123456789abcdef")
        substituted = reduced_prince_cipher.s_layer(arr)
        self.assertEqual(substituted, BitArray("0xbf32ac916780e5d4"))
        self.assertFalse(arr is substituted)
        inversed = reduced_prince_cipher.inverse_s_layer(substituted)
        self.assertEqual(inversed, arr)
        self.assertFalse(substituted is inversed)
        self.assertFalse(arr is inversed)

    def test_m_prime_layer(self):
        arr = BitArray("0x0123456789abcdef")
        multiplied = reduced_prince_cipher.m_prime_layer(arr)
        re_multiplied = reduced_prince_cipher.m_prime_layer(multiplied)
        self.assertEqual(arr, re_multiplied)

    def test_shift_rows(self):
        arr = BitArray("0x0123456789abcdef")
        shifted = reduced_prince_cipher.shift_rows(arr)
        self.assertEqual(shifted, BitArray("0x05af49e38d27c16b"))
        self.assertFalse(arr is shifted)
        inversed = reduced_prince_cipher.inverse_shift_rows(shifted)
        self.assertEqual(inversed, arr)
        self.assertFalse(shifted is inversed)
        self.assertFalse(arr is inversed)

    def test_inverse_m_layer(self):
        arr = BitArray("0x0123456789abcdef")
        after_m_layer = reduced_prince_cipher.m_layer(arr)
        inversed = reduced_prince_cipher.inverse_m_layer(after_m_layer)
        self.assertEqual(arr, inversed)
        self.assertFalse(arr is inversed)


if __name__ == "__main__":
    unittest.main()
