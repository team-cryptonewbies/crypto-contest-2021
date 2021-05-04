import unittest
from bitstring import BitArray

import reduced_prince_cipher

class TestCipher(unittest.TestCase):
    def test_s_layer(self):
        arr = BitArray('0x0123456789abcdef')
        substituted = reduced_prince_cipher.s_layer(arr)
        self.assertEqual(substituted, BitArray('0xbf32ac916780e5d4'))
        self.assertFalse(arr is substituted)
        inversed = reduced_prince_cipher.inverse_s_layer(substituted)
        self.assertEqual(inversed, arr)
        self.assertFalse(substituted is inversed)
        self.assertFalse(arr is inversed)

if __name__ == '__main__':
    unittest.main()
