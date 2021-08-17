import unittest
from stack_processor.ecdsa.numbertheory import tonelli


class TestNumberTheory(unittest.TestCase):
    def test_tonelli(self):
        p = 41
        for i in range(1, 40):
            squared = i ** 2 % p
            self.assertIn(tonelli(squared, p), (i, p - i))
        with self.assertRaises(AssertionError):
            tonelli(2, 3)
