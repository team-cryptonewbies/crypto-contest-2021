import unittest
from stack_processor.lsh256 import LSHDigest


class TestLSH256Hash(unittest.TestCase):
    def test_digest(self):
        self.assertEqual(
            LSHDigest.digest(data=b"abc").hex(),
            "5fbf365daea5446a7053c52b57404d77a07a5f48a1f7c1963a0898ba1b714741",
        )
