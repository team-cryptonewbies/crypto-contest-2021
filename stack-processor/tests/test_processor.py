import unittest
from base64 import b64encode
from stack_processor.processor import StackProcessor


class TestStackProcessor(unittest.TestCase):
    def test_init(self):
        processor = StackProcessor([])
        self.assertIsNotNone(processor)

    def test_add(self):
        processor = StackProcessor("1 2 ADD".split())
        result = processor.run()
        self.assertListEqual(list(result), [3])

    def test_equal(self):
        processor = StackProcessor("1 1 EQUAL".split())
        result = processor.run()
        self.assertListEqual(list(result), [True])
        processor = StackProcessor("1 2 EQUAL".split())
        result = processor.run()
        self.assertListEqual(list(result), [False])
        processor = StackProcessor("1 2 OP_EqualVerify".split())
        result = processor.run()
        self.assertListEqual(list(result), [False])
        processor = StackProcessor("1 2 ADD 3 EQUAL".split())
        result = processor.run()
        self.assertListEqual(list(result), [True])

    def test_op_dup(self):
        processor = StackProcessor("1 OP_DUP".split())
        result = processor.run()
        self.assertListEqual(list(result), [1, 1])

    def test_datatypes(self):
        message = "Let Team Crypt0newbies win Crypto Contest 2021!"
        encoded_message = b64encode(message.encode("utf-8")).decode("ascii")
        processor = StackProcessor(
            ["bytes_utf8:" + message, "base64:" + encoded_message, "EQUAL"]
        )
        result = processor.run()
        self.assertListEqual(list(result), [True])
