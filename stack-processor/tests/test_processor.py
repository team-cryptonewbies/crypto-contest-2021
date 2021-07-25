import unittest
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


if __name__ == "__main__":
    unittest.main()
