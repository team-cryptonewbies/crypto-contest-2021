import unittest
from stack_processor.ecdsa.data_conversion import (
    field_elem_to_octet_list,
    octet_list_to_field_elem,
    octet_list_to_int,
    octet_str_to_int,
    octet_str_to_octet_list,
)


class TestDataConversion(unittest.TestCase):
    def test_data_conversion(self):
        self.assertEqual(octet_str_to_int("11223344"), 0x11223344)
        self.assertEqual(
            octet_list_to_int([0x11, 0x22, 0x33, 0x44]),
            0x11223344,
        )
        self.assertEqual(octet_list_to_field_elem([0x2, 0x0F], 8191), 527)
        self.assertListEqual(
            octet_str_to_octet_list("1223344"), [0x01, 0x22, 0x33, 0x44]
        )
        self.assertListEqual(
            field_elem_to_octet_list(0x11223344), [0x11, 0x22, 0x33, 0x44]
        )
        self.assertListEqual(
            field_elem_to_octet_list(0x0111223344), [0x01, 0x11, 0x22, 0x33, 0x44]
        )
