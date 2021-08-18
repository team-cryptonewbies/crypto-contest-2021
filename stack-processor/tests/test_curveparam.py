import unittest
from stack_processor.ecdsa.curveparam import CurveParam


class TestCurveParam(unittest.TestCase):
    def test_data_conversion(self):
        self.assertEqual(
            CurveParam._CurveParam__octet_str_to_int("11223344"), 0x11223344  # type: ignore
        )
        self.assertEqual(
            CurveParam._CurveParam__octet_list_to_int([0x11, 0x22, 0x33, 0x44]), 0x11223344  # type: ignore
        )
        self.assertEqual(
            CurveParam._CurveParam__octet_list_to_field_elem([0x2, 0x0F], 8191), 527  # type: ignore
        )

    def test_init(self):
        secp256r1 = CurveParam(
            "secp256r1",
            "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF",
            "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC",
            "5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B",
            "03 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296",
            "FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551",
            "01",
        )
        another = CurveParam(
            "secp256r1",
            "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF",
            "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC",
            "5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B",
            "04 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5",
            "FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551",
            "01",
        )
        self.assertIsNotNone(secp256r1)
        self.assertIsNotNone(another)
        self.assertEqual(secp256r1.basepoint, another.basepoint)
