from stack_processor.ecdsa.curveparam import secp256r1
from stack_processor.ecdsa.curvepoint import CurvePoint
import unittest


class TestCurvePoint(unittest.TestCase):
    def test_init(self):
        P = CurvePoint(secp256r1, pos=(0, 0))
        self.assertIsNotNone(P)
        self.assertEqual(P.x, 0)
        self.assertEqual(P.y, 0)
        with self.assertRaises(ValueError):
            CurvePoint(secp256r1)

    def test_add(self):
        P = CurvePoint(
            secp256r1,
            x=0x11952303F0F1F145671498E43980CE2539026E7234FE02388AEACCFB3A3D4DDC,
            y=0xD96D3CFE8B55BFEAC33AA1591354B3917945B73B49D90E962ADE79D349DC79CA,
        )
        Q = CurvePoint(
            secp256r1,
            x=0x2CB1FA4F24275E2992C4FEE7AA32D8F0A36F967F677CDEC9B8398685C30FB1C3,
            y=0xF717F9FF2F0710A3D7FCF05916F24FF0E73C94BD3B26EE6BF31195506A94D4C5,
        )
        R = CurvePoint(
            secp256r1,
            x=0x22AD6644EE8E0F6423A5C64246976FB1A28777E8EBD2CFA542A635366E095ED0,
            y=0xA542EAC46B1D79F18F27BD07945DEF31981D6582D73CB1079B28FFB133632DB1,
        )
        self.assertEqual(P + P, Q)
        self.assertEqual(P + Q, R)
        self.assertEqual(-P + P, CurvePoint(secp256r1, pos=(0, 0)))

    def test_mul(self):
        P = CurvePoint(
            secp256r1,
            x=0x11952303F0F1F145671498E43980CE2539026E7234FE02388AEACCFB3A3D4DDC,
            y=0xD96D3CFE8B55BFEAC33AA1591354B3917945B73B49D90E962ADE79D349DC79CA,
        )
        added = CurvePoint(secp256r1, pos=(0, 0))
        for i in range(100):
            self.assertEqual(i * P, added)
            self.assertEqual((-i) * P, -added)
            self.assertEqual((-i) * P + i * P, CurvePoint(secp256r1, pos=(0, 0)))
            added += P

    def test_serialization(self):
        P = CurvePoint(secp256r1, pos=secp256r1.basepoint)
        self.assertEqual(
            P.octet_str().upper(),
            (
                "03"
                "6B17D1F2 E12C4247 F8BCE6E5 63A440F2"
                "77037D81 2DEB33A0 F4A13945 D898C296"
            ).replace(" ", ""),
        )
