import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from stack_processor.ecdsa.ecdsa import ECDSA
from stack_processor.ecdsa.curvepoint import CurvePoint
from stack_processor.ecdsa.curveparam import secp256r1


key_pair = (
    0xFBD35EDDE64629B62C0BDB7EC48053627E19033F28BDFB3CAD66420C65CA3DED,
    CurvePoint(
        0x97B8857D197C8076B29B88E5F893C518E9054C9BEEAA6BE1C31FA6EA4AD83E81,
        0xA23A356F8C69025DA4845ED80F85434DB8A653035BEE977FE4BD46BDCA05F4BD,
        secp256r1,
    ),
)
ecdsa = ECDSA(secp256r1, key_pair)
message = "Let Team Crypt0newbies win Crypto Contest 2021!"


class TestECDSA(unittest.TestCase):
    def test_verify(self):
        # signature generated by OpenSSL
        signature = (
            0xE74013272166ED7216B81428E151C1F4196BCB16A442E590C63685839B32A8C9,
            0xD231C993EDCB1E808A3018227051493F2E73E1FC0FB37C7C5D4A46A7A749C451,
        )
        self.assertTrue(ecdsa.verify_sign(message, signature))

    def test_sign(self):
        signature = utils.encode_dss_signature(
            *ecdsa.create_sign(message.encode("utf-8"))
        )
        private_key = ec.derive_private_key(key_pair[0], ec.SECP256R1())
        public_key = private_key.public_key()
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(message.encode("utf-8"))
        digest = hasher.finalize()
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(chosen_hash)))
