import tinyec.ec as ec
import secrets
from lsh import LSHDigest
from math import isfinite




def __init__(self, key):
    key = None
    
    self.__MAX_S = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    self.privKey = secrets.randbelow(curve.field.n)
    self.pubkey = self.privKey * curve.g
    EC_CURVE_REGISTRY = {
                    "secp256r1": {"p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                                "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
                                "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                                "g": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                                        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
                                "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
                                "h": 0x1}}


#타원 곡선 함수
def get_curve(self, name):
    curve_params = {}
    for k, v in self.EC_CURVE_REGISTRY.items():
        if name.lower() == k.lower():
            curve_params = v
    if curve_params == {}:
        raise ValueError("Unknown elliptic curve name")
    try:
        sub_group = ec.SubGroup(curve_params["p"], curve_params["g"], curve_params["n"], curve_params["h"])
        curve = ec.Curve(curve_params["a"], curve_params["b"], sub_group, name)
    except KeyError:
        raise RuntimeError("Missing parameters for curve %s" % name)
    return curve


curve = get_curve('secp256r1')

# 서명
def SignHash(self, r, s):
    n = self.curve.field.n
    r = 0
    s = 0

    hm = hash

    while s == 0:
        # choose random k
        k = secrets.randbelow(curve.field.n)
        kG = k * curve.g

        x1 = curve.g.x

        # r
        r = x1 % n
        if r == 0:
            continue

        # s
        k_1 = CurvePoint.neg(k)
        s = (k_1 * (hm + self.privKey * r)) % n

        # BIP 62 : choose Low S value only
        if s > self.__MAX_S:
            s = 0 # try another k

    return (r, s)
curve.field.n
# 서명 검증
def VerifyHash(self, hash, r, s):
    n = self.curve.field.n
    q = self.pubKey
    R = r
    S = s
    pass

    # validate public key
    curve = get_curve('secp256r1')
    if q.IsInfinity or (not curve.IsPointOnCurve(q)) or not (curve.field.n * q).IsInfinity:
        return False

    # check (r, s)
    if R <= 0 or R > n or S <= 0 or S > n:
        return False

    # hash
    hm = hash

    # verify
    w = CurvePoint.neg(s)
    u1 = (hm * w) % n
    u2 = (R * w) % n
    t1 = CurvePoint.mul(u1, curve.g)
    t2 = CurvePoint.mul(u2, q)
    t3 = CurvePoint.add(t1,t2)
    if t3.IsInfinity:
        return False
    v = t3.X % n

    return v is R

