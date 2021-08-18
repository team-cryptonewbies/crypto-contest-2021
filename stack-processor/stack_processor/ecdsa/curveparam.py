import math

from itertools import zip_longest
from typing import Dict, Iterable, List, Tuple
from .numbertheory import tonelli


class CurveParam:
    def __init__(self, name: str, p: str, a: str, b: str, G: str, n: str, h: str):
        """
        Initialize a CurveParam object.

        :param p: An octet string representation of p specifying the field F_p.
        :param a: An octet string representation of the coeff. a of EC.
        :param b: An octet string representation of the coeff. b of EC.
        :param G: An octet string representation of the base point G.
        :param n: An octet string representation of the group order n.
        :param h: An octet string representation of the cofactor h.
        """
        self.name = name
        self.params = {
            "p": self.__octet_str_to_int(p),
            "a": self.__octet_str_to_int(a),
            "b": self.__octet_str_to_int(b),
            "n": self.__octet_str_to_int(n),
            "h": self.__octet_str_to_int(h),
        }
        assert 4 * (self.params["a"] ** 3) + 27 * (self.params["b"] ** 2) != 0
        self.basepoint = self.__octet_str_to_point(G, self.params)

    @staticmethod
    def __octet_str_to_int(octet_str: str) -> int:
        return int(octet_str.replace(" ", ""), 16)

    @staticmethod
    def __octet_list_to_int(octet_list: List[int]) -> int:
        result = 0
        for octet in octet_list:
            result <<= 8
            result += octet
        return result

    @staticmethod
    def __octet_list_to_field_elem(octet_list: List[int], p: int) -> int:
        elem = CurveParam.__octet_list_to_int(octet_list)
        if not 0 <= elem < p:
            raise ValueError(f"Field F_{p} does not contain: {elem}")
        return elem

    @staticmethod
    def __grouper(n: int, iterable: Iterable) -> List[int]:
        return list(
            map(
                lambda x: int("".join(x), 16),
                zip_longest(*[iter(iterable)] * n, fillvalue=None),
            )
        )

    @staticmethod
    def __octet_str_to_point(octet_str: str, params: Dict[str, int]) -> Tuple[int, int]:
        octets = CurveParam.__grouper(2, octet_str.replace(" ", ""))
        if len(octets) == 1 and octets[0] == "00":
            return (0, 0)
        if len(octets) == math.ceil(math.log2(params["p"]) / 8) + 1:
            Y = octets[0]
            X = octets[1:]
            x_P = CurveParam.__octet_list_to_field_elem(X, params["p"])
            if Y not in (2, 3):
                raise ValueError(f"Invalid Y value: {Y}")
            y_tilde_P = 0 if Y == 2 else 1
            if params["p"] % 2 == 0:
                raise NotImplementedError("Support for F_{2^m} is not implemented")
            alpha = (x_P ** 3 + params["a"] * x_P + params["b"]) % params["p"]
            beta = tonelli(alpha, params["p"])
            if (beta - y_tilde_P) % 2 == 0:
                y_P = beta
            else:
                y_P = params["p"] - beta
            return (x_P, y_P)
        elif len(octets) == 2 * math.ceil(math.log2(params["p"]) / 8) + 1:
            W = octets[0]
            coord_len = math.ceil(math.log2(params["p"]) / 8)
            X = octets[1 : coord_len + 1]
            Y = octets[coord_len + 1 :]
            if W != 4:
                raise ValueError(f"Invalid W value: {W}")
            x_P = CurveParam.__octet_list_to_field_elem(X, params["p"])
            y_P = CurveParam.__octet_list_to_field_elem(Y, params["p"])
            return (x_P, y_P)
        raise ValueError("Invalid octet string length")
