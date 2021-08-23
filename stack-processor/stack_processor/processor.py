from asn1crypto.core import Integer, OctetBitString, Sequence
from base64 import b64decode
from collections import deque
from typing import List
from .hashes import lsh256
from .ecdsa.ecdsa import ECDSA
from .ecdsa.curveparam import secp256r1
from .ecdsa.curvepoint import CurvePoint
import binascii


class StackProcessor:
    class Signature(Sequence):
        _fields = [("r", Integer), ("s", Integer)]

    class PubkeyDER(Sequence):
        _fields = [("curveinfo", Sequence), ("pubkey", OctetBitString)]

    def __init__(self, data: List[str], hash_func=lsh256):
        self.data = data
        self.hash_func = hash_func
        self.halt = False

    def __add(self):
        op1 = self.stack.pop()
        op2 = self.stack.pop()
        self.stack.append(op1 + op2)

    def __equal(self):
        op1 = self.stack.pop()
        op2 = self.stack.pop()
        self.stack.append(op1 == op2)

    def __equalverify(self):
        op1 = self.stack.pop()
        op2 = self.stack.pop()
        self.halt = op1 != op2

    def __dup(self):
        op = self.stack.pop()
        self.stack.append(op)
        self.stack.append(op)

    def __hash(self):
        op = self.stack.pop()
        if type(op) == StackProcessor.PubkeyDER:
            self.stack.append(self.hash_func(op.dump()).encode("utf-8"))
        else:
            self.stack.append(self.hash_func(op).encode("utf-8"))

    def __check_sig(self):
        pubkey = self.stack.pop()
        signature = self.stack.pop()
        message = self.stack.pop()
        ecdsa = ECDSA(
            secp256r1,
            self.hash_func,
            (None, CurvePoint(secp256r1, octet_str=pubkey["pubkey"].native.hex())),
        )
        self.stack.append(ecdsa.verify_sign(message, signature))

    @staticmethod
    def __parse_data(data: str):
        try:
            parsed = int(data)
            return parsed
        except ValueError:
            pass
        if data.startswith("0x"):
            try:
                parsed = int(data.replace("0x", "", 1), 16)
                return parsed
            except ValueError:
                pass
        if data.startswith("base64:"):
            try:
                parsed = b64decode(data.replace("base64:", "", 1))
                return parsed
            except binascii.Error:
                pass
        if data.startswith("bytes_utf8:"):
            parsed = data.replace("bytes_utf8:", "", 1).encode("utf-8")
            return parsed
        if data.startswith("sig:"):
            parsed = b64decode(data.replace("sig:", "", 1))
            signature = StackProcessor.Signature.load(parsed)
            return (signature["r"].native, signature["s"].native)  # type: ignore
        if data.startswith("pubkey:"):
            parsed = b64decode(data.replace("pubkey:", "", 1))
            pubkey = StackProcessor.PubkeyDER.load(parsed)
            return pubkey
        return data

    def run(self):
        """
        Run the stack processor.

        :returns: Execution result.
        :raises KeyError: Raises KeyError when command is invalid.
        """
        self.stack = deque()
        for elem in self.data:
            print(self.stack)
            if self.halt:
                return deque([False])
            parsed = self.__parse_data(elem)
            if type(parsed) in (int, bytes, tuple, StackProcessor.PubkeyDER):
                self.stack.append(parsed)
            else:
                cmd_table = {
                    "ADD": self.__add,
                    "EQUAL": self.__equal,
                    "OP_EqualVerify": self.__equalverify,
                    "OP_DUP": self.__dup,
                    "OP_HASH": self.__hash,
                    "OP_CheckSig": self.__check_sig,
                }
                cmd_table[parsed]()  # type: ignore
        return self.stack
