from base64 import b64decode
from collections import deque
from typing import List
from .hashes import lsh256
import binascii


class StackProcessor:
    def __init__(self, data: List[str]):
        self.data = data

    def __add(self):
        op1 = self.stack.pop()
        op2 = self.stack.pop()
        self.stack.append(op1 + op2)

    def __equal(self):
        op1 = self.stack.pop()
        op2 = self.stack.pop()
        self.stack.append(op1 == op2)

    def __dup(self):
        op = self.stack.pop()
        self.stack.append(op)
        self.stack.append(op)

    def __hash(self):
        op = self.stack.pop()
        self.stack.append(lsh256(op).encode("utf-8"))

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
        return data

    def run(self):
        """
        Run the stack processor.

        :returns: Execution result.
        :raises KeyError: Raises KeyError when command is invalid.
        """
        self.stack = deque()
        for elem in self.data:
            parsed = self.__parse_data(elem)
            if type(parsed) == int:
                self.stack.append(parsed)
            elif type(parsed) == bytes:
                self.stack.append(parsed)
            else:
                cmd_table = {
                    "ADD": self.__add,
                    "EQUAL": self.__equal,
                    "OP_EqualVerify": self.__equal,
                    "OP_DUP": self.__dup,
                    "OP_HASH": self.__hash,
                }
                cmd_table[parsed]()  # type: ignore
        return self.stack
