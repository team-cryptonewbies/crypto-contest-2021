from collections import deque
from typing import List


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

    @staticmethod
    def __parse_data(data: str):
        try:
            parsed = int(data)
            return parsed
        except ValueError:
            pass
        if data[:2] == "0x":
            try:
                parsed = int(data[2:], 16)
                return parsed
            except ValueError:
                pass
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
            else:
                cmd_table = {
                    "ADD": self.__add,
                    "EQUAL": self.__equal,
                    "OP_DUP": self.__dup,
                }
                cmd_table[parsed]()  # type: ignore
        return self.stack
