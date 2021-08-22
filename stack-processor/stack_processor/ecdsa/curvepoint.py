from .curveparam import CurveParam
from .numbertheory import inv_mod
from math import floor, log2


class CurvePoint:
    def __init__(self, x: int, y: int, curve: CurveParam):
        self.x = x
        self.y = y
        self.curve = curve

    def __add__(self, another: "CurvePoint") -> "CurvePoint":
        """
        Add two CurvePoint objects.

        :param another: The point to add.
        :raises AssertionError: Assertion fails when two points are from
        different curves.
        :returns: Addition result of two points.
        """
        assert self.curve.params == another.curve.params
        if self.x == self.y == 0:
            return CurvePoint(another.x, another.y, self.curve)
        elif another.x == another.y == 0:
            return CurvePoint(self.x, self.y, self.curve)
        elif self.x == another.x:
            if self.y == another.y:
                lambda_ = (
                    (3 * self.x ** 2 + self.curve.params["a"])
                    * inv_mod(2 * self.y, self.curve.params["p"])
                    % self.curve.params["p"]
                )
                result_x = (lambda_ ** 2 - 2 * self.x) % self.curve.params["p"]
                result_y = (lambda_ * (self.x - result_x) - self.y) % self.curve.params[
                    "p"
                ]
                return CurvePoint(result_x, result_y, self.curve)
            return CurvePoint(0, 0, self.curve)
        lambda_ = (
            (another.y - self.y)
            * inv_mod(another.x - self.x, self.curve.params["p"])
            % self.curve.params["p"]
        )
        result_x = (lambda_ ** 2 - self.x - another.x) % self.curve.params["p"]
        result_y = (lambda_ * (self.x - result_x) - self.y) % self.curve.params["p"]
        return CurvePoint(result_x, result_y, self.curve)

    def __rmul__(self, scalar: int) -> "CurvePoint":
        """
        Multply the point by scalar.

        :param scalar: The scalar to multiply the point with.
        :returns: Multiplication result.
        """
        if scalar < 0:
            return -((-scalar) * self)
        elif scalar == 0:
            return CurvePoint(0, 0, self.curve)
        result = CurvePoint(0, 0, self.curve)
        bitlen = floor(log2(scalar)) + 1
        for shift in range(bitlen - 1, -1, -1):
            bit = (scalar >> shift) & 1
            result += result
            if bit == 1:
                result += self
        return result

    def __neg__(self) -> "CurvePoint":
        """
        Negate the point.

        :returns: Negative of self.
        """
        return CurvePoint(self.x, -self.y, self.curve)

    def __eq__(self, another: "CurvePoint") -> bool:
        """
        Check equality of two points.

        :param another: The point to compare with.
        :returns: Equality check result.
        """
        return (
            self.x == another.x
            and self.y == another.y
            and self.curve.name == another.curve.name
        )

    def __repr__(self) -> str:
        """
        Get a representation of the point.

        :returns: Representation in string.
        """
        return (
            f"({self.x}, {self.y}) on curve "
            f"y^2 = x^3 + {self.curve.params['a']}x + {self.curve.params['b']}, "
            f"F_{self.curve.params['p']}"
        )
