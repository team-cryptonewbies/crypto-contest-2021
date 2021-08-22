from hashlib import sha256 as _sha256
from .lsh256 import LSHDigest


def lsh256(message: bytes) -> str:
    """
    Calculate LSH 256 hash digest in hex string form.

    :param message: Message to get hash from.
    :returns: Hash digest in hex string form.
    """
    return LSHDigest.digest(data=message).hex()


def sha256(message: bytes) -> str:
    """
    Calculate SHA256 hash digest in hex string form.

    :param message: Message to get hash from.
    :returns: Hash digest in hex string form.
    """
    return _sha256(message).hexdigest()
