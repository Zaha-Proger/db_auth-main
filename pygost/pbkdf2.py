# coding: utf-8
"""PBKDF2 implementation suitable for GOST R 34.11-94/34.11-2012.

This implementation is based on Python 3.5.2 source code's one.
PyGOST does not register itself in hashlib anyway, so use it instead.
"""

from pygost.utils import strxor


def pbkdf2(hasher, password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """PBKDF2 implementation suitable for GOST R 34.11-94/34.11-2012
    """
    inner = hasher()
    outer = hasher()
    password = password + b"\x00" * (inner.block_size - len(password))
    inner.update(strxor(password, len(password) * b"\x36"))
    outer.update(strxor(password, len(password) * b"\x5C"))

    def prf(msg):
        icpy = inner.copy()
        ocpy = outer.copy()
        icpy.update(msg)
        ocpy.update(icpy.digest())
        return ocpy.digest()

    dkey = b""
    loop = 1
    while len(dkey) < dklen:
        prev = prf(salt + loop.to_bytes(4, "big"))
        rkey = int.from_bytes(prev, "big")
        for _ in range(iterations - 1):
            prev = prf(prev)
            rkey ^= int.from_bytes(prev, "big")
        loop += 1
        dkey += rkey.to_bytes(inner.digest_size, "big")
    return dkey[:dklen]
