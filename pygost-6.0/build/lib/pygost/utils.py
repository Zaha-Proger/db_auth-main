# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2026 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from codecs import getdecoder
from codecs import getencoder


def strxor(a: bytes, b: bytes) -> bytes:
    """XOR of two strings

    This function will process only shortest length of both strings,
    ignoring remaining one.
    """
    mlen = min(len(a), len(b))
    a, b, xor = bytearray(a), bytearray(b), bytearray(mlen)
    for i in range(mlen):
        xor[i] = a[i] ^ b[i]
    return bytes(xor)


def modinvert(a: int, n: int) -> int:
    """Modular multiplicative inverse

    :returns: inverse number. -1 if it does not exist

    Realization is taken from:
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    if a < 0:
        # k^-1 = p - (-k)^-1 mod p
        return n - modinvert(-a, n)
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotinent = r // newr
        t, newt = newt, t - quotinent * newt
        r, newr = newr, r - quotinent * newr
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t
