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
"""Key derivation functions, ТК26 Р 50.1.113-2016, ТК26 Р 1323565.1.020-2018
"""

from typing import List
import hmac

from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import Point
from pygost.gost3410_vko import kek_34102012256
from pygost.gost3410_vko import kek_34102012512
from pygost.gost34112012256 import GOST34112012256


def kdf_gostr3411_2012_256(key: bytes, label: bytes, seed: bytes) -> bytes:
    """KDF_GOSTR3411_2012_256
    """
    return hmac.new(
        key=key,
        msg=b"".join((b"\x01", label, b"\x00", seed, b"\x01\x00")),
        digestmod=GOST34112012256,
    ).digest()


def kdf_tree_gostr3411_2012_256(
        key: bytes,
        label: bytes,
        seed: bytes,
        keys: int,
        i_len=1,
) -> List[bytes]:
    """KDF_TREE_GOSTR3411_2012_256

    :param keys: number of generated keys
    :param i_len: length of iterations value (called "R")
    :returns: list of 256-bit keys
    """
    keymat = []
    _len = (keys * 32 * 8).to_bytes(2, "big")
    for i in range(keys):
        keymat.append(hmac.new(
            key=key,
            msg=b"".join((
                (i + 1).to_bytes(i_len, "big"),
                label, b"\x00", seed, _len,
            )),
            digestmod=GOST34112012256,
        ).digest())
    return keymat


def keg(curve: GOST3410Curve, prv: int, pub: Point, h: bytes) -> bytes:
    """Export key generation (ТК26 Р 1323565.1.020-2018)

    :param h: "h"-value, 32 bytes
    """
    if len(h) != 32:
        raise ValueError("h must be 32 bytes long")
    ukm = int.from_bytes(h[:16], "big")
    if ukm == 0:
        ukm = 1
    if curve.point_size == 64:
        return kek_34102012512(curve, prv, pub, ukm)
    k_exp = kek_34102012256(curve, prv, pub, ukm)
    return b"".join(kdf_tree_gostr3411_2012_256(k_exp, b"kdf tree", h[16:24], 2))
