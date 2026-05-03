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
"""Security Evaluated Standardized Password-Authenticated Key Exchange

:rfc:`8133`
https://eprint.iacr.org/2015/1237.pdf
https://habr.com/ru/articles/282043/
"""

from os import urandom
import hmac

from pygost import gost34112012256
from pygost import gost34112012512
from pygost.gost3410 import GOST3410Curve
from pygost.gost3410 import Point
from pygost.pbkdf2 import pbkdf2

Qs = {
    "id-GostR3410-2001-CryptoPro-A-ParamSet": (
        int.from_bytes(bytes.fromhex("a69d51caf1a309fa9e9b66187759b0174c274e080356f23cfcbfe84d396ad7bb"), "big"),
        int.from_bytes(bytes.fromhex("5d26f29ecc2e9ac0404dcf7986fa55fe94986362170f54b9616426a659786dac"), "big"),
    ),
    "id-GostR3410-2001-CryptoPro-B-ParamSet": (
        int.from_bytes(bytes.fromhex("3d715a874a4b17cb3b517893a9794a2b36c89d2ffc693f01ee4cc27e7f49e399"), "big"),
        int.from_bytes(bytes.fromhex("1c5a641fcf7ce7e87cdf8cea38f3db3096eace2fad158384b53953365f4fe7fe"), "big"),
    ),
    "id-GostR3410-2001-CryptoPro-C-ParamSet": (
        int.from_bytes(bytes.fromhex("1e36383e43bb6cfa2917167d71b7b5dd3d6d462b43d7c64282ae67dfbec2559d"), "big"),
        int.from_bytes(bytes.fromhex("137478a9f721c73932ea06b45cf72e37eb78a63f29a542e563c614650c8b6399"), "big"),
    ),
    "id-tc26-gost-3410-2012-512-paramSetA": (
        int.from_bytes(bytes.fromhex("2a17f8833a32795327478871b5c5e88aefb91126c64b4b8327289bea62559425d18198f133f400874328b220c74497cd240586cb249e158532cb8090776cd61c"), "big"),
        int.from_bytes(bytes.fromhex("728f0c4a73b48da41ce928358fad26b47a6e094e9362bae82559f83cddc4ec3a4676bd3707edeaf4cd85e99695c64c241edc622be87dc0cf87f51f4367f723c5"), "big"),
    ),
    "id-tc26-gost-3410-2012-512-paramSetB": (
        int.from_bytes(bytes.fromhex("7e1fae8285e035bec244bef2d0e5ebf436633cf50e55231dea9c9cf21d4c8c33df85d4305de92971f0a4b4c07e00d87bdbc720eb66e49079285aaf12e0171149"), "big"),
        int.from_bytes(bytes.fromhex("2cc89998b875d4463805ba0d858a196592db20ab161558ff2f4ef7a85725d20953967ae621afdeae89bb77c83a2528ef6fce02f68bda4679d7f2704947dbc408"), "big"),
    ),
    "id-tc26-gost-3410-2012-256-paramSetA": (
        int.from_bytes(bytes.fromhex("b51adf93a40ab15792164fad3352f95b66369eb2a4ef5efae32829320363350e"), "big"),
        int.from_bytes(bytes.fromhex("74a358cc08593612f5955d249c96afb7e8b0bb6d8bd2bbe491046650d822be18"), "big"),
        # U: ebe97afffe0d0f88b8b0114b8de430ac2b34564e4420af24728e7305bc48aeaa
        # V: 828f2dcf8f06612b4fea4da72ca509c0f76dd37df424ea22bfa6f4f65748c1e4
    ),
    "id-tc26-gost-3410-2012-512-paramSetC": (
        int.from_bytes(bytes.fromhex("489c91784e02e98f19a803abca319917f37689e5a18965251ce2ff4e8d8b298f5ba7470f9e0e713487f96f4a8397b3d09a270c9d367eb5e0e6561adeeb51581d"), "big"),
        int.from_bytes(bytes.fromhex("684ea885aca64eaf1b3fee36c0852a3be3bd8011b0ef18e203ff87028d6eb5db2c144a0dcc71276542bfd72ca2a43fa4f4939da66d9a60793c704a8c94e16f18"), "big"),
        # U: 3a3496f97e96b3849a4fa7db60fd93858bde89958e4beebd05a6b3214216b37c9d9a560076e7ea59714828b18fbfef996ffc98bf3dc9f2d3cb0ed36a0d6ace88
        # V: 52d884c8bf0ad6c5f7b3973e32a668daa1f1ed092eff138dae6203b2ccdec56147464d35fec4b727b2480eb143074712c76550c7a54ff3ea26f70059480dcb50
    ),
}


class A:
    def __init__(
            self,
            curve: GOST3410Curve,
            q: Point,
            pw: bytes,
            salt: bytes,
            idA: bytes,
            idB: bytes,
            idAlg=b"",
            ind=b"\x01",
            fIters=2000,
            fpw=None,
            alpha=None,
    ):
        self.curve = curve
        self.idA = idA
        self.idAlg = idAlg
        self.salt = salt
        self.ind = ind
        self.idB = idB
        if fpw is None:
            fpw = pbkdf2(gost34112012512.new, pw, salt, fIters, 64)
        self.qpw = self.curve.exp(
            int.from_bytes(fpw[:self.curve.point_size], "little"), q[0], q[1])
        self.alpha = (
            int.from_bytes(urandom(self.curve.point_size), "big") % self.curve.q
        ) if alpha is None else alpha
        alphaP = self.curve.exp(self.alpha)
        tmp = self.curve.exp(self.curve.q-1, self.qpw[0], self.qpw[1])
        self.u1 = self.curve._add(alphaP[0], alphaP[1], tmp[0], tmp[1])

    def ka(self, u2: Point, dataA=b""):
        if not self.curve.contains(u2):
            raise ValueError("u2 is not on curve")
        self.u2 = u2
        self.dataA = dataA
        tmp = self.curve.exp(self.curve.q-1, self.qpw[0], self.qpw[1])
        qA = self.curve._add(self.u2[0], self.u2[1], tmp[0], tmp[1])
        # TODO: check zero point
        tmp = self.curve.exp(
            (self.curve.cofactor * self.alpha) % self.curve.q, qA[0], qA[1])
        self.k = gost34112012256.new(
            tmp[0].to_bytes(self.curve.point_size, "little") +
            tmp[1].to_bytes(self.curve.point_size, "little")
        ).digest()
        u1 = (
            self.u1[0].to_bytes(self.curve.point_size, "little") +
            self.u1[1].to_bytes(self.curve.point_size, "little")
        )
        u2 = (
            self.u2[0].to_bytes(self.curve.point_size, "little") +
            self.u2[1].to_bytes(self.curve.point_size, "little")
        )
        macA = hmac.new(key=self.k, msg=b"".join((
            b"\x01", self.idA, self.ind, self.salt, u1, u2, self.idAlg,
            self.dataA,
        )), digestmod=gost34112012256).digest()
        return macA

    def kc(self, macB: bytes, dataB=b""):
        u1 = (
            self.u1[0].to_bytes(self.curve.point_size, "little") +
            self.u1[1].to_bytes(self.curve.point_size, "little")
        )
        u2 = (
            self.u2[0].to_bytes(self.curve.point_size, "little") +
            self.u2[1].to_bytes(self.curve.point_size, "little")
        )
        _macB = hmac.new(key=self.k, msg=b"".join((
            b"\x02", self.idB, self.ind, self.salt, u1, u2, self.idAlg,
            self.dataA, dataB,
        )), digestmod=gost34112012256).digest()
        if not hmac.compare_digest(_macB, macB):
            raise ValueError("wrong macB")


class B:
    def __init__(
            self,
            curve: GOST3410Curve,
            q: Point,
            pw: bytes,
            idA: bytes,
            idB: bytes,
            idAlg=b"",
            ind=b"\x01",
            salt=None,
            saltLen=16,
            fIters=2000,
            fpw=None,
    ):
        self.curve = curve
        self.q = q
        self.idA = idA
        self.idB = idB
        self.idAlg = idAlg
        self.ind = ind
        if salt is None:
            salt = urandom(saltLen)
        self.salt = salt
        if fpw is None:
            fpw = pbkdf2(gost34112012512.new, pw, self.salt, fIters, 64)
        self.fpw = fpw
        self.qpw = self.curve.exp(
            int.from_bytes(fpw[:self.curve.point_size], "little"), q[0], q[1])

    def ka(self, u1: Point, beta=None):
        if not self.curve.contains(u1):
            raise ValueError("u1 is not on curve")
        self.u1 = u1
        qB = self.curve._add(self.u1[0], self.u1[1], self.qpw[0], self.qpw[1])
        # TODO: check zero point
        if beta is None:
            beta = int.from_bytes(urandom(self.curve.point_size), "big") % self.curve.q
        tmp = self.curve.exp((self.curve.cofactor * beta) % self.curve.q, qB[0], qB[1])
        self.k = gost34112012256.new(
            tmp[0].to_bytes(self.curve.point_size, "little") +
            tmp[1].to_bytes(self.curve.point_size, "little")
        ).digest()
        betaP = self.curve.exp(beta)
        self.u2 = self.curve._add(betaP[0], betaP[1], self.qpw[0], self.qpw[1])
        return self.u2

    def kc(self, macA: bytes, dataA=b"", dataB=b""):
        u1 = (
            self.u1[0].to_bytes(self.curve.point_size, "little") +
            self.u1[1].to_bytes(self.curve.point_size, "little")
        )
        u2 = (
            self.u2[0].to_bytes(self.curve.point_size, "little") +
            self.u2[1].to_bytes(self.curve.point_size, "little")
        )
        _macA = hmac.new(key=self.k, msg=b"".join((
            b"\x01", self.idA, self.ind, self.salt, u1, u2, self.idAlg,
            dataA,
        )), digestmod=gost34112012256).digest()
        if not hmac.compare_digest(_macA, macA):
            raise ValueError("wrong macA")
        self.dataA = dataA
        macB = hmac.new(key=self.k, msg=b"".join((
            b"\x02", self.idB, self.ind, self.salt, u1, u2, self.idAlg,
            self.dataA, dataB,
        )), digestmod=gost34112012256).digest()
        return macB
