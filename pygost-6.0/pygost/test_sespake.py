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

from os import urandom
from random import randint
from unittest import TestCase
import hmac

from pygost import gost34112012256
from pygost import gost34112012512
from pygost import sespake
from pygost.gost3410 import CURVES
from pygost.pbkdf2 import pbkdf2


class TestQs(TestCase):
    def runTest(self):
        """Test RFC's Qs generation code results

        Calculation code is taken from RFC too. Its style is altered.
        Ported to Python3. Native Streebog and utilities are used.
        """
        def XGCD(a, b):
            """XGCD(a,b) returns a list of form [g,x,y], where g is GCD(a,b) and
            x,y satisfy the equation g = ax + by."""
            a1 = 1
            b1 = 0
            a2 = 0
            b2 = 1
            aneg = 1
            bneg = 1
            swap = False
            if a < 0:
                a = -a
                aneg=-1
            if b < 0:
                b = -b
                bneg=-1
            if b > a:
                swap = True
                a, b = b, a
            while True:
                quot = -(a // b)
                a = a % b
                a1 = a1 + quot*a2
                b1 = b1 + quot*b2
                if a == 0:
                    if swap:
                        return (b, b2*bneg, a2*aneg)
                    return (b, a2*aneg, b2*bneg)
                quot = -(b // a)
                b = b % a
                a2 = a2 + quot*a1
                b2 = b2 + quot*b1
                if b == 0:
                    if swap:
                        return (a, b1*bneg, a1*aneg)
                    return (a, a1*aneg, b1*bneg)

        def getMultByMask(elems, mask):
            n = len(elems)
            r = 1
            for i in range(n):
                if mask & 1:
                    r *= elems[n - 1 - i]
                mask = mask >> 1
            return r

        def subF(P, other, p):
            return (P - other) % p

        def divF(P, other, p):
            return mulF(P, invF(other, p), p)

        def addF(P, other, p):
            return (P + other) % p

        def mulF(P, other, p):
            return (P * other) % p

        def invF(R, p):
            assert (R != 0)
            return XGCD(R, p)[1] % p

        def negF(R, p):
            return (-R) % p

        def powF(R, m, p):
            assert R is not None
            if m == 0:
                assert R != 0
                return 1
            if m < 0:
                t = invF(R, p)
                return powF(t, (-m), p)
            i = m.bit_length() - 1
            r = 1
            while i > 0:
                if (m >> i) & 1:
                    r = (r * R) % p
                r = (r * r) % p
                i -= 1
            if m & 1:
                r = (r * R) % p
            return r

        def add(Px, Py, Qx, Qy, p, a, b):
            if (Qx is None) and (Qy is None):
                return (Px, Py)
            if (Px is None) and (Py is None):
                return (Qx, Qy)
            if (Px == Qx) and (Py == negF(Qy, p)):
                return (None, None)
            if (Px == Qx) and (Py == Qy):
                assert Py != 0
                return duplicate(Px, Py, p, a)
            l = divF(subF(Qy, Py, p), subF(Qx, Px, p), p)
            resX = subF(subF(powF(l, 2, p), Px, p), Qx, p)
            resY = subF(mulF(l, subF(Px, resX, p), p), Py, p)
            return (resX, resY)

        def duplicate(Px, Py, p, a):
            if (Px is None) and (Py is None):
                return (None, None)
            if Py == 0:
                return (None, None)
            l = divF(addF(mulF(powF(Px, 2, p), 3, p), a, p), mulF(Py, 2, p), p)
            resX = subF(powF(l, 2, p), mulF(Px, 2, p), p)
            resY = subF(mulF(l, subF(Px, resX, p), p), Py, p)
            return (resX, resY)

        def mul(Px, Py, s, p, a, b):
            assert (Px is not None) and (Py is not None)
            X = Px
            Y = Py
            i = s.bit_length() - 1
            resX = None
            resY = None
            while i > 0:
                if (s >> i) & 1:
                    resX, resY = add(resX, resY, X, Y, p, a, b)
                resX, resY = duplicate(resX, resY, p, a)
                i -= 1
            if s & 1:
                resX, resY = add(resX, resY, X, Y, p, a, b)
            return (resX, resY)

        def Ord(Px, Py, m, q, p, a, b):
            assert (Px is not None) and (Py is not None)
            assert (m is not None) and (q is not None)
            assert mul(Px, Py, m, p, a, b) == (None, None)
            X = Px
            Y = Py
            r = m
            for mask in range(1 << len(q)):
                t = getMultByMask(q, mask)
                Rx, Ry = mul(X, Y, t, p, a, b)
                if (Rx is None) and (Ry is None):
                    r = min(r, t)
            return r

        def isQuadraticResidue(R, p):
            if R == 0:
                assert False
            temp = powF(R, ((p - 1) // 2), p)
            if temp == (p - 1):
                return False
            assert temp == 1
            return True

        def getRandomQuadraticNonresidue(p):
            from random import randint
            r = (randint(2, p - 1)) % p
            while isQuadraticResidue(r, p):
                r = (randint(2, p - 1)) % p
            return r

        def ModSqrt(R, p):
            assert R is not None
            assert isQuadraticResidue(R, p)
            if p % 4 == 3:
                res = powF(R, (p + 1) // 4, p)
                if powF(res, 2, p) != R:
                    res = None
                return (res, negF(res, p))
            ainvF = invF(R, p)
            s = p - 1
            alpha = 0
            while (s % 2) == 0:
                alpha += 1
                s = s // 2
            b = powF(getRandomQuadraticNonresidue(p), s, p)
            r = powF(R, (s + 1) // 2, p)
            bj = 1
            for k in range(0, alpha - 1): # alpha >= 2 because p % 4 = 1
                d = 2 ** (alpha - k - 2)
                x = powF(mulF(powF(mulF(bj, r, p), 2, p), ainvF, p), d, p)
                if x != 1:
                    bj = mulF(bj, powF(b, (2 ** k), p), p)
            res = mulF(bj, r, p)
            return (res, negF(res, p))

        def generateQs(p, point_size, a, b, q, cofactor, Px, Py):
            seed = 0
            while True:
                hashSrc = (
                    Px.to_bytes(point_size, "little") +
                    Py.to_bytes(point_size, "little") +
                    seed.to_bytes(4, "little")
                )
                if point_size == 32:
                    QxRaw = gost34112012256.new(hashSrc).digest()
                else:
                    QxRaw = gost34112012512.new(hashSrc).digest()
                Qx = int.from_bytes(QxRaw, "little") % p
                R = addF(addF(powF(Qx, 3, p), mulF(Qx, a, p), p), b, p)
                if (R == 0) or not isQuadraticResidue( R, p ):
                    seed += 1
                    continue
                Qy = min(ModSqrt(R, p))
                orderDivisors = (q,) if (cofactor == 1) else (2, 2, q)
                if cofactor * Ord(
                    Qx, Qy, cofactor*q, orderDivisors, p, a, b
                ) == cofactor*q:
                    yield ((Qx, Qy), seed)
                seed += 1

        seeds = {
            "id-GostR3410-2001-CryptoPro-A-ParamSet": 0x01,
            "id-GostR3410-2001-CryptoPro-B-ParamSet": 0x00,
            "id-GostR3410-2001-CryptoPro-C-ParamSet": 0x06,
            "id-tc26-gost-3410-2012-512-paramSetA": 0x01,
            "id-tc26-gost-3410-2012-512-paramSetB": 0x00,
            "id-tc26-gost-3410-2012-256-paramSetA": 0x01,
            "id-tc26-gost-3410-2012-512-paramSetC": 0x13,
        }
        for name, (x, y) in sespake.Qs.items():
            curve = CURVES[name]
            (qx, qy), seed = next(generateQs(
                curve.p,
                curve.point_size,
                curve.a,
                curve.b,
                curve.q,
                curve.cofactor,
                curve.x,
                curve.y,
            ))
            self.assertEqual(qx, x)
            self.assertEqual(qy, y)
            self.assertEqual(seed, seeds[name])


class TestSymmetric(TestCase):
    def _test(self, curve, q):
        for i in range(10):
            pw = urandom(randint(4, 8))
            idA = urandom(randint(0, 4))
            idB = urandom(randint(0, 4))
            idAlg = urandom(randint(0, 4))
            ind = urandom(1)
            b = sespake.B(curve, q, pw, idA=idA, idB=idB, idAlg=idAlg, ind=ind, fIters=2)
            a = sespake.A(curve, q, pw, b.salt, idA, idB, idAlg, ind, fIters=2)
            u2 = b.ka(a.u1)
            macA = a.ka(u2)
            macB = b.kc(macA)
            a.kc(macB)
            self.assertEqual(a.k, b.k)

    def test_256A(self):
        curveName = "id-tc26-gost-3410-2012-256-paramSetA"
        self._test(CURVES[curveName], sespake.Qs[curveName])

    def test_512C(self):
        curveName = "id-tc26-gost-3410-2012-512-paramSetC"
        self._test(CURVES[curveName], sespake.Qs[curveName])


class TestExamples(TestCase):
    fpw = bytes.fromhex("bd04673f7149b18e98155bd1e2724e71d0099aa25174f792d3326c6f181270671c6213e3930efdda26451792c6208122ee60d200520d695dfd9f5f0fd5aba702")
    salt = bytes.fromhex("2923be84e16cd6ae529049f1f1bbe9eb")
    idA = 4 * b"\x00"
    idB = 4 * b"\x00"

    def test_fpw(self):
        fpw = pbkdf2(gost34112012512.new, b"123456", self.salt, 2000, 64)
        self.assertSequenceEqual(fpw, self.fpw)

    def _test(
        self,
        curveName,
        qpwExpected,
        alpha,
        alphaPExpected,
        u1Expected,
        beta,
        kBSrcExpected,
        kBExpected,
        betaPExpected,
        u2Expected,
        macAExpected,
        macBExpected,
    ):
        curve = CURVES[curveName]
        q = sespake.Qs[curveName]
        qpw = curve.exp(int.from_bytes(self.fpw[:curve.point_size], "little"), q[0], q[1])
        self.assertSequenceEqual(qpw[0].to_bytes(curve.point_size, "big").hex(), qpwExpected[0])
        self.assertSequenceEqual(qpw[1].to_bytes(curve.point_size, "big").hex(), qpwExpected[1])

        alphaP = curve.exp(alpha)
        self.assertSequenceEqual(alphaP[0].to_bytes(curve.point_size, "big").hex(), alphaPExpected[0])
        self.assertSequenceEqual(alphaP[1].to_bytes(curve.point_size, "big").hex(), alphaPExpected[1])
        tmp = curve.exp(curve.q-1, qpw[0], qpw[1])
        u1 = curve._add(alphaP[0], alphaP[1], tmp[0], tmp[1])
        self.assertSequenceEqual(u1[0].to_bytes(curve.point_size, "big").hex(), u1Expected[0])
        self.assertSequenceEqual(u1[1].to_bytes(curve.point_size, "big").hex(), u1Expected[1])

        self.assertTrue(curve.contains(u1))
        qB = curve._add(u1[0], u1[1], qpw[0], qpw[1])
        self.assertEqual(qB, alphaP)
        tmp = curve.exp((curve.cofactor * beta) % curve.q, qB[0], qB[1])
        self.assertSequenceEqual(tmp[0].to_bytes(curve.point_size, "little").hex(), kBSrcExpected[0])
        self.assertSequenceEqual(tmp[1].to_bytes(curve.point_size, "little").hex(), kBSrcExpected[1])
        kB = gost34112012256.new(
            tmp[0].to_bytes(curve.point_size, "little") +
            tmp[1].to_bytes(curve.point_size, "little")
        ).digest()
        self.assertSequenceEqual(kB.hex(), kBExpected)
        betaP = curve.exp(beta)
        self.assertSequenceEqual(betaP[0].to_bytes(curve.point_size, "big").hex(), betaPExpected[0])
        self.assertSequenceEqual(betaP[1].to_bytes(curve.point_size, "big").hex(), betaPExpected[1])
        u2 = curve._add(betaP[0], betaP[1], qpw[0], qpw[1])
        self.assertSequenceEqual(u2[0].to_bytes(curve.point_size, "big").hex(), u2Expected[0])
        self.assertSequenceEqual(u2[1].to_bytes(curve.point_size, "big").hex(), u2Expected[1])

        self.assertTrue(curve.contains(u2))
        tmp = curve.exp(curve.q-1, qpw[0], qpw[1])
        qA = curve._add(u2[0], u2[1], tmp[0], tmp[1])
        tmp = curve.exp((curve.cofactor * alpha) % curve.q, qA[0], qA[1])
        kA = gost34112012256.new(
            tmp[0].to_bytes(curve.point_size, "little") +
            tmp[1].to_bytes(curve.point_size, "little")
        ).digest()
        self.assertEqual(kA, kB)

        macA = hmac.new(
            key=kA,
            msg=b"".join((
                b"\x01", self.idA, b"\x01", self.salt,
                u1[0].to_bytes(curve.point_size, "little"),
                u1[1].to_bytes(curve.point_size, "little"),
                u2[0].to_bytes(curve.point_size, "little"),
                u2[1].to_bytes(curve.point_size, "little"),
            )),
            digestmod=gost34112012256,
        ).digest()
        self.assertSequenceEqual(macA.hex(), macAExpected)

        macB = hmac.new(
            key=kB,
            msg=b"".join((
                b"\x02", self.idB, b"\x01", self.salt,
                u1[0].to_bytes(curve.point_size, "little"),
                u1[1].to_bytes(curve.point_size, "little"),
                u2[0].to_bytes(curve.point_size, "little"),
                u2[1].to_bytes(curve.point_size, "little"),
            )),
            digestmod=gost34112012256,
        ).digest()
        self.assertSequenceEqual(macB.hex(), macBExpected)
        self._test_lib(
            curveName,
            alpha,
            beta,
            u1Expected,
            u2Expected,
            macAExpected,
            macBExpected,
            kBExpected,
        )

    def _test_lib(
            self,
            curveName,
            alpha,
            beta,
            u1Expected,
            u2Expected,
            macAExpected,
            macBExpected,
            kExpected,
    ):
        curve = CURVES[curveName]
        q = sespake.Qs[curveName]
        a = sespake.A(
            curve,
            q,
            b"cached",
            self.salt,
            self.idA,
            self.idB,
            fpw=self.fpw,
            alpha=alpha,
        )
        self.assertSequenceEqual(a.u1[0].to_bytes(curve.point_size, "big").hex(), u1Expected[0])
        self.assertSequenceEqual(a.u1[1].to_bytes(curve.point_size, "big").hex(), u1Expected[1])
        b = sespake.B(
            curve,
            q,
            b"cached",
            idA=self.idA,
            idB=self.idB,
            salt=self.salt,
            fpw=self.fpw,
        )
        u2 = b.ka(a.u1, beta=beta)
        self.assertSequenceEqual(u2[0].to_bytes(curve.point_size, "big").hex(), u2Expected[0])
        self.assertSequenceEqual(u2[1].to_bytes(curve.point_size, "big").hex(), u2Expected[1])
        macA = a.ka(u2)
        self.assertSequenceEqual(macA.hex(), macAExpected)
        macB = b.kc(macA)
        self.assertSequenceEqual(macB.hex(), macBExpected)
        a.kc(macB)
        self.assertEqual(a.k, b.k)
        self.assertSequenceEqual(a.k.hex(), kExpected)

    def test_256B(self):
        self._test(
            "id-GostR3410-2001-CryptoPro-A-ParamSet",
            qpwExpected=(
                "59495655d1e7c7424c622485f575ccf121f3122d274101e8ab734cc9c9a9b45e",
                "48d1c311d33c9b701f3b03618562a4a07a044e3af31e3999e67b487778b53c62",
            ),
            alpha=0x1f2538097d5a031fa68bbb43c84d12b3de47b7061c0d5e24993e0c873cdba6b3,
            alphaPExpected=(
                "bbc77cf42dc1e62d06227935379b4aa4d14fea4f565ddf4cb4fa4d31579f9676",
                "8e16604a4afdf28246684d4996274781f6cb80abbba1414c1513ec988509dabf",
            ),
            u1Expected=(
                "204f564383b2a76081b907f3fca8795e806be2c2ed228730b5b9e37074229e8d",
                "e84f9e442c61dde37b601a7f37e7ca11c56183fa071dfa9320ede3e7521f9d41",
            ),
            beta=0xdc497d9ef6324912fd367840ee509a2032aedb1c0a890d133b45f596fccbd45d,
            kBSrcExpected=(
                "2e01a3d84fdb7e947bb8929be9363df5f725d6401aa559d41a6724f8d5f18e2c",
                "a0dba93105cddaf4bfaea3906fdd719dbeb297b6a17f4fbd96dcc723ea3472a9",
            ),
            kBExpected="1a626554921dc2e92b4dd8d67dbe5a5662e56299373f06799535ad26094ecaa3",
            betaPExpected=(
                "6097341c1be388e83e7ca2df47fab86e2271fd942e5b7b2eb2409e49f742bc29",
                "c81aa48bdb4ca6fa0ef18b9788ae25fe30857aa681b3942217f9fed151bab7d0",
            ),
            u2Expected=(
                "dc137a2f1d4a35aebc0ecbf6d3486def8480bfdc752a86dd4f207d7d1910e22d",
                "7532f0ce99dcc772a4d77861dae57c138f07ae304a727907fb0aafdb624ed572",
            ),
            macAExpected="237a03c35f4917ce86b3589445f11e1a6f108b2fdd0aa9e810664b255960b579",
            macBExpected="9ee0e8733b069850804d9798731dcd1cffe87a3b151f0ae83ea96afb4ffc31e4",
        )

    def test_256C(self):
        self._test(
            "id-GostR3410-2001-CryptoPro-B-ParamSet",
            qpwExpected=(
                "6dc2ae26bc691fca5a73d9c452790d15e34ba5404d92955b914c8d2662abb985",
                "3b02aaa9dd65ae30c335ced12f3154bbac059f66b088306747453edf6e5db077",
            ),
            alpha=0x499d72b90299cab0da1f8be19d9122f622a13b32b730c46bd0664044f2144fad,
            alphaPExpected=(
                "61d6f916db717222d74877f179f7ebef7cd4d24d8c1f523c048e34a1df30f8dd",
                "3ec48863049cfcfe662904082e78503f4973a4e105e2f1b18c69a5e7fb209000",
            ),
            u1Expected=(
                "21f5437af33d2a1171a070226b4ae82d3765cd0eebff1ecefe158ebc50c63ab1",
                "5c9553b5d11aaaece738ad9a9f8cb4c100ad4fa5e089d3cbccea8c0172eb7ecc",
            ),
            beta=0x0f69ff614957ef83668edc2d7ed614be76f7b253db23c5cc9c52bf7df8f4669d,
            kBSrcExpected=(
                "50140a5ded3343efc8257b79e646d9f0df43828c04919bd460c97ad14ba3a86b",
                "00c406b5744d8eb149dc8e7fc84064d85320253e57a9b6b13d0d38fea8ee5e0a",
            ),
            kBExpected="a626de01b1680ff7513009122bcee1896883394f96030172455c9ae060cce44a",
            betaPExpected=(
                "33bc6f7e9c0ba10cfb2b72546c327171295508ea97f8c8ba9f890f2478ab4d6c",
                "75d57b396c396f492f057e9222ccc686437a2aad464e452ef426fc8eeed1a4a6",
            ),
            u2Expected=(
                "089ddee718ee8a224a7f37e22cffd731c25fcbf58860364ee322412cdcef99ac",
                "0ece03d4e395a6354c571871bef425a532d5d463b0f8fd427f91a43e20cda55c",
            ),
            macAExpected="b91f43902afa90d3e5c691cbdc438a1ebf547f4c2cb41443cc38797be247a7d0",
            macBExpected="79d55483fd99b12bcca5edc6bbe1d7b915ce0451b0891e775d4a61cb16e33fcc",
        )

    def test_256D(self):
        self._test(
            "id-GostR3410-2001-CryptoPro-C-ParamSet",
            qpwExpected=(
                "945821daf91e158b839939630655a3b21ff3e146d27041e86c05650eb3b46b59",
                "3a0c2816ac97421fa0e879605f17f0c9c3eb734cff196937f6284438d70bdc48",
            ),
            alpha=0x3a54ac3f19ad9d0b1eac8acdcea70e581f1dac33d13feafd81e762378639c1a8,
            alphaPExpected=(
                "96b7f09c94d297c257a7da48364c0076e59e48d221cba604ae111ca3933b446a",
                "54e4953d86b77ecceb578500931e822300f7e091f79592ca202a020d762c34a6",
            ),
            u1Expected=(
                "81bbd6fca464d2e2404a66d786ce4a777e739a89aeb68c2dac99d53273b75387",
                "6b6dbd922ea7e060998f8b230ab6ef07ad2ec86b2bf66391d82a30612eadd411",
            ),
            beta=0x448781782bf7c0e52a1dd9e6758fd3482d90d3cfccf42232cf357e59a4d49fd4,
            kBSrcExpected=(
                "16a12d88547e1c9006baa008e8cbecc9d16891edc836cfb75f8eb956fa761194",
                "d28e25dad3818d163c494b059a8c70a5a1b88a7f80a2ee3549301846542c470b",
            ),
            kBExpected="be7e7e47b41116f2c77e3b8fce403072ca82450d65defc71a95649e4deeaecee",
            betaPExpected=(
                "4b9c0ab55a938121f282f48a2cc4396eb16e7e0068b495b0c1dd4667786a3eb7",
                "223460aa8e09383e9df9844c5a0f2766484738e5b30128a171b69a77d9509b96",
            ),
            u2Expected=(
                "2ed9b903254003a672e89ebebc9e31503726ad124bb5fc0a726ee0e6fcce323e",
                "4cf5e1042190120391ec8db62fe25e9e26ec60fb0b78b242199839c295fcd022",
            ),
            macAExpected="d3b41ae2c9431136063e6d08a61be963bd5ed6a1fff937fa8b090a98e162bfed",
            macBExpected="d6b39a4499bed3e04facf955502d16b2cb674a205fac3cd83d54ec2fd5fce258",
        )

    def test_512A(self):
        self._test(
            "id-tc26-gost-3410-2012-512-paramSetA",
            qpwExpected=(
                "0c0ab53d0e0a9c607cad758f558915a0a7dc5dc87b45e9a58fddf30ec3385960283e030cd322d9e46b070637785fd49d2cd711f46807a24c40af9a42c8e2d740",
                "df93a8012b86d3a3d4f8a4d487da15fc739eb31b20b3b0e8c8c032aaf8072c6337cf7d5b404719e5b4407c41d9a3216a08ca69c271484e9ed72b8aaa52e28b8b",
            ),
            alpha=0x3ce54325db52fe798824aead11bb16fa766857d04a4af7d468672f16d90e7396046a46f815693e85b1ce5464da9270181f82333b0715057bbe8d61d400505f0e,
            alphaPExpected=(
                "b93093eb0fcc463239b7df276e09e592fcfc9b635504ea4531655d76a0a3078e2b4e51cfe2fa400cc5de9fbe369db204b3e8ed7edd85ee5cca654c1aed70e396",
                "809770b8d910ea30bd2fa89736e91dc31815d2d9b31128077eedc371e9f69466f497dc64dd5b1fadc587f860ee256109138c4a9cd96b628e65a8f590520fc882",
            ),
            u1Expected=(
                "e7510a9edd37b869566c81052e2515e1563fdfe79f1d782d6200f33c3cc2764d40d0070b73ad5a47bae9a8f2289c1b07dac26a1a2ff9d3ecb0a8a94a4f179f13",
                "ba333b912570777b626a5337bc7f727952460eeba2775707fe4537372e902df5636080b25399751bf48fb154f3c2319a91857c23f39f89ef54a8f043853f82de",
            ),
            beta=0xb5c286a79aa8e97ec0e19bc1959a1d15f12f8c97870ba9d68cc12811a56a3bb11440610825796a49d468cdc9c2d02d76598a27973d5960c5f50bce28d8d345f4,
            kBSrcExpected=(
                "8459c20cb5c532416db928eb50c0520fb21b9cd39a4e7606b221be15ca1d02da0815dec44979c08c7d2307af247dda1f89ec812069f5d9cde306aff0bc3fd26e",
                "d201b95352a25606b643e888302efc8d3e951e3eb4684adb5c057b8f8c89b6cc0deed100065b518a1c717f7682ff612bbc798ec7b2490fb7003f943387371c1d",
            ),
            kBExpected="5324def848b663cc26422f5e45eec34c51d24361b16560ca58a3d3284586cb7a",
            betaPExpected=(
                "238b38644e440452a99fa6b93d9fd7da0cb83c32d3c1e3cfe5df5c3eb0f9db91e588daedc849ea2fb867ae855a21b4077353c0794716a6480995113d8c20c7af",
                "b2273d5734c1897f8d15a7008b862938c8c74ca7e877423d95243eb7ebd02fd2c456cf9fc956f078a59aa86f19dd1075e5167e4ed35208718ea93161c530ed14",
            ),
            u2Expected=(
                "c33844126216e81b372001e77c1fe9c7547f9223cf7bb865c4472ec18be0c79a678cc5ae4028e3f3620cce355514f1e589f8a0c433ceafcbd2ee87884d953411",
                "8b520d083aaf257e8a54ec90cbadbaf4feed2c2d868c82ff04fcbb9ef6f38e56f6baf9472d477414da7e36f538ed223d2e2ee02fae1a20a98c5a9fcf03b6f30d",
            ),
            macAExpected="e8ef9ea8f1e6b12668e58cd22dd8eec64a16710039faa6b603992220fafe5614",
            macBExpected="61143460836b235cecd0b49b587ea45d513c3a38783f1c9d3b05970a956a55ba",
        )

    def test_512B(self):
        self._test(
            "id-tc26-gost-3410-2012-512-paramSetB",
            qpwExpected=(
                "7d03e65b8050d1e12cbb601a17b9273b0e728f5021cd47c8a4dd822e4627ba5f9c696286a2cdda9a065509866b4dededc4a118409604ad549f87a60afa621161",
                "16037dad45421ec50b00d50bdc6ac3b85348bc1d3a2f85db27c3373580fef87c2c743b7ed30f22be22958044e716f93a61ca3213a361a2797a16a3ae62957377",
            ),
            alpha=0x715e893fa639bf341296e0623e6d29dadf26b163c278767a7982a989462a3863fe12aef8bd403d59c4dc4720570d4163db0805c7c10c4e818f9cb785b04b9997,
            alphaPExpected=(
                "10c479ea1c04d3c2c02b0576a9c42d96226ff033c1191436777f66916030d87d02fb93738ed7669d07619ffce7c1f3c4db5e5df49e2186d6fa1e2eb5767602b9",
                "039f6044191404e707f26d59d979136a831cce43e1c5f0600d1ddf8f39d0ca3d52fbd943bf04ddced1aa2ce8f5ebd7487acdef239c07d015084d796784f35436",
            ),
            u1Expected=(
                "45c05cce8290762f2470b719b4306d62b2911ceb144f7f72ef11d10498c7e921ff163fe72044b4e7332ad8cbec3c12117820f53a60762315bceb5bc6da5cf1e0",
                "5be483e382d0f5f0748c4f6a5045d99e62755b5acc9554ec4a5b2093e121a2dd5c6066bc9ede39373ba19899208bb419e38b39bbdedeb0b09a5caaeaa984d02e",
            ),
            beta=0x30fa8c2b4146c2dbbe82bed04d7378877e8c06753bd0a0ff71ebf2befe8da8f3dc0836468e2ce7c5c961281b6505140f8407413f03c2cb1d201ea1286ce30e6d,
            kBSrcExpected=(
                "3f0402e40a9d5963205bcdf4fd8977919bbaf480f8e4fbd1255aece6ed57264bd0a287984f59d10204b5f45e4d77f3cf8a63b31beb2df59f8af73c209cca8b50",
                "b418d801e490ae133f04f4f3f4d8fe8e19646a1baf44d236fcc21b7f4d8fc6a1e29d6b69acceed4e62abb20dad78acf4feb0ed838ed91e9212aba389714e560c",
            ),
            kBExpected="d590e05ef5aece8b7cfbfc71be455f29a5cc666f85cdb17e7cc716c59ff170e9",
            betaPExpected=(
                "34c0149e7bb91ae377b02573fcc48af7bfb7b16deb8f9ce870f384688e3241a3a868588cc0ef4364cca67d17e3260cd82485c202adc76f895d5df673b1788e67",
                "608e944929bd643569ed5189db871453f13333a1eaf82b2fe1be8100e775f13dd9925bd317b63bfaf05024d4a738852332b64501195c1b2ef789e34f23ddafc5",
            ),
            u2Expected=(
                "0535f95463444c4594b5a2e14b35760491c670925060b4bebc97de3a3076d1a581f89026e04282b040925d9250201024aca4b2713569b6c3916a6f3344b840ad",
                "40e6c2e55aec31e7bcb6ea0242857fc6dfb5409803edf4ca20141f72cc3c7988706e076765f4f004340e5294a7f8e53ba59cb67502f0044558c854a7d63fe900",
            ),
            macAExpected="de46bb4c8ce08a6ef3b8dfaccc1a39b08d8c27b6cb0fcf592386a648f4e5bd8c",
            macBExpected="ecb11de2061c55f1d11459cb51ce31409999992fcaa1222fb14fceab96ee7aac",
        )

    def test_256A(self):
        self._test(
            "id-tc26-gost-3410-2012-256-paramSetA",
            qpwExpected=(
                "dbf99827078956812fa48c6e695df589def1d18a2d4d35a96d75bf6854237629",
                "9fddd48bfbc57bee1da0cff282884f284d471b388893c48f5ecb02fc18d67589",
            ),
            alpha=0x147b72f6684fb8fd1b418a899f7dbecaf5fce60b13685baa95328654a7f0707f,
            alphaPExpected=(
                "33fbac14eae538275a769417829c431bd9fa622b6f02427ef55bd60ee6bc2888",
                "22f2ebcf960a82e6cdb4042d3ddda511b2fba925383c2273d952ea2d406eae46",
            ),
            u1Expected=(
                "e569ab544e3a13c41077de97d659a1b7a13f61ddd808b633a5621fe2583a2c43",
                "a21a743a08f4d715661297ecd6f86553a808925bf34802bf7ec34c548a40b2c0",
            ),
            beta=0x30d5cfadaa0e31b405e6734c03ec4c5df0f02f4ba25c9a3b320ee6453567b4cb,
            kBSrcExpected=(
                "a339a0b89cef1a6ffd4ca128049e0684df4a9775b689a337841bf7d791207f35",
                "118628f7288eaa0f7ec81da20a24ff1e6993c63d9dd26a90b74dd1a266280663",
            ),
            kBExpected="7df71ac327ed517d0de403e817c6204bc19165b9d1002b9f1088a6cda6eacf27",
            betaPExpected=(
                "2b2d89fab735433970564f2f28cfa1b57d640cb902bc6334a538f44155022cb2",
                "10ef6a82eef1e70f942aa81d6b4ce5dec0ddb9447512962874870e6f2849a96f",
            ),
            u2Expected=(
                "190d2f283f7e861065db53227d7fbdf429cebf93791262cb29569bdf63c86ca4",
                "b3f1715721e9221897ccde046c9b843a8386dbf7818a112f15a02bc820ac8f6d",
            ),
            macAExpected="f929b61a3c833985b829f268557fa811009f820ab1a730b5aa334c3e6ba3177f",
            macBExpected="a2928a5cf620bbc4900de403f7fc59a5e980b68be046d0b5d9b4ae6abfa80bd6",
        )

    def test_512C(self):
        self._test(
            "id-tc26-gost-3410-2012-512-paramSetC",
            qpwExpected=(
                "0185ae6271a81bb7f236a955f7caa26fb63849813c0287d96c83a15ae6b6a86467ab13b6d88ce8cd7dc2e5b97ff5f28fac2c108f2a3cf3db5515c9e6d7d210e8",
                "ed0220f92ef771a71c64ecc77986db7c03d37b3e2ab3e83f32ce5e074a762ec08253c9e2102b87532661275c4b1d16d2789cdabc58acfdf7318de70ab64f09b8",
            ),
            alpha=0x332f930421d14cfe260042159f18e49fd5a54167e94108ad80b1de60b13de7999a34d611e63f3f870e5110247df8ec7466e648acf385e52ccb889abf491edff0,
            alphaPExpected=(
                "561655966d52952e805574f4281f1ed3a2d498932b00cba9decb42837f09835bffbfe2d84d6b6b242fe7b57f92e1a6f2413e12ddd6383e4437e13d72693469ad",
                "f6b18328b2715bd7f4178615273a36135bc0bf62f7d8bb9f080164ad36470ad03660f51806c64c6691badef30f793720f8e3feaed631d6a54a4c372dcbf80e82",
            ),
            u1Expected=(
                "40645b4b9a908d74def98886a336f98bae6ada4c1ac9b7594a33d5e4a16486c5533c7f3c5dd84797ab5b4340bfc70caf1011b69a01a715e5b9b5432d5151cbd7",
                "267fbb18d0b79559d1875909f2a15f7b49ecd8ed166cf7f4fcd1f448915504835e80d52be8d34ada5b5e159cf52979b1bcfe8f5048dc443a0983aa19192b8407",
            ),
            beta=0x38481771e7d054f96212686b613881880bd8a6c89ddbc656178f014d2c093432a033ee10415f13a160d44c2ad61e6e2e05a7f7ec286bcea3ea4d4d53f8634fa2,
            kBSrcExpected=(
                "4f4d64b5d07008e9e685874f882c3e1e60a6675eed421fc234163fdeb44c6918b7bcceab88a0f3fb788da8db101851ff1a416822ba37c353cec4c5a52395b772",
                "ac93c054e3f4055ced6ff0bee4a6a24ed68b86fefa70de4a2b16085142a4dff05d32ec7ddfe304f5c704fdfa060f64e9e832140025f392e50350770e3fb62cac",
            ),
            kBExpected="a08384a62f4be1ae4898fca36daa3faa451b3ec5b59ce375f89e929f4b13258c",
            betaPExpected=(
                "b7c5818687083433bc1aff61cb5ca79e38232025e0c1f123b8651e62173ce6873f3e6ffe7281c2e45f4f524f66b0c263616ed08fd210ac4355ca3292b51d71c3",
                "497f14205dbdc89bddaf50520ed3b1429ad30777310186be5e68070f016a44e0c766db08e8ac23fbdfde6d675aa4df591eb18ba0d348df7aa40973a2f1dcfa55",
            ),
            u2Expected=(
                "b772fd97d6fdec1da0771bc059b3e5adf9858311031eae5aec6a6ec8104b4105c45a6c65689a8ee636c687db62cc0afc9a48ca66e381286cc73f374c1dd8f445",
                "c64f69425ffeb2995130e85a08edc3a686ec28ee6e8469f7f09bd3bcbdd843ac573578da6ba1cb3f5f069f205233853f06255c4b28586c9a1643537497b1018c",
            ),
            macAExpected="1263f2890e90ee426b9ba08ab9ea7f1fff26e1605cc65de296969115e5317687",
            macBExpected="6dfd06045d6d97a0e419b00e0035b9d2e3ab098b7ca4ad525460fab62185aa57",
        )
