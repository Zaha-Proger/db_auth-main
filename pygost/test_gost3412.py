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

from unittest import TestCase

from pygost.gost3412 import C
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3412 import GOST3412Magma
from pygost.gost3412 import L
from pygost.gost3412 import PI


def S(blk):
    return bytearray(PI[v] for v in blk)


def R(blk):
    return L(blk, rounds=1)


class STest(TestCase):
    def test_vec1(self):
        blk = bytearray(bytes.fromhex("ffeeddccbbaa99881122334455667700"))
        self.assertSequenceEqual(S(blk), bytes.fromhex("b66cd8887d38e8d77765aeea0c9a7efc"))

    def test_vec2(self):
        blk = bytearray(bytes.fromhex("b66cd8887d38e8d77765aeea0c9a7efc"))
        self.assertSequenceEqual(S(blk), bytes.fromhex("559d8dd7bd06cbfe7e7b262523280d39"))

    def test_vec3(self):
        blk = bytearray(bytes.fromhex("559d8dd7bd06cbfe7e7b262523280d39"))
        self.assertSequenceEqual(S(blk), bytes.fromhex("0c3322fed531e4630d80ef5c5a81c50b"))

    def test_vec4(self):
        blk = bytearray(bytes.fromhex("0c3322fed531e4630d80ef5c5a81c50b"))
        self.assertSequenceEqual(S(blk), bytes.fromhex("23ae65633f842d29c5df529c13f5acda"))


class RTest(TestCase):
    def test_vec1(self):
        blk = bytearray(bytes.fromhex("00000000000000000000000000000100"))
        self.assertSequenceEqual(R(blk), bytes.fromhex("94000000000000000000000000000001"))

    def test_vec2(self):
        blk = bytearray(bytes.fromhex("94000000000000000000000000000001"))
        self.assertSequenceEqual(R(blk), bytes.fromhex("a5940000000000000000000000000000"))

    def test_vec3(self):
        blk = bytearray(bytes.fromhex("a5940000000000000000000000000000"))
        self.assertSequenceEqual(R(blk), bytes.fromhex("64a59400000000000000000000000000"))

    def test_vec4(self):
        blk = bytearray(bytes.fromhex("64a59400000000000000000000000000"))
        self.assertSequenceEqual(R(blk), bytes.fromhex("0d64a594000000000000000000000000"))


class LTest(TestCase):
    def test_vec1(self):
        blk = bytearray(bytes.fromhex("64a59400000000000000000000000000"))
        self.assertSequenceEqual(L(blk), bytes.fromhex("d456584dd0e3e84cc3166e4b7fa2890d"))

    def test_vec2(self):
        blk = bytearray(bytes.fromhex("d456584dd0e3e84cc3166e4b7fa2890d"))
        self.assertSequenceEqual(L(blk), bytes.fromhex("79d26221b87b584cd42fbc4ffea5de9a"))

    def test_vec3(self):
        blk = bytearray(bytes.fromhex("79d26221b87b584cd42fbc4ffea5de9a"))
        self.assertSequenceEqual(L(blk), bytes.fromhex("0e93691a0cfc60408b7b68f66b513c13"))

    def test_vec4(self):
        blk = bytearray(bytes.fromhex("0e93691a0cfc60408b7b68f66b513c13"))
        self.assertSequenceEqual(L(blk), bytes.fromhex("e6a8094fee0aa204fd97bcb0b44b8580"))


class KuznechikTest(TestCase):
    key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    ciphertext = bytes.fromhex("7f679d90bebc24305a468d42b9d4edcd")

    def test_c(self):
        self.assertSequenceEqual(C[0], bytes.fromhex("6ea276726c487ab85d27bd10dd849401"))
        self.assertSequenceEqual(C[1], bytes.fromhex("dc87ece4d890f4b3ba4eb92079cbeb02"))
        self.assertSequenceEqual(C[2], bytes.fromhex("b2259a96b4d88e0be7690430a44f7f03"))
        self.assertSequenceEqual(C[3], bytes.fromhex("7bcd1b0b73e32ba5b79cb140f2551504"))
        self.assertSequenceEqual(C[4], bytes.fromhex("156f6d791fab511deabb0c502fd18105"))
        self.assertSequenceEqual(C[5], bytes.fromhex("a74af7efab73df160dd208608b9efe06"))
        self.assertSequenceEqual(C[6], bytes.fromhex("c9e8819dc73ba5ae50f5b570561a6a07"))
        self.assertSequenceEqual(C[7], bytes.fromhex("f6593616e6055689adfba18027aa2a08"))

    def test_roundkeys(self):
        ciph = GOST3412Kuznechik(self.key)
        self.assertSequenceEqual(ciph.ks[0], bytes.fromhex("8899aabbccddeeff0011223344556677"))
        self.assertSequenceEqual(ciph.ks[1], bytes.fromhex("fedcba98765432100123456789abcdef"))
        self.assertSequenceEqual(ciph.ks[2], bytes.fromhex("db31485315694343228d6aef8cc78c44"))
        self.assertSequenceEqual(ciph.ks[3], bytes.fromhex("3d4553d8e9cfec6815ebadc40a9ffd04"))
        self.assertSequenceEqual(ciph.ks[4], bytes.fromhex("57646468c44a5e28d3e59246f429f1ac"))
        self.assertSequenceEqual(ciph.ks[5], bytes.fromhex("bd079435165c6432b532e82834da581b"))
        self.assertSequenceEqual(ciph.ks[6], bytes.fromhex("51e640757e8745de705727265a0098b1"))
        self.assertSequenceEqual(ciph.ks[7], bytes.fromhex("5a7925017b9fdd3ed72a91a22286f984"))
        self.assertSequenceEqual(ciph.ks[8], bytes.fromhex("bb44e25378c73123a5f32f73cdb6e517"))
        self.assertSequenceEqual(ciph.ks[9], bytes.fromhex("72e9dd7416bcf45b755dbaa88e4a4043"))

    def test_encrypt(self):
        ciph = GOST3412Kuznechik(self.key)
        self.assertSequenceEqual(ciph.encrypt(self.plaintext), self.ciphertext)

    def test_decrypt(self):
        ciph = GOST3412Kuznechik(self.key)
        self.assertSequenceEqual(ciph.decrypt(self.ciphertext), self.plaintext)


class MagmaTest(TestCase):
    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex("fedcba9876543210")
    ciphertext = bytes.fromhex("4ee901e5c2d8ca3d")

    def test_encrypt(self):
        ciph = GOST3412Magma(self.key)
        self.assertSequenceEqual(ciph.encrypt(self.plaintext), self.ciphertext)

    def test_decrypt(self):
        ciph = GOST3412Magma(self.key)
        self.assertSequenceEqual(ciph.decrypt(self.ciphertext), self.plaintext)
