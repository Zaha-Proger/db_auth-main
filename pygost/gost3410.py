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
"""GOST R 34.10 public-key signature function.

This is implementation of GOST R 34.10-2001 (:rfc:`5832`), GOST R
34.10-2012 (:rfc:`7091`). The difference between 2001 and 2012 is the
key, digest and signature lengths.
"""

from os import urandom
from typing import Tuple

from pygost.utils import modinvert


Point = Tuple[int, int]


def point_size(point: int):
    """Determine is it either 256 or 512 bit point
    """
    return (512 // 8) if point.bit_length() > 256 else (256 // 8)


class GOST3410Curve:
    """GOST 34.10 validated curve

    >>> curve = CURVES["id-GostR3410-2001-TestParamSet"]
    >>> prv = prv_unmarshal(urandom(32))
    >>> signature = sign(curve, prv, GOST341194(data).digest())
    >>> pub = public_key(curve, prv)
    >>> verify(curve, pub, GOST341194(data).digest(), signature)
    True

    :param p: characteristic of the underlying prime field
    :param q: elliptic curve subgroup order
    :param a, b: coefficients of the equation of the elliptic curve in
                 the canonical form
    :param x, y: the coordinate of the point P (generator of the
                 subgroup of order q) of the elliptic curve in
                 the canonical form
    :param e, d: coefficients of the equation of the elliptic curve in
                 the twisted Edwards form
    :param name: human-readable curve name
    """

    def __init__(
            self,
            p: int,
            q: int,
            a: int,
            b: int,
            x: int,
            y: int,
            cofactor: int=1,
            e: int=None,
            d: int=None,
            name: str=None,
    ):
        self.p = p
        self.q = q
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        self.cofactor = cofactor
        self.e = e
        self.d = d
        if not self.contains((x, y)):
            raise ValueError("Invalid parameters")
        self._st = None
        self.name = name

    @property
    def point_size(self) -> int:
        return point_size(self.p)

    def __repr__(self) -> str:
        return "<%s: %s>" % (self.__class__.__name__, self.name)

    def pos(self, v: int) -> int:
        """Make positive number
        """
        if v < 0:
            return v + self.p
        return v

    def contains(self, point: Point):
        """Is point on the curve?
        """
        x, y = point
        r1 = y * y % self.p
        r2 = ((x * x + self.a) * x + self.b) % self.p
        return r1 == self.pos(r2)

    def _add(self, p1x: int, p1y: int, p2x: int, p2y: int) -> Point:
        if p1x == p2x and p1y == p2y:
            # double
            t = ((3 * p1x * p1x + self.a) * modinvert(2 * p1y, self.p)) % self.p
        else:
            tx = self.pos(p2x - p1x) % self.p
            ty = self.pos(p2y - p1y) % self.p
            t = (ty * modinvert(tx, self.p)) % self.p
        tx = self.pos(t * t - p1x - p2x) % self.p
        ty = self.pos(t * (p1x - tx) - p1y) % self.p
        return tx, ty

    def exp(self, degree: int, x: int=None, y: int=None) -> Point:
        x = x or self.x
        y = y or self.y
        tx = x
        ty = y
        if degree == 0:
            raise ValueError("Bad degree value")
        degree -= 1
        while degree != 0:
            if degree & 1 == 1:
                tx, ty = self._add(tx, ty, x, y)
            degree = degree >> 1
            x, y = self._add(x, y, x, y)
        return tx, ty

    def st(self) -> Point:
        """Compute s/t parameters for twisted Edwards curve points conversion
        """
        if self.e is None or self.d is None:
            raise ValueError("Non twisted Edwards curve")
        if self._st is not None:
            return self._st
        self._st = (
            self.pos(self.e - self.d) * modinvert(4, self.p) % self.p,
            (self.e + self.d) * modinvert(6, self.p) % self.p,
        )
        return self._st


CURVES = {
    "GostR3410_2001_ParamSet_cc": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("C0000000000000000000000000000000000000000000000000000000000003C7"), "big"),
        q=int.from_bytes(bytes.fromhex("5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85"), "big"),
        a=int.from_bytes(bytes.fromhex("C0000000000000000000000000000000000000000000000000000000000003c4"), "big"),
        b=int.from_bytes(bytes.fromhex("2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c"), "big"),
        x=int.from_bytes(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002"), "big"),
        y=int.from_bytes(bytes.fromhex("a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c"), "big"),
    ),
    "id-GostR3410-2001-TestParamSet": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000431"), "big"),
        q=int.from_bytes(bytes.fromhex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"), "big"),
        a=int.from_bytes(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000007"), "big"),
        b=int.from_bytes(bytes.fromhex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"), "big"),
        x=int.from_bytes(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002"), "big"),
        y=int.from_bytes(bytes.fromhex("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"), "big"),
    ),
    "id-tc26-gost-3410-12-256-paramSetA": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"), "big"),
        q=int.from_bytes(bytes.fromhex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"), "big"),
        a=int.from_bytes(bytes.fromhex("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"), "big"),
        b=int.from_bytes(bytes.fromhex("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"), "big"),
        x=int.from_bytes(bytes.fromhex("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"), "big"),
        y=int.from_bytes(bytes.fromhex("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"), "big"),
        cofactor=4,
        e=0x01,
        d=int.from_bytes(bytes.fromhex("0605F6B7C183FA81578BC39CFAD518132B9DF62897009AF7E522C32D6DC7BFFB"), "big"),
    ),
    "id-tc26-gost-3410-12-256-paramSetB": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"), "big"),
        q=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"), "big"),
        a=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"), "big"),
        b=int.from_bytes(bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000a6"), "big"),
        x=int.from_bytes(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001"), "big"),
        y=int.from_bytes(bytes.fromhex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"), "big"),
    ),
    "id-tc26-gost-3410-12-256-paramSetC": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000C99"), "big"),
        q=int.from_bytes(bytes.fromhex("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"), "big"),
        a=int.from_bytes(bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000C96"), "big"),
        b=int.from_bytes(bytes.fromhex("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"), "big"),
        x=int.from_bytes(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001"), "big"),
        y=int.from_bytes(bytes.fromhex("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"), "big"),
    ),
    "id-tc26-gost-3410-12-256-paramSetD": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B"), "big"),
        q=int.from_bytes(bytes.fromhex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"), "big"),
        a=int.from_bytes(bytes.fromhex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"), "big"),
        b=int.from_bytes(bytes.fromhex("000000000000000000000000000000000000000000000000000000000000805a"), "big"),
        x=int.from_bytes(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"), "big"),
        y=int.from_bytes(bytes.fromhex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"), "big"),
    ),
    "id-tc26-gost-3410-12-512-paramSetTest": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373"), "big"),
        q=int.from_bytes(bytes.fromhex("4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF"), "big"),
        a=7,
        b=int.from_bytes(bytes.fromhex("1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC"), "big"),
        x=int.from_bytes(bytes.fromhex("24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A"), "big"),
        y=int.from_bytes(bytes.fromhex("2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E"), "big"),
    ),
    "id-tc26-gost-3410-12-512-paramSetA": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"), "big"),
        q=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"), "big"),
        a=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"), "big"),
        b=int.from_bytes(bytes.fromhex("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"), "big"),
        x=int.from_bytes(bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003"), "big"),
        y=int.from_bytes(bytes.fromhex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"), "big"),
    ),
    "id-tc26-gost-3410-12-512-paramSetB": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F"), "big"),
        q=int.from_bytes(bytes.fromhex("800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"), "big"),
        a=int.from_bytes(bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"), "big"),
        b=int.from_bytes(bytes.fromhex("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"), "big"),
        x=int.from_bytes(bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"), "big"),
        y=int.from_bytes(bytes.fromhex("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"), "big"),
    ),
    "id-tc26-gost-3410-12-512-paramSetC": GOST3410Curve(
        p=int.from_bytes(bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"), "big"),
        q=int.from_bytes(bytes.fromhex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED"), "big"),
        a=int.from_bytes(bytes.fromhex("DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"), "big"),
        b=int.from_bytes(bytes.fromhex("B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1"), "big"),
        x=int.from_bytes(bytes.fromhex("E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148"), "big"),
        y=int.from_bytes(bytes.fromhex("F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"), "big"),
        cofactor=4,
        e=0x01,
        d=int.from_bytes(bytes.fromhex("9E4F5D8C017D8D9F13A5CF3CDF5BFE4DAB402D54198E31EBDE28A0621050439CA6B39E0A515C06B304E2CE43E79E369E91A0CFC2BC2A22B4CA302DBB33EE7550"), "big"),
    ),
}
CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"] = CURVES["id-tc26-gost-3410-12-256-paramSetB"]
CURVES["id-GostR3410-2001-CryptoPro-B-ParamSet"] = CURVES["id-tc26-gost-3410-12-256-paramSetC"]
CURVES["id-GostR3410-2001-CryptoPro-C-ParamSet"] = CURVES["id-tc26-gost-3410-12-256-paramSetD"]
CURVES["id-GostR3410-2001-CryptoPro-XchA-ParamSet"] = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]
CURVES["id-GostR3410-2001-CryptoPro-XchB-ParamSet"] = CURVES["id-GostR3410-2001-CryptoPro-C-ParamSet"]
CURVES["id-tc26-gost-3410-2012-256-paramSetA"] = CURVES["id-tc26-gost-3410-12-256-paramSetA"]
CURVES["id-tc26-gost-3410-2012-256-paramSetB"] = CURVES["id-tc26-gost-3410-12-256-paramSetB"]
CURVES["id-tc26-gost-3410-2012-256-paramSetC"] = CURVES["id-tc26-gost-3410-12-256-paramSetC"]
CURVES["id-tc26-gost-3410-2012-256-paramSetD"] = CURVES["id-tc26-gost-3410-12-256-paramSetD"]
CURVES["id-tc26-gost-3410-2012-512-paramSetTest"] = CURVES["id-tc26-gost-3410-12-512-paramSetTest"]
CURVES["id-tc26-gost-3410-2012-512-paramSetA"] = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
CURVES["id-tc26-gost-3410-2012-512-paramSetB"] = CURVES["id-tc26-gost-3410-12-512-paramSetB"]
CURVES["id-tc26-gost-3410-2012-512-paramSetC"] = CURVES["id-tc26-gost-3410-12-512-paramSetC"]
for _name, _curve in CURVES.items():
    _curve.name = _name
DEFAULT_CURVE = CURVES["id-tc26-gost-3410-12-256-paramSetB"]


def public_key(curve: GOST3410Curve, prv: int, mask: int=None) -> Point:
    """Generate public key from the private one
    """
    pub = curve.exp(prv)
    if mask is not None:
        pub = curve.exp(mask, pub[0], pub[1])
    return pub


def sign(
        curve: GOST3410Curve,
        prv: int,
        digest: bytes,
        rand: bytes=None,
        mask: int=None,
) -> bytes:
    """Calculate signature for provided digest

    :param prv: private key
    :param digest: digest to sign
    :type digest: bytes, 32 or 64 bytes
    :param rand: optional predefined random data used for k/r generation
    :type rand: bytes, 32 or 64 bytes
    :returns: signature, BE(S) || BE(R)
    :rtype: bytes, 64 or 128 bytes
    """
    size = curve.point_size
    q = curve.q
    e = int.from_bytes(digest, "big") % q
    if e == 0:
        e = 1
    while True:
        if rand is None:
            rand = urandom(size)
        elif len(rand) != size:
            raise ValueError("rand length != %d" % size)
        k = int.from_bytes(rand, "big") % q
        if k == 0:
            continue
        r, y = curve.exp(k)
        if mask is not None:
            r, y = curve.exp(mask, x=r, y=y)
        r %= q
        if r == 0:
            continue
        d = prv * r
        k *= e
        s = d + k
        if mask is not None:
            s *= mask
        s %= q
        if s == 0:
            continue
        break
    return s.to_bytes(size, "big") + r.to_bytes(size, "big")


def verify(curve: GOST3410Curve, pub: Point, digest: bytes, signature: bytes) -> bool:
    """Verify provided digest with the signature

    :param digest: digest needed to check
    :type digest: bytes, 32 or 64 bytes
    :param signature: signature to verify with
    :type signature: bytes, 64 or 128 bytes
    """
    size = curve.point_size
    if len(signature) != size * 2:
        raise ValueError("Invalid signature length")
    q = curve.q
    p = curve.p
    s = int.from_bytes(signature[:size], "big")
    r = int.from_bytes(signature[size:], "big")
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    e = int.from_bytes(digest, "big") % curve.q
    if e == 0:
        e = 1
    v = modinvert(e, q)
    z1 = s * v % q
    z2 = q - r * v % q
    p1x, p1y = curve.exp(z1)
    q1x, q1y = curve.exp(z2, pub[0], pub[1])
    lm = q1x - p1x
    if lm < 0:
        lm += p
    lm = modinvert(lm, p)
    z1 = q1y - p1y
    lm = lm * z1 % p
    lm = lm * lm % p
    lm = lm - p1x - q1x
    lm = lm % p
    if lm < 0:
        lm += p
    lm %= q
    # This is not constant time comparison!
    return lm == r


def prv_unmarshal(prv: bytes) -> int:
    """Unmarshal little-endian private key

    It is advisable to use :py:func:`pygost.gost3410.prv_marshal` to
    assure that key i in curve's Q field for better compatibility with
    some implementations.
    """
    return int.from_bytes(prv, "little")


def prv_marshal(curve: GOST3410Curve, prv: int) -> bytes:
    """Marshal little-endian private key

    Key is in curve's Q field.
    """
    return (prv % curve.q).to_bytes(point_size(prv), "little")


def pub_marshal(pub: Point) -> bytes:
    """Marshal public key

    :returns: LE(X) || LE(Y)
    """
    size = point_size(pub[0])
    return pub[0].to_bytes(size, "little") + pub[1].to_bytes(size, "little")


def pub_unmarshal(pub: bytes) -> Point:
    """Unmarshal public key

    :param pub: LE(X) || LE(Y)
    """
    size = len(pub) // 2
    return (int.from_bytes(pub[:size], "little"), int.from_bytes(pub[size:], "little"))


def uv2xy(curve: GOST3410Curve, u: int, v: int) -> Point:
    """Convert twisted Edwards curve U,V coordinates to Weierstrass X,Y
    """
    s, t = curve.st()
    k1 = (s * (1 + v)) % curve.p
    k2 = curve.pos(1 - v)
    x = t + k1 * modinvert(k2, curve.p)
    y = k1 * modinvert(u * k2, curve.p)
    return x % curve.p, y % curve.p


def xy2uv(curve: GOST3410Curve, x: int, y: int) -> Point:
    """Convert Weierstrass X,Y coordinates to twisted Edwards curve U,V
    """
    s, t = curve.st()
    xmt = curve.pos(x - t)
    u = xmt * modinvert(y, curve.p)
    v = curve.pos(xmt - s) * modinvert(xmt + s, curve.p)
    return u % curve.p, v % curve.p
