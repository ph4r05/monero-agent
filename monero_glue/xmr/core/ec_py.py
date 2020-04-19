#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import hashlib
import hmac
import struct

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Random import random as rand

from monero_glue.xmr.core.backend import ed25519ietf
from monero_glue.xmr.core.backend.ed25519 import expmod
from monero_glue.xmr.core.backend.ed25519_2 import inv
from monero_glue.xmr.core.ec_base import *
from monero_serialize import xmrserialize


def cmp(a, b):
    return (a > b) - (a < b)


def memcpy(dst, dst_off, src, src_off, len):
    for i in range(len):
        dst[dst_off + i] = src[src_off + i]
    return dst


_decodeint = ed25519.decodeint
_encodeint = ed25519.encodeint
_encodepoint = ed25519_2.encodepoint
_decodepoint = ed25519_2.decodepoint


class EdScalar(object):
    def __init__(self, v=None, offset=0):
        self.v = 0
        self.init(v, offset)

    def init(self, src=None, offset=0):
        if src is None:
            self.v = 0
        elif isinstance(src, int):
            self.v = src % l
        elif isinstance(src, EdScalar):
            self.v = src.v
        else:
            self.v = _decodeint(src[offset:]) % l
        return self

    def _assert_scalar(self, other):
        if not isinstance(other, EdScalar):
            raise ValueError("operand is not EdScalar")

    def __repr__(self):
        return "EdScalar(%s)" % binascii.hexlify(_encodeint(self.v))

    def __cmp__(self, other):
        if isinstance(other, int):
            return cmp(self.v, other)
        if not isinstance(other, EdScalar):
            raise ValueError("Neither EdScalar nor integer")
        return cmp(self.v, other.v)

    def __eq__(self, other):
        self._assert_scalar(other)
        return self.v == other.v

    def __bytes__(self):
        return _encodeint(self.v)

    def modinv(self):
        self.v = pow(self.v, l - 2, l)
        return self

    def __neg__(self):
        return EdScalar(-1 * self.v)

    def __add__(self, other):
        self._assert_scalar(other)
        return EdScalar(self.v + other.v)

    def __sub__(self, other):
        return EdScalar(self.v - other.v)

    def __mul__(self, other):
        return EdScalar(self.v * other.v)

    @classmethod
    def ensure_scalar(cls, x):
        if isinstance(x, EdScalar):
            return x
        return EdScalar(x)


class EdPoint(object):
    def __init__(self, v=None, offset=0):
        self.v = ed25519_2.ident
        self.init(v, offset)

    def init(self, src=None, offset=0):
        if src is None:
            self.v = ed25519_2.ident
        elif isinstance(src, EdPoint):
            self.v = src.v
        elif isinstance(src, tuple):
            self.v = src
        else:
            self.v = _decodepoint(src[offset:])
        return self

    def __repr__(self):
        return "EdPoint(%r)" % binascii.hexlify(_encodepoint(self.v))

    def __getitem__(self, item):
        return self.v[item]

    def __eq__(self, other):
        if isinstance(other, EdPoint):
            return ed25519ietf.point_equal(self.v, other.v)
        elif isinstance(other, tuple):
            return ed25519ietf.point_equal(self.v, other)
        else:
            ValueError("Neither EdPoint nor quadruple")

    def __bytes__(self):
        return _encodepoint(self.v)

    def check(self):
        if not ed25519_2.isoncurve(self.v):
            raise ValueError("P is not on ed25519 curve")

    @staticmethod
    def invert_v(v):
        return -1 * v[0] % q, v[1], v[2], -1 * v[3] % q

    def invert(self):
        self.v = EdPoint.invert_v(self.v)
        return self

    def _assert_point(self, other):
        if not isinstance(other, EdPoint):
            raise ValueError("operand is not EdPoint")

    def __add__(self, other):
        self._assert_point(other)
        return EdPoint(ed25519_2.edwards_add(self.v, other.v))

    def __neg__(self):
        return EdPoint(self).invert()

    def __sub__(self, other):
        self._assert_point(other)
        return EdPoint(ed25519_2.edwards_add(self.v, EdPoint.invert_v(other.v)))

    def __mul__(self, other):
        return EdPoint(ed25519_2.scalarmult(self.v, other.v))


BASE = EdPoint(ed25519_2.B)
Ge25519 = EdPoint
Sc25519 = EdScalar


def new_point():
    return EdPoint()


def new_scalar():
    return EdScalar()


def random_bytes(by):
    """
    Generates X random bytes, returns byte-string
    :param by:
    :return:
    """
    return get_random_bytes(by)


def get_keccak(*args, **kwargs):
    """
    Simple keccak 256
    :return:
    """
    k = keccak2.Keccak256()
    if len(args) == 1:
        k.update(args[0])
    return k


def keccak_hash(inp, size=None):
    """
    Hashesh input in one call
    :return:
    """
    inpx = inp if size is None else inp[:size]
    ctx = get_keccak()
    ctx.update(inpx)
    return ctx.digest()


def keccak_hash_into(r, inp, size=None):
    b = keccak_hash(inp, size)
    return memcpy(r, 0, b, 0, 32)


def keccak_2hash(inp):
    """
    Keccak double hashing
    :param inp:
    :return:
    """
    return keccak_hash(keccak_hash(inp))


def get_hmac(key, msg=None):
    """
    Returns HMAC object (uses Keccak256)
    :param key:
    :param msg:
    :return:
    """
    return hmac.new(key, msg=msg, digestmod=get_keccak)


def compute_hmac(key, msg=None):
    """
    Computes and returns HMAC of the msg using Keccak256
    :param key:
    :param msg:
    :return:
    """
    h = hmac.new(key, msg=msg, digestmod=get_keccak)
    return h.digest()


def pbkdf2(inp, salt, length=32, count=1000, prf=None):
    """
    PBKDF2 with default PRF as SHA256
    HMAC-KECCAK-256 was used before but trezor-crypto does not have pbkdf2 with keccak256.
    :param inp:
    :param salt:
    :param length:
    :param count:
    :param prf:
    :return:
    """

    if prf is None:
        prf = lambda p, s: hmac.new(p, msg=s, digestmod=hashlib.sha256).digest()
    return PBKDF2(inp, salt, length, count, prf)


#
# Basic point enc/dec
#


def _offset(x, offset=0):
    if offset == 0:
        return x
    return x[offset:]


def decodeint(x, offset=0):
    return EdScalar(_offset(x, offset))


def decodeint_into(r, x, offset=0):
    r = r if r else new_scalar()
    return r.init(_offset(x, offset))


def decodeint_into_noreduce(r, x, offset=0):
    r = r if r else new_scalar()
    r.v = _decodeint(_offset(x, offset))
    return r


def encodeint(x):
    return bytes(x)


def encodeint_into(b, x, offset=0):
    r = bytes(x)
    return memcpy(b, offset, r, 0, 32)


def check_ed25519point(P):
    P.check()


def encodepoint(P):
    return bytes(P)


def encodepoint_into(b, P, offset=0):
    r = bytes(P)
    return memcpy(b, offset, r, 0, 32)


def conv_xy_to_ext(P):
    """
    Converts x,y representation to extended form
    (x % q, y % q, 1, x*y % q)
    :param P:
    :return:
    """
    return P[0] % q, P[1] % q, 1, (P[0] * P[1]) % q


def conv_ext_to_xy(P):
    """
    Converts extended representation to x,y
    Accepts also projective representation.
    :param P:
    :return:
    """
    x, y, z = P[0], P[1], P[2]
    zi = inv(z)
    x = (x * zi) % q
    y = (y * zi) % q
    return x, y


def conv_xy_to_precomp(P):
    """
    Transform x,y representation to precomputed form
    :param P:
    :return:
    """
    x, y = P
    return y - x, y + x, 2 * ed25519.d * x * y


def conv_ext_to_proj(P):
    """
    Extended coordinates to projective
    :param P:
    :return:
    """
    return P[0], P[1], P[2]


def conv_p1p1_to_ext(P):
    """
    p1p1 representation to extended
    :param P:
    :return:
    """
    x0, y0, z0, t0 = P
    return x0 * t0 % q, y0 * z0 % q, z0 * t0 % q, x0 * y0 % q


def invert_ext(P):
    """
    Inverts extended point coordinate
    :param P:
    :return:
    """
    return P.invert()


def point_eq(P, Q):
    P.check() and Q.check()
    return P == Q


def decodepoint(b, offset=0):
    return EdPoint(_offset(b, offset))


def decodepoint_into(r, b, offset=0):
    r = r if r else new_point()
    return r.init(_offset(b, offset))


#
# Zmod(2^255 - 19) operations, fe (field element)
# Not constant time! PoC only.
#


def fe_1():
    return 1


def fe_mod(a):
    return a % q


def fe_add(a, b):
    return (a + b) % q


def fe_sub(a, b):
    return (a - b) % q


def fe_sq(a):
    return (a * a) % q


def fe_mul(a, b):
    return (a * b) % q


def fe_expmod(b, e):
    return ed25519.expmod(b, e, q)


def fe_divpowm1(u, v):
    """
    uv^3(uv^7)^((q-5)/8)
    :param u:
    :param v:
    :return:
    """
    uv3 = ((u * v) ^ 3) % q
    uv7 = ((u * v) ^ 7) % q

    return uv3 * fe_expmod(uv7, ((q - 5) / 8))


def fe_isnegative(x):
    return x < 0


def fe_isnonzero(x):
    return x != 0


#
# Zmod(order), scalar values field
#


def sc_0():
    return EdScalar(0)


def sc_0_into(r):
    r = r if r else new_scalar()
    return r.init(0)


def sc_init(x):
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return EdScalar(x)


def sc_init_into(r, x):
    r = r if r else new_scalar()
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return r.init(x)


def sc_copy(r, x):
    r = r if r else new_scalar()
    return r.init(x)


def sc_get64(x):
    return x.v


def sc_check(key):
    """
    sc_check is not relevant for long-integer scalar representation.

    :param key:
    :return:
    """
    if key.v % l == 0:
        return -1
    return 0 if key.v == sc_reduce32(key.v) else -1


def check_sc(key):
    """
    throws exception on invalid key
    :param key:
    :return:
    """
    if sc_check(key) != 0:
        raise ValueError("Invalid scalar value")


def sc_reduce32(data):
    return data % l


def sc_add(aa, bb):
    return aa + bb


def sc_add_into(r, aa, bb):
    r = r if r else new_scalar()
    return r.init(aa + bb)


def sc_sub(aa, bb):
    return aa - bb


def sc_sub_into(r, aa, bb):
    r = r if r else new_scalar()
    return r.init(aa - bb)


def sc_isnonzero(c):
    return c != ZERO


def sc_eq(a, b):
    return a == b


def sc_mul(a, b):
    return a * b


def sc_mul_into(r, a, b):
    r = r if r else new_scalar()
    return r.init(a * b)


def sc_mulsub(aa, bb, cc):
    """
    (cc - aa * bb) % l
    """
    return cc - aa * bb


def sc_mulsub_into(r, aa, bb, cc):
    """
    (cc - aa * bb) % l
    """
    r = r if r else new_scalar()
    return r.init(cc - aa * bb)


def sc_muladd(aa, bb, cc):
    return cc + aa * bb


def sc_muladd_into(r, aa, bb, cc):
    r = r if r else new_scalar()
    return r.init(cc + aa * bb)


def sc_inv(aa):
    return EdScalar(aa).modinv()


def sc_inv_into(r, x):
    r = r if r else new_scalar()
    return r.init(x).modinv()


def random_scalar():
    return EdScalar(rand.getrandbits(64 * 8) % l)


def random_scalar_into(r):
    r = r if r else new_scalar()
    return r.init(random_scalar())


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = (
            remainder,
            divmod(lastremainder, remainder),
        )
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def mul_inverse_egcd(x, n, s=1, t=0, N=0):
    return (
        n < 2 and t % N or mul_inverse_egcd(n, x % n, t, s - x // n * t, N or n),
        -1,
    )[n < 1]


#
# GE - ed25519 group
#


def scalarmult_base(a):
    return EdPoint(ed25519_2.scalarmult_B(a.v))


def scalarmult_base_into(r, a):
    r = r if r else new_point()
    return r.init(ed25519_2.scalarmult_B(a.v))


def scalarmult(P, e):
    return P * e


def scalarmult_into(r, P, e):
    r = r if r else new_point()
    return r.init(P * e)


def point_add(A, B):
    return A + B


def point_add_into(r, A, B):
    r = r if r else new_point()
    return r.init(A + B)


def point_sub(A, B):
    return A - B


def point_sub_into(r, A, B):
    r = r if r else new_point()
    return r.init(A - B)


def point_double(P):
    return EdPoint(P + P)


def point_double_into(r, P):
    r = r if r else new_point()
    return r.init(P + P)


def point_norm(P):
    return P


def point_mul8(P):
    return P * EIGHT


INV_EIGHT = b"\x79\x2f\xdc\xe2\x29\xe5\x06\x61\xd0\xda\x1c\x7d\xb3\x9d\xd3\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06"
INV_EIGHT_SC = EdScalar(decodeint(INV_EIGHT))
ZERO = EdScalar(0)
ONE = EdScalar(1)
TWO = EdScalar(2)
EIGHT = EdScalar(8)


def point_mulinv8(P):
    return P * INV_EIGHT_SC


def point_mul8_into(r, P):
    r = r if r else new_point()
    return r.init(P * EIGHT)


def sc_inv_eight():
    return INV_EIGHT_SC


def ge_double_scalarmult_base_vartime(a, A, b):
    """
    void ge_double_scalarmult_base_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b)
    r = a * A + b * B

    :param a:
    :param A:
    :param b:
    :return:
    """
    return point_add(scalarmult(A, a), scalarmult_base(b))


def ge_double_scalarmult_base_vartime2(a, A, b, B):
    """
    void ge_double_scalarmult_base_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b)
    r = a * A + b * B

    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    return point_add(scalarmult(A, a), scalarmult(B, b))


def ge_double_scalarmult_precomp_vartime(a, A, b, Bi):
    """
    void ge_double_scalarmult_precomp_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b, const ge_dsmp Bi)
    :return:
    """
    return ge_double_scalarmult_precomp_vartime2(a, A, b, Bi)


def ge_double_scalarmult_precomp_vartime2(a, Ai, b, Bi):
    """
    void ge_double_scalarmult_precomp_vartime2(ge_p2 *r, const unsigned char *a, const ge_dsmp Ai, const unsigned char *b, const ge_dsmp Bi)
    :param a:
    :param Ai:
    :param b:
    :param Bi:
    :return:
    """
    return point_add(scalarmult(Ai, a), scalarmult(Bi, b))


def identity(byte_enc=False):
    """
    Identity point
    :return:
    """
    idd = EdPoint()
    return idd if not byte_enc else bytes(idd)


def identity_into(r):
    r = r if r else new_point()
    return r.init(ed25519_2.ident)


def ge_frombytes_vartime_check(point):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html
    http://elligator.cr.yp.to/
    http://elligator.cr.yp.to/elligator-20130828.pdf

    Basically it takes some bytes of data
    converts to a point on the edwards curve
    if the bytes aren't on the curve
    also does some checking on the numbers
    ex. your secret key has to be at least >= 4294967277
    also it rejects certain curve points, i.e. "if x = 0, sign must be positive"

    sqrt(s) = s^((q+3) / 8) if s^((q+3)/4) == s
            = sqrt(-1) s ^((q+3) / 8) otherwise

    :param key:
    :return:
    """
    x, y = point[:2]
    z = fe_1()
    u = fe_sq(y)
    v = fe_mul(u, d)
    u = fe_sub(u, z)  # u = y^2-1
    v = fe_add(v, z)  # v = dy^2+1

    # x = uv^3(uv^7)^((q-5)/8)

    vxx = fe_sq(x)
    vxx = fe_mul(vxx, v)
    check = fe_sub(vxx, u)  # vx^2-u
    if fe_isnonzero(check):
        check = fe_add(vxx, u)
        if fe_isnegative(check):
            # return -1
            raise ValueError("Point check failed")
    return 0


def ge_frombytes_vartime(point):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html

    :param key:
    :return:
    """
    ge_frombytes_vartime_check(point)
    return point


def precomp(point):
    """
    Precomputation placeholder
    :param point:
    :return:
    """
    return point


def ge_dsm_precomp(point):
    """
    void ge_dsm_precomp(ge_dsmp r, const ge_p3 *s)
    :param point:
    :return:
    """
    return point


#
# Monero specific
#


def cn_fast_hash(buff):
    """
    Keccak 256, original one (before changes made in SHA3 standard)
    :param buff:
    :return:
    """
    kc2 = keccak2.Keccak256()
    kc2.update(buff)
    return kc2.digest()


def hash_to_scalar(data, length=None):
    """
    H_s(P)
    :param data:
    :param length:
    :return:
    """
    hash = cn_fast_hash(data[:length] if length else data)
    return decodeint(hash)


def hash_to_scalar_into(r, data, length=None):
    r = r if r else new_scalar()
    return r.init(hash_to_scalar(data, length))


def hash_to_point(buf):
    """
    H_p(buf)

    Code adapted from MiniNero: https://github.com/monero-project/mininero
    https://github.com/monero-project/research-lab/blob/master/whitepaper/ge_fromfe_writeup/ge_fromfe.pdf
    http://archive.is/yfINb
    :param key:
    :return:
    """
    u = _decodeint(cn_fast_hash(buf)) % q
    A = 486662

    w = (2 * u * u + 1) % q
    xp = (w * w - 2 * A * A * u * u) % q

    # like sqrt (w / x) although may have to check signs..
    # so, note that if a squareroot exists, then clearly a square exists..
    rx = ed25519.expmod(w * ed25519.inv(xp), (q + 3) // 8, q)
    # rx is ok.

    x = rx * rx * (w * w - 2 * A * A * u * u) % q

    y = (2 * u * u + 1 - x) % q  # w - x, if y is zero, then x = w

    negative = False
    if y != 0:
        y = (w + x) % q  # checking if you got the negative square root.
        if y != 0:
            negative = True

        else:
            rx = rx * -1 * fe_fffb1 % q
            negative = False
    else:
        # y was 0..
        rx = (rx * -1 * fe_fffb2) % q

    if not negative:
        rx = (rx * u) % q
        z = (-2 * A * u * u) % q
        sign = 0

    else:
        z = -1 * A
        x = x * fe_sqrtm1 % q  # ..
        y = (w - x) % q
        if y != 0:
            rx = rx * fe_fffb3 % q
        else:
            rx = rx * -1 * fe_fffb4 % q
        sign = 1

    # setsign
    if (rx % 2) != sign:
        rx = -(rx) % q

    rz = (z + w) % q
    ry = (z - w) % q
    rx = rx * rz % q
    rt = 1

    # extended representation
    rt = ((rx * ry % q) * inv(rz)) % q

    P = EdPoint((rx, ry, rz, rt))
    P8 = scalarmult(P, EdScalar(8))
    return P8


def hash_to_point_into(r, buf):
    r = r if r else new_point()
    return r.init(hash_to_point(buf))


#
# XMR
#


XMR_H = b"\x8b\x65\x59\x70\x15\x37\x99\xaf\x2a\xea\xdc\x9f\xf1\xad\xd0\xea\x6c\x72\x51\xd5\x41\x54\xcf\xa9\x2c\x17\x3a\x0d\xd3\x9c\x1f\x94"
XMR_H_PT = EdPoint(XMR_H)


def compute_H():
    """
    Returns point H
    8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94
    :return:
    """
    h = cn_fast_hash(encodepoint(scalarmult_base(1)))
    return scalarmult(decodepoint(h), 8)


def xmr_H():
    return EdPoint(XMR_H_PT)


def scalarmult_h(i):
    return XMR_H_PT * EdScalar.ensure_scalar(i)


def add_keys2(a, b, B):
    """
    aG + bB, G is basepoint
    :param a:
    :param b:
    :param B:
    :return:
    """
    return point_add(scalarmult_base(a), scalarmult(B, b))


def add_keys2_into(r, a, b, B):
    r = r if r else new_point()
    return r.init(add_keys2(a, b, B))


def add_keys3(a, A, b, B):
    """
    aA + bB
    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    return point_add(scalarmult(A, a), scalarmult(B, b))


def add_keys3_into(r, a, A, b, B):
    r = r if r else new_point()
    return r.init(add_keys3(a, A, b, B))


def gen_c(a, amount):
    """
    Generates Pedersen commitment
    C = aG + bH

    :param a:
    :param amount:
    :return:
    """
    aG = scalarmult_base(a)
    return point_add(aG, scalarmult_h(amount))


def generate_key_derivation(key1, key2):
    """
    Key derivation: 8*(key2*key1)

    :param key1: public key of receiver Bob (see page 7)
    :param key2: Alice's private
    :return:
    """
    if sc_check(key2) != 0:
        # checks that the secret key is uniform enough...
        raise ValueError("error in sc_check in keyder")
    if ge_frombytes_vartime_check(key1) != 0:
        raise ValueError("didn't pass curve checks in keyder")

    check_ed25519point(key1)
    point2 = scalarmult(key1, key2)
    point3 = point_mul8(
        point2
    )  # This has to do with n==0 mod 8 by dedfinition, c.f. the top paragraph of page 5 of http://cr.yp.to/ecdh/curve25519-20060209.pdf
    # and also c.f. middle of page 8 in same document (Bernstein)
    return point3


def derivation_to_scalar(derivation, output_index):
    """
    H_s(derivation || varint(output_index))
    :param derivation:
    :param output_index:
    :return:
    """
    check_ed25519point(derivation)
    buf2 = encodepoint(derivation) + xmrserialize.dump_uvarint_b(output_index)
    return hash_to_scalar(buf2, len(buf2))


def derive_public_key(derivation, output_index, base):
    """
    H_s(derivation || varint(output_index))G + base

    :param derivation:
    :param output_index:
    :param base:
    :return:
    """
    if ge_frombytes_vartime_check(base) != 0:  # check some conditions on the point
        raise ValueError("derive pub key bad point")
    check_ed25519point(base)

    scalar = derivation_to_scalar(derivation, output_index)
    point2 = scalarmult_base(scalar)
    point4 = point_add(base, point2)
    return point4


def derive_secret_key(derivation, output_index, base):
    """
    base + H_s(derivation || varint(output_index))
    :param derivation:
    :param output_index:
    :param base:
    :return:
    """
    if sc_check(base) != 0:
        raise ValueError("cs_check in derive_secret_key")
    scalar = derivation_to_scalar(derivation, output_index)
    return sc_add(base, scalar)


def get_subaddress_secret_key(secret_key: Sc25519, major=0, minor=0) -> Sc25519:
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)

    :param secret_key:
    :param index:
    :param major:
    :param minor:
    :return:
    """
    prefix = b"SubAddr"
    buffer = bytearray(len(prefix) + 1 + 32 + 4 + 4)
    struct.pack_into(
        "<7sb32sLL", buffer, 0, prefix, 0, encodeint(secret_key), major, minor
    )
    return hash_to_scalar(buffer)


ge25519_double_scalarmult_base_vartime = ge_double_scalarmult_base_vartime

#
# Backend config
#


class PyECBackend(ECBackendBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def has_crypto_into_functions(self):
        return True

    def is_fast(self):
        return False


BACKEND_OBJ = None


def get_backend():
    global BACKEND_OBJ
    if BACKEND_OBJ is None:
        BACKEND_OBJ = PyECBackend()
    return BACKEND_OBJ
