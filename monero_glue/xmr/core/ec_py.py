#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import hmac
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Random import random as rand

from monero_glue.xmr.core.ec_base import *
from monero_glue.xmr.core.backend.ed25519_2 import inv
from monero_glue.xmr.core.backend.ed25519 import expmod
from monero_serialize import xmrserialize


REPR_XY = 0
REPR_EXT = 1
POINT_REPR = REPR_EXT


def random_bytes(by):
    """
    Generates X random bytes, returns byte-string
    :param by:
    :return:
    """
    return get_random_bytes(by)


def get_keccak():
    """
    Simple keccak 256
    :return:
    """
    return keccak2.Keccak256()


def keccak_hash(inp):
    """
    Hashesh input in one call
    :return:
    """
    ctx = get_keccak()
    ctx.update(inp)
    return ctx.digest()


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
    PBKDF2 with default PRF as HMAC-KECCAK-256
    :param inp:
    :param salt:
    :param length:
    :param count:
    :param prf:
    :return:
    """

    if prf is None:
        prf = lambda p, s: hmac.new(p, msg=s, digestmod=get_keccak).digest()
    return PBKDF2(inp, salt, length, count, prf)


#
# Basic point enc/dec
#


def decodeint(x):
    """
    bytearray to integer scalar
    :param x:
    :return:
    """
    return ed25519.decodeint(x)


def encodeint(x):
    """
    Encodeint
    :param x:
    :return:
    """
    return ed25519.encodeint(x)


def check_ed25519point(P):
    """
    Simple check if the point has exactly 2 coordinates
    :param P:
    :return:
    """
    check_point_fmt(P)
    if not isoncurve(P):
        raise ValueError('P is not on ed25519 curve')


def decodepoint_xy(P):
    """
    Decodes point bit representation to the point representation
    :param P:
    :return:
    """
    return ed25519.decodepointcheck(P)


def encodepoint_xy(P):
    """
    Encodes point to the bit representation
    :param P:
    :return:
    """
    return ed25519.encodepoint(P)


def encodepoint_ext(P):
    """
    Encodes point in extended coordinates form (x,y,z,t) to the bit representation
    :param P:
    :return:
    """
    check_ed25519point(P)
    (x, y, z, t) = P
    zi = inv(z)
    x = (x * zi) % q
    y = (y * zi) % q
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]

    # noinspection PyTypeChecker
    return b''.join([
        int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
        for i in range(b // 8)
    ])


def isoncurve_ext(P):
    """
    Tests if P is on Ed25519
    :param P:
    :return:
    """
    (x, y, z, t) = P
    return (z % q != 0 and
            x * y % q == z * t % q and
            (y * y - x * x - z * z - ed25519.d * t * t) % q == 0)


def decodepoint_ext(s):
    """
    Decodes point representation to the extended coordinates (x,y,z,t) point representation
    :param s:
    :return:
    """
    x,y = ed25519.decodepointcheck(s)
    P = (x, y, 1, (x*y) % q)
    if not isoncurve_ext(P):
        raise ValueError("decoding point that is not on curve")
    return P


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
    return x0*t0 % q, y0*z0 % q, z0*t0 % q, x0*y0 % q


def invert_ext(P):
    """
    Inverts extended point coordinate
    :param P:
    :return:
    """
    check_ed25519point(P)
    return -1*P[0] % q, P[1], P[2], -1*P[3] % q


def check_ext(P):
    """
    Check format of the Ext point
    :param P:
    :return:
    """
    if not isinstance(P, (list, tuple)) or len(P) != 4:
        raise ValueError('P is not a ed25519 ext point')


def check_xy(P):
    """
    Check format of the xy point
    :param P:
    :return:
    """
    if not isinstance(P, (list, tuple)) or len(P) != 2:
        raise ValueError('P is not a ed25519 ext point')


def point_sub_ext(A, B):
    """
    Subtracts,  A - B points in ext coords
    :param A:
    :param B:
    :return:
    """
    check_ed25519point(A)
    return ed25519_2.edwards_add(A, invert_ext(B))


def point_eq_ext(P, Q):
    """
    Point equivalence, extended coordinates
    x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    :param P:
    :param Q:
    :return:
    """
    check_ed25519point(P)
    check_ed25519point(Q)
    if (P[0] * Q[2] - Q[0] * P[2]) % q != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % q != 0:
        return False
    return True


def point_eq_xy(P, Q):
    """
    Point equivalence
    :param P:
    :param Q:
    :return:
    """
    check_ed25519point(P)
    check_ed25519point(Q)
    return P == Q


#
# Point representation
#

idd = lambda x: x
decodepoint = idd
encodepoint = idd

conv_to_xy = idd
conv_to_ext = idd
conv_from_xy = idd
conv_from_ext = idd

isoncurve = idd
check_point_fmt = idd

scalarmult_base = idd
scalarmult = lambda x, y: y
point_add = lambda x, y: y
point_sub = lambda x, y: y
point_eq = lambda x, y: y


def setup_repr(repr):
    """
    Configures point representation
    :param repr:
    :return:
    """
    global decodepoint, encodepoint, conv_to_xy, conv_to_ext, conv_from_xy, conv_from_ext, \
        isoncurve, check_point_fmt, scalarmult_base, scalarmult, \
        point_add, point_sub, point_eq

    decodepoint = decodepoint_xy if repr == REPR_XY else decodepoint_ext
    encodepoint = encodepoint_xy if repr == REPR_XY else encodepoint_ext

    conv_to_xy = idd if repr == REPR_XY else conv_ext_to_xy
    conv_to_ext = conv_xy_to_ext if repr == REPR_XY else idd

    conv_from_xy = idd if repr == REPR_XY else conv_xy_to_ext
    conv_from_ext = conv_ext_to_xy if repr == REPR_XY else idd

    isoncurve = ed25519.isoncurve if repr == REPR_XY else isoncurve_ext
    check_point_fmt = check_xy if repr == REPR_XY else check_ext

    scalarmult_base = ed25519.scalarmultbase if repr == REPR_XY else ed25519_2.scalarmult_B
    scalarmult = ed25519.scalarmult if repr == REPR_XY else ed25519_2.scalarmult
    point_add = ed25519.edwards if repr == REPR_XY else ed25519_2.edwards_add
    point_sub = ed25519.edwards_Minus if repr == REPR_XY else point_sub_ext
    point_eq = point_eq_xy if repr == REPR_XY else point_eq_ext


setup_repr(POINT_REPR)

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
    uv3 = ((u*v)^3) % q
    uv7 = ((u*v)^7) % q

    return uv3 * fe_expmod(uv7, ((q - 5) / 8))


def fe_isnegative(x):
    return x < 0


def fe_isnonzero(x):
    return x != 0


#
# Zmod(order), scalar values field
#

def sc_0():
    """
    Sets 0 to the scalar value Zmod(m)
    :return:
    """
    return 0


def sc_init(x):
    """
    Sets x to the scalar value Zmod(m)
    :return:
    """
    return sc_reduce32(x)


def sc_get64(x):
    """
    Returns 64bit value from the sc
    :param x:
    :return:
    """
    return x


def sc_check(key):
    """
    sc_check is not relevant for long-integer scalar representation.

    :param key:
    :return:
    """
    if key % l == 0:
        return -1
    return 0 if key == sc_reduce32(key) else -1


def check_sc(key):
    """
    throws exception on invalid key
    :param key:
    :return:
    """
    if sc_check(key) != 0:
        raise ValueError('Invalid scalar value')


def sc_reduce32(data):
    """
    Exactly the same as sc_reduce (which is default lib sodium)
    except it is assumed that your input s is alread in the form:
    s[0]+256*s[1]+...+256^31*s[31] = s

    And the rest is reducing mod l,
    so basically take a 32 byte input, and reduce modulo the prime.
    :param data:
    :return:
    """
    return data % l


def sc_add(aa, bb):
    """
    Scalar addition
    :param aa:
    :param bb:
    :return:
    """
    return (aa + bb) % l


def sc_sub(aa, bb):
    """
    Scalar subtraction
    :param aa:
    :param bb:
    :return:
    """
    return (aa - bb) % l


def sc_isnonzero(c):
    """
    Returns true if scalar is non-zero
    :param c:
    :return:
    """
    return c % l != 0


def sc_eq(a, b):
    """
    Returns true if scalars are equal
    :param a:
    :param b:
    :return:
    """
    return (a - b) % l == 0


def sc_mulsub(aa, bb, cc):
    """
    (cc - aa * bb) % l
    :param aa:
    :param bb:
    :param cc:
    :return:
    """
    return (cc - aa * bb) % l


def sc_muladd(aa, bb, cc):
    """
    (cc + aa * bb) % l
    :param aa:
    :param bb:
    :param cc:
    :return:
    """
    return (cc + aa * bb) % l


def random_scalar():
    """
    Generates random scalar (secret key)
    :return:
    """
    return sc_reduce32(rand.getrandbits(64 * 8))


#
# GE - ed25519 group
#


def point_double(P):
    return scalarmult(P, 2)


def point_norm(P):
    """
    Normalizes point after multiplication
    Extended edwards coordinates (X,Y,Z,T)
    :param P:
    :return:
    """
    return P


def ge_scalarmult(a, A):
    """
    a*A
    http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
    :param a: scalar
    :param A: point
    :return:
    """
    # Alice's secret key a is a uniform random 32-byte string then
    # clampC(a) is a uniform random Curve25519 secret key
    # i.e. n, where n/8 is a uniform random integer between
    # 2^251 and 2^252-1
    # Alice's public key is n/Q compressed to the x-coordinate
    # so that means, ge_scalarmult is not actually doing scalar mult
    # clamping makes the secret be between 2^251 and 2^252 and should really be done
    check_ed25519point(A)
    return scalarmult(A, a)


def ge_mul8(P):
    """
    3 times doubling the point
    :param P:
    :return:
    """
    check_ed25519point(P)
    return ge_scalarmult(8, P)


def ge_scalarmult_base(a):
    """
    In this function in the original code, they've assumed it's already clamped ...
    c.f. also https://godoc.org/github.com/agl/ed25519/edwards25519
    It will return h = a*B, where B is ed25519 bp (x,4/5)
    And a = a[0] + 256a[1] + ... + 256^31 a[31]
    it assumes that a[31 <= 127 already
    :param a:
    :return:
    """
    a = sc_reduce32(a)
    return scalarmult_base(a)


def ge_double_scalarmult_base_vartime(a, A, b):
    """
    void ge_double_scalarmult_base_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b)
    r = a * A + b * B
        where a = a[0]+256*a[1]+...+256^31 a[31].
        and b = b[0]+256*b[1]+...+256^31 b[31].
        B is the Ed25519 base point (x,4/5) with x positive.

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
    idd = scalarmult_base(0)
    return idd if not byte_enc else encodepoint(idd)


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
            raise ValueError('Point check failed')
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
    res = decodeint(hash)
    return sc_reduce32(res)


def hash_to_ec(buf):
    """
    H_p(buf)

    Code adapted from MiniNero: https://github.com/monero-project/mininero
    https://github.com/monero-project/research-lab/blob/master/whitepaper/ge_fromfe_writeup/ge_fromfe.pdf
    http://archive.is/yfINb
    :param key:
    :return:
    """
    u = decodeint(cn_fast_hash(buf)) % q
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
        rx = - (rx) % q

    rz = (z + w) % q
    ry = (z - w) % q
    rx = rx * rz % q
    rt = 1

    if POINT_REPR == REPR_EXT:
        rt = ((rx * ry % q) * inv(rz)) % q

    P = conv_from_ext((rx, ry, rz, rt))
    P8 = scalarmult(P, 8)
    return P8


#
# XMR
#


def gen_H():
    """
    Returns point H
    8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94
    :return:
    """
    h = cn_fast_hash(encodepoint(scalarmult_base(1)))
    return scalarmult(decodepoint(h), 8)


def scalarmult_h(i):
    return scalarmult(gen_H(), i)


def add_keys2(a, b, B):
    """
    aG + bB, G is basepoint
    :param a:
    :param b:
    :param B:
    :return:
    """
    return point_add(scalarmult_base(a), scalarmult(B, b))


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
    point2 = ge_scalarmult(key2, key1)
    point3 = ge_mul8(point2)  # This has to do with n==0 mod 8 by dedfinition, c.f. the top paragraph of page 5 of http://cr.yp.to/ecdh/curve25519-20060209.pdf
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


#
# Backend config
#


class PyECBackend(ECBackendBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


BACKEND_OBJ = None


def get_backend():
    global BACKEND_OBJ
    if BACKEND_OBJ is None:
        BACKEND_OBJ = PyECBackend()
    return BACKEND_OBJ


