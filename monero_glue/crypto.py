#!/usr/bin/env python
# -*- coding: utf-8 -*-
import math
import sys
import operator

from Crypto.Random import random as rand
from mnero import mnemonic  # making 25 word mnemonic to remember your keys
import binascii  # conversion between hex, int, and binary. Also for the crc32 thing
from mnero import ed25519  # Bernsteins python ed25519 code from cr.yp.to
from mnero import ed25519ietf
from mnero import ed25519_2

from mnero.ed25519 import b, q, l, d

from mnero import keccak2
from monero_serialize import xmrtypes, xmrserialize
from . import common as common


# Useful for very coarse version differentiation.
PY3 = sys.version_info[0] == 3

if PY3:
    indexbytes = operator.getitem
    intlist2bytes = bytes
    int2byte = operator.methodcaller('to_bytes', 1, 'big')

else:
    int2byte = chr
    range = xrange

    def indexbytes(buf, i):
        return ord(buf[i])

    def intlist2bytes(l):
        return b"".join(chr(c) for c in l)


# Extended curve coordinates
B_ext = (ed25519.Bx % q, ed25519.By % q, 1, (ed25519.Bx * ed25519.By) % q)
I_ext = (0, 1, 1, 0)

fe_m1 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec      # -1
fe_sqrtm1 = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0  # sqrt(-1)
fe_d2 = (2 * ed25519.d) % q

# fe_A = 2 * (1 - ed25519.d) * ed25519.inv(1 + ed25519.d)
fe_A = 486662
fe_ma = -486662
fe_ma2 = -1 * fe_A * fe_A

# k.<a> = FiniteField(2**255-19, 'a')
# A = fe_A * a
# Monero C-values: ed25519.radix255(fe_fffb1)
fe_fffb1 = 0x018e04102529e4e8df563ac8be04e61c2e6bfb5746d58c72dd58968acde3bdff   # sqrt(-2 * A * (A + 2))
fe_fffb2 = 0x32f9e1f5fba5d3096e2bae483fe9a041ae21fcb9fba908202d219b7c9f83650d   # sqrt( 2 * A * (A + 2))
fe_fffb3 = 0x18b5eef2eb3df710476ab9bfc0f25d12bfdb00b15a69bdd6a7e48278e8cfd387   # sqrt(-sqrt(-1*a) * A * (A + 2))
fe_fffb4 = 0x1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186   # sqrt( sqrt(-1*a) * A * (A + 2))

REPR_XY = 0
REPR_EXT = 1
POINT_REPR = REPR_EXT


def fe_mod(a):
    return a % q


def fe_add(a, b):
    return (a + b) % q


def fe_mul(a, b):
    return (a * b) % q


def fe_expmod(b, e):
    return ed25519.expmod(b, e, q)


def b16_to_scalar(bts):
    """
    Converts hexcoded bytearray to the scalar
    :param bts:
    :return:
    """
    return ed25519.decodeint(binascii.unhexlify(bts))


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


def pow2(x, p):
    """== pow(x, 2**p, q)"""
    while p > 0:
        x = x * x % q
        p -= 1
    return x


def expmod(b, e, m):
    """
    Modular exponentiation
    :param b:
    :param e:
    :param m:
    :return:
    """
    return ed25519.expmod(b, e, m)


def inv(z):
    """
    Modular inversion from edd25519ietf.py
    :param z:
    :return:
    """
    """$= z^{-1} \mod q$, for z != 0"""
    # Adapted from curve25519_athlon.c in djb's Curve25519.
    z2 = z * z % q                                # 2
    z9 = pow2(z2, 2) * z % q                      # 9
    z11 = z9 * z2 % q                             # 11
    z2_5_0 = (z11 * z11) % q * z9 % q             # 31 == 2^5 - 2^0
    z2_10_0 = pow2(z2_5_0, 5) * z2_5_0 % q        # 2^10 - 2^0
    z2_20_0 = pow2(z2_10_0, 10) * z2_10_0 % q     # ...
    z2_40_0 = pow2(z2_20_0, 20) * z2_20_0 % q
    z2_50_0 = pow2(z2_40_0, 10) * z2_10_0 % q
    z2_100_0 = pow2(z2_50_0, 50) * z2_50_0 % q
    z2_200_0 = pow2(z2_100_0, 100) * z2_100_0 % q
    z2_250_0 = pow2(z2_200_0, 50) * z2_50_0 % q   # 2^250 - 2^0
    return pow2(z2_250_0, 5) * z11 % q            # 2^255 - 2^5 + 11 = q - 2


def encodepoint_ext(P):
    """
    Encodes point in extended coordinates form (x,y,z,t) to the bit representation
    :param P:
    :return:
    """
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
            x*y % q == z*t % q and
            (y*y - x*x - z*z - ed25519.d*t*t) % q == 0)


def decodepoint_ext(s):
    """
    Decodes point representation to the extended coordinates (x,y,z,t) point representation
    :param s:
    :return:
    """
    x,y = ed25519.decodepoint(s)
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
    x,y = P
    return y-x, y+x, 2*ed25519.d*x*y


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
    return ed25519_2.edwards_add(A, invert_ext(B))


#
# Repr
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


def setup_repr(repr):
    """
    Configures point representation
    :param repr:
    :return:
    """
    global decodepoint, encodepoint, conv_to_xy, conv_to_ext, conv_from_xy, conv_from_ext, \
        isoncurve, check_point_fmt, scalarmult_base, scalarmult, \
        point_add, point_sub

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


setup_repr(POINT_REPR)

#
# Repr invariant
#


def public_key(sk):
    """
    Creates public key from the private key (integer scalar)
    Returns encoded point
    :param sk:
    :return:
    """
    return encodepoint(scalarmult_base(sk))


def cn_fast_hash(buff):
    """
    Keccak 256, original one (before changes made in SHA3 standard)
    :param buff:
    :return:
    """
    kc2 = keccak2.Keccak256()
    kc2.update(buff)
    return kc2.digest()


def random_scalar():
    """
    Generates random scalar (secret key)
    :return:
    """
    return 8 * (rand.getrandbits(64 * 8)) % l


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


def check_ed25519point(P):
    """
    Simple check if the point has exactly 2 coordinates
    :param P:
    :return:
    """
    check_point_fmt(P)
    if not isoncurve(P):
        raise ValueError('P is not on ed25519 curve')


def sc_check(key):
    """
    TODO: Implement secret key check
    :param key:
    :return:
    """
    return 0


def sc_reduce32(data):
    """
    Exactly the same as sc_reduce (which is default lib sodium)
    except it is assumed that your input s is alread in the form:
    s[0]+256*s[1]+...+256^31*s[31] = s

    And the rest is just reducing mod l,
    so basically take a 32 byte input, and reduce modulo the prime.
    :param data:
    :return:
    """
    return data % l


def sc_add(aa, bb):
    return (aa + bb) % l


def sc_sub(aa, bb):
    return (aa - bb) % l


def sc_isnonzero(c):
    return c % l != 0


def sc_mulsub(aa, bb, cc):
    return (cc - aa * bb) % l


def ge_scalarmult(a, A):
    """
    a*A
    http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
    :param a: scalar
    :param A: point
    :return:
    """
    # "Alice's secret key a is a uniform random 32-byte string then
    #clampC(a) is a uniform random Curve25519 secret key
    #i.e. n, where n/8 is a uniform random integer between
    #2^251 and 2^252-1
    #Alice's public key is n/Q compressed to the x-coordinate
    #so that means, ge_scalarmult is not actually doing scalar mult
    #clamping makes the secret be between 2^251 and 2^252
    #and should really be done
    check_ed25519point(A)
    return scalarmult(A, a)


def ge_mul8(P):
    """
    3 times doubling the point
    :param P:
    :return:
    """
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
    return scalarmult_base(8*a)


def ge_frombytes_vartime(key):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html

    Basically it takes some bytes of data
    converts to a point on the edwards curve
    if the bytes aren't on the curve
    also does some checking on the numbers
    ex. your secret key has to be at least >= 4294967277
    also it rejects certain curve points, i.e. "if x = 0, sign must be positive"

    :param key:
    :return:
    """
    return 0


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
    if ge_frombytes_vartime(key1) != 0:
        raise ValueError("didn't pass curve checks in keyder")

    point = key1
    point2 = ge_scalarmult(key2, point)
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
    if ge_frombytes_vartime(base) != 0:  # check some conditions on the point
        raise ValueError("derive pub key bad point")
    check_ed25519point(base)

    point1 = base
    scalar = derivation_to_scalar(derivation, output_index)
    point2 = scalarmult_base(scalar)
    point3 = point2  # I think the cached is just for the sake of adding
    # because the CN code adds using the monty curve
    point4 = point_add(point1, point3)
    return point4


def derive_secret_key(derivation, output_index, base):
    """
    base + H_s(derivation || varint(output_index))
    :param derivation:
    :param output_index:
    :param base:
    :return:
    """
    if sc_check(base) !=0:
        raise ValueError("cs_check in derive_secret_key")
    scalar = derivation_to_scalar(derivation, output_index)
    return base + scalar


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
    sqrtm1 = ed25519.sqroot(-1)

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
        x = x * sqrtm1 % q  # ..
        y = (w - x) % q
        if (y != 0):
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
        rt = (rx * ry % q) * inv(rz)

    P = conv_from_ext([rx, ry, rz, rt])
    P8 = ge_scalarmult(8, P)
    return P8


def generate_key_image(public_key, secret_key):
    """
    Key image: H_p(pub_key) * secret_key
    :param public_key:
    :param secret_key:
    :return:
    """
    if sc_check(secret_key) != 0:
        raise ValueError("sc check error in key image")
    point = hash_to_ec(public_key)
    point2 = ge_scalarmult(secret_key, point)
    return point2


def derive_subaddress_public_key(out_key, derivation, output_index):
    """
    out_key - H_s(derivation || varint(output_index))G
    :param out_key:
    :param derivation:
    :param output_index:
    :return:
    """
    check_ed25519point(out_key)
    scalar = derivation_to_scalar(derivation, output_index)
    point2 = scalarmult_base(scalar)
    point4 = point_sub(out_key, point2)
    return point4




