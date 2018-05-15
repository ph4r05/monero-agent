#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_serialize import xmrtypes
from monero_glue.xmr.core.ec_base import *
from monero_glue.xmr.core.backend import trezor_crypto as tcry
from monero_glue.xmr.core import ec_py


# Initialize randomn number generator / libsodium component in the library
tcry.init_lib()


def decodepoint(x):
    return tcry.ge25519_unpack_vartime_r(x)


def encodepoint(pt):
    return tcry.ge25519_pack_r(pt)


def decodeint(x):
    return tcry.expand256_modm_r(x)


def encodeint(x):
    return tcry.contract256_modm_r(x)


def check_ed25519point(x):
    if tcry.ge25519_check(x) != 1:
        raise ValueError('P is not on ed25519 curve')


def scalarmult_base(a):
    return tcry.ge25519_scalarmult_base_wrapper_r(a)


def scalarmult(P, e):
    return tcry.ge25519_scalarmult_wrapper_r(P, e)


def point_add(P, Q):
    return tcry.ge25519_add_r(P, Q, 0)


def point_sub(P, Q):
    return tcry.ge25519_add_r(P, Q, 1)


def point_eq(P, Q):
    return tcry.ge25519_eq(P, Q)


def point_double(P):
    return tcry.ge25519_double_r(P)


def point_norm(P):
    """
    Normalizes point after multiplication
    Extended edwards coordinates (X,Y,Z,T)
    :param P:
    :return:
    """
    return tcry.ge25519_norm_r(P)


#
# Zmod(2^255 - 19) operations, fe (field element)
# Not constant time! PoC only.
#


def fe_1():
    return tcry.curve25519_set_r(1)


def fe_mod(a):
    return tcry.curve25519_reduce_r(a)


def fe_add(a, b):
    return tcry.curve25519_add_r(a, b)


def fe_sub(a, b):
    return tcry.curve25519_sub_reduce_r(a, b)


def fe_sq(a):
    return tcry.curve25519_square_r(a)


def fe_mul(a, b):
    return tcry.curve25519_mul_r(a, b)


def fe_expmod(b, e):
    raise ValueError('Not implemented')


def fe_divpowm1(u, v):
    raise ValueError('Not implemented')


def fe_isnegative(x):
    return tcry.curve25519_isnegative(x)


def fe_isnonzero(x):
    return tcry.curve25519_isnonzero(x)


#
# Zmod(order), scalar values field
#

def sc_0():
    """
    Sets 0 to the scalar value Zmod(m)
    :return:
    """
    return tcry.init256_modm_r(0)


def sc_init(x):
    """
    Sets x to the scalar value Zmod(m)
    :return:
    """
    if x >= (1 << 64):
        raise ValueError('Initialization works up to 64-bit only')
    return tcry.init256_modm_r(x)


def sc_get64(x):
    """
    Returns 64bit value from the sc
    :param x:
    :return:
    """
    return tcry.get256_modm_r(x)


def sc_check(key):
    """
    sc_check is not relevant for long-integer scalar representation.

    :param key:
    :return:
    """
    return not tcry.check256_modm(key)


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
    return tcry.barrett_reduce256_modm_r(sc_0(), data)


def sc_add(aa, bb):
    """
    Scalar addition
    :param aa:
    :param bb:
    :return:
    """
    return tcry.add256_modm_r(aa, bb)


def sc_sub(aa, bb):
    """
    Scalar subtraction
    :param aa:
    :param bb:
    :return:
    """
    return tcry.sub256_modm_r(aa, bb)


def sc_isnonzero(c):
    """
    Returns true if scalar is non-zero
    :param c:
    :return:
    """
    return not tcry.iszero256_modm(c)


def sc_eq(a, b):
    """
    Returns true if scalars are equal
    :param a:
    :param b:
    :return:
    """
    return tcry.eq256_modm(a, b)


def sc_mulsub(aa, bb, cc):
    """
    (cc - aa * bb) % l
    :param aa:
    :param bb:
    :param cc:
    :return:
    """
    return tcry.mulsub256_modm_r(aa, bb, cc)


def sc_muladd(aa, bb, cc):
    """
    (cc + aa * bb) % l
    :param aa:
    :param bb:
    :param cc:
    :return:
    """
    return tcry.muladd256_modm_r(aa, bb, cc)


def random_scalar():
    return tcry.xmr_random_scalar_r()


#
# GE - ed25519 group
#


def ge_scalarmult(a, A):
    check_ed25519point(A)
    return scalarmult(A, a)


def ge_mul8(P):
    check_ed25519point(P)
    return tcry.ge25519_mul8_r(P)


def ge_scalarmult_base(a):
    a = sc_reduce32(a)
    return scalarmult_base(a)


def ge_double_scalarmult_base_vartime(a, A, b):
    """
    void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
    r = a * A + b * B
        where a = a[0]+256*a[1]+...+256^31 a[31].
        and b = b[0]+256*b[1]+...+256^31 b[31].
        B is the Ed25519 base point (x,4/5) with x positive.

    :param a:
    :param A:
    :param b:
    :return:
    """
    R = tcry.ge25519_double_scalarmult_vartime_r(A, a, b)
    tcry.ge25519_norm(R, R)
    return R


def ge_double_scalarmult_base_vartime2(a, A, b, B):
    """
    void ge25519_double_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const ge25519 *p2, const bignum256modm s2);
    r = a * A + b * B

    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    R = tcry.ge25519_double_scalarmult_vartime2_r(A, a, B, b)
    tcry.ge25519_norm(R, R)
    return R


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
    return tcry.xmr_add_keys3_r(a, Ai, b, Bi)


def identity(byte_enc=False):
    """
    Identity point
    :return:
    """
    idd = tcry.ge25519_set_neutral_r()
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
    # if tcry.ge25519_check(point) != 1:
    #     raise ValueError('Point check failed')
    #
    # return 0

    x, y = point.x, point.y
    d = tcry.curve25519_set_d_r()
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
    return tcry.xmr_hash_to_scalar_r(data[:length] if length else data)


def hash_to_ec(buf):
    """
    H_p(buf)

    Code adapted from MiniNero: https://github.com/monero-project/mininero
    https://github.com/monero-project/research-lab/blob/master/whitepaper/ge_fromfe_writeup/ge_fromfe.pdf
    http://archive.is/yfINb
    :param key:
    :return:
    """
    return tcry.xmr_hash_to_ec_r(buf)


#
# XMR
#


def gen_H():
    """
    Returns point H
    8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94
    :return:
    """
    return tcry.ge25519_set_xmr_h_r()


def scalarmult_h(i):
    return scalarmult(gen_H(), sc_init(i) if isinstance(i, int) else i)


def add_keys2(a, b, B):
    """
    aG + bB, G is basepoint
    :param a:
    :param b:
    :param B:
    :return:
    """
    return tcry.xmr_add_keys2_vartime_r(a, b, B)


def add_keys3(a, A, b, B):
    """
    aA + bB
    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    return tcry.xmr_add_keys3_vartime_r(a, A, b, B)


def gen_c(a, amount):
    """
    Generates Pedersen commitment
    C = aG + bH

    :param a:
    :param amount:
    :return:
    """
    return tcry.xmr_gen_c_r(a, amount)


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

    return tcry.xmr_generate_key_derivation_r(key1, key2)


def derivation_to_scalar(derivation, output_index):
    """
    H_s(derivation || varint(output_index))
    :param derivation:
    :param output_index:
    :return:
    """
    check_ed25519point(derivation)
    return tcry.xmr_derivation_to_scalar_r(derivation, output_index);


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

    return tcry.xmr_derive_public_key_r(derivation, output_index, base)
    

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
    return tcry.xmr_derive_private_key_r(derivation, output_index, base)


def prove_range(amount, last_mask=None):
    """
    Range proof provided by the backend. Implemented in C for speed.

    :param amount:
    :param last_mask:
    :return:
    """
    C, a, R = tcry.gen_range_proof(amount, last_mask)

    # Rewrap to serializable structures
    nrsig = xmrtypes.RangeSig()
    nrsig.Ci = R.Ci
    nrsig.asig = xmrtypes.BoroSig()
    nrsig.asig.s0 = R.asig.s0
    nrsig.asig.s1 = R.asig.s1
    nrsig.asig.ee = R.asig.ee
    return C, a, nrsig

#
# Backend config
#


class TcryECBackend(ECBackendBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def has_rangeproof_borromean(self):
        return True

    def has_rangeproof_bulletproof(self):
        return False


BACKEND_OBJ = None


def get_backend():
    global BACKEND_OBJ
    if BACKEND_OBJ is None:
        BACKEND_OBJ = TcryECBackend()
    return BACKEND_OBJ



