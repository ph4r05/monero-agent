#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Resources:
# https://cr.yp.to
# https://github.com/monero-project/mininero
# https://godoc.org/github.com/agl/ed25519/edwards25519
# https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-00#section-4
# https://github.com/monero-project/research-lab

import sys
import operator

from Crypto.Random import random as rand
import binascii

from monero_glue.xmr.core.backend import ed25519_2, trezor_types as tty
from monero_glue.xmr.core.backend.ed25519 import b, q, l, d
from monero_glue.xmr.core.backend import keccak2, ed25519
from monero_glue.xmr.core.pycompat import *

from monero_serialize import xmrserialize
from monero_glue.xmr import common as common

from monero_glue.xmr.core.ec import *
from monero_glue.xmr.core.ec_conv import *


#from monero_glue.xmr.core.backend import trezor_crypto as tcry
#print(tcry.init_lib())
#print(tcry.init_lib())


def b16_to_scalar(bts):
    """
    Converts hexcoded bytearray to the scalar
    :param bts:
    :return:
    """
    return decodeint(binascii.unhexlify(bts))


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


def gen_Hpow(size):
    """
    Returns powers of point H
    :return:
    """
    HPow2 = gen_H()
    H2 = [None] * size
    for i in range(0, size):
        H2[i] = HPow2
        HPow2 = point_double(HPow2)
    return H2


def hmac_point(key, point):
    """
    HMAC single point
    :param key:
    :param point:
    :return:
    """
    return common.compute_hmac(key, encodepoint(point))


def generate_signature(data, priv):
    """
    Generate EC signature
    crypto_ops::generate_signature(const hash &prefix_hash, const public_key &pub, const secret_key &sec, signature &sig)

    :param data:
    :param priv:
    :return:
    """
    pub = scalarmult_base(priv)

    k = random_scalar()
    comm = scalarmult_base(k)

    buff = data + encodepoint(pub) + encodepoint(comm)
    c = hash_to_scalar(buff)
    r = sc_mulsub(k, priv, c)
    return c, r, pub


def check_signature(data, c, r, pub):
    """
    EC signature verification

    :param data:
    :param pub:
    :param c:
    :param r:
    :return:
    """
    check_ed25519point(pub)
    c = sc_reduce32(c)
    r = sc_reduce32(r)
    if sc_check(c) != 0 or sc_check(r) != 0:
        raise ValueError('Signature error')

    tmp2 = point_add(scalarmult(pub, c), scalarmult_base(r))
    buff = data + encodepoint(pub) + encodepoint(tmp2)
    tmp_c = hash_to_scalar(buff)
    res = sc_sub(tmp_c, c)
    return not sc_isnonzero(res)


