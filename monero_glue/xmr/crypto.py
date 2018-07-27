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

import binascii
import operator
import sys

from Crypto.Random import random as rand
from monero_glue.misc import b58_mnr
from monero_glue.xmr import common
from monero_glue.xmr.core.backend import ed25519, ed25519_2, keccak2
from monero_glue.xmr.core.backend.ed25519 import b, d, l, q
from monero_glue.xmr.core.ec import *
from monero_glue.xmr.core.ec_conv import *
from monero_glue.xmr.core.pycompat import *
from monero_serialize import xmrserialize


def b16_to_scalar(bts):
    """
    Converts hexcoded bytearray to the scalar
    :param bts:
    :return:
    """
    return decodeint(binascii.unhexlify(bts))


def public_key(sk):
    """
    Creates public key from the private key (integer scalar)
    Returns encoded point
    :param sk:
    :return:
    """
    return encodepoint(scalarmult_base(sk))


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
    return compute_hmac(key, encodepoint(point))


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
    r = sc_mulsub(priv, c, k)
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
        raise ValueError("Signature error")

    tmp2 = point_add(scalarmult(pub, c), scalarmult_base(r))
    buff = data + encodepoint(pub) + encodepoint(tmp2)
    tmp_c = hash_to_scalar(buff)
    res = sc_sub(tmp_c, c)
    return not sc_isnonzero(res)


def xmr_base58_addr_encode_check(version, buff):
    buf = bytes([version]) + buff
    h = cn_fast_hash(buf)
    buf = binascii.hexlify(buf + h[0:4])
    return b58_mnr.b58encode(buf)


def xmr_base58_addr_decode_check(buff):
    d = b58_mnr.b58decode(data_bin=buff)

    addr_checksum = d[-4:]
    calc_checksum = cn_fast_hash(d[:-4])[:4]
    if addr_checksum == calc_checksum:
        version = ord(d[:1])
        return d[1:], version

    else:
        raise ValueError("Invalid address checksum")
