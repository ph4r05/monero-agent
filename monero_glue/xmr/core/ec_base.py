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
from monero_glue.xmr.core.backend import ed25519, ed25519_2, keccak2
from monero_glue.xmr.core.backend.ed25519 import b, d, l, q
from monero_glue.xmr.core.pycompat import *

# py constants
py_b = b
py_q = q
py_l = l
py_d = d

# Extended curve coordinates
py_B_ext = B_ext = (ed25519.Bx % q, ed25519.By % q, 1, (ed25519.Bx * ed25519.By) % q)
py_I_ext = I_ext = (0, 1, 1, 0)

py_fe_m1 = (
    fe_m1
) = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec  # -1
py_fe_sqrtm1 = (
    fe_sqrtm1
) = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0  # sqrt(-1)
py_fe_d2 = fe_d2 = (2 * ed25519.d) % q

# fe_A = 2 * (1 - ed25519.d) * ed25519.inv(1 + ed25519.d)
py_fe_A = fe_A = 486662
py_fe_ma = fe_ma = -486662
py_fe_ma2 = fe_ma2 = -1 * fe_A * fe_A

# k.<a> = FiniteField(2**255-19, 'a')
# A = fe_A * a
# Monero C-values: ed25519.radix255(fe_fffb1)
py_fe_fffb1 = (
    fe_fffb1
) = (
    0x018e04102529e4e8df563ac8be04e61c2e6bfb5746d58c72dd58968acde3bdff
)  # sqrt(-2 * A * (A + 2))
py_fe_fffb2 = (
    fe_fffb2
) = (
    0x32f9e1f5fba5d3096e2bae483fe9a041ae21fcb9fba908202d219b7c9f83650d
)  # sqrt( 2 * A * (A + 2))
py_fe_fffb3 = (
    fe_fffb3
) = (
    0x18b5eef2eb3df710476ab9bfc0f25d12bfdb00b15a69bdd6a7e48278e8cfd387
)  # sqrt(-sqrt(-1*a) * A * (A + 2))
py_fe_fffb4 = (
    fe_fffb4
) = (
    0x1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186
)  # sqrt( sqrt(-1*a) * A * (A + 2))

NULL_KEY_ENC = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def pow2(x, p):
    """== pow(x, 2**p, q)"""
    while p > 0:
        x = x * x % q
        p -= 1
    return x


#
# Bignum encodings
#


def encode_edd25519_xmr_const(arr):
    """
    Converts Monero based ed25519 constants to int32_t constants

    :param arr:
    :return:
    """
    bits = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25]
    limbs = []
    c = 0  # carry bit
    for i, x in enumerate(arr):
        r = x + c
        if x < 0:
            r = r + (1 << bits[i])
            c = x >> bits[i]
        else:
            c = 0
        limbs.append(r)
    return limbs


def encode_ed25519(n):
    """
    Encodes Zmod(2^255-19) integer to hexcoded limbs with 25.5 radix

    :param n:
    :return:
    """
    n = n % q
    limbs = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    bits = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25]
    for i in range(10):
        limbs[i] = n & ((1 << bits[i]) - 1)
        n >>= bits[i]
    return limbs


def decode_ed25519(limbs):
    """
    Decodes hexcoded limbs with 25.5 radix to Zmod(2^255-19) integer

    :param n:
    :return:
    """
    n = 0
    c = 0
    shift = 0
    bits = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25]
    for i in range(10):
        n += ((limbs[i] & ((1 << bits[i]) - 1)) + c) << shift
        c = limbs[i] >> bits[i]
        shift += bits[i]
    return n


def encode_ed25519_sign(x):
    """
    Encodes Zmod(2^255-19) integer to decimal-coded, signed limbs with 25.5 radix

    :param x:
    :return:
    """
    x = x % q
    if x + x > q:
        x -= q
    x = [x, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    bits = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25]
    for i in range(9):
        carry = (x[i] + (1 << (bits[i] - 1))) // (1 << bits[i])
        x[i] -= carry * (1 << bits[i])
        x[i + 1] += carry
    return x


def encode_modm(n):
    """
    Encodes scalar mod m to limbs with base 30
    :param x:
    :return:
    """
    n = n % l
    mask = (1 << 30) - 1
    limbs = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(9):
        limbs[i] = n & mask
        n >>= 30
    return limbs


def decode_modm(limbs):
    """
    Decodes scalar mod m from limbs with base 30
    :param n:
    :return:
    """
    n = 0
    c = 0
    shift = 0
    mask = (1 << 30) - 1

    for i in range(9):
        n += ((limbs[i] & mask) + c) << shift
        c = limbs[i] >> 30
        shift += 30
    return n


#
# Backend config
#


class ECBackendBase(object):
    """
    Base EC backend specs
    """

    def __init__(self, *args, **kwargs):
        pass

    def has_rangeproof_borromean(self):
        return False

    def has_rangeproof_bulletproof(self):
        return False

    def has_crypto_into_functions(self):
        return False
