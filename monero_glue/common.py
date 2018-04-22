#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from monero_serialize import xmrtypes, xmrserialize, protobuf as xproto
from mnero import keccak2
import hmac
import functools


def hash_bytearray(ba):
    """
    Hashing bytearray
    :param ba:
    :return:
    """
    return functools.reduce(lambda a,d: (a*256 + d) & 0xffffffffffffffff, ba, 0)


class HashWrapper(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def update(self, buf):
        if len(buf) == 0:
            return
        if isinstance(buf, bytearray):
            self.ctx.update(bytes(buf))  # TODO: optimize
        else:
            self.ctx.update(buf)

    def digest(self):
        return self.ctx.digest()

    def hexdigest(self):
        return self.ctx.hexdigest()


class KeccakArchive(object):
    def __init__(self):
        self.kwriter = get_keccak_writer()
        self.ar = xmrserialize.Archive(self.kwriter, True)


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


def get_keccak_writer(sub_writer=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :return:
    """
    return xproto.AHashWriter(HashWrapper(get_keccak()), sub_writer=sub_writer)


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


def ct_equal(a, b):
    """
    Constant time a,b comparisson
    :param a:
    :param b:
    :return:
    """
    return hmac.compare_digest(a, b)


def check_permutation(permutation):
    """
    Check permutation sanity
    :param permutation:
    :return:
    """
    for n in range(len(permutation)):
        if n not in permutation:
            raise ValueError('Invalid permutation')


def apply_permutation(permutation, swapper):
    """
    Apply permutation from idx. Used for in-place permutation application with swapper.
    Ported from Monero.
    :param permutation:
    :param swapper: function(x,y)
    :return:
    """
    check_permutation(permutation)
    perm = list(permutation)
    for i in range(len(perm)):
        current = i
        while i != perm[current]:
            nxt = perm[current]
            swapper(current, nxt)
            perm[current] = current
            current = nxt
        perm[current] = current


def is_empty(inp):
    """
    True if none or empty
    :param inp:
    :return:
    """
    return inp is None or len(inp) == 0

