#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from Crypto.Random import get_random_bytes
from Crypto.Random import random as rand

import hmac
import functools


class XmrException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


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


def random_bytes(by):
    """
    Generates X random bytes, returns byte-string
    :param by:
    :return:
    """
    return get_random_bytes(by)


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


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defval_empty(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if not is_empty(val) else default


def defvalkey(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if js is None:
        return default
    if key not in js:
        return default
    if js[key] is None and not take_none:
        return default
    return js[key]


def defvalkeys(js, key, default=None):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    Key is array of keys. js[k1][k2][k3]...

    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if js is None:
        return default
    if not isinstance(key, (tuple, list)):
        key = key.split('.')
    try:
        cur = js
        for ckey in key:
            cur = cur[ckey]
        return cur
    except:
        pass
    return default

