#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import binascii

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def bit(h, i):
    return ((h[i // 8]) >> (i % 8)) & 1


def hex_to_int(h):
    s = binascii.unhexlify(h)
    bb = len(h) * 4
    return sum(2 ** i * bit(s, i) for i in range(0, bb))


def rev_bytes(a):
    b = [a[i:i + 2] for i in range(0, len(a) - 1, 2)]
    return b''.join(b[::-1])


def b58encode(v):
    a = [rev_bytes(v[i:i + 16]) for i in range(0, len(v) - 16, 16)]
    rr = -2 * ((len(v) // 2) % 16)

    res = b''
    for b in a:
        bb = hex_to_int(b)
        result = b''
        while bb >= __b58base:
            div, mod = divmod(bb, __b58base)
            result = __b58chars[mod:mod + 1] + result
            bb = div
        result = __b58chars[bb:bb + 1] + result
        res += result
    result = b''
    if rr < 0:
        bf = hex_to_int(rev_bytes(v[rr:]))  # since we only reversed the ones in the array..
        result = b''
        while bf >= __b58base:
            div, mod = divmod(bf, __b58base)
            result = __b58chars[mod:mod + 1] + result
            bf = div
        result = __b58chars[bf:bf + 1] + result
    res += result
    return res
