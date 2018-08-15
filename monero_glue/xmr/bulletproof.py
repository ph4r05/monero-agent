#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018

import logging

from monero_serialize.core.int_serialize import dump_uvarint_b

from monero_glue.xmr import common, crypto, mlsag2, monero
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)
ATOMS = 64


# curve size
l = 2**252 + 3*610042537739*15158679415041928064055629


# Constants

ZERO = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
ONE = b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


#
# Rct keys operation
#


buff_tmp1 = bytearray(32)
buff_tmp2 = bytearray(32)
buff_tmp3 = bytearray(32)
buff_tmp4 = bytearray(32)

tmp_pt_1 = crypto.new_point()
tmp_pt_2 = crypto.new_point()
tmp_pt_3 = crypto.new_point()
tmp_pt_4 = crypto.new_point()

tmp_sc_1 = crypto.new_scalar()
tmp_sc_2 = crypto.new_scalar()
tmp_sc_3 = crypto.new_scalar()
tmp_sc_4 = crypto.new_scalar()


# TODO: sc_* functions in crypto with dst provided, sc_add_into(dst, a, b), etc.
# TODO: crypto should provide constructors for points and scalars (for temporary buffers, avoids fragmentation), will be passed to sc_add_into()


def _ensure_dst_key(dst=None):
    if dst is None:
        dst = bytearray(32)
    return dst


def copy_key(dst, src):
    for i in range(32):
        dst[i] = src[i]


def invert(dst, x):
    """
    Modular inversion mod l
    Naive approach
    :param x: 32byte contracted
    :param dst:
    :return:
    """
    dst = _ensure_dst_key(dst)
    xlimbs = [int(x[i]) for i in range(9)]
    xint = crypto.decode_modm(xlimbs)  # x is tt.MODM() = ctypes.c_uint32 * 9
    xinv = pow(xint, l - 2, l)
    xinvlimbs = crypto.encode_modm(xinv)
    for i in range(9):
        tmp_sc_1[i] = xinvlimbs[i]
    crypto.encodeint_into(tmp_sc_1, dst)
    return dst


def scalarmult_key(dst, P, s):
    dst = _ensure_dst_key(dst)
    Pd = crypto.decodepoint(P)
    sd = crypto.decodeint(s)
    res = crypto.scalarmult(Pd, sd)
    crypto.encodepoint_into(res, dst)
    return dst


def scalarmult_base(dst, x):
    dst = _ensure_dst_key(dst)
    xd = crypto.decodeint(x)
    res = crypto.scalarmult_base(xd)
    crypto.encodepoint_into(res, dst)
    return dst


def sc_add(dst, a, b):
    dst = _ensure_dst_key(dst)
    r = crypto.sc_add(crypto.decodeint(a), crypto.decodeint(b))
    crypto.encodeint_into(r, dst)
    return dst


def sc_sub(dst, a, b):
    dst = _ensure_dst_key(dst)
    r = crypto.sc_sub(crypto.decodeint(a), crypto.decodeint(b))
    crypto.encodeint_into(r, dst)
    return dst


def sc_mul(dst, a, b):
    pass  # TODO:


def sc_muladd(dst, a, b, c):
    pass  # TODO:


def sc_mulsub(dst, a, b, c):
    pass  # TODO:


def add_keys(dst, A, B):
    pass  # TODO:


def add_keys2(dst, a, b, B):
    pass  # TODO:


def add_keys3(dst, a, A, b, B):
    pass  # TODO:


def hash_to_scalar(dst, data):
    pass  # TODO:


def sk_gen(dst=None):
    pass  # TODO:


#
#
#


class KeyV(object):
    """
    KeyVector abstraction
    Constant precomputed buffers = bytes, frozen. Same operation as normal.
    """
    def __init__(self, elems=64, src=None, buffer=None):
        self.current_idx = 0
        self.d = None
        self.size = elems
        if src:
            self.d = bytearray(src.d)
            self.size = src.size
        elif buffer:
            self.d = buffer  # can be immutable (bytes)
            self.size = len(buffer) // 32
        else:
            self.d = bytearray(32 * elems)

    def __getitem__(self, item):
        """
        Returns corresponding 32 byte array
        :param item:
        :return:
        """
        return memoryview(self.d)[item * 32 : (item + 1) * 32]

    def __setitem__(self, key, value):
        """
        Sets given key to the particular place
        :param key:
        :param value:
        :return:
        """
        ck = self[key]
        for i in range(32):
            ck[i] = value[i]

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx > self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def slice(self, res, start, stop):
        for i in range(start, stop):
            res[i - start] = self[i]

    def slice_r(self, start, stop):
        res = KeyV(stop - start)
        return self.slice(res, start, stop)

    def copy(self, dst=None):
        if dst:
            dst.size = self.size
            dst.d = bytearray(self.d)
        else:
            dst = KeyV(src=self)
        return dst

    def resize(self, nsize):
        if self.size == nsize:
            return self
        elif self.size > nsize:
            self.d = self.d[ : nsize * 32]
        else:
            self.d = bytearray(nsize * 32)
        self.size = nsize


class KeyVEval(KeyV):
    """
    KeyVector computed / evaluated on demand
    """
    def __init__(self, elems=64, src=None):
        self.size = elems
        self.fnc = src

    def __getitem__(self, item):
        return memoryview(self.fnc(item))

    def __setitem__(self, key, value):
        raise ValueError('Constant vector')

    def slice(self, res, start, stop):
        raise ValueError('Not supported')

    def slice_r(self, start, stop):
        raise ValueError('Not supported')

    def copy(self, dst=None):
        raise ValueError('Not supported')

    def resize(self, nsize):
        raise ValueError('Not supported')


def _ensure_dst_keyvect(dst=None, size=None):
    if dst is None:
        dst = KeyV()
    if size is not None:
        dst.resize(size)
    return dst


def skv_gen(dst, n):
    pass  # TODO:


def vector_exponent(a, b, dst=None):
    dst = _ensure_dst_key(dst)
    for i in range(a.size):
        pass  # TODO:


def vector_exponent_custom(A, B, a, b, dst=None):
    dst = _ensure_dst_key(dst)
    pass  # TODO:


def vector_powers(x, n, dst=None):
    dst = _ensure_dst_keyvect(dst, n)
    pass  # TODO:


def inner_product(a, b, dst=None):
    dst = _ensure_dst_key(dst)
    pass  # TODO:


def hadamard(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, a.size)
    pass  # TODO:


def hadamard2(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, a.size)
    pass  # TODO:


def vector_add(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, a.size)
    pass  # TODO:


def vector_subtract(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, a.size)
    pass  # TODO:


def vector_scalar(a, x, dst=None):
    dst = _ensure_dst_keyvect(dst, a.size)
    pass  # TODO:


def vector_scalar2(a, x, dst=None):
    dst = _ensure_dst_keyvect(dst, a.size)
    pass  # TODO:


def hash_cache_mash(hash_cache, mash0, mash1, mash2=None, mash3=None):
    pass  # TODO:


class BulletProofBuilder(object):
    def __init__(self, value, mask):
        self.value = value
        self.value_enc = crypto.encodeint(value)
        self.gamma = mask
        self.gamma_enc = crypto.encodeint(mask)
        self.proof_sec = crypto.random_bytes(128)

    def aL(self, i, dst=None):
        dst = _ensure_dst_key(dst)
        if self.value_enc[i//8] & (1 << i%8):
            copy_key(dst, ONE)
        else:
            copy_key(dst, ZERO)
        return dst

    def aR(self, i, dst=None):
        dst = _ensure_dst_key(dst)
        a_tmp = self.aL(i)
        sc_sub(dst, a_tmp, ONE)
        return dst

    def aL_vct(self):
        return KeyVEval(64, lambda x: self.aL(x))

    def aR_vct(self):
        return KeyVEval(64, lambda x: self.aR(x))

    def _det_mask(self, i, is_sL=True, dst=None):
        dst = _ensure_dst_key(dst)
        src = crypto.keccak_2hash(self.proof_sec + (b"sL" if is_sL else b"sR") + dump_uvarint_b(i))
        sc = crypto.new_scalar()
        crypto.decodeint_into(sc, src)
        crypto.encodeint_into(sc, dst)
        return dst

    def sL(self, i, dst=None):
        return self._det_mask(i, True, dst)

    def sR(self, i, dst=None):
        return self._det_mask(i, False, dst)

    def sL_vct(self):
        return KeyVEval(64, lambda x: self.sL(x))

    def sR_vct(self):
        return KeyVEval(64, lambda x: self.sR(x))

    def sX_gen(self):
        buff = bytearray(64 * 32)
        buff_mv = memoryview(buff)
        sc = crypto.new_scalar()
        for i in range(64):
            crypto.random_scalar_into(sc)
            crypto.encodeint_into(sc, buff_mv[i * 32 : (i + 1) * 32])
        return KeyV(buffer=buff)

