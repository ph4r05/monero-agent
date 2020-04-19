#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import logging

from . import ec_picker

logger = logging.getLogger(__name__)
backend = ec_picker.get_ec_backend()


if backend == ec_picker.EC_BACKEND_PY:
    from monero_glue.xmr.core.ec_py import *

elif backend == ec_picker.EC_BACKEND_TREZOR:
    try:
        from monero_glue.xmr.core.ec_trezor import *

    except Exception as e:
        logger.warning("Trezor-crypto backend not usable: %s" % e)
        if ec_picker.get_ec_backend_force():
            raise

        from monero_glue.xmr.core.ec_py import *

else:
    raise ValueError("Unknown EC backend: %s" % backend)


from monero_glue.compat.utils import memcpy


class PRNG:
    BLOCK_SIZE = 32

    def __init__(self, seed=b""):
        self.seed = bytes(seed)
        self.state = bytes(self.seed)
        self.ctr = 0
        self.h = get_keccak(self.state)
        self.leftover = bytearray(0)
        self.leftover_bytes = 0

    def reset(self, seed=None):
        if seed is not None:
            self.seed = seed
        self.state = bytes(self.seed)
        self.ctr = 0
        self.h = get_keccak(self.state)
        self.leftover = bytearray(0)
        self.leftover_bytes = 0

    def _gen(self):
        self.ctr += 1
        self.h.reset()
        self.h.update(self.state + self.ctr.to_bytes(32, 'big'))
        return self.h.digest()

    def rewind(self, n):
        self.next(n)

    def next(self, num, buff=None):
        buff = buff if buff is not None else bytearray(num)
        off = 0
        while (num - off) > 0:
            left = num - off
            cur = self._gen()
            tocopy = min(len(cur), left)
            memcpy(buff, off, cur, 0, tocopy)
            off += tocopy
        return buff


def prng(seed=b""):
    return PRNG(seed)
