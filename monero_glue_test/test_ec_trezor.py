#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest
import binascii

import aiounittest

from monero_glue.xmr import crypto, common
from monero_glue.xmr.core import ec_trezor
from monero_glue.xmr.core.backend import trezor_crypto as tcry
from monero_glue.xmr.core import ec_py
from monero_glue.xmr.core import ec_trezor


class EcTrezorTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(EcTrezorTest, self).__init__(*args, **kwargs)

    def test_ed_crypto(self):
        h = binascii.unhexlify(b'8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94')
        pt = tcry.ge25519_unpack_vartime_r(h)
        print(pt)
        print(binascii.hexlify(tcry.ge25519_pack_r(pt)))

    def test_modm(self):
        x = ec_py.encodeint(0xaa)
        y = ec_trezor.decodeint(x)
        print(y)
        yy = ec_trezor.encodeint(y)
        print(binascii.hexlify(yy))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


