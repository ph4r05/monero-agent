#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest
import binascii
import logging

import aiounittest

from monero_glue.xmr import crypto, common
from monero_glue.xmr.core import ec_py


logger = logging.getLogger(__name__)


try:
    from monero_glue.xmr.core import ec_trezor
    tcry = ec_trezor.tcry
    LOADED = 1

except Exception as e:
    logger.info('Trezor backend loading error: %s' % e)
    LOADED = 0


class EcTrezorTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(EcTrezorTest, self).__init__(*args, **kwargs)

    def test_ed_crypto(self):
        if not LOADED:
            self.skipTest('Trezor crypto missing')
            
        h_hex = b'8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'
        h = binascii.unhexlify(h_hex)
        pt = tcry.ge25519_unpack_vartime_r(tcry.KEY_BUFF(*bytes(h)))
        packed = tcry.ge25519_pack_r(pt)
        self.assertEqual(h, packed)

    def test_modm(self):
        if not LOADED:
            self.skipTest('Trezor crypto missing')

        x = ec_py.encodeint(0xaa)
        y = ec_trezor.decodeint(x)
        yy = ec_trezor.encodeint(y)
        self.assertEqual(yy[0], 0xaa)
        self.assertEqual(yy[1], 0x00)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


