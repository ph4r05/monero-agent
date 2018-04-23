#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import unittest

import aiounittest

from monero_glue.misc import b58


class Base58Test(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Base58Test, self).__init__(*args, **kwargs)

    def test_base(self):
        """
        Simple b58 encode test
        :return:
        """
        self.assertIsNotNone(b58.b58encode(b''))
        self.assertIsNotNone(b58.b58encode(binascii.unhexlify(b'1234567890')))
        self.assertIsNotNone(b58.b58encode(binascii.unhexlify(b'1234567890' * 50)))
        self.assertEqual(b58.b58encode(binascii.unhexlify(b'0092A1A1E820F70A881E529C844178B56FE745DCBE4588659E')),
                         b'1ENKHRkBKtXnSHuQt1LR2VFdPtw6NvbrfX')

        tst = binascii.unhexlify(b'1234567890')
        self.assertEqual(b58.b58decode(b58.b58encode(tst)), tst)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover

