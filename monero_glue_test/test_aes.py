#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest
import aiounittest

from monero_glue.xmr import crypto
from monero_glue.xmr.enc import aesgcm


class AesTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(AesTest, self).__init__(*args, **kwargs)

    def test_enc(self):
        key = crypto.keccak_hash(b'0')
        plain = b'1234'
        assoc = b'4567'
        iv, cip, tag = aesgcm.encrypt(key, plain, assoc)

        plain2 = aesgcm.decrypt(key, iv, cip, tag, assoc)
        self.assertEqual(plain, plain2)

        with self.assertRaises(ValueError):
            plain2 = aesgcm.decrypt(key, iv, cip, tag, assoc + b'1')

        with self.assertRaises(ValueError):
            plain2 = aesgcm.decrypt(key, bytes(iv[0] ^ 0xff) + iv[1:], cip, tag, assoc)

        with self.assertRaises(ValueError):
            plain2 = aesgcm.decrypt(key, iv, bytes(cip[0] ^ 0xff) + cip[1:], tag, assoc)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


