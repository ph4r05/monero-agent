#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest

import aiounittest

from monero_glue.xmr import crypto
from monero_glue.xmr.enc import chacha


class ChachaTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(ChachaTest, self).__init__(*args, **kwargs)

    def test_encrypt_base(self):
        for i in range(10):
            key = crypto.cn_fast_hash(crypto.encodeint(crypto.random_scalar()))
            data = crypto.cn_fast_hash(crypto.encodeint(crypto.random_scalar())) * (i + 1)

            ciphertext = chacha.encrypt(key, data)
            plaintext = chacha.decrypt(key, ciphertext)
            self.assertEqual(plaintext, data)

            plaintext2 = chacha.decrypt(key, bytes(int(ciphertext[0]) ^ 0xff) + ciphertext[1:])
            self.assertNotEqual(plaintext2, data)

    def test_encrypt(self):
        self.back_encrypt(False)

    def test_encrypt_auth(self):
        self.back_encrypt(True)

    def back_encrypt(self, authenticated=True):
        for i in range(5):
            priv_key = crypto.random_scalar()
            data = crypto.cn_fast_hash(crypto.encodeint(crypto.random_scalar())) * (i + 1)

            blob = chacha.encrypt_xmr(priv_key, data, authenticated=authenticated)
            plaintext = chacha.decrypt_xmr(priv_key, blob, authenticated=authenticated)
            self.assertEqual(data, plaintext)

            try:
                plaintext2 = chacha.decrypt_xmr(crypto.sc_add(priv_key, crypto.sc_init(1)), blob, authenticated=authenticated)
                if authenticated:
                    self.fail('Signature error expected')
                else:
                    self.assertNotEqual(data, plaintext2)

            except:
                if not authenticated:
                    raise


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


