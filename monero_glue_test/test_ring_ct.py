#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest
import binascii

import aiounittest

from monero_glue.xmr import monero, ring_ct, crypto


class RingCtTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(RingCtTest, self).__init__(*args, **kwargs)

    def test_range_proof(self):
        proof = ring_ct.prove_range(0)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)
        self.assertTrue(crypto.point_eq(proof[0], crypto.point_add(
            crypto.scalarmult_base(proof[1]),
            crypto.scalarmult_h(0))))

        proof = ring_ct.prove_range(0, mem_opt=False)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)
        self.assertTrue(crypto.point_eq(proof[0], crypto.point_add(
            crypto.scalarmult_base(proof[1]),
            crypto.scalarmult_h(0))))

    def test_range_proof_back(self):
        proof = ring_ct.prove_range(0, backend_impl=True)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

    def test_range_proof2(self):
        amount = 17 + (1 << 60)
        proof = ring_ct.prove_range(amount)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)
        self.assertTrue(crypto.point_eq(proof[0], crypto.point_add(
            crypto.scalarmult_base(proof[1]),
            crypto.scalarmult_h(amount))))

        proof = ring_ct.prove_range(amount, mem_opt=False, decode=True)
        res = ring_ct.ver_range(proof[0], proof[2], decode=False)
        self.assertTrue(res)

        res = ring_ct.ver_range(crypto.point_add(proof[0], crypto.scalarmult_base(crypto.sc_init(4))), proof[2], decode=False)
        self.assertFalse(res)

    def test_range_proof2_back(self):
        proof = ring_ct.prove_range(123456789, backend_impl=True)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

        res = ring_ct.ver_range(crypto.point_add(proof[0], crypto.scalarmult_base(crypto.sc_init(4))), proof[2])
        self.assertFalse(res)

    def test_range_proof3(self):
        proof = ring_ct.prove_range(123456789)
        rsig = proof[2]

        monero.recode_rangesig(rsig, encode=False)
        monero.recode_rangesig(rsig, encode=True)
        res = ring_ct.ver_range(proof[0], rsig)
        self.assertTrue(res)

    def test_range_proof_old(self):
        proof = ring_ct.prove_range(0, use_asnl=True, mem_opt=False, decode=True)
        res = ring_ct.ver_range(proof[0], proof[2], use_asnl=True, decode=False)
        self.assertTrue(res)

    def test_range_proof2_old(self):
        proof = ring_ct.prove_range(123456789, use_asnl=True, mem_opt=False, decode=True)
        res = ring_ct.ver_range(proof[0], proof[2], use_asnl=True, decode=False)
        self.assertTrue(res)
        res = ring_ct.ver_range(crypto.point_add(proof[0], crypto.scalarmult_base(crypto.sc_init(4))), proof[2], use_asnl=True, decode=False)
        self.assertFalse(res)

    def test_key_image_signature(self):
        ki = binascii.unhexlify(b'a248206cea806a7d60ea936cdc35efdf44a189b1026c4e658f42216aec155383')
        c0 = binascii.unhexlify(b'032725822d2c0f37bb67f29e116dc8c64ec02c4e8c69b147f596e7dbbc899409')
        r0 = binascii.unhexlify(b'2e4839b81c74f5b17d842d5f15723813b5287cfbc44539c9154d9222b65d2b07')
        pub = binascii.unhexlify(b'346354ca120bf3210976b1f5a9cee897628f3745fb80d5525c22f8cffd78a5c7')

        self.assertEqual(1, ring_ct.check_ring_singature(ki, crypto.decodepoint(ki),
                                                         [crypto.decodepoint(pub)],
                                                         [[crypto.decodeint(c0), crypto.decodeint(r0)]]))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


