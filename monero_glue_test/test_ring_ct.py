#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest

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

        proof = ring_ct.prove_range(0, mem_opt=False)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

    def test_range_proof2(self):
        proof = ring_ct.prove_range(123456789)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

        proof = ring_ct.prove_range(123456789, mem_opt=False)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

        res = ring_ct.ver_range(crypto.point_add(proof[0], crypto.scalarmult_base(4)), proof[2])
        self.assertFalse(res)

    def test_range_proof3(self):
        proof = ring_ct.prove_range(123456789)
        rsig = proof[2]

        monero.recode_rangesig(rsig, encode=True)
        monero.recode_rangesig(rsig, encode=False)
        res = ring_ct.ver_range(proof[0], rsig)
        self.assertTrue(res)

    def test_range_proof_old(self):
        proof = ring_ct.prove_range(0, use_asnl=True, mem_opt=False)
        res = ring_ct.ver_range(proof[0], proof[2], use_asnl=True)
        self.assertTrue(res)

    def test_range_proof2_old(self):
        proof = ring_ct.prove_range(123456789, use_asnl=True, mem_opt=False)
        res = ring_ct.ver_range(proof[0], proof[2], use_asnl=True)
        self.assertTrue(res)
        res = ring_ct.ver_range(crypto.point_add(proof[0], crypto.scalarmult_base(4)), proof[2], use_asnl=True)
        self.assertFalse(res)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


