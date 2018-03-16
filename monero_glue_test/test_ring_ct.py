#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import random
import base64
import unittest
import pkg_resources
import requests
import asyncio
import aiounittest
import binascii

import monero_serialize as xmrser
from monero_serialize import xmrserialize, xmrtypes
from monero_glue import trezor, monero, common, crypto, agent, ring_ct


class RingCtTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(RingCtTest, self).__init__(*args, **kwargs)

    def test_range_proof(self):
        proof = ring_ct.prove_range(0)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

    def test_range_proof2(self):
        proof = ring_ct.prove_range(123456789)
        res = ring_ct.ver_range(proof[0], proof[2])
        self.assertTrue(res)

    def test_range_proof3(self):
        proof = ring_ct.prove_range(123456789)
        rsig = proof[2]

        monero.recode_rangesig(rsig, encode=True)
        monero.recode_rangesig(rsig, encode=False)
        res = ring_ct.ver_range(proof[0], rsig)
        self.assertTrue(res)

    def test_range_proof_old(self):
        proof = ring_ct.prove_range(0, use_asnl=True)
        res = ring_ct.ver_range(proof[0], proof[2], use_asnl=True)
        self.assertTrue(res)

    def test_range_proof2_old(self):
        proof = ring_ct.prove_range(123456789, use_asnl=True)
        res = ring_ct.ver_range(proof[0], proof[2], use_asnl=True)
        self.assertTrue(res)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


