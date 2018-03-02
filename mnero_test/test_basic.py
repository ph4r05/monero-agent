#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import base64
import unittest
import pkg_resources

import asyncio
import aiounittest

from mnero import mininero
from mnero import PaperWallet as pw
from mnero import mnemonic


__author__ = 'dusanklinec'


class Basetest(unittest.TestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Basetest, self).__init__(*args, **kwargs)

    def test_base(self):
        """
        Simple b58 encode test
        :return:
        """
        self.assertIsNotNone(mininero.b58encode(b'1234567890'))

    def test_pw(self):
        """
        Paper wallet test
        :return:
        """
        while True:
            sk = pw.skGen()
            vk = mininero.getViewMM(sk)  # note this is the sc_reduced version..
            worked = 1

            try:
                mininero.toPoint(vk)
            except:
                worked = 0
                print("bad vk")

            if vk == mininero.sc_reduce_key(vk) and worked == 1:  # already reduced
                break

        self.assertIsNotNone(sk)
        self.assertIsNotNone(vk)
        self.assertTrue(len(sk) > 10)
        self.assertTrue(len(vk) > 10)

        pk = mininero.publicFromSecret(sk)
        pvk = mininero.publicFromSecret(vk)
        self.assertIsNotNone(pk)
        self.assertIsNotNone(pvk)

        addr = mininero.getAddrMM(sk)
        self.assertIsNotNone(addr)
        self.assertTrue(len(addr) > 10)

        wl = mnemonic.mn_encode(sk)
        cks = mininero.electrumChecksum(wl)
        self.assertIsNotNone(wl)
        self.assertIsNotNone(cks)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


