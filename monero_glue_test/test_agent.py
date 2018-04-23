#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
import unittest
import pkg_resources
import aiounittest
import binascii

from monero_serialize import xmrserialize, xmrtypes
from monero_glue.xmr import monero, crypto
from monero_glue.old import agent, trezor
import zlib


class AgentTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(AgentTest, self).__init__(*args, **kwargs)

    async def test_tx_sign_simple(self):
        """
        Testing tx signature, simple, multiple inputs
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns01.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))

        await self.tx_sign(unsigned_tx)

    async def test_tx_sign(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns02.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign(unsigned_tx)

    async def test_tx_sign_sub_dest(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns03.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign(unsigned_tx)

    async def test_tx_sign_sub_2dest(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns04.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign(unsigned_tx)

    async def tx_sign(self, unsigned_tx):
        """
        Tx sign test with given unsigned transaction data
        :param unsigned_tx:
        :return:
        """
        reader = xmrserialize.MemoryReaderWriter(bytearray(unsigned_tx))
        ar = xmrserialize.Archive(reader, False)
        unsig = xmrtypes.UnsignedTxSet()
        await ar.message(unsig)

        tagent = self.init_agent()
        await tagent.transfer_unsigned(unsig)

    def get_creds(self):
        """
        Wallet credentials
        :return:
        """
        return monero.AccountCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08'),
            priv_spend_key=crypto.b16_to_scalar(b'f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a'),
            network_type=monero.NetworkTypes.TESTNET)

    def init_trezor(self):
        """
        Initialize new trezor instance
        :return:
        """
        trez = trezor.Trezor()
        trez.creds = self.get_creds()
        return trez

    def init_agent(self):
        """
        Initialize new agent instance
        :return:
        """
        return agent.Agent(self.init_trezor())


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


