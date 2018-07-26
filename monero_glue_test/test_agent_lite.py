#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import os
import unittest
import zlib

import pkg_resources
from monero_serialize import xmrboost, xmrserialize, xmrtypes

from monero_glue.agent import agent_lite
from monero_glue.hwtoken import token
from monero_glue.xmr import crypto, monero, wallet
from .base_tx_test import BaseTxTest


class AgentLiteTest(BaseTxTest):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(AgentLiteTest, self).__init__(*args, **kwargs)

    async def test_tx_sign_simple(self):
        """
        Testing tx signature, simple, multiple inputs
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_uns01.txt")
        )
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))

        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_uns02.txt")
        )
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign_sub_dest(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_uns03.txt")
        )
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign_sub_2dest(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_uns04.txt")
        )
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign_pending01_boost_full_2dest(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        pending_hex = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_pending01.txt")
        )
        pending_bin = binascii.unhexlify(pending_hex)
        await self.tx_sign_pending_boost(pending_bin)

    async def test_tx_sign_pending02_boost_full_sub_3dest(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        pending_hex = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_pending02.txt")
        )
        pending_bin = binascii.unhexlify(pending_hex)
        await self.tx_sign_pending_boost(pending_bin)

    async def test_tx_sign_uns01_boost_full_2dest(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_uns_enc01.txt")
        )

        creds = self.get_creds()
        unsigned_tx = await wallet.load_unsigned_tx(
            creds.view_key_private, unsigned_tx_c
        )
        await self.tx_sign_unsigned_msg(unsigned_tx)

    async def test_tx_sign_uns01_boost_full_2dest_sub(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_uns_enc02.txt")
        )

        creds = self.get_creds()
        unsigned_tx = await wallet.load_unsigned_tx(
            creds.view_key_private, unsigned_tx_c
        )
        await self.tx_sign_unsigned_msg(unsigned_tx)

    async def test_trezor_txs(self):
        if os.getenv('SKIP_TREZOR_TSX', False):
            self.skipTest('Skipped by ENV var')

        files = self.get_trezor_tsx_tests()
        creds = self.get_trezor_creds(0)
        all_creds = [self.get_trezor_creds(0), self.get_trezor_creds(1), self.get_trezor_creds(2)]
        
        for fl in files:
            with self.subTest(msg=fl):
                unsigned_tx_c = pkg_resources.resource_string(
                    __name__, os.path.join("data", fl)
                )

                unsigned_tx = await wallet.load_unsigned_tx(
                    creds.view_key_private, unsigned_tx_c
                )

                tagent = self.init_agent(creds=creds)
                txes = await tagent.sign_unsigned_tx(unsigned_tx)
                await self.verify(txes[0], tagent.last_transaction_data(), creds=creds)
                await self.receive(txes[0], all_creds)

    async def tx_sign_unsigned_msg(self, unsigned_tx):
        """
        Signs tx stored in unsigned tx message
        :param unsigned_tx:
        :return:
        """
        tagent = self.init_agent()
        txes = await tagent.sign_unsigned_tx(unsigned_tx)
        await self.verify(txes[0], tagent.last_transaction_data(), creds=self.get_creds())
        return await self.receive(txes[0], [self.get_creds(), self.get_creds_01(), self.get_creds_02()])

    async def tx_sign_unsigned(self, unsigned_tx):
        """
        Tx sign test with given unsigned transaction data
        :param unsigned_tx:
        :return:
        """
        reader = xmrserialize.MemoryReaderWriter(bytearray(unsigned_tx))
        ar = xmrserialize.Archive(reader, False)
        unsig = xmrtypes.UnsignedTxSet()
        await ar.message(unsig)
        await self.tx_sign_unsigned_msg(unsig)

    async def tx_sign_unsigned_boost(self, unsigned_tx):
        """
        Tx sign test with given unsigned transaction data, serialized by boost -
        unsigned tx produced by watch-only cli wallet.

        :param unsigned_tx:
        :return:
        """
        reader = xmrserialize.MemoryReaderWriter(bytearray(unsigned_tx))
        ar = xmrboost.Archive(reader, False)
        unsig = xmrtypes.UnsignedTxSet()
        await ar.root()
        await ar.message(unsig)
        await self.tx_sign_unsigned_msg(unsig)

    async def tx_sign_pending_boost(self, pending_tx):
        """
        Signs transaction produced by the wallet-rpc, metadata parser, boost
        :param metadata:
        :return:
        """
        reader = xmrserialize.MemoryReaderWriter(bytearray(pending_tx))
        ar = xmrboost.Archive(reader, False)
        pending = xmrtypes.PendingTransaction()
        await ar.root()
        await ar.message(pending)

        tagent = self.init_agent()
        txes = await tagent.sign_tx(pending.construction_data)
        await self.verify(txes[0], tagent.last_transaction_data(), creds=self.get_creds())
        await self.receive(txes[0], [self.get_creds(), self.get_creds_01(), self.get_creds_02()])

    def init_trezor(self, creds=None):
        """
        Initialize new trezor instance
        :type creds: object
        :return:
        """
        trez = token.TokenLite()
        trez.creds = self.get_creds() if creds is None else creds
        return trez

    def init_agent(self, creds=None):
        """
        Initialize new agent instance
        :return:
        """
        return agent_lite.Agent(self.init_trezor(creds=creds))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
