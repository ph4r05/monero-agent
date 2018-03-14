#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
import base64
import unittest
import pkg_resources
import requests
import asyncio
import aiounittest
import binascii
import pkg_resources

import monero_serialize as xmrser
from monero_serialize import xmrserialize, xmrtypes
from monero_glue import trezor, monero, common, crypto, agent


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

        reader = xmrserialize.MemoryReaderWriter(bytearray(unsigned_tx))
        ar = xmrserialize.Archive(reader, False)
        unsig = xmrtypes.UnsignedTxSet()
        await ar.message(unsig)

        tagent = self.init_agent()
        await tagent.transfer_unsigned(unsig)

    async def test_tx_sign(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns02.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))

        reader = xmrserialize.MemoryReaderWriter(bytearray(unsigned_tx))
        ar = xmrserialize.Archive(reader, False)
        unsig = xmrtypes.UnsignedTxSet()
        await ar.message(unsig)

        tagent = self.init_agent()
        await tagent.transfer_unsigned(unsig)

    async def test_tx_prefix(self):
        return
        url = 'http://localhost:48084/json_rpc'
        req = {
            "jsonrpc": "2.0", "id": "0", "method": "transfer_unsigned", "params":
                {
                    "destinations":
                        [{
                            "amount": 384500000000,
                            "address": "9twQxUpHzXrQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB7ufnmk"
                        }],
                    "account_index": 0,
                    "subaddr_indices": [],
                    "priority": 5,
                    "mixin": 2,
                    "unlock_time": 0,
                    "payment_id": "deadc0dedeadc0d1",
                    "get_tx_keys": True,
                    "do_not_relay": True,
                    "get_tx_hex": True,
                    "get_tx_metadata": True
                }
        }

        resp = requests.post(url, json=req)
        js = resp.json()

        # Transaction parsing
        blobs = js['result']['tx_blob_list']
        tx_blob = blobs[0]
        tx_unsigned = js['result']['tx_unsigned']

        tsx_bin = base64.b16decode(tx_blob, True)
        reader = xmrserialize.MemoryReaderWriter(bytearray(tsx_bin))
        ar = xmrserialize.Archive(reader, False)
        msg = xmrtypes.Transaction()
        await ar.message(msg)

        # Unsigned transaction parsing
        tsx_unsigned_bin = base64.b16decode(tx_unsigned, True)
        reader = xmrserialize.MemoryReaderWriter(bytearray(tsx_unsigned_bin))
        ar = xmrserialize.Archive(reader, False)
        unsig = xmrtypes.UnsignedTxSet()
        await ar.message(unsig)

        tagent = self.init_agent()
        await tagent.transfer_unsigned(unsig)

        print('Done')

    def get_creds(self):
        """
        Wallet credentials
        :return:
        """
        return trezor.WalletCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08'),
            priv_spend_key=crypto.b16_to_scalar(b'f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a'))

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


