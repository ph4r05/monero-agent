#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import base64
import unittest
import pkg_resources
import requests
import asyncio
import aiounittest

from mnero import mininero
import monero_serialize as xmrser
from monero_serialize import xmrserialize, xmrtypes
from monero_glue import trezor

__author__ = 'dusanklinec'


class Basetest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Basetest, self).__init__(*args, **kwargs)

    def test_base(self):
        mininero.b58encode(b'123')

    async def test_tx_prefix(self):
        url = 'http://localhost:48084/json_rpc'
        req = {
            "jsonrpc": "2.0", "id": "0", "method": "transfer_unsigned", "params":
                {
                    "destinations":
                        [{
                            "amount": 3845000000000,
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

        trez = trezor.Trezor()

        print(js)

        for tx in unsig.txes:
            # Init transaction
            tsx_data = trezor.TsxData()
            tsx_data.payment_id = []  # TODO: extract payment id
            tsx_data.outputs = tx.dests

            await trez.init_transaction(tsx_data)

        print('Vertig')



if __name__ == "__main__":
    unittest.main()  # pragma: no cover


