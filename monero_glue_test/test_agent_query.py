#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import base64
import unittest
import requests
import aiounittest
import binascii

from monero_serialize import xmrserialize, xmrtypes
from monero_glue import trezor_lite, agent_lite
from monero_glue.xmr import monero, crypto
from monero_glue.old import agent, trezor


class AgentTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(AgentTest, self).__init__(*args, **kwargs)

    async def test_tx_prefix(self):
        return
        url = 'http://localhost:48084/json_rpc'
        req = {
            "jsonrpc": "2.0", "id": "0", "method": "transfer_unsigned", "params":
                {
                    "destinations": [
                        {
                            "amount": 2110000000000,
                            "address": "BZZeyHTQYZ9W9KX2M69WWxWat1Z6JQYsi4LjnZxuVTmCbsNxrUyLFbXiZHRwXgBcaESRz8HtHxTDGSCtgxDdEFpQFrKqXoX"
                        },
                        {
                            "amount": 2120000000000,
                            "address": "BZg53n1EgLJhYDZNCi3VvxXFMdmmgk6HhhFCvvw9sMf1RQFp7LyjGvrNuF7TzukfaGh7Gsin2bEDpUNRv9oc8qSGMKCnktw"
                        },
                        {
                            "amount": 2130000000000,
                            "address": "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8"
                        },
                    ],
                    "account_index": 0,
                    "subaddr_indices": [],
                    "priority": 5,
                    "mixin": 4,
                    "unlock_time": 0,
                    # "payment_id": "deadc0dedeadc0d1",
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
        txes = await tagent.sign_unsigned_tx(unsig)

        resp = requests.post('http://localhost:48081/sendrawtransaction', json={
            'tx_as_hex': binascii.hexlify(txes[0]).decode('utf8'),
            'do_not_relay': False,
        })
        print(resp)

        print('Txblob: \n %s\n' % tx_blob)
        print('TxUns: \n %s\n' % tx_unsigned)
        print('TxMeta: \n %s\n' % js['result']['tx_metadata_list'][0])
        print('Done')

    def get_creds(self):
        """
        Wallet credentials
        :return:
        """
        return monero.AccountCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08'),
            priv_spend_key=crypto.b16_to_scalar(b'f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a'))

    def init_trezor(self, lite=True):
        """
        Initialize new trezor instance
        :return:
        """
        trez = trezor.Trezor() if not lite else trezor_lite.TrezorLite()
        trez.creds = self.get_creds()
        return trez

    def init_agent(self, lite=True):
        """
        Initialize new agent instance
        :return:
        """
        t = self.init_trezor(lite=lite)
        return agent.Agent(t) if not lite else agent_lite.Agent(t)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


