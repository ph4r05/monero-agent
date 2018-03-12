#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import base64
import unittest
import pkg_resources
import requests
import asyncio
import aiounittest
import binascii

from mnero import mininero
import monero_serialize as xmrser
from monero_serialize import xmrserialize, xmrtypes
from monero_glue import trezor, monero, common, crypto
from mnero import keccak2

__author__ = 'dusanklinec'


class Basetest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Basetest, self).__init__(*args, **kwargs)

    def test_base(self):
        mininero.b58encode(b'123')

    def test_ed_crypto(self):
        sqr = crypto.fe_expmod(crypto.fe_sqrtm1, 2)
        self.assertEqual(sqr, crypto.fe_mod(-1))
        self.assertEqual(crypto.fe_A, crypto.fe_mod(2 * (1 - crypto.d) * crypto.inv(1 + crypto.d)))

        self.assertEqual(crypto.fe_expmod(crypto.fe_fffb1, 2), crypto.fe_mod(-2 * crypto.fe_A * (crypto.fe_A+2)))
        self.assertEqual(crypto.fe_expmod(crypto.fe_fffb2, 2), crypto.fe_mod( 2 * crypto.fe_A * (crypto.fe_A+2)))
        self.assertEqual(crypto.fe_expmod(crypto.fe_fffb3, 2), crypto.fe_mod(-crypto.fe_sqrtm1 * crypto.fe_A * (crypto.fe_A+2)))
        self.assertEqual(crypto.fe_expmod(crypto.fe_fffb4, 2), crypto.fe_mod( crypto.fe_sqrtm1 * crypto.fe_A * (crypto.fe_A+2)))

    def test_cn_fast_hash(self):
        inp = bytes(
            [0x25, 0x9e, 0xf2, 0xab, 0xa8, 0xfe, 0xb4, 0x73, 0xcf, 0x39, 0x05, 0x8a, 0x0f, 0xe3, 0x0b, 0x9f, 0xf6, 0xd2,
             0x45, 0xb4, 0x2b, 0x68, 0x26, 0x68, 0x7e, 0xbd, 0x6b, 0x63, 0x12, 0x8a, 0xff, 0x64, 0x05])
        res = crypto.cn_fast_hash(inp)
        self.assertEqual(res, bytes(
            [0x86, 0xdb, 0x87, 0xb8, 0x3f, 0xb1, 0x24, 0x6e, 0xfc, 0xa5, 0xf3, 0xb0, 0xdb, 0x09, 0xce, 0x3f, 0xa4, 0xd6,
             0x05, 0xb0, 0xd1, 0x0e, 0x65, 0x07, 0xca, 0xc2, 0x53, 0xdd, 0x31, 0xa3, 0xec, 0x16]))

    def test_hash_to_scalar(self):
        inp = bytes(
            [0x25, 0x9e, 0xf2, 0xab, 0xa8, 0xfe, 0xb4, 0x73, 0xcf, 0x39, 0x05, 0x8a, 0x0f, 0xe3, 0x0b, 0x9f, 0xf6, 0xd2,
             0x45, 0xb4, 0x2b, 0x68, 0x26, 0x68, 0x7e, 0xbd, 0x6b, 0x63, 0x12, 0x8a, 0xff, 0x64, 0x05])
        res = crypto.hash_to_scalar(inp)
        self.assertEqual(res, 0x6eca331dd53c2ca07650ed1b005d6a42aef0ffd0dfc092616124e255b920799)

    def test_derive_subaddress_public_key(self):
        out_key = bytes(
            [0xf4, 0xef, 0xc2, 0x9d, 0xa4, 0xcc, 0xd6, 0xbc, 0x6e, 0x81, 0xf5, 0x2a, 0x6f, 0x47, 0xb2, 0x95, 0x29, 0x66,
             0x44, 0x2a, 0x7e, 0xfb, 0x49, 0x90, 0x1c, 0xce, 0x06, 0xa7, 0xa3, 0xbe, 0xf3, 0xe5])
        deriv = bytes(
            [0x25, 0x9e, 0xf2, 0xab, 0xa8, 0xfe, 0xb4, 0x73, 0xcf, 0x39, 0x05, 0x8a, 0x0f, 0xe3, 0x0b, 0x9f, 0xf6, 0xd2,
             0x45, 0xb4, 0x2b, 0x68, 0x26, 0x68, 0x7e, 0xbd, 0x6b, 0x63, 0x12, 0x8a, 0xff, 0x64])
        res = monero.derive_subaddress_public_key(out_key, deriv, 5)
        self.assertEqual(res, bytes(
            [0x5a, 0x10, 0xcc, 0xa9, 0x00, 0xee, 0x47, 0xa7, 0xf4, 0x12, 0xcd, 0x66, 0x1b, 0x29, 0xf5, 0xab, 0x35, 0x6d,
             0x6a, 0x19, 0x51, 0x88, 0x45, 0x93, 0xbb, 0x17, 0x0b, 0x5e, 0xc8, 0xb6, 0xf2, 0xe8]))

    def test_hp(self):
        data = bytes(
            [0x42, 0xf6, 0x83, 0x5b, 0xf8, 0x31, 0x14, 0xa1, 0xf5, 0xf6, 0x07, 0x6f, 0xe7, 0x9b, 0xdf, 0xa0, 0xbd, 0x67,
             0xc7, 0x4b, 0x88, 0xf1, 0x27, 0xd5, 0x45, 0x72, 0xd3, 0x91, 0x0d, 0xd0, 0x92, 0x01])
        res = crypto.hash_to_ec(data)
        res_p = crypto.encodepoint(res)
        self.assertEqual(res_p, bytes(
            [0x54, 0x86, 0x3a, 0x04, 0x64, 0xc0, 0x08, 0xac, 0xc9, 0x9c, 0xff, 0xb1, 0x79, 0xbc, 0x6c, 0xf3, 0x4e, 0xb1,
             0xbb, 0xdf, 0x6c, 0x29, 0xf7, 0xa0, 0x70, 0xa7, 0xc6, 0x37, 0x6a, 0xe3, 0x0a, 0xb5]))

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
        trez.creds = trezor.WalletCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08'),
            priv_spend_key=crypto.b16_to_scalar(b'f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a'))

        print(js)

        for tx in unsig.txes:
            extras = await monero.parse_extra_fields(tx.extra)
            extra_nonce = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraNonce)
            if extra_nonce and monero.has_encrypted_payment_id(extra_nonce.nonce):
                payment_id = monero.get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce)

            # Init transaction
            tsx_data = trezor.TsxData()
            tsx_data.payment_id = payment_id
            tsx_data.outputs = tx.dests
            tsx_data.change_dts = tx.change_dts
            await trez.init_transaction(tsx_data)

            # Subaddresses
            await trez.precompute_subaddr(tx.subaddr_account, tx.subaddr_indices)

            # Set transaction inputs
            for src in tx.sources:
                await trez.set_tsx_input(src)




        print('Vertig')



if __name__ == "__main__":
    unittest.main()  # pragma: no cover


