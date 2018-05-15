#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import json
import os
import unittest

import aiounittest
import pkg_resources
from monero_serialize import xmrserialize, xmrtypes

from monero_glue.xmr import monero, mlsag2, ring_ct, crypto


class MoneroTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(MoneroTest, self).__init__(*args, **kwargs)

    def test_wallet_addr(self):
        addr = monero.encode_addr(
            monero.net_version(),
            binascii.unhexlify(b'3bec484c5d7f0246af520aab550452b5b6013733feabebd681c4a60d457b7fc1'),
            binascii.unhexlify(b'2d5918e31d3c003da3c778592c07b398ad6f961a67082a75fd49394d51e69bbe'))
        self.assertEqual(addr, b'43tpGG9PKbwCpjRvNLn1jwXPpnacw2uVUcszAtgmDiVcZK4VgHwjJT9BJz1WGF9eMxSYASp8yNMkuLjeQfWqJn3CNWdWfzV')

        w = monero.AccountCreds.new_wallet(
            crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08'),
            crypto.b16_to_scalar(b'f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a'),
            network_type=monero.NetworkTypes.TESTNET
        )
        self.assertEqual(w.address, b'9vacMKaj8JJV6MnwDzh2oNVdwTLJfTDyNRiB6NzV9TT7fqvzLivH2dB8Tv7VYR3ncn8vCb3KdNMJzQWrPAF1otYJ9cPKpkr')

    def test_derive_subaddress_public_key(self):
        out_key = crypto.decodepoint(bytes(
            [0xf4, 0xef, 0xc2, 0x9d, 0xa4, 0xcc, 0xd6, 0xbc, 0x6e, 0x81, 0xf5, 0x2a, 0x6f, 0x47, 0xb2, 0x95, 0x29, 0x66,
             0x44, 0x2a, 0x7e, 0xfb, 0x49, 0x90, 0x1c, 0xce, 0x06, 0xa7, 0xa3, 0xbe, 0xf3, 0xe5]))
        deriv = crypto.decodepoint(bytes(
            [0x25, 0x9e, 0xf2, 0xab, 0xa8, 0xfe, 0xb4, 0x73, 0xcf, 0x39, 0x05, 0x8a, 0x0f, 0xe3, 0x0b, 0x9f, 0xf6, 0xd2,
             0x45, 0xb4, 0x2b, 0x68, 0x26, 0x68, 0x7e, 0xbd, 0x6b, 0x63, 0x12, 0x8a, 0xff, 0x64]))
        res = crypto.encodepoint(monero.derive_subaddress_public_key(out_key, deriv, 5))
        self.assertEqual(res, bytes(
            [0x5a, 0x10, 0xcc, 0xa9, 0x00, 0xee, 0x47, 0xa7, 0xf4, 0x12, 0xcd, 0x66, 0x1b, 0x29, 0xf5, 0xab, 0x35, 0x6d,
             0x6a, 0x19, 0x51, 0x88, 0x45, 0x93, 0xbb, 0x17, 0x0b, 0x5e, 0xc8, 0xb6, 0xf2, 0xe8]))

    def test_get_subaddress_secret_key(self):
        a = crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08')
        m = monero.get_subaddress_secret_key(secret_key=a, major=0, minor=1)
        self.assertEqual(crypto.encodeint(m), bytes(
            [0xb6, 0xff, 0x4d, 0x68, 0x9b, 0x95, 0xe3, 0x31, 0x0e, 0xfb, 0xf6, 0x83, 0x85, 0x0c, 0x07, 0x5b, 0xcd, 0xe4,
             0x63, 0x61, 0x92, 0x30, 0x54, 0xe4, 0x2e, 0xf3, 0x00, 0x16, 0xb2, 0x87, 0xff, 0x0c]))

    def test_public_spend(self):
        derivation = bytes([0xe7,0x20,0xa0,0x9f,0x2e,0x3a,0x0b,0xbf,0x4e,0x4b,0xa7,0xad,0x93,0x65,0x3b,0xb2,0x96,0x88,0x55,0x10,0x12,0x1f,0x80,0x6a,0xcb,0x2a,0x5f,0x91,0x68,0xfa,0xfa,0x01])
        base = bytes([0x7d,0x99,0x6b,0x0f,0x2d,0xb6,0xdb,0xb5,0xf2,0xa0,0x86,0x21,0x1f,0x23,0x99,0xa4,0xa7,0x47,0x9b,0x2c,0x91,0x1a,0xf3,0x07,0xfd,0xc3,0xf7,0xf6,0x1a,0x88,0xcb,0x0e])
        pkey_ex = bytes([0x08,0x46,0xca,0xe7,0x40,0x50,0x77,0xb6,0xb7,0x80,0x0f,0x0b,0x93,0x2c,0x10,0xa1,0x86,0x44,0x83,0x70,0xb6,0xdb,0x31,0x8f,0x8c,0x9e,0x13,0xf7,0x81,0xda,0xb5,0x46])
        pkey_comp = crypto.derive_public_key(crypto.decodepoint(derivation), 0, crypto.decodepoint(base))
        self.assertEqual(pkey_ex, crypto.encodepoint(pkey_comp))

    async def test_node_transaction(self):
        tx_j = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_01.json'))
        tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_01_plain.txt'))
        tx_u_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_01_uns.txt'))
        tx_js = json.loads(tx_j.decode('utf8'))

        reader = xmrserialize.MemoryReaderWriter(bytearray(binascii.unhexlify(tx_c)))
        ar = xmrserialize.Archive(reader, False)
        tx = xmrtypes.Transaction()
        await ar.message(tx)

        reader = xmrserialize.MemoryReaderWriter(bytearray(binascii.unhexlify(tx_u_c)))
        ar = xmrserialize.Archive(reader, False)
        uns = xmrtypes.UnsignedTxSet()
        await ar.message(uns)

        # Test message hash computation
        tx_prefix_hash = await monero.get_transaction_prefix_hash(tx)
        message = binascii.unhexlify(tx_js['tx_prefix_hash'])
        self.assertEqual(tx_prefix_hash, message)

        # RingCT, range sigs, hash
        rv = tx.rct_signatures
        rv.message = message
        rv.mixRing = self.mixring(tx_js)
        digest = await monero.get_pre_mlsag_hash(rv)
        full_message = binascii.unhexlify(tx_js['pre_mlsag_hash'])
        self.assertEqual(digest, full_message)

        # Recompute missing data
        monero.expand_transaction(tx)

        # Unmask ECDH data, check range proofs
        for i in range(len(tx_js['amount_keys'])):
            ecdh = monero.copy_ecdh(rv.ecdhInfo[i])
            monero.recode_ecdh(ecdh, encode=False)

            ecdh = ring_ct.ecdh_decode(ecdh, derivation=binascii.unhexlify(tx_js['amount_keys'][i]))
            self.assertEqual(crypto.sc_get64(ecdh.amount), tx_js['outamounts'][i])
            self.assertTrue(crypto.sc_eq(ecdh.mask, crypto.decodeint(binascii.unhexlify(tx_js['outSk'][i])[32:])))

            C = crypto.decodepoint(rv.outPk[i].mask)
            rsig = rv.p.rangeSigs[i]

            res = ring_ct.ver_range(C, rsig)
            self.assertTrue(res)

            res = ring_ct.ver_range(crypto.point_add(C, crypto.scalarmult_base(crypto.sc_init(3))), rsig)
            self.assertFalse(res)

        is_simple = len(tx.vin) > 1
        monero.recode_rct(rv, encode=False)

        if is_simple:
            for index in range(len(rv.p.MGs)):
                pseudo_out = crypto.decodepoint(binascii.unhexlify(tx_js['tx']['rct_signatures']['pseudoOuts'][index]))
                r = mlsag2.ver_rct_mg_simple(full_message, rv.p.MGs[index], rv.mixRing[index], pseudo_out)
                self.assertTrue(r)

                r = mlsag2.ver_rct_mg_simple(full_message, rv.p.MGs[index], rv.mixRing[index - 1], pseudo_out)
                self.assertFalse(r)

        else:
            txn_fee_key = crypto.scalarmult_h(rv.txnFee)
            r = mlsag2.ver_rct_mg(rv.p.MGs[0], rv.mixRing, rv.outPk, txn_fee_key, digest)
            self.assertTrue(r)

            r = mlsag2.ver_rct_mg(rv.p.MGs[0], rv.mixRing, rv.outPk, crypto.scalarmult_h(rv.txnFee - 100), digest)
            self.assertTrue(r)

    def mixring(self, js):
        mxr = []
        mx = js['mixRing']
        for i in range(len(mx)):
            mxr.append([])
            for j in range(len(mx[i])):
                dt = binascii.unhexlify(mx[i][j])
                mxr[i].append(xmrtypes.CtKey(dest=dt[:32], mask=dt[32:]))
        return mxr


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


