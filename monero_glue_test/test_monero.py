#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import json
import os
import unittest

import aiounittest
import pkg_resources

from monero_glue.messages import MoneroRctKeyPublic
from monero_glue.xmr import crypto, mlsag2, monero, ring_ct
from monero_serialize import xmrserialize, xmrtypes
from monero_serialize.core import versioning


class MoneroTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(MoneroTest, self).__init__(*args, **kwargs)

    def test_wallet_addr(self):
        addr = monero.encode_addr(
            monero.net_version(),
            binascii.unhexlify(
                b"3bec484c5d7f0246af520aab550452b5b6013733feabebd681c4a60d457b7fc1"
            ),
            binascii.unhexlify(
                b"2d5918e31d3c003da3c778592c07b398ad6f961a67082a75fd49394d51e69bbe"
            ),
        )
        self.assertEqual(
            addr,
            b"43tpGG9PKbwCpjRvNLn1jwXPpnacw2uVUcszAtgmDiVcZK4VgHwjJT9BJz1WGF9eMxSYASp8yNMkuLjeQfWqJn3CNWdWfzV",
        )

        w = monero.AccountCreds.new_wallet(
            crypto.b16_to_scalar(
                b"4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08"
            ),
            crypto.b16_to_scalar(
                b"f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a"
            ),
            network_type=monero.NetworkTypes.TESTNET,
        )
        self.assertEqual(
            w.address,
            b"9vacMKaj8JJV6MnwDzh2oNVdwTLJfTDyNRiB6NzV9TT7fqvzLivH2dB8Tv7VYR3ncn8vCb3KdNMJzQWrPAF1otYJ9cPKpkr",
        )

    def test_derive_subaddress_public_key(self):
        out_key = crypto.decodepoint(
            binascii.unhexlify(
                b"f4efc29da4ccd6bc6e81f52a6f47b2952966442a7efb49901cce06a7a3bef3e5"
            )
        )
        deriv = crypto.decodepoint(
            binascii.unhexlify(
                b"259ef2aba8feb473cf39058a0fe30b9ff6d245b42b6826687ebd6b63128aff64"
            )
        )
        res = crypto.encodepoint(monero.derive_subaddress_public_key(out_key, deriv, 5))
        self.assertEqual(
            res,
            binascii.unhexlify(
                b"5a10cca900ee47a7f412cd661b29f5ab356d6a1951884593bb170b5ec8b6f2e8"
            ),
        )

    def test_get_subaddress_secret_key(self):
        a = crypto.b16_to_scalar(
            b"4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08"
        )
        m = monero.get_subaddress_secret_key(secret_key=a, major=0, minor=1)
        self.assertEqual(
            crypto.encodeint(m),
            binascii.unhexlify(
                b"b6ff4d689b95e3310efbf683850c075bcde46361923054e42ef30016b287ff0c"
            ),
        )

    def test_public_spend(self):
        derivation = binascii.unhexlify(
            b"e720a09f2e3a0bbf4e4ba7ad93653bb296885510121f806acb2a5f9168fafa01"
        )
        base = binascii.unhexlify(
            b"7d996b0f2db6dbb5f2a086211f2399a4a7479b2c911af307fdc3f7f61a88cb0e"
        )
        pkey_ex = binascii.unhexlify(
            b"0846cae7405077b6b7800f0b932c10a186448370b6db318f8c9e13f781dab546"
        )
        pkey_comp = crypto.derive_public_key(
            crypto.decodepoint(derivation), 0, crypto.decodepoint(base)
        )
        self.assertEqual(pkey_ex, crypto.encodepoint(pkey_comp))

    def _get_bc_ver(self):
        """
        Returns version settings for the used data. Testing data are fixed at these versions.
        :return:
        """
        return xmrtypes.hf_versions(9)

    async def test_node_transaction(self):
        tx_j = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_01.json")
        )
        tx_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_01_plain.txt")
        )
        tx_u_c = pkg_resources.resource_string(
            __name__, os.path.join("data", "tsx_01_uns.txt")
        )
        tx_js = json.loads(tx_j.decode("utf8"))

        reader = xmrserialize.MemoryReaderWriter(bytearray(binascii.unhexlify(tx_c)))
        ar = xmrserialize.Archive(reader, False, self._get_bc_ver())
        tx = xmrtypes.Transaction()
        await ar.message(tx)

        reader = xmrserialize.MemoryReaderWriter(bytearray(binascii.unhexlify(tx_u_c)))
        ar = xmrserialize.Archive(reader, False, self._get_bc_ver())
        uns = xmrtypes.UnsignedTxSet()
        await ar.message(uns)

        # Test message hash computation
        tx_prefix_hash = await monero.get_transaction_prefix_hash(tx)
        message = binascii.unhexlify(tx_js["tx_prefix_hash"])
        self.assertEqual(tx_prefix_hash, message)

        # RingCT, range sigs, hash
        rv = tx.rct_signatures
        rv.message = message
        rv.mixRing = self.mixring(tx_js)
        digest = await monero.get_pre_mlsag_hash(rv)
        full_message = binascii.unhexlify(tx_js["pre_mlsag_hash"])
        self.assertEqual(digest, full_message)

        # Recompute missing data
        monero.expand_transaction(tx)

        # Unmask ECDH data, check range proofs
        for i in range(len(tx_js["amount_keys"])):
            ecdh = monero.copy_ecdh(rv.ecdhInfo[i])
            monero.recode_ecdh(ecdh, encode=False)

            ecdh = ring_ct.ecdh_decode(
                ecdh, derivation=binascii.unhexlify(tx_js["amount_keys"][i])
            )
            self.assertEqual(crypto.sc_get64(ecdh.amount), tx_js["outamounts"][i])
            self.assertTrue(
                crypto.sc_eq(
                    ecdh.mask,
                    crypto.decodeint(binascii.unhexlify(tx_js["outSk"][i])[32:]),
                )
            )

            C = crypto.decodepoint(rv.outPk[i].mask)
            rsig = rv.p.rangeSigs[i]

            res = ring_ct.ver_range(C, rsig)
            self.assertTrue(res)

            res = ring_ct.ver_range(
                crypto.point_add(C, crypto.scalarmult_base(crypto.sc_init(3))), rsig
            )
            self.assertFalse(res)

        is_simple = len(tx.vin) > 1
        monero.recode_rct(rv, encode=False)

        if is_simple:
            for index in range(len(rv.p.MGs)):
                pseudo_out = crypto.decodepoint(
                    binascii.unhexlify(
                        tx_js["tx"]["rct_signatures"]["pseudoOuts"][index]
                    )
                )
                r = mlsag2.ver_rct_mg_simple(
                    full_message, rv.p.MGs[index], rv.mixRing[index], pseudo_out
                )
                self.assertTrue(r)

                r = mlsag2.ver_rct_mg_simple(
                    full_message, rv.p.MGs[index], rv.mixRing[index - 1], pseudo_out
                )
                self.assertFalse(r)

        else:
            txn_fee_key = crypto.scalarmult_h(rv.txnFee)
            r = mlsag2.ver_rct_mg(
                rv.p.MGs[0], rv.mixRing, rv.outPk, txn_fee_key, digest
            )
            self.assertTrue(r)

            r = mlsag2.ver_rct_mg(
                rv.p.MGs[0],
                rv.mixRing,
                rv.outPk,
                crypto.scalarmult_h(rv.txnFee - 100),
                digest,
            )
            self.assertFalse(r)

    def mixring(self, js):
        mxr = []
        mx = js["mixRing"]
        for i in range(len(mx)):
            mxr.append([])
            for j in range(len(mx[i])):
                dt = binascii.unhexlify(mx[i][j])
                mxr[i].append(MoneroRctKeyPublic(dest=dt[:32], commitment=dt[32:]))
        return mxr


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
