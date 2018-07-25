#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import collections
import aiounittest
from monero_glue.xmr import crypto, monero, ring_ct, common, mlsag2
from monero_glue.hwtoken import misc
from monero_serialize import xmrserialize, xmrtypes

from monero_glue.xmr.enc import chacha_poly


class BaseTxTest(aiounittest.AsyncTestCase):

    async def verify(self, tx, con_data=None, creds=None):
        """
        Transaction verification
        :param tx:
        :param con_data:
        :param creds:
        :return:
        """

        # Unserialize the transaction
        tx_obj = xmrtypes.Transaction()
        reader = xmrserialize.MemoryReaderWriter(bytearray(tx))
        ar1 = xmrserialize.Archive(reader, False)

        await ar1.message(tx_obj, msg_type=xmrtypes.Transaction)
        extras = await monero.parse_extra_fields(tx_obj.extra)
        monero.expand_transaction(tx_obj)

        tx_pub = crypto.decodepoint(monero.find_tx_extra_field_by_type(
            extras, xmrtypes.TxExtraPubKey
        ).pub_key)

        additional_pub_keys = monero.find_tx_extra_field_by_type(
            extras, xmrtypes.TxExtraAdditionalPubKeys
        )
        additional_pub_keys = [crypto.decodepoint(x) for x in additional_pub_keys.data] if additional_pub_keys is not None else None

        num_outs = len(tx_obj.vout)

        # Verify range proofs
        for idx, rsig in enumerate(tx_obj.rct_signatures.p.rangeSigs):
            out_pk = tx_obj.rct_signatures.outPk[idx]
            C = crypto.decodepoint(out_pk.mask)
            res = ring_ct.ver_range(C, rsig)
            self.assertTrue(res)

        # Prefix hash
        prefix_hash = await monero.get_transaction_prefix_hash(tx_obj)
        is_simple = len(tx_obj.vin) > 1

        self.assertEqual(prefix_hash, con_data.tx_prefix_hash)
        tx_obj.rct_signatures.message = prefix_hash

        # MLSAG hash
        mlsag_hash = await monero.get_pre_mlsag_hash(tx_obj.rct_signatures)

        # Decrypt transaction key
        tx_key = misc.compute_tx_key(creds.spend_key_private, prefix_hash, salt=con_data.enc_salt1, rand_mult=con_data.enc_salt2)[0]
        key_buff = chacha_poly.decrypt_pack(tx_key, con_data.enc_keys)

        tx_priv_keys = [crypto.decodeint(x) for x in common.chunk(key_buff, 32) if x]
        tx_priv = tx_priv_keys[0]
        tx_additional_priv = tx_priv_keys[1:]

        # Verify mlsag signature
        monero.recode_msg(tx_obj.rct_signatures.p.MGs, encode=False)
        for idx in range(len(tx_obj.vin)):
            if is_simple:
                mix_ring = [x[1] for x in con_data.tx_data.sources[idx].outputs]
                pseudo_out = crypto.decodepoint(bytes(tx_obj.rct_signatures.pseudoOuts[idx]))
                self.assertTrue(mlsag2.ver_rct_mg_simple(
                    mlsag_hash, tx_obj.rct_signatures.p.MGs[idx], mix_ring, pseudo_out
                ))

            else:
                txn_fee_key = crypto.scalarmult_h(tx_obj.rct_signatures.txnFee)
                mix_ring = [[x[1]] for x in con_data.tx_data.sources[idx].outputs]
                self.assertTrue(mlsag2.ver_rct_mg(
                    tx_obj.rct_signatures.p.MGs[idx], mix_ring, tx_obj.rct_signatures.outPk, txn_fee_key, mlsag_hash
                ))

    async def receive(self, tx, all_creds):
        """
        Test transaction receive with known view/spend keys of destinations.
        :return:
        """
        # Unserialize the transaction
        tx_obj = xmrtypes.Transaction()
        reader = xmrserialize.MemoryReaderWriter(bytearray(tx))
        ar1 = xmrserialize.Archive(reader, False)

        await ar1.message(tx_obj, msg_type=xmrtypes.Transaction)
        extras = await monero.parse_extra_fields(tx_obj.extra)
        tx_pub = monero.find_tx_extra_field_by_type(
            extras, xmrtypes.TxExtraPubKey
        ).pub_key
        additional_pub_keys = monero.find_tx_extra_field_by_type(
            extras, xmrtypes.TxExtraAdditionalPubKeys
        )
        num_outs = len(tx_obj.vout)
        num_received = 0

        # Try to receive tsx outputs with each account.
        tx_money_got_in_outs = collections.defaultdict(lambda: 0)
        outs = []

        for idx, creds in enumerate(all_creds):
            wallet_subs = {}
            for account in range(0, 5):
                monero.compute_subaddresses(creds, account, range(5), wallet_subs)

            derivation = monero.generate_key_derivation(
                crypto.decodepoint(tx_pub), creds.view_key_private
            )
            additional_derivations = []
            if additional_pub_keys and additional_pub_keys.data:
                for x in additional_pub_keys.data:
                    additional_derivations.append(
                        monero.generate_key_derivation(
                            crypto.decodepoint(x), creds.view_key_private
                        )
                    )

            for ti, to in enumerate(tx_obj.vout):
                tx_scan_info = monero.check_acc_out_precomp(
                    to, wallet_subs, derivation, additional_derivations, ti
                )
                if not tx_scan_info.received:
                    continue

                num_received += 1
                tx_scan_info = monero.scan_output(
                    creds, tx_obj, ti, tx_scan_info, tx_money_got_in_outs, outs, False
                )

                # Check spending private key correctness
                self.assertTrue(
                    crypto.point_eq(
                        crypto.decodepoint(tx_obj.rct_signatures.outPk[ti].mask),
                        crypto.gen_c(tx_scan_info.mask, tx_scan_info.amount),
                    )
                )

                self.assertTrue(
                    crypto.point_eq(
                        crypto.decodepoint(tx_obj.vout[ti].target.key),
                        crypto.scalarmult_base(tx_scan_info.in_ephemeral),
                    )
                )

        # All outputs have to be successfully received
        self.assertEqual(num_outs, num_received)
