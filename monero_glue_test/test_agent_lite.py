#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
import unittest
import pkg_resources
import aiounittest
import binascii
import collections

from monero_serialize import xmrserialize, xmrtypes, xmrboost
from monero_glue import trezor_lite, agent_lite
from monero_glue.xmr import wallet, monero, crypto
import zlib


class AgentLiteTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(AgentLiteTest, self).__init__(*args, **kwargs)

    async def test_tx_sign_simple(self):
        """
        Testing tx signature, simple, multiple inputs
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns01.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))

        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns02.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign_sub_dest(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns03.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign_sub_2dest(self):
        """
        Testing tx signature, one input. non-simple RCT
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns04.txt'))
        unsigned_tx = zlib.decompress(binascii.unhexlify(unsigned_tx_c))
        await self.tx_sign_unsigned(unsigned_tx)

    async def test_tx_sign_pending01_boost_full_2dest(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        pending_hex = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_pending01.txt'))
        pending_bin = binascii.unhexlify(pending_hex)
        await self.tx_sign_pending_boost(pending_bin)

    async def test_tx_sign_pending02_boost_full_sub_3dest(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        pending_hex = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_pending02.txt'))
        pending_bin = binascii.unhexlify(pending_hex)
        await self.tx_sign_pending_boost(pending_bin)

    async def test_tx_sign_uns01_boost_full_2dest(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns_enc01.txt'))

        creds = self.get_creds()
        unsigned_tx = await wallet.load_unsigned_tx(creds.view_key_private, unsigned_tx_c)
        await self.tx_sign_unsigned_msg(unsigned_tx)

    async def test_tx_sign_uns01_boost_full_2dest_sub(self):
        """
        Testing tx signature, one input. full RCT, boost serialized
        :return:
        """
        unsigned_tx_c = pkg_resources.resource_string(__name__, os.path.join('data', 'tsx_uns_enc02.txt'))

        creds = self.get_creds()
        unsigned_tx = await wallet.load_unsigned_tx(creds.view_key_private, unsigned_tx_c)
        await self.tx_sign_unsigned_msg(unsigned_tx)

    async def tx_sign_unsigned_msg(self, unsigned_tx):
        """
        Signs tx stored in unsigned tx message
        :param unsigned_tx:
        :return:
        """
        tagent = self.init_agent()
        txes = await tagent.sign_unsigned_tx(unsigned_tx)
        return await self.receive(txes[0])

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
        await self.receive(txes[0])

    async def receive(self, tx):
        """
        Test transaction receive with known view/spend keys of destinations.
        :return:
        """
        wallet_creds = [self.get_creds(), self.get_creds_01(), self.get_creds_02()]

        # Unserialize the transaction
        tx_obj = xmrtypes.Transaction()
        reader = xmrserialize.MemoryReaderWriter(bytearray(tx))
        ar1 = xmrserialize.Archive(reader, False)

        await ar1.message(tx_obj, msg_type=xmrtypes.Transaction)
        extras = await monero.parse_extra_fields(tx_obj.extra)
        tx_pub = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraPubKey).pub_key
        additional_pub_keys = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraAdditionalPubKeys)
        num_outs = len(tx_obj.vout)
        num_received = 0

        # Try to receive tsx outputs with each account.
        tx_money_got_in_outs = collections.defaultdict(lambda: 0)
        outs = []

        for idx, creds in enumerate(wallet_creds):
            wallet_subs = {}
            for account in range(0, 5):
                monero.compute_subaddresses(creds, account, range(5), wallet_subs)

            derivation = monero.generate_key_derivation(crypto.decodepoint(tx_pub), creds.view_key_private)
            additional_derivations = []
            if additional_pub_keys and additional_pub_keys.data:
                for x in additional_pub_keys.data:
                    additional_derivations.append(
                        monero.generate_key_derivation(crypto.decodepoint(x), creds.view_key_private))

            for ti, to in enumerate(tx_obj.vout):
                tx_scan_info = monero.check_acc_out_precomp(to, wallet_subs, derivation, additional_derivations, ti)
                if not tx_scan_info.received:
                    continue

                num_received += 1
                tx_scan_info = monero.scan_output(creds, tx_obj, ti, tx_scan_info, tx_money_got_in_outs, outs, False)

                # Check spending private key correctness
                self.assertTrue(crypto.point_eq(crypto.decodepoint(tx_obj.rct_signatures.outPk[ti].mask),
                                                crypto.gen_c(tx_scan_info.mask, tx_scan_info.amount)))

                self.assertTrue(crypto.point_eq(crypto.decodepoint(tx_obj.vout[ti].target.key),
                                                crypto.scalarmult_base(tx_scan_info.in_ephemeral)))

        # All outputs have to be successfully received
        self.assertEqual(num_outs, num_received)

    def get_creds(self):
        """
        Wallet credentials
        :return:
        """
        return monero.AccountCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'4ce88c168e0f5f8d6524f712d5f8d7d83233b1e7a2a60b5aba5206cc0ea2bc08'),
            priv_spend_key=crypto.b16_to_scalar(b'f2644a3dd97d43e87887e74d1691d52baa0614206ad1b0c239ff4aa3b501750a'),
            network_type=monero.NetworkTypes.TESTNET)

    def get_creds_01(self):
        """
        Wallet 02 credentials
        :return:
        """
        return monero.AccountCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'42ba20adb337e5eca797565be11c9adb0a8bef8c830bccc2df712535d3b8f608'),
            priv_spend_key=crypto.b16_to_scalar(b'b0ef6bd527b9b23b9ceef70dc8b4cd1ee83ca14541964e764ad23f5151204f0f'),
            network_type=monero.NetworkTypes.TESTNET)

    def get_creds_02(self):
        """
        Wallet 01 credentials
        :return:
        """
        return monero.AccountCreds.new_wallet(
            priv_view_key=crypto.b16_to_scalar(b'9e7aba8ae9ee134e5d5464d9145a4db26793d7411af7d06f20e755cb2a5ad50f'),
            priv_spend_key=crypto.b16_to_scalar(b'283d8bab1aeaee8f8b5aed982fc894c67d3e03db9006e488321c053f5183310d'),
            network_type=monero.NetworkTypes.TESTNET)

    def init_trezor(self):
        """
        Initialize new trezor instance
        :return:
        """
        trez = trezor_lite.TrezorLite()
        trez.creds = self.get_creds()
        return trez

    def init_agent(self):
        """
        Initialize new agent instance
        :return:
        """
        return agent_lite.Agent(self.init_trezor())


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


